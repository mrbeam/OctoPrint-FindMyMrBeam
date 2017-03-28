#!/usr/bin/env python
# coding=utf-8

import octoprint.plugin
import octoprint.util
import octoprint.events

import flask
import requests
import netaddr
import socket

LOCALHOST = netaddr.IPNetwork("127.0.0.0/8")

class FindMyMrBeamPlugin(octoprint.plugin.StartupPlugin,
						 octoprint.plugin.SettingsPlugin,
						 octoprint.plugin.BlueprintPlugin,
						 octoprint.plugin.EventHandlerPlugin):

	def __init__(self):
		self._port = None
		self._thread = None
		self._url = None
		self._client_seen = False

		from random import choice
		import string
		chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
		self._secret = "".join(choice(chars) for _ in range(32))

	def initialize(self):
		self._url = self._settings.get(["url"])

	##~~ SettingsPlugin

	def get_settings_defaults(self):
		return dict(url="http://find.mr-beam.org:5000/registry",
		            interval_client=300.0,
		            interval_noclient=60.0,
					# configured in config.yaml in appearance:{name: aBook}
		            instance_with_name=u"{name}",
		            instance_with_host=u"{host}",
					instance_dev_name=u"MrBeam Development on '{}'",
		            disable_if_exists=[],
		            public=dict(uuid=None,
		                        scheme=None,
		                        port=None,
		                        path=None,
		                        httpUser=None,
		                        httpPass=None))

	##~~ StartupPlugin

	def on_startup(self, host, port):
		if self._url and self._not_disabled():
			self._start_update_thread(host, port)

	##~~ BlueprintPlugin

	def is_blueprint_protected(self):
		return False

	@octoprint.plugin.BlueprintPlugin.route("/<secret>.gif", methods=["GET"])
	def is_online_gif(self, secret):

		if self._secret != secret:
			flask.abort(404)

		# send a transparent 1x1 px gif
		import base64
		response = flask.make_response(bytes(base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")))
		response.headers["Content-Type"] = "image/gif"
		return response


	##~~ EventHandlerPlugin

	def on_event(self, event, payload):
		if not event in (octoprint.events.Events.CLIENT_OPENED,):
			return
		self._logger.info("Client seen, switching to slower interval for FindMyMrBeam registrations")
		self._client_seen = True

	##~~ internal helpers

	def _find_name(self):
		device_name = ""
		name = self._settings.global_get(["appearance", "name"])
		if name:
			device_name = self._settings.get(["instance_with_name"]).format(name=name)
		else:
			device_name = self._settings.get(["instance_with_host"]).format(host=socket.gethostname())

		if not device_name.lower().startswith("mrbeam"):
			device_name = self._settings.get(["instance_dev_name"]).format(device_name)

		return device_name

	def _find_color(self):
		return self._settings.global_get(["appearance", "color"])

	def _get_setting(self, global_paths, local_path, default_value=None, validator=None):
		if validator is None:
			validator = lambda x: x is not None

		for global_path in global_paths:
			value = self._settings.global_get(global_path, merged=True)
			if validator(value):
				return value

		value = self._settings.get(local_path)
		if validator(value):
			return value

		return default_value

	def _start_update_thread(self, host, port):
		# determine port to use, first try discovery plugin, then our settings
		port = self._get_setting([["plugins", "discovery", "publicPort"], ],
		                         ["public", "port"],
		                         default_value=port)

		# determine scheme (http/https) to use
		scheme = self._get_setting([["plugins", "discovery", "publicScheme"], ],
		                           ["public", "scheme"],
		                           default_value="http")

		# determine uuid to use
		uuid = self._get_setting([["plugins", "discovery", "upnpUuid"], ],
		                         ["public", "uuid"])
		if uuid is None:
			import uuid as u
			uuid = str(u.uuid4())
			self._settings.set(["public", "uuid"], uuid)
			self._settings.save()

		# determine path to use
		path = self._get_setting([["plugins", "discovery", "pathPrefix"],
		                          ["server", "reverseProxy", "prefixFallback"]],
		                         ["public", "path"],
		                         default_value="/")

		# determine http user and password to use
		http_user = self._get_setting([["plugins", "discovery", "httpUsername"], ],
		                              ["public", "httpUser"])
		http_password = self._get_setting([["plugins", "discovery", "httpPassword"], ],
		                                  ["public", "httpPass"])

		# start registration thread
		self._logger.info("Registering with FindMyMrBeam at {}".format(self._url))
		self._thread = octoprint.util.RepeatedTimer(self._get_interval,
		                                            self._perform_update_request,
		                                            args=(uuid, scheme, port, path),
		                                            kwargs=dict(http_user=http_user, http_password=http_password),
		                                            run_first=True,
		                                            condition=self._not_disabled,
		                                            on_condition_false=self._on_disabled)
		self._thread.start()

	def _get_interval(self):
		if self._client_seen:
			interval = self._settings.get_float(["interval_client"])
		else:
			interval = self._settings.get_float(["interval_noclient"])
		return interval

	def _not_disabled(self):
		import os
		for path in self._settings.get(["disable_if_exists"]):
			if os.path.exists(path):
				return False
		return True

	def _on_disabled(self, *args, **kwargs):
		self._logger.info("Registration with FindMyMrBeam disabled.")

	def _perform_update_request(self, uuid, scheme, port, path, http_user=None, http_password=None):
		urls = []

		def compile_url(addr):
			return self._compile_url(scheme,
			                         addr,
			                         port,
			                         path,
			                         http_user=http_user,
			                         http_password=http_password)

		# all ips
		for addr in octoprint.util.interface_addresses():
			if netaddr.IPAddress(addr) in LOCALHOST:
				continue

			urls.append(compile_url(addr))

		hostname = socket.gethostname()

		urls = [compile_url(hostname + ".local"), compile_url(hostname)] + sorted(urls)

		data = dict(uuid=uuid,
		            name=self._find_name(),
		            color=self._find_color(),
		            urls=urls,
		            query="plugin/{}/{}".format(self._identifier, self._secret))

		headers = {"User-Agent": "OctoPrint-FindMyMrBeam/{}".format(self._plugin_version)}

		response = 0
		try:
			r = requests.post(self._url, json=data, headers=headers)
			response = r.status_code
			if r.status_code != 200:
				self._logger.debug("Could not update registration with FindMyMrBeam, got status {}".format(r.status_code))
		except Exception as e:
			response = -1
			self._logger.debug("Error while updating registration with FindMyMrBeam, Exception: %s", e.args)

		self._logger.info("Registration to FindMyMrBeam. response: %s" , response)

	@staticmethod
	def _compile_url(scheme, host, port, path, http_user=None, http_password=None):
		prefix = ""
		if http_user is not None:
			if http_password is not None:
				prefix = "{}:{}@".format(http_user, http_password)
			else:
				prefix = "{}@".format(http_user)
		return "{}://{}{}:{}{}".format(scheme, prefix, host, port, path)


__plugin_name__ = "FindMyMrBeam"

def __plugin_load__():
	global __plugin_implementation__
	__plugin_implementation__ = FindMyMrBeamPlugin()

	global __plugin_hooks__
	__plugin_hooks__ = {}
