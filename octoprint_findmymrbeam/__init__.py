#!/usr/bin/env python
# coding=utf-8

import octoprint.plugin
import octoprint.util
import octoprint.events

import flask
import requests
import netaddr
import time
import socket

LOCALHOST = netaddr.IPNetwork("127.0.0.0/8")

class FindMyMrBeamPlugin(octoprint.plugin.AssetPlugin,
						 octoprint.plugin.StartupPlugin,
						 octoprint.plugin.SettingsPlugin,
						 octoprint.plugin.BlueprintPlugin,
						 octoprint.plugin.EventHandlerPlugin,
						 octoprint.plugin.TemplatePlugin):

	def __init__(self):
		self._port = None
		self._thread = None
		self._url = None
		self._client_seen = False
		self._registered = None
		self._lastPing = 0
		self._calls = []
		self._public_ip = None
		self._uuid = None

		from random import choice
		import string
		chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
		self._secret = "".join(choice(chars) for _ in range(32))
		self._not_so_secret = "ping_ap_mode"

	def initialize(self):
		self._url = self._settings.get(["url"])
		self._logger.info("FindMyMrBeam enabled: %s", self.is_enabled())
		self.update_frontend()

	##~~ SettingsPlugin

	def get_settings_defaults(self):
		return dict(enabled=True,
					url="http://find.mr-beam.org/registry",
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


	def on_settings_load(self):
		return self.get_state_data()

	def on_settings_save(self, data):
		if "enabled" in data:
			enabled = bool(data["enabled"])
			self._logger.info("User changed findmymrbeam enabled to: %s", enabled)
			self._settings.set_boolean(["enabled"], enabled)
			self.start_findmymrbeam()

	##~~ AssetPlugin mixin

	def get_assets(self):
		# Define your plugin's asset files to automatically include in the
		# core UI here.
		assets = dict(
			js=["js/findmymrbeam_settings_viewmodel.js"],
		)
		return assets

	##~~ StartupPlugin

	def on_startup(self, host, port):
		self._port = port
		self.start_findmymrbeam()

	##~~ BlueprintPlugin

	def is_blueprint_protected(self):
		return False

	@octoprint.plugin.BlueprintPlugin.route("/<secret>.gif", methods=["GET"])
	def is_online_gif(self, secret):

		if secret not in (self._secret, self._not_so_secret):
			flask.abort(404)

		if not self.is_enabled():
			flask.abort(404)

		self._track_ping()

		# send a transparent 1x1 px gif
		import base64
		response = flask.make_response(bytes(base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")))
		response.headers["Content-Type"] = "image/gif"
		return response


	##~~ EventHandlerPlugin

	def on_event(self, event, payload):
		if not event in (octoprint.events.Events.CLIENT_OPENED,):
			return
		if not self._client_seen and self.is_enabled():
			self._logger.info("Client seen, switching to slower interval for FindMyMrBeam registrations")
		self._client_seen = True
		self.update_frontend()


	##~~ TemplatePlugin mixin

	def get_template_configs(self):
		result = [
			dict(type='settings', name="find.mr-beam.org", template='findmymrbeam_settings.jinja2', custom_bindings=True)
		]
		return result

	##~~ internal helpers

	def is_registered(self):
		"""
		Is device registered at find.mr-beam.org?
		:return: Bool True if registered, False if registering failed or if feature is disabled, None if not registered yet
		:rtype:
		"""
		if self.is_enabled():
			return self._registered
		else:
			return False

	def update_frontend(self):
		payload = self.get_state_data()
		self._plugin_manager.send_plugin_message("findmymrbeam", payload)

	def get_state_data(self):
		ping = self._lastPing > 0
		return dict(
			name = self._find_name(),
			uuid = self._uuid,
			enabled=self._settings.get(['enabled']),
			registered=self.is_registered(),
			ping=ping,
			public_ip=self._public_ip,
		)

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

	def start_findmymrbeam(self):
		if self._url and self.is_enabled():
			self._start_update_thread()

	def _start_update_thread(self):
		if self._thread:
			self._logger.warn("_start_update_thread() thread object already present. skipping")
			return

		# determine port to use, first try discovery plugin, then our settings
		port = self._get_setting([["plugins", "discovery", "publicPort"], ],
		                         ["public", "port"],
		                         default_value=self._port)

		# determine scheme (http/https) to use
		scheme = self._get_setting([["plugins", "discovery", "publicScheme"], ],
		                           ["public", "scheme"],
		                           default_value="http")

		# determine uuid to use
		self._uuid = self._get_setting([["plugins", "discovery", "upnpUuid"], ],
		                         ["public", "uuid"])
		if self._uuid is None:
			import uuid as u
			self._uuid = str(u.uuid4())
			self._settings.set(["public", "uuid"], self._uuid)
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
		                                            args=(self._uuid, scheme, port, path),
		                                            kwargs=dict(http_user=http_user, http_password=http_password),
		                                            run_first=True,
		                                            condition=self._not_disabled,
		                                            on_condition_false=self._on_disabled)
		self._thread.start()

	def _track_ping(self):
		my_call = dict(host=flask.request.host,
		               ref=flask.request.referrer,
		               remote_ip=flask.request.headers.get("X-Forwarded-For"))
		if not my_call in self._calls:
			self._calls.append(my_call)
			self._logger.info("First ping received from: %s", my_call)
			self._logger.info("All unique pings: %s", self._calls)
		self._lastPing = time.time()
		self.update_frontend()

	def _get_interval(self):
		if self._client_seen:
			interval = self._settings.get_float(["interval_client"])
		else:
			interval = self._settings.get_float(["interval_noclient"])
		return interval

	def is_enabled(self):
		return self._not_disabled()

	def _not_disabled(self):
		enabled = False
		try:
			enabled = self._settings.get(["enabled"])
			if enabled:
				import os
				for path in self._settings.get(["disable_if_exists"]):
					if os.path.exists(path):
						enabled = False
		except:
			self._logger.exception("Exception in _not_disabled(): ")
		return enabled

	def _on_disabled(self, *args, **kwargs):
		"""
		found out that this one is never called, even if _not_disabled() returned False.
		Not sure why, do not want to debug further atm
		"""
		try:
			self._logger.info("Registration with FindMyMrBeam disabled.")
		except:
			self._logger.exception("Exception in _on_disabled(): ")

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

		urls = [compile_url(hostname + ".local"),
		        compile_url(hostname + ".fritz.box"),
		        compile_url(hostname)]\
		       + sorted(urls)

		data = dict(uuid=uuid,
		            name=self._find_name(),
		            color=self._find_color(),
		            urls=urls,
		            query="plugin/{}/{}".format(self._identifier, self._secret))

		headers = {"User-Agent": "OctoPrint-FindMyMrBeam/{}".format(self._plugin_version)}

		status_code = 0
		body = None
		try:
			r = requests.post(self._url, json=data, headers=headers)
			status_code = r.status_code
			try:
				body = r.json()
			except ValueError as e:
				self._logger.warn("Error while parsing JSON from response: %s", e)
		except requests.ConnectionError as e:
			status_code = -1
		except Exception as e:
			status_code = -1
			self._logger.warn("Error while updating registration with FindMyMrBeam, Exception: %s", e.args)

		self._public_ip = body['remote_ip'] if body is not None and 'remote_ip' in body else None
		self._registered = (status_code == 200)
		self.update_frontend()

		if status_code == 200:
			self._logger.info("FindMyMrBeam registration: OK  - status_code: %s, public_ip: %s, url candidates: %s" , status_code, self._public_ip, urls)
		else:
			self._logger.info("FindMyMrBeam registration: ERR - status_code: %s, body: %s", status_code, body)

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
