#!/usr/bin/env python
# coding=utf-8

import random
import socket
import time

import flask
import netaddr
import octoprint.events
import octoprint.plugin
import octoprint.util
# from flask import request, jsonify, make_response, url_for
import requests
from octoprint.server import NO_CONTENT

from analytics import Analytics

LOCALHOST = netaddr.IPNetwork("127.0.0.0/8")
SUPPORT_STICK_FILE_PATH = '/home/pi/usb_mount/support'

SEARCH_ID_LENGTH = 10
SEARCH_ID_CHARS = "ABCDEFGHKLMNPQRSTUVWXYZ0123456789"  # no IJO

# internal modes
MODE_SUPPORT = "SUPPORT"
MODE_CALIBRATION_TOOL = "CALIBRATION_TOOL"


class FindMyMrBeamPlugin(octoprint.plugin.AssetPlugin,
						 octoprint.plugin.StartupPlugin,
						 octoprint.plugin.SettingsPlugin,
						 # octoprint.plugin.SimpleApiPlugin,
						 octoprint.plugin.BlueprintPlugin,
						 octoprint.plugin.EventHandlerPlugin,
						 octoprint.plugin.TemplatePlugin,
						 octoprint.plugin.EnvironmentDetectionPlugin):
	_socket_getaddrinfo_regular = None

	def __init__(self):
		self._port = None
		self._thread = None
		self._url = None
		self._client_seen = False
		self._registered = None
		self._lastPing = 0
		self._calls = []
		self._public_ip = None
		self._public_ip6 = None
		self._uuid = None
		self._search_id = None
		self._analytics = None

		from random import choice
		import string
		chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
		self._secret = "".join(choice(chars) for _ in range(32))
		self._not_so_secret = ["ping_ap_mode", "find_mrbeam_ping"]
		self._all_secrets = self._not_so_secret + [self._secret]

	def initialize(self):
		self._uuid = self._get_setting([["plugins", "discovery", "upnpUuid"], ], ["public", "uuid"]) or self._generate_uuid()
		self._search_id = self._settings.get(["public", "search_id"]) or self._generate_search_id()
		self._analytics = Analytics(self)
		self._url = self._settings.get(["url"])
		self._logger.info("FindMyMrBeam enabled: %s", self.is_enabled())
		self._analytics.log_enabled(self.is_enabled())
		self.update_frontend()


	def get_additional_environment(self):
		"""
			Mixin: octoprint.plugin.EnvironmentDetectionPlugin
			:return: dict of environment data
			"""
		return dict(
			version=self._plugin_version,
            # uuid and search_id will be None on first boot
			uuid=self._uuid,
			search_id=self._search_id,
		)

	##~~ data providers ##

	"""
	This data is sent to the server during device registration.
	"""
	def _get_server_registry_data(self):
		return dict(_version=__version__,
					uuid=self._uuid,
					search_id=self._search_id,
					name=self._find_name(),
					hostname=socket.gethostname(),
					local_ips=self._get_local_ips(),
					netconnectd_state=self._get_netconnectd_state(),
					modes=self._get_internal_modes(),
					query="plugin/{}/{}".format(self._identifier, self._secret),
					plugin_version=self._get_plugin_version(),
					)


	"""
	This data is sent as a response the the data JSON request coming from the find.mr-beam page in the brwoser
	This is currently not used in production.
	"""
	def _get_local_ping_data(self):
		return dict(_version=__version__,
					uuid=self._uuid,
					search_id=self._search_id,
					name=self._find_name(),
					hostname=socket.gethostname(),
					local_ips=self._get_local_ips(),
					netconnectd_state=self._get_netconnectd_state(),
					modes=self._get_internal_modes(),
					query="plugin/{}/{}".format(self._identifier, self._secret),
					plugin_version=self._get_plugin_version(),
					)

	##~~ SettingsPlugin

	def get_settings_defaults(self):
		return dict(enabled=True,
					url="https://find.mr-beam.org/registry",
					interval_client=300.0,
					interval_noclient=60.0,
					# configured in config.yaml in appearance:{name: aBook}
					instance_with_name=u"{name}",
					instance_with_host=u"{host}",
					instance_dev_name=u"MrBeam Development on '{}'",
					disable_if_exists=[],
					public=dict(uuid=None,
								search_id=None,
								),
					)

	def on_settings_load(self):
		return self.get_frontend_data()

	def on_settings_save(self, data):
		if "enabled" in data:
			enabled = bool(data["enabled"])
			self._logger.info("User changed findmymrbeam enabled to: %s", enabled)
			self._settings.set_boolean(["enabled"], enabled)
			self._analytics.log_enabled(self.is_enabled())
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

	def on_after_startup(self):
		self.start_findmymrbeam()

	##~~ BlueprintPlugin

	def is_blueprint_protected(self):
		return False

	@octoprint.plugin.BlueprintPlugin.route("/<secret>.gif", methods=["GET"])
	def is_online_gif(self, secret):

		if secret not in self._all_secrets:
			flask.abort(404)

		if not self.is_enabled():
			flask.abort(404)

		self._track_ping()

		# send a transparent 1x1 px gif
		import base64
		response = flask.make_response(
			bytes(base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")))
		response.headers["Content-Type"] = "image/gif"
		return response

	@octoprint.plugin.BlueprintPlugin.route("/<secret>.json", methods=["GET", "OPTIONS"])
	def current_status_endpoint(self, secret):

		if secret not in self._all_secrets:
			flask.abort(404)

		if not self.is_enabled():
			flask.abort(404)

		self._track_ping()

		res = dict()
		if flask.request.method == "GET":
			res = self._get_local_ping_data()
		response = flask.make_response(flask.jsonify(res), 200)
		response.headers['Access-Control-Allow-Origin'] = '*'
		return response

	@octoprint.plugin.BlueprintPlugin.route("/analytics_data", methods=["POST"])
	def route_analytics_data(self):
		json_data = None
		try:
			json_data = flask.request.json
		except flask.JSONBadRequest:
			return flask.make_response("Malformed JSON body in request", 400)

		event = json_data.get('event')
		payload = json_data.get('payload', dict())
		self._analytics.log_frontend_event(event, payload)
		return NO_CONTENT

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
			dict(type='settings', name="find.mr-beam", template='findmymrbeam_settings.jinja2', custom_bindings=True)
		]
		return result

	##~~ internal helpers

	def _generate_uuid(self):
		import uuid as u
		temp_uuid = str(u.uuid4())
		self._settings.set(["public", "uuid"], temp_uuid, force=True)
		self._settings.save()
		return temp_uuid

	def _generate_search_id(self):
		self._search_id = ''.join(random.choice(SEARCH_ID_CHARS) for _ in range(SEARCH_ID_LENGTH))
		self._settings.set(["public", "search_id"], self._search_id)
		self._settings.save()

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
		payload = self.get_frontend_data()
		self._plugin_manager.send_plugin_message("findmymrbeam", payload)

	def get_frontend_data(self):
		ping = self._lastPing > 0
		return dict(
			name=self._find_name(),
			uuid=self._uuid,
			enabled=self._settings.get(['enabled']),
			registered=self.is_registered(),
			ping=ping,
			public_ip=self._public_ip,
			public_ip6=self._public_ip6,
			dev=self._settings.get(['dev']),
			searchId=self._search_id
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

	def _get_local_ips(self):
		return [addr for addr in octoprint.util.interface_addresses() if netaddr.IPAddress(addr) not in LOCALHOST]

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

		# start registration thread
		self._logger.info("Registering with FindMyMrBeam at {}".format(self._url))
		self._thread = octoprint.util.RepeatedTimer(self._get_interval,
													self._perform_update_request,
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
		self._analytics.log_pinged(host=my_call['host'], remote_ip=my_call['remote_ip'], referrer=my_call['ref'])
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
			if len(self._get_internal_modes()) > 0:
				enabled = True
			else:
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

	def _get_netconnectd_state(self):
		res = dict(wifi=None, ap=None, wired=None)
		try:
			pluginInfo = self._plugin_manager.get_plugin_info("netconnectd")
			if pluginInfo is not None:
				status = pluginInfo.implementation._get_status()
				if "wifi" in status["connections"]:
					res["wifi"] = status["connections"]["wifi"]
				if "ap" in status["connections"]:
					res["ap"] = status["connections"]["ap"]
				if "wired" in status["connections"]:
					res["wired"] = status["connections"]["wired"]
		except Exception as e:
			self._logger.exception(
				"Exception while reading wifi/ap state from netconnectd: {}".format(e)
			)
		return res

	def _get_internal_modes(self):
		internal_modes = []
		try:
			pluginInfo = self._plugin_manager.get_plugin_info("mrbeam")
			if pluginInfo is not None:
				if pluginInfo.implementation.support_mode:
					internal_modes.append(MODE_SUPPORT)
				if pluginInfo.implementation.calibration_tool_mode:
					internal_modes.append(MODE_CALIBRATION_TOOL)
		except Exception as e:
			self._logger.exception("Exception while reading support mode state from mrbeam: {}".format(e))
		return internal_modes

	def _get_plugin_version(self):
		try:
			pluginInfo = self._plugin_manager.get_plugin_info("mrbeam")
			if pluginInfo is not None and pluginInfo.implementation._plugin_version:
				return pluginInfo.implementation._plugin_version
		except Exception as e:
			self._logger.exception(
				"Exception while reading version from mrbeam: {}".format(e)
			)
		return None

	def _perform_update_request(self):
		try:
			data = self._get_server_registry_data()
			self._logger.debug('server registry data - {}'.format(data))

			headers = {"User-Agent": "OctoPrint-FindMyMrBeam/{}".format(self._plugin_version)}

			ip4_status_code, ip_4body, ip4_err = self._do_request_ipv4(data, headers)
			ip6_status_code, ip_6body, ip6_err = self._do_request_ipv6(data, headers)

			self._public_ip = ip_4body['remote_ip'] if ip_4body is not None and 'remote_ip' in ip_4body else None
			self._public_ip6 = ip_6body['remote_ip'] if ip_6body is not None and 'remote_ip' in ip_6body else None
			self._registered = (ip4_status_code == 200 or ip6_status_code == 200)
			self._analytics.log_registered(self._registered, ip4_status_code, ip6_status_code, ip4_err, ip6_err)
			self.update_frontend()

			if ip4_status_code == 200 or ip6_status_code == 200:
				self._logger.info(
					"FindMyMrBeam registration: OK  - ip4_status: %s, public_ip: %s, ip6_status: %s, "
					"public_ip6: %s, hostname: %s, local_ips: %s, netconnectd_state: %s, internal_modes: %s",
					(ip4_status_code if ip4_status_code > 0 else ip4_err), self._public_ip,
					(ip6_status_code if ip6_status_code > 0 else ip6_err), self._public_ip6,
					data['hostname'], ", ".join(data['local_ips']), data['netconnectd_state'], data['modes'])
			else:
				self._logger.info(
					"FindMyMrBeam registration: ERR - ip4_status: %s, ip6_status: %s, hostname: %s, local_ips: %s, netconnectd_state: %s",
					(ip4_status_code if ip4_status_code > 0 else ip4_err),
					(ip6_status_code if ip6_status_code > 0 else ip6_err),
					data['hostname'], ", ".join(data['local_ips']), data['netconnectd_state'])
		except:
			self._logger.exception("Exception in periodic call of _perform_update_request():")

	def _do_request_ipv4(self, data, headers):
		status_code = 0
		body = None
		err = None
		FindMyMrBeamPlugin._set_ipv4_only()
		try:
			status_code, body, err = self.__do_request(data, headers)
		except Exception as e:
			self._logger.exception("Exception in _do_request_ipv4() while updating registration with FindMyMrBeam:")
		finally:
			FindMyMrBeamPlugin._set_ip_regular()

		return status_code, body, err

	def _do_request_ipv6(self, data, headers):
		status_code = 0
		body = None
		err = None
		FindMyMrBeamPlugin._set_ipv6_only()
		try:
			status_code, body, err = self.__do_request(data, headers)
		except Exception as e:
			self._logger.exception("Exception in _do_request_ipv4() while updating registration with FindMyMrBeam:")
		finally:
			FindMyMrBeamPlugin._set_ip_regular()

		return status_code, body, err

	def __do_request(self, data, headers):
		status_code = 0
		body = None
		err = None
		try:
			r = requests.post(self._url, json=data, headers=headers)
			status_code = r.status_code
			self._logger.debug('request json data - {}'.format(r))
			try:
				body = r.json()
			except ValueError as e:
				self._logger.warn("Error while parsing JSON from response: %s", e)
		except requests.exceptions.RequestException as e:
			err = 'requests.{}'.format(type(e).__name__)
			status_code = -1
		except Exception as e:
			err = type(e).__name__
			status_code = -1
			self._logger.exception(
				"Exception in __do_request() while updating registration with FindMyMrBeam")

		return status_code, body, err

	@staticmethod
	def _set_ipv4_only():
		if FindMyMrBeamPlugin._socket_getaddrinfo_regular is None:
			FindMyMrBeamPlugin._socket_getaddrinfo_regular = socket.getaddrinfo
		socket.getaddrinfo = FindMyMrBeamPlugin.__socket_getaddrinfo_ipv4_only

	@staticmethod
	def _set_ipv6_only():
		if FindMyMrBeamPlugin._socket_getaddrinfo_regular is None:
			FindMyMrBeamPlugin._socket_getaddrinfo_regular = socket.getaddrinfo
		socket.getaddrinfo = FindMyMrBeamPlugin.__socket_getaddrinfo_ipv6_only

	@staticmethod
	def _set_ip_regular():
		if FindMyMrBeamPlugin._socket_getaddrinfo_regular is not None:
			socket.getaddrinfo = FindMyMrBeamPlugin._socket_getaddrinfo_regular

	@staticmethod
	def __socket_getaddrinfo_ipv4_only(*args, **kwargs):
		responses = FindMyMrBeamPlugin._socket_getaddrinfo_regular(*args, **kwargs)
		return [response
				for response in responses
				if response[0] == socket.AF_INET]

	@staticmethod
	def __socket_getaddrinfo_ipv6_only(*args, **kwargs):
		responses = FindMyMrBeamPlugin._socket_getaddrinfo_regular(*args, **kwargs)
		return [response
				for response in responses
				if response[0] == socket.AF_INET6]


__plugin_name__ = "FindMyMrBeam"


def __plugin_load__():
	global __plugin_implementation__
	__plugin_implementation__ = FindMyMrBeamPlugin()

	global __plugin_hooks__
	__plugin_hooks__ = {}

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
