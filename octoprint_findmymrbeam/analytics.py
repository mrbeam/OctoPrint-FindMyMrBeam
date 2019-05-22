






class Analytics(object):

	ANALYTICS_DATA =    "MrbAnalyticsData"

	EVENT_ENABLED =     'findmrbeam_enabled'
	EVENT_REGISTERED =  'findmrbeam_registered'
	EVENT_PINGED =      'findmrbeam_pinged'

	def __init__(self, plugin):
		self._plugin = plugin
		self._logger = self._plugin._logger

		self._last_registered = None
		self._known_pings = []

	def log_enabled(self, enabled):
		try:
			data = dict(
				user_enabled = enabled
			)
			self._send_op_event(eventname=self.EVENT_ENABLED, data=data)
		except:
			self._logger.exception("Exception while writing enabled state to analytics.")

	def log_registered(self, succ, ip4_status_code, ip6_status_code, ip4_err=None, ip6_err=None):
		try:
			data = dict(
				succ = succ,
				status_code_ip4 = ip4_status_code,
				status_code_ip6 = ip6_status_code,
				err_ip4 = ip4_err,
				err_ip6 = ip6_err,
			)
			if data != self._last_registered:
				self._last_registered = data
				self._send_op_event(eventname=self.EVENT_REGISTERED, data=data)
		except:
			self._logger.exception("Exception while writing rigistered state to analytics.")

	def log_pinged(self, host, remote_ip, referrer):
		try:
			data = dict(
				host = host,
				remote_ip = remote_ip,
				referrer = referrer
			)
			if data not in self._known_pings:
				self._known_pings.append(data)
				self._send_op_event(eventname=self.EVENT_PINGED, data=data)
		except:
			self._logger.exception("Exception while writing pinged state to analytics.")


	def _send_op_event(self, eventname, data):
		payload =dict(
			plugin = 'findmymrbeam',
			eventname = eventname,
			data = data
		)
		self._plugin._event_bus.fire(self.ANALYTICS_DATA, payload)



