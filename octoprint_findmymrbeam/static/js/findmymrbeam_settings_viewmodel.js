$(function () {
    const FRONTEND_VERIFIED = 'findmrbeam_verified';

    function FindmymrbeamSettingsViewModel(params) {
        var self = this;
        window.mrbeam.viewModels['findmymrbeamSettingsViewModel'] = self;

        self.settings = params[0];
        self.loginState = params[1];

        self.name = ko.observable(null);
        self.uuid = ko.observable(null);
        self.registered = ko.observable(null);
        self.ping = ko.observable(false);
        self.public_ip = ko.observable(null);
        self.public_ip6 = ko.observable(null);
        self.find_url = ko.computed(function(){
            return "https://find.mr-beam.org"
                +"?name=" + encodeURIComponent(self.name())
                +"&uuid=" + encodeURIComponent(self.uuid())
                +"&public_ip=" + encodeURIComponent(self.public_ip())
                +"&public_ip6=" + encodeURIComponent(self.public_ip6())
                ;
        });
        self.verified = ko.observable(false);
        self.verification_response = null;

        self.onAllBound = function () {
            self.name(self.settings.settings.plugins.findmymrbeam.name());
            self.uuid(self.settings.settings.plugins.findmymrbeam.uuid());
            self.registered(self.settings.settings.plugins.findmymrbeam.registered());
            self.ping(self.settings.settings.plugins.findmymrbeam.ping());
        };

        self.onStartupComplete = function () {
            self.verifyByFrontend();
        };

        self.onSettingsShown = function () {
            self.verifyByFrontend();
        };

        self.onDataUpdaterPluginMessage = function (plugin, data) {
            if (plugin !== "findmymrbeam" || !data) return;
            if ('name' in data) {
                self.name(data['name']);
            }
            if ('uuid' in data) {
                self.uuid(data['uuid']);
            }
            if ('registered' in data) {
                self.registered(data['registered']);
            }
            if ('ping' in data) {
                self.ping(data['ping']);
            }
            if ('public_ip' in data) {
                self.public_ip(data['public_ip']);
            }
            if ('public_ip6' in data) {
                self.public_ip6(data['public_ip6']);
            }
            self.verifyByFrontend();
        };

        self.verifyByFrontend = function() {
            if (self.registered()) {
                let registryUrl = "http://find.mr-beam.org/verify";
                let requestData = {
                    uuid: self.uuid(),
                    frontendHost: document.location.host
                };
                let status = null;
                $.get(registryUrl, requestData)
                    .done(function (response, textStatus, jqXHR) {
                        self.verified(response['verified'] || false);
                        self.verification_response = response;
                        status = jqXHR.status;
                    })
                    .fail(function (jqXHR) {
                        self.verified(false);
                        self.verification_response = null;
                        status = jqXHR.status;
                    })
                    .always(function () {
                        let payload = {
                            verified: self.verified(),
                            status_code: status
                        };
                        self.send_fontend_event(FRONTEND_VERIFIED, payload)
                    })
            } else {
                self.verified(false);
            }
        };

        self.send_fontend_event = function (event, payload) {
            return self._send(event, payload);
        };

        self._send = function (event, payload) {
            if(self.loginState.isUser()){
                let data = {
                    event: event,
                    payload: payload || {}
                };
                return OctoPrint.simpleApiCommand("findmymrbeam", "analytics_data", data);
            } else {
                // TODO tbd. if store and send later?
            }
        }
    }

    // view model class, parameters for constructor, container to bind to
    OCTOPRINT_VIEWMODELS.push([
        FindmymrbeamSettingsViewModel,

        // e.g. loginStateViewModel, settingsViewModel, ...
        ["settingsViewModel", "loginStateViewModel"],

        // e.g. #settings_plugin_mrbeam, #tab_plugin_mrbeam, ...
        ["#settings_plugin_findmymrbeam"]
    ]);
});
