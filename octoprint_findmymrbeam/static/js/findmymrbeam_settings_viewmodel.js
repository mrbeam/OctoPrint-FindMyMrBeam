$(function () {
    const FRONTEND_VERIFIED = 'findmrbeam_verified';

    function FindmymrbeamSettingsViewModel(params) {
        var self = this;
        window.mrbeam.viewModels['findmymrbeamSettingsViewModel'] = self;
        self.settings = params[0];

        self.enabled = ko.observable(null);

        self.name = ko.observable(null);
        self.uuid = ko.observable(null);
        self.searchId = ko.observable(null);
        self.registered = ko.observable(null);
        self.ping = ko.observable(false);
        self.public_ip = ko.observable(null);
        self.public_ip6 = ko.observable(null);
        self.find_url = ko.computed(function () {
            return "https://find.mr-beam.org"
                + "?name=" + encodeURIComponent(self.name())
                + "&uuid=" + encodeURIComponent(self.uuid())
                + "&search_id=" + encodeURIComponent(self.searchId())
                + "&public_ip=" + encodeURIComponent(self.public_ip())
                + "&public_ip6=" + encodeURIComponent(self.public_ip6())
                ;
        });
        self.verified = ko.observable(false);
        self.verification_response = null;

        self.onAllBound = function () {
            self.enabled = self.settings.settings.plugins.findmymrbeam.enabled;

            self.name(self.settings.settings.plugins.findmymrbeam.name());
            self.uuid(self.settings.settings.plugins.findmymrbeam.uuid());
            self.searchId(self.settings.settings.plugins.findmymrbeam.searchId());
            self.registered(self.settings.settings.plugins.findmymrbeam.registered());
            self.ping(self.settings.settings.plugins.findmymrbeam.ping());

            self.enabled.subscribe(function () {
                self.sendToExtension()
            })
        };

        self.onStartupComplete = function () {
            self.verifyByFrontend();
            self.sendToExtension()
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

        self.sendToExtension = function () {
            if (self.enabled()) {
                // send to find.mr-beam extension's contentScript
                // TODO: should be done whenever searchID changes...
                let payload = {
                    uui: self.uuid(),
                    searchId: self.searchId(),
                    name: self.name()
                }
                window.postMessage(payload, window.origin)
            }
        }

        self.verifyByFrontend = function () {
            if (self.registered()) {
                let registryUrl = "https://find.mr-beam.org/verify";
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
                        self.send_fontend_event(FRONTEND_VERIFIED, payload, "analytics_data")
                    })
            } else {
                self.verified(false);
            }
        };

        self.send_fontend_event = function (event, payload, endpoint) {
            return self._send(event, payload, endpoint);
        };

        self._send = function (event, payload, endpoint) {
            let data = {
                event: event,
                payload: payload || {}
            };
            return $.ajax({
                url: "plugin/findmymrbeam/" + endpoint,
                type: "POST",
                dataType: "json",
                contentType: "application/json; charset=UTF-8",
                data: JSON.stringify(data),
            });
        }
    }

    // view model class, parameters for constructor, container to bind to
    OCTOPRINT_VIEWMODELS.push([
        FindmymrbeamSettingsViewModel,

        // e.g. loginStateViewModel, settingsViewModel, ...
        ["settingsViewModel"],

        // e.g. #settings_plugin_mrbeam, #tab_plugin_mrbeam, ...
        ["#settings_plugin_findmymrbeam"]
    ]);
});
