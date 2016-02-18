// Use LANG environment variable to choose locale
pref("intl.locale.matchOS", true);

// Disable default browser checking.
pref("browser.shell.checkDefaultBrowser", false);

// Don't disable our bundled extensions in the application directory
pref("extensions.autoDisableScopes", 11);
pref("extensions.shownSelectionUI", true);

// Disable "alt" as a shortcut key to open full menu bar. Conflicts with "alt" as a modifier
pref("ui.key.menuAccessKeyFocuses", false);

// Disable the GeoLocation API for content
//pref("geo.enabled", false);

// Make sure that the request URL of the GeoLocation backend is empty
//pref("geo.wifi.uri", "");

// Disable Pocket and make sure that the request URLs of the Pocket are empty
pref("browser.pocket.enabled", false);
pref("browser.pocket.api", "");
pref("browser.pocket.site", "");
pref("browser.pocket.oAuthConsumerKey", "");
pref("browser.pocket.useLocaleList", false);
pref("browser.pocket.enabledLocales", "");

// Disable Freedom Violating DRM Feature
pref("browser.eme.ui.enabled", false);
pref("media.eme.enabled", false);
pref("media.eme.apiVisible", false);

// Default to classic view for about:newtab
pref("browser.newtabpage.enhanced", false);

// Poodle attack
pref("security.tls.version.min", 1);

// Don't call home for blacklisting
pref("extensions.blocklist.enabled", false);

// Disable plugin installer
pref("plugins.hide_infobar_for_missing_plugin", true);
pref("plugins.hide_infobar_for_outdated_plugin", true);
pref("plugins.notifyMissingFlash", false);

//https://developer.mozilla.org/en-US/docs/Web/API/MediaSource
//pref("media.mediasource.enabled",true);

//Speeding it up
pref("network.http.pipelining", true);
pref("network.http.proxy.pipelining", true);
pref("network.http.pipelining.maxrequests", 10);
pref("nglayout.initialpaint.delay", 0);

// Disable third party cookies
pref("network.cookie.cookieBehavior", 1);

// Prevent EULA dialog to popup on first run
pref("browser.EULA.override", true);

// disable app updater url
pref("app.update.url", "http://127.0.0.1/");"

// Set useragent to Firefox compatible
pref("general.useragent.compatMode.firefox", true);
// Spoof the useragent to a generic one
//pref("general.useragent.compatMode.firefox", true);
// Spoof the useragent to a generic one
//pref("general.useragent.override", "Mozilla/5.0 (Windows NT 6.1; rv:41.0) Gecko/20100101 Firefox/41.0");
//pref("general.appname.override", "Netscape");
//pref("general.appversion.override", "41.0");
//pref("general.buildID.override", "Gecko/20100101");
//pref("general.oscpu.override", "Windows NT 6.1");
//pref("general.platform.override", "Win32");

// Privacy & Freedom Issues
// https://webdevelopmentaid.wordpress.com/2013/10/21/customize-privacy-settings-in-mozilla-firefox-part-1-aboutconfig/
// https://panopticlick.eff.org
// http://ip-check.info
// http://browserspy.dk
// https://wiki.mozilla.org/Fingerprinting
// http://www.browserleaks.com
// http://fingerprint.pet-portal.eu
pref("privacy.donottrackheader.enabled", true);
pref("privacy.donottrackheader.value", 1);
pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);
pref("browser.safebrowsing.enabled", false);
pref("browser.safebrowsing.malware.enabled", false);
//pref("services.sync.privacyURL", "https://www.gnu.org/software/gnuzilla/");
pref("social.enabled", false);
pref("social.remote-install.enabled", false);
pref("datareporting.healthreport.uploadEnabled", false);
pref("datareporting.healthreport.about.reportUrl", "127.0.0.1");
pref("datareporting.healthreport.documentServerURI", "127.0.0.1");
pref("healthreport.uploadEnabled", false);
pref("social.toast-notifications.enabled", false);
pref("datareporting.policy.dataSubmissionEnabled", false);
pref("datareporting.healthreport.service.enabled", false);
pref("browser.slowStartup.notificationDisabled", true);
pref("network.http.sendRefererHeader", 2);
pref("network.http.referer.spoofSource", true);
//http://grack.com/blog/2010/01/06/3rd-party-cookies-dom-storage-and-privacy/
//pref("dom.storage.enabled", false);
pref("dom.event.clipboardevents.enabled",false);
pref("network.prefetch-next", false);
pref("network.dns.disablePrefetch", true);
pref("network.http.sendSecureXSiteReferrer", false);
pref("toolkit.telemetry.enabled", false);
// Do not tell what plugins do we have enabled: https://mail.mozilla.org/pipermail/firefox-dev/2013-November/001186.html
pref("plugins.enumerable_names", "");
pref("plugin.state.flash", 1);
// Do not autoupdate search engines
pref("browser.search.update", false);
// Warn when the page tries to redirect or refresh
//pref("accessibility.blockautorefresh", true);
pref("dom.battery.enabled", false);
pref("device.sensors.enabled", false);
pref("camera.control.face_detection.enabled", false);
pref("camera.control.autofocus_moving_callback.enabled", false);
pref("network.http.speculative-parallel-limit", 0);

// Crypto hardening
// https://gist.github.com/haasn/69e19fc2fe0e25f3cff5
//General settings
pref("security.tls.unrestricted_rc4_fallback", false);
pref("security.tls.insecure_fallback_hosts.use_static_list", false);
pref("security.tls.version.min", 1);
pref("security.ssl.require_safe_negotiation", true);
pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
pref("security.ssl3.rsa_seed_sha", true);
pref("security.OCSP.enabled", 1);
pref("security.OCSP.require", true);
//Disable unnecessary protocols
pref("security.ssl3.rsa_rc4_128_sha", false);
pref("security.ssl3.rsa_rc4_128_md5", false);
pref("security.ssl3.rsa_des_ede3_sha", false);
pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha", false);
pref("security.ssl3.ecdhe_rsa_rc4_128_sha", false);
// https://directory.fsf.org/wiki/Disable_DHE
// Avoid logjam attack
pref("security.ssl3.dhe_rsa_aes_128_sha", false);
pref("security.ssl3.dhe_rsa_aes_256_sha", false);
pref("security.ssl3.dhe_dss_aes_128_sha", false);
pref("security.ssl3.dhe_rsa_des_ede3_sha", false);
//Optional
//Perfect forward secrecy
// pref("security.ssl3.rsa_aes_256_sha", false);
//Force TLS 1.2
// pref("security.tls.version.min", 3);

// Disable channel updates
pref("app.update.enabled", false);
pref("app.update.auto", false);

//pref("font.default.x-western", "sans-serif");

// Preferences for the Get Add-ons panel
pref ("extensions.webservice.discoverURL", "https://directory.fsf.org/wiki/GNU_IceCat");
pref ("extensions.getAddons.search.url", "https://directory.fsf.org/wiki/GNU_IceCat");

// Mobile
pref("privacy.announcements.enabled", false);
pref("browser.snippets.enabled", false);
pref("browser.snippets.syncPromo.enabled", false);
pref("browser.snippets.geoUrl", "http://127.0.0.1/");
pref("browser.snippets.updateUrl", "http://127.0.0.1/");
pref("browser.snippets.statsUrl", "http://127.0.0.1/");
pref("datareporting.policy.firstRunTime", 0);
pref("datareporting.policy.dataSubmissionPolicyVersion", 2);
pref("browser.webapps.checkForUpdates", 0);
pref("browser.webapps.updateCheckUrl", "http://127.0.0.1/");
pref("app.faqURL", "http://libreplanet.org/wiki/Group:IceCat/FAQ");

// PFS url
pref("pfs.datasource.url", "http://gnuzilla.gnu.org/plugins/PluginFinderService.php?mimetype=%PLUGIN_MIMETYPE%");
pref("pfs.filehint.url", "http://gnuzilla.gnu.org/plugins/PluginFinderService.php?mimetype=%PLUGIN_MIMETYPE%");

// Disable Gecko media plugins: https://wiki.mozilla.org/GeckoMediaPlugins
pref("media.gmp-manager.url", "http://127.0.0.1/");
pref("media.gmp-manager.url.override", "data:text/plain,");
pref("media.gmp-provider.enabled", false);
// Don't install openh264 codec
pref("media.gmp-gmpopenh264.enabled", false);

//Disable heartbeat
pref("browser.selfsupport.url", "");

//Disable Link to FireFox Marketplace, currently loaded with non-free "apps"
pref("browser.apps.URL", "");

//Disable Firefox Hello
//pref("loop.enabled",false);
//pref("loop.feedback.baseUrl", "");
//pref("loop.gettingStarted.url", "");
//pref("loop.learnMoreUrl", "");
//pref("loop.legal.ToS_url", "");
//pref("loop.legal.privacy_url", "");
//pref("loop.oauth.google.redirect_uri", "");
//pref("loop.oauth.google.scope", "");
//pref("loop.server", "");
//pref("loop.soft_start_hostname", "");
//pref("loop.support_url", "");
//pref("loop.throttled2",false);

// Use old style preferences, that allow javascript to be disabled
//pref("browser.preferences.inContent",false);

// Don't download ads for the newtab page
pref("browser.newtabpage.directory.source", "");
pref("browser.newtabpage.directory.ping", "");
pref("browser.newtabpage.introShown", true);

// Disable home snippets
pref("browser.aboutHomeSnippets.updateUrl", "data:text/html");

// Disable hardware acceleration and WebGL
//pref("layers.acceleration.disabled", false);
//pref("webgl.disabled", false);

// Disable SSDP
pref("browser.casting.enabled", false);

//Disable directory service
pref("social.directories", "");
pref("social.whitelist", "");
pref("social.shareDirectory", "");
