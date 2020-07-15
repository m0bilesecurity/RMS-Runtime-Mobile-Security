/************************************************************************
 * Name: SSL Pinning Multiple Libraries Bypass 
 * OS: Android
 * Authors: Maurizio Siddu
 * Source: https://github.com/akabe1/my-FRIDA-scripts
 *************************************************************************/

setTimeout(function () {
    Java.perform(function () {
        send('');
        send('======');
        send('[#] Android Bypass for various Certificate Pinning methods [#]');
        send('======');


        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');


        // TrustManager (Android < 7)
        var TrustManager = Java.registerClass({
            // Implement a custom TrustManager
            name: 'dev.asd.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {
                    return [];
                }
            }
        });

        // Prepare the TrustManager array to pass to SSLContext.init()
        var TrustManagers = [TrustManager.$new()];
        // Get a handle on the init() on the SSLContext class
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        try {
            // Override the init method, specifying the custom TrustManager
            SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                send('[+] Bypassing Trustmanager (Android < 7) request');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };

        } catch (err) {
            send('[-] TrustManager (Android < 7) pinner not found');
            //send(err);
        }



        // OkHTTPv3 (double bypass)
        try {
            var okhttp3_Activity = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                send('[+] Bypassing OkHTTPv3 {1}: ' + str);
                return true;
            };
            // This method of CertificatePinner.check could be found in some old Android app
            okhttp3_Activity.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str) {
                send('[+] Bypassing OkHTTPv3 {2}: ' + str);
                return true;
            };

        } catch (err) {
            send('[-] OkHTTPv3 pinner not found');
            //send(err);
        }



        // Trustkit (triple bypass)
        try {
            var trustkit_Activity = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            trustkit_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                send('[+] Bypassing Trustkit {1}: ' + str);
                return true;
            };
            trustkit_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                send('[+] Bypassing Trustkit {2}: ' + str);
                return true;
            };
            var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
            trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
                send('[+] Bypassing Trustkit {3}');
            };

        } catch (err) {
            send('[-] Trustkit pinner not found');
            //send(err);
        }



        // TrustManagerImpl (Android > 7)
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                send('[+] Bypassing TrustManagerImpl (Android > 7): ' + host);
                return untrustedChain;
            };

        } catch (err) {
            send('[-] TrustManagerImpl (Android > 7) pinner not found');
            //send(err);
        }



        // Appcelerator Titanium
        try {
            var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
            appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
                send('[+] Bypassing Appcelerator PinningTrustManager');
            };

        } catch (err) {
            send('[-] Appcelerator PinningTrustManager pinner not found');
            //send(err);
        }



        // OpenSSLSocketImpl Conscrypt
        try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                send('[+] Bypassing OpenSSLSocketImpl Conscrypt');
            };

        } catch (err) {
            send('[-] OpenSSLSocketImpl Conscrypt pinner not found');
            //send(err);        
        }


        // OpenSSLEngineSocketImpl Conscrypt
        try {
            var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
            OpenSSLSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (str1, str2) {
                send('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + str2);
            };

        } catch (err) {
            send('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
            //send(err);
        }



        // OpenSSLSocketImpl Apache Harmony
        try {
            var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                send('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
            };

        } catch (err) {
            send('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
            //send(err);      
        }



        // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
        try {
            var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
            phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (str) {
                send('[+] Bypassing PhoneGap sslCertificateChecker: ' + str);
                return true;
            };

        } catch (err) {
            send('[-] PhoneGap sslCertificateChecker pinner not found');
            //send(err);
        }



        // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
        try {
            var WLClient_Activity = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient_Activity.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
                send('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
                return;
            };
            WLClient_Activity.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
                send('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
                return;
            };

        } catch (err) {
            send('[-] IBM MobileFirst pinTrustedCertificatePublicKey pinner not found');
            //send(err);
        }



        // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
        try {
            var worklight_Activity = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (str) {
                send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + str);
                return;
            };
            worklight_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + str);
                return;
            };
            worklight_Activity.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (str) {
                send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + str);
                return;
            };
            worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + str);
                return true;
            };

        } catch (err) {
            send('[-] IBM WorkLight HostNameVerifierWithCertificatePinning pinner not found');
            //send(err);
        }



        // Conscrypt CertPinManager
        try {
            var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
            conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                send('[+] Bypassing Conscrypt CertPinManager: ' + str);
                return true;
            };

        } catch (err) {
            send('[-] Conscrypt CertPinManager pinner not found');
            //send(err);
        }



        // CWAC-Netsecurity (unofficial back-port pinner for Android < 4.2) CertPinManager
        try {
            var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
            cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                send('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + str);
                return true;
            };

        } catch (err) {
            send('[-] CWAC-Netsecurity CertPinManager pinner not found');
            //send(err);
        }



        // Worklight Androidgap WLCertificatePinningPlugin
        try {
            var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
            androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (str) {
                send('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + str);
                return true;
            };

        } catch (err) {
            send('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
            //send(err);
        }



        // Netty FingerprintTrustManagerFactory
        try {
            var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
            //NOTE: sometimes this below implementation could be useful 
            //var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
            netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
                send('[+] Bypassing Netty FingerprintTrustManagerFactory');
            };

        } catch (err) {
            send('[-] Netty FingerprintTrustManagerFactory pinner not found');
            //send(err);
        }



        // Squareup CertificatePinner [OkHTTP < v3] (double bypass)
        try {
            var Squareup_CertificatePinner_Activity = Java.use('com.squareup.okhttp.CertificatePinner');
            Squareup_CertificatePinner_Activity.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str1, str2) {
                send('[+] Bypassing Squareup CertificatePinner {1}: ' + str1);
                return;
            };

            Squareup_CertificatePinner_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function (str1, str2) {
                send('[+] Bypassing Squareup CertificatePinner {2}: ' + str1);
                return;
            };

        } catch (err) {
            send('[-] Squareup CertificatePinner pinner not found');
            //send(err);
        }



        // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
        try {
            var Squareup_OkHostnameVerifier_Activity = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            Squareup_OkHostnameVerifier_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str1, str2) {
                send('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + str1);
                return true;
            };

            Squareup_OkHostnameVerifier_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str1, str2) {
                send('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + str1);
                return true;
            };

        } catch (err) {
            send('[-] Squareup OkHostnameVerifier pinner not found');
            //send(err);
        }



        // Android WebViewClient
        try {
            var AndroidWebViewClient_Activity = Java.use('android.webkit.WebViewClient');
            AndroidWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                send('[+] Bypassing Android WebViewClient');
            };

        } catch (err) {
            send('[-] Android WebViewClient pinner not found');
            //send(err);
        }



        // Apache Cordova WebViewClient
        try {
            var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
            CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                send('[+] Bypassing Apache Cordova WebViewClient');
                obj3.proceed();
            };

        } catch (err) {
            send('[-] Apache Cordova WebViewClient pinner not found');
            //send(err):
        }



        // Boye AbstractVerifier
        try {
            var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
            boye_AbstractVerifier.verify.implementation = function (host, ssl) {
                send('[+] Bypassing Boye AbstractVerifier: ' + host);
            };

        } catch (err) {
            send('[-] Boye AbstractVerifier pinner not found');
            //send(err):
        }


    });

}, 0);