/************************************************************************
 * Name: SSL Pinning Universal Bypass (without CA)
 * OS: Android
 * Authors: Maurizio Siddu
 * Source: https://github.com/akabe1/my-FRIDA-scripts
 *************************************************************************/

setTimeout(function () {
    Java.perform(function () {
        send('');
        send('======');
        send('[#] Android Universal Certificate Pinning Bypasser [#]');
        send('======');

        // TrustManagerImpl Certificate Pinning Bypass             
        try {
            var array_list = Java.use('java.util.ArrayList');
            var custom_TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

            //custom_TrustManagerImpl.checkTrustedRecursive.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            custom_TrustManagerImpl.checkTrustedRecursive.implementation = function (a, b, c, d, e, f, g, h) {
                //if host:
                send('[+] Bypassing TrustManagerImpl pinner for: ' + b + '...');
                //else:
                //     send('[+] Bypassing TrustManagerImpl pinner...');
                var fakeTrusted = array_list.$new();
                return fakeTrusted;
            }
        } catch (err) {
            send('[-] TrustManagerImpl pinner not found');
        }


        // OpenSSLSocketImpl Certificate Pinning Bypass
        try {
            var custom_OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            custom_OpenSSLSocketImpl.verifyCertificateChain.implementation = function (g, i) {
                send('[+] Bypassing OpenSSLSocketImpl pinner...');
            }
        } catch (err) {
            send('[-] OpenSSLSocketImpl pinner not found');
        }

    });
}, 0);