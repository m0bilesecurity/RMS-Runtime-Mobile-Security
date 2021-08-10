/****************************************************************************
 * Name: okhttp3 SSL Pinning Bypass
 * OS: Android
 * Authors: @apps3c and @pcipolloni
 * Source: https://codeshare.frida.re/@federicodotta/okhttp3-pinning-bypass/
 *****************************************************************************/


Java.perform(function () {

    var okhttp3_CertificatePinner_class = null;
    try {
        okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');
    } catch (err) {
        send('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
        okhttp3_CertificatePinner_class = null;
    }

    if (okhttp3_CertificatePinner_class != null) {

        try {
            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str, list) {
                send('[+] Bypassing OkHTTPv3 1: ' + str);
                return true;
            };
            send('[+] Loaded OkHTTPv3 hook 1');
        } catch (err) {
            send('[-] Skipping OkHTTPv3 hook 1');
        }

        try {
            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str, cert) {
                send('[+] Bypassing OkHTTPv3 2: ' + str);
                return true;
            };
            send('[+] Loaded OkHTTPv3 hook 2');
        } catch (err) {
            send('[-] Skipping OkHTTPv3 hook 2');
        }

        try {
            okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str, cert_array) {
                send('[+] Bypassing OkHTTPv3 3: ' + str);
                return true;
            };
            send('[+] Loaded OkHTTPv3 hook 3');
        } catch (err) {
            send('[-] Skipping OkHTTPv3 hook 3');
        }

        try {
            okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str, obj) {
                send('[+] Bypassing OkHTTPv3 4 (4.2+): ' + str);
            };
            send('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
        } catch (err) {
            send('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
        }

    }

});