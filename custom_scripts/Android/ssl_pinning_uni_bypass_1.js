/************************************************************************
 * Name: Universal SSL Pinning Bypass (without CA)
 * OS: Android
 * Authors: Mattia Vinci and Maurizio Agazzini (Mediaservice)
 * Source: https://techblog.mediaservice.net/2018/11/universal-android-ssl-pinning-bypass-2/
 *************************************************************************/

Java.perform(function() {

    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
        send('Bypassing SSL Pinning');
        var k = array_list.$new();
        return k;
    }

}, 0);