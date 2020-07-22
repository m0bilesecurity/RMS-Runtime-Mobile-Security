/*************************************************************************************
 * Name: Intercepts Crypto Operations
 * OS: Android
 * Author: @fadeevab
 * Source: https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/
 **************************************************************************************/


function bin2ascii(array) {
    var result = [];

    for (var i = 0; i < array.length; ++i) {
        result.push(String.fromCharCode( // hex2ascii part
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
                16
            )
        ));
    }
    return result.join('');
}

function bin2hex(array, length) {
    var result = "";

    length = length || array.length;

    for (var i = 0; i < length; ++i) {
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    }
    return result;
}

Java.perform(function() {
    Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B', 'java.lang.String').implementation = function(key, spec) {
        send("KEY: " + bin2hex(key) + " | " + bin2ascii(key));
        return this.$init(key, spec);
    };

    Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String').implementation = function(spec) {
        send("CIPHER: " + spec);
        return this.getInstance(spec);
    };

    Java.use('javax.crypto.Cipher')['doFinal'].overload('[B').implementation = function(data) {
        send("doFinal!");
        send(bin2ascii(data));
        return this.doFinal(data);
    };
});