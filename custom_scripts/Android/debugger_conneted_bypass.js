/************************************************************************
 * Name: Debugger Connected Bypass
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info: isDebuggerConnected() always return false
*************************************************************************/

Java.perform(function () {
    send("--> isDebuggerConnected - Bypass Loaded")
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        send("isDebuggerConnected - bypass done!");
        return false;
    }
});