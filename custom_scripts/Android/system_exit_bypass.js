/************************************************************************
 * Name: System.exit() Bypass
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
*************************************************************************/

Java.perform(function () {
    const System = Java.use('java.lang.System')

    send("--> System.exit() Bypass - Script Loaded")
    System.exit.implementation = function(){
        send("System.exit() Bypassed!");
    }
});