/************************************************************************
 * Name: Enumerate Native Lib Exports
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
*************************************************************************/

Java.perform(function () {
    var lib_name = "Insert_lib_name" //e.g. libnative-lib.so 

    var exports = Module.enumerateExportsSync(lib_name);

    send("Enumerate Native Lib Exports - started")
    send("Native lib name: " + lib_name)

    if (exports === undefined || exports.length == 0) {
        send("No exported methods for " + lib_name)
    }
    for (var i = 0; i < exports.length; i++) {
        var current_export = {
            name: exports[i].name,
            address: exports[i].address
        };
        send(JSON.stringify(current_export, null, 1))
    }
    send("Enumerate Native Lib Exports - completed")
});