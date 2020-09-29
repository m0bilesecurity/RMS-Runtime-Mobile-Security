/************************************************************************
 * Name: Enumerate ALL Native Libs Exports
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
*************************************************************************/

Java.perform(function () {
    send("Enumerate ALL Native Libs Exports - started")
    const ActivityThread = Java.use('android.app.ActivityThread');
    const file = Java.use("java.io.File");

    var targetApp = ActivityThread.currentApplication();
    var context = targetApp.getApplicationContext();
    var libFolder = context.getFilesDir().getParent() + "/lib"

    var currentPath = file.$new(libFolder);
    var nativelibs = currentPath.listFiles();

    nativelibs.forEach(function (f) {
        var libName = f.getName()
        send("Native lib name: " + libName)
 
        var exports = Module.enumerateExportsSync(libName)
        send("Exported methods:")
        if (exports === undefined || exports.length == 0) {
            send("No exported methods for " + libName)
        }

        for (var i = 0; i < exports.length; i++) {
            var current_export = {
                name: exports[i].name,
                address: exports[i].address
            };
            send(JSON.stringify(current_export, null, 1))
        }

    });
    send("Enumerate ALL Native Libs Exports - completed")
});