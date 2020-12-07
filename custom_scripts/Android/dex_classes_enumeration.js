/************************************************************************
 * Name: Dex Classes Enumeration
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
*************************************************************************/

Java.perform(function () {
    send("Dex Classes Enumeration - started")
    const ActivityThread = Java.use('android.app.ActivityThread');
    const DexFile = Java.use("dalvik.system.DexFile");

    var targetApp = ActivityThread.currentApplication();
    var context = targetApp.getApplicationContext();
    var apk_path = context.getPackageCodePath().toString()

    var df = DexFile.$new(apk_path);
    var dexClasses = df.entries()
    
    while (dexClasses.hasMoreElements()) {
        send(String(dexClasses.nextElement()))
    }
    send("Dex Classes Enumeration - completed")
});