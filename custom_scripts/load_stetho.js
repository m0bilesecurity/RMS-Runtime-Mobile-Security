/************************************************************************
 * Name: Load Stetho by Facebook - a debug bridge for Android apps
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info: How to use Stetho?
   1. Download Stetho - http://facebook.github.io/stetho/
   2. Rename to stetho.jar
   3. Download dextojar https://sourceforge.net/projects/dex2jar/
   4. Convert the jar file to dex - d2j-jar2dex.sh stetho.jar
   5. Push the dex file in /data/local/tmp/
      adb push stetho-jar2dex.dex /data/local/tmp/stetho.jar
   6. Open chrome at this address - chrome://inspect/#devices
   7. Inspect your app!
*************************************************************************/

Java.perform(function () {

    const stethoJarFilePath = "/data/local/tmp/stetho.jar"

    const stethoClassName = "com.facebook.stetho.Stetho";
    const pathClassLoader = Java.use("dalvik.system.PathClassLoader");
    const javaFile = Java.use("java.io.File");
    const activityThread = Java.use("android.app.ActivityThread");
    const app = activityThread.currentApplication();
    const context = app.getApplicationContext();

    const stethoJarFile = javaFile.$new(stethoJarFilePath);
    const loader = pathClassLoader.$new(stethoJarFile.getAbsolutePath(),
                                        null,
                                        app.getClassLoader()); 
    try {
        loader.loadClass(stethoClassName);

        var classLoaders = Java.enumerateClassLoadersSync();
        classLoaders=classLoaders.filter(function (cl) {
            return cl.toString().includes("stetho");
        });

        Java.classFactory.loader = classLoaders[0];
        const stetho = Java.use(stethoClassName);
        stetho.initializeWithDefaults(context);
        send("Stetho successfully loaded!");
        send("Open Chrome at chrome://inspect/#devices")

    } catch (err) {
        send("Stetho NOT loaded!");
        send(err.toString());
    }
});