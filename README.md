
# Runtime Mobile Security (RMS) 📱🔥 #

![RMS_logo](/static/RMS_Github_Header.png)

by [@mobilesecurity_](https://twitter.com/mobilesecurity_) 

**Runtime Mobile Security (RMS)**, powered by [FRIDA](https://github.com/frida/frida), is a powerful web interface that helps you to manipulate <b>Android and iOS Apps</b> at Runtime. 

You can easily dump all the loaded classes and relative methods, hook everything on the fly, trace methods args and return value, load custom scripts and many other useful stuff.

Please check below a **short video** (1min42s) that shows RMS in action on an iOS device. Same functionalities are of course also available for Android devices.

### iOS DEMO - VIDEO
[![RMS - iOS DEMO](https://img.youtube.com/vi/EtsYHYA9ID4/0.jpg)](https://www.youtube.com/watch?v=EtsYHYA9ID4)

### Android DEMO - VIDEO
[![RMS - Android DEMO](https://img.youtube.com/vi/Gq0bXeRu-I0/0.jpg)](https://www.youtube.com/watch?v=Gq0bXeRu-I0)

### Tutorial - Android
- [Solving **OWASP** UnCrackable Android **App Level 1** with **Runtime Mobile Security (RMS)**](https://youtu.be/P6rNPkM2DdY)
- [Solving **OWASP** UnCrackable Android **App Level 2** with **Runtime Mobile Security (RMS)**](https://youtu.be/xRQVljerl0A)

# Prerequisites

**FRIDA server up and running on the target device**

Refer to the official FRIDA guide for the installation: 
* [Android](https://frida.re/docs/android/)
* [iOS](https://frida.re/docs/ios/)

### Quick smoke-test

As suggested by the official FRIDA doc, please perform a **quick smoke-test** to make sure **FRIDA is working properly on your test device**.

By running the ```frida-ps -U``` command from your desktop, you should receive the list of the processes running on your connected mobile device.

```
Android                    | iOS
  PID NAME                 |  PID NAME
 1590 com.facebook.katana  |  488 Clock
 3282 com.twitter.android  |  116 Facebook
 …                            …
```
### Tips
Some cool projects that can help you to **auto** install, update and run frida on Android devices:
* [MagiskFrida - Android](https://github.com/ViRb3/magisk-frida)
* [FridaLoader - Android](https://github.com/dineshshetty/FridaLoader)

They are not needed on iOS devices, since FRIDA starts just after the boot of the device (jailbreak mode).

# Installation

1. **(optional)** Create a python virtual environment
2. ```pip3 install -r requirements.txt```
3. Make sure frida-server is up and running on the target device. Instructions are here: [Prerequisites](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#prerequisites) / [Quick smoke-test](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#quick-smoke-test)
4. ```python3 mobilesecurity.py```
5. Open your browser at ```http://127.0.0.1:5000/```

### Notes and possibile issues
1. In case of issues with your favorite Browser (e.g. logs not printed in the web console), please use <b>Google Chrome</b> (fully supported)
2. If <b>RMS is not able to detect your device</b>, please perform the following checks:
    * double check if frida-server is up and running on the target device. Instructions are here: [Prerequisites](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#prerequisites)
    / [Quick smoke-test](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#quick-smoke-test)
    * RMS must be started **after** frida-server
    * make sure that **only 1 device** is connected to your computer. RMS is currently not able to detect multiple devices
    * kill RMS and start it again 

# General Info
Runtime Mobile Security (RMS) supports <b>Android</b> and <b>iOS</b> devices.

It has been tested on MacOS and with the following devices:
* AVD emulator
* Genymotion emulator 
* Amazon Fire Stick 4K
* iPhone 7
* Chrome (Web Interface)

It should also work well on Windows and Linux but some minor adjustments may be needed.

Do not connect more than one device at the same time. RMS is not so smart at the moment 😉

<b>NOTE:</b> Socket are not working on Safari, <b>please use Chrome</b> instead.

# Known issues and improvements
* Sometime RMS fails to load complex methods. Use a filter when this happens or feel free to improve the algo (agent/RMS_core.js).
* Code is not optimized
* Feel free to send me your best JS sript via a Pull request. I'll be happy to bundle all the best as default scripts in the next RMS release (e.g. root detection bypass, ssl pinning, etc)


# Usage

## 1. Run your favorite app by simply inserting its package name ##
**NOTE** RMS attachs a persistence process called **com.android.systemui** on Android and **SpringBoard** on iOS devices to get the list of all the classes that are already loaded in memory before the launch of the target app. If you have an issue with them, try to find a different default package that works well on your device. 
You can set another default package via the Config Tab or by simply editing the **config.json** file.

![DEMO_1_Android](/DEMO/Android/DEMO_1_Device.gif)

![DEMO_1_iOS](/DEMO/iOS/DEMO_1_Device.gif)

## 2. Check which Classes and Methods have been loaded in memory  ##
![DEMO_2_Android](/DEMO/Android/DEMO_2_Dump.gif)

![DEMO_2_iOS](/DEMO/iOS/DEMO_2_Dump.gif)

## 3. Hook on the fly Classes/Methods and trace their args and return values  ##
![DEMO_3_a](/DEMO/Android/DEMO_3_Massive_Hook.gif)

Go back to the dump page in order to have an overview of all the **hooked methods that have been executed by the app** ✅

![DEMO_3_b](/DEMO/Android/DEMO_3_Overview_Methods.gif)

## 4. Search instances of a specific class on the Heap and call its methods ##
![DEMO_4_Android](/DEMO/Android/DEMO_4_Heap_Search.gif)

![DEMO_4_iOS](/DEMO/iOS/DEMO_4_Heap_Search.gif)

## 5. Select a Class and generate on the fly an Hook template for all its methods  ##
![DEMO_5_Android](/DEMO/Android/DEMO_5_Hook_Hack.gif)

![DEMO_5_iOS](/DEMO/iOS/DEMO_5_Hook_Hack.gif)

## 6. Easily detect new classes that have been loaded in memory   ##
![DEMO_6](/DEMO/Android/DEMO_6_Diff_Classes.gif)

## 7. Inject your favorite FRIDA CUSTOM SCRIPTS on the fly   ##

Just add your .js files inside the custom_script folder and they will be automatically loaded by the web interface ready to be executed.

![DEMO_7_Android](/DEMO/Android/DEMO_7_Custom_Script.gif)

![DEMO_7_iOS](/DEMO/iOS/DEMO_7_Custom_Script.gif)

## 8. API Monitor - Android Only ##

via the API Monitor TAB you can easily monitor tons of Android APIs organized in 20 different Categories. Support can be easily extended by adding more classes/methods to the **api_monitor.json** file.

![DEMO_10](/DEMO/Android/DEMO_10_API_Monitor.png)

You can also monitor native functions: libc.so - open, close, read, write, unlink, remove

![DEMO_8](/DEMO/Android/DEMO_8_FS_monitor.png)

## 9. FRIDA Script to load Stetho by Facebook [BONUS]  ##

Inject the FRIDA script to load the amazing [Stetho](http://facebook.github.io/stetho/).

Stetho is a sophisticated debug bridge for Android applications. When enabled, developers have access to the Chrome Developer Tools feature natively part of the Chrome desktop browser. Developers can also choose to enable the optional dumpapp tool which offers a powerful command-line interface to application internals.

![DEMO_9](/DEMO/Android/DEMO_9_Stetho.gif)

## 10. File Manager [BETA]  ##

A simple File Manager has been implemented to help you exploring app's private folders and files. **This feature is still in BETA.**

[frida-fs](https://github.com/nowsecure/frida-fs) has been implemented to enable files download directly from the browser (File Manager TAB).

In order to enable the download button, follow the steps below:
1. Open the file called "**mobilesecurity.py**" and set the **BETA** variable to **True**
2. Compile the "**RMS_Core.js**" agent via frida-compile! Just run the command ```npm install``` directly from the **agent** folder. A file called "**_RMS_Core_BETA.js**" will be generated.
3. Run RMS!

![DEMO_11_Android](/DEMO/Android/DEMO_11_File_Manager.png)

![DEMO_11_iOS](/DEMO/iOS/DEMO_11_File_Manager.gif)

## 11. Static Analysis - iOS Only  ##
![DEMO_12_iOS](/DEMO/iOS/DEMO_12_Static_Analysis.gif)

# Acknowledgements
Special thanks to the following Open Source projects for the inspiration:
* [FRIDA](https://github.com/frida/frida)
* [Objection](https://github.com/sensepost/objection)
* [House](https://github.com/nccgroup/house)
* [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

### FRIDA Custom Scripts bundled in RMS - Credits:
* [Runtime Mobile Security (RMS)](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security)
* [FSecureLABS](https://github.com/FSecureLABS/)
* [Mediaservice](https://techblog.mediaservice.net/)
* [federicodotta](https://github.com/federicodotta/Brida)
* [iddoeldor](https://github.com/iddoeldor)
* [dzonerzy](https://github.com/dzonerzy)
* [akabe1](https://github.com/akabe1/my-FRIDA-scripts)
* [Areizen](https://github.com/Areizen)
* [int3rf3r3nc3](https://github.com/interference-security/frida-scripts)
* [dki](https://codeshare.frida.re/@dki/ios10-ssl-bypass/)
* [ay-kay](https://codeshare.frida.re/@ay-kay/ios-dataprotection/)
* [chaitin](https://github.com/chaitin/passionfruit)
* [lich4](https://codeshare.frida.re/@lichao890427/dump-ios/)
* [fadeevab](https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/)
* [realgam3](https://codeshare.frida.re/@realgam3/dynamichooks/)
* [noobpk](https://github.com/noobpk/frida-ios-hook)


### DEMO apps:

* [RootBeer Sample](https://play.google.com/store/apps/details?id=com.scottyab.rootbeer.sample) is the DEMO app used to show how RMS works.
[RootBeer](https://github.com/scottyab/rootbeer) is an **amazing root detection library**. I decided to use the Sample app as DEMO just to show that, as every client-side only check, its root detection logic can be easily bypassed if not combined with a server-side validation. 
* [DVIA](http://damnvulnerableiosapp.com/) a vulnerable app to test your iOS Penetration Testing Skills
* [Anti-Frida](https://github.com/b-mueller/frida-detection-demo) Frida Detection Examples by Bernhard Mueller.

# License
RMS is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html).