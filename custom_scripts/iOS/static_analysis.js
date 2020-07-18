/************************************************************************
 * Name: iOS app's static analysis
 * OS: iOS
 * Author: @xploresec
 * Source: https://github.com/interference-security/frida-scripts
 * Info: 
    1. App Meta Information 
    2. Xcode Build Meta Information
    3. Application Environment 
    4. Raw Contents of Info.plist
    5. URL Schemes 
    6. Protected Resources / Permissions
    7. App Transport Security Settings
    8. Classes for potential jailbreak detection
    9. Methods for potential jailbreak detection
*************************************************************************/
var DEBUG=false
var s=""

s=s+"\n[Static_Analysis]"
s=s+"\n"
s=s+"\n--------------------------------"
s=s+"\n|     App Meta Information     |"
s=s+"\n--------------------------------"
try {
    s=s+"\nBundle Name: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleName").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDisplay Name: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleDisplayName").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nExecutable Name: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleExecutable").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nBundle Identifier: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleIdentifier").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nInfo Dictionary Version: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleInfoDictionaryVersion").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nNumeric Version: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleNumericVersion").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nShort Version: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleShortVersionString").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nBundle Version: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleVersion").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nMinimum OS Version: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("MinimumOSVersion").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nBundle Package Type: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundlePackageType").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nBuildMachineOSBuild: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("BuildMachineOSBuild").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDevelopment Region: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleDevelopmentRegion").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\niPhone Environment Required: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("LSRequiresIPhoneOS").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}

s=s+"\n"
s=s+"\n--------------------------------"
s=s+"\n| Xcode Build Meta Information |"
s=s+"\n--------------------------------"
try {
    s=s+"\nDTCompiler: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTCompiler").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDTPlatformBuild: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTPlatformBuild").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDTPlatformName: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTPlatformName").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDTPlatformVersion: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTPlatformVersion").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDTSDKBuild: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTSDKBuild").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDTSDKName: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTSDKName").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDTXcode: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTXcode").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
try {
    s=s+"\nDTXcodeBuild: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("DTXcodeBuild").toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}
//try { s=s+"\nNSAppTransportSecurity: " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").toString())



s=s+"\n"
s=s+"\n-----------------------------------"
s=s+"\n|     Application Environment     |"
s=s+"\n-----------------------------------"
const NSUserDomainMask = 1
const NSLibraryDirectory = 5
const NSDocumentDirectory = 9
const NSCachesDirectory = 13

var NSBundle = ObjC.classes.NSBundle.mainBundle()
var NSFileManager = ObjC.classes.NSFileManager.defaultManager();

function getPathForNSLocation (NSPath){
    var path=NSFileManager.URLsForDirectory_inDomains_(NSPath, NSUserDomainMask).lastObject();
    return path.path().toString();
}

var env = {
    mainDirectory: getPathForNSLocation(NSLibraryDirectory).replace("Library",""),
    BundlePath: NSBundle.bundlePath().toString(),
    CachesDirectory: getPathForNSLocation(NSCachesDirectory),
    DocumentDirectory: getPathForNSLocation(NSDocumentDirectory),
    LibraryDirectory: getPathForNSLocation(NSLibraryDirectory)
};

s=s+"\nmainDirectory: "+env.mainDirectory
s=s+"\nBundlePath: "+env.BundlePath
s=s+"\nCachesDirectory: "+env.CachesDirectory
s=s+"\nDocumentDirectory: "+env.DocumentDirectory
s=s+"\nLibraryDirectory: "+env.LibraryDirectory



s=s+"\n"
s=s+"\n--------------------------------"
s=s+"\n|  Raw Contents of Info.plist  |"
s=s+"\n--------------------------------"
try {
    s=s+"\n"+ObjC.classes.NSBundle.mainBundle().infoDictionary().toString()
} catch (err) {
    if (DEBUG) {
        console.error("[!] Error: " + err.message);
    }
}



s=s+"\n"
s=s+"\n--------------------------------"
s=s+"\n|         URL Schemes          |"
s=s+"\n--------------------------------"
var nsDictionary = ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("CFBundleURLTypes");
if (nsDictionary == null) {
    s=s+"\n[*] URL scheme not defined by app"
}
nsDictionary = nsDictionary.objectAtIndex_(0);
var dictKeys = nsDictionary.allKeys();
for (var i = 0; i < dictKeys.count(); i++) {
    if (dictKeys.objectAtIndex_(i) == "CFBundleURLSchemes") {
        var urlSchemesString = "";
        var nsArray = nsDictionary.objectForKey_("CFBundleURLSchemes");
        for (var i = 0; i < nsArray.count(); i++) {
            urlSchemesString = urlSchemesString + nsArray.objectAtIndex_(i).toString() + ", ";
        }
        urlSchemesString = urlSchemesString.substr(0, urlSchemesString.length - 2)
        s=s+"\nURL Schemes : " + urlSchemesString
    } else if (dictKeys.objectAtIndex_(i) == "CFBundleURLName") {
        var key = dictKeys.objectAtIndex_(i);
        var value = nsDictionary.objectForKey_(key);
        s=s+"\nURL Scheme Name : " + value
    } else if (dictKeys.objectAtIndex_(i) == "CFBundleURLIconFile") {
        var key = dictKeys.objectAtIndex_(i);
        var value = nsDictionary.objectForKey_(key);
        s=s+"\nURL Icon File : " + value
    } else if (dictKeys.objectAtIndex_(i) == "CFBundleTypeRole") {
        var key = dictKeys.objectAtIndex_(i);
        var value = nsDictionary.objectForKey_(key);
        s=s+"\nApp's Role : " + value
    } else {
        var key = dictKeys.objectAtIndex_(i);
        var value = nsDictionary.objectForKey_(key);
        s=s+"\n"+key + " : " + value
    }

}

s=s+"\n"
s=s+"\n-----------------------------------"
s=s+"\n|Protected Resources / Permissions|"
s=s+"\n-----------------------------------"
s=s+"\nSource: https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources"
var dictKeys = ObjC.classes.NSBundle.mainBundle().infoDictionary().allKeys();
var permissionListArray = [
    "NSBluetoothAlwaysUsageDescription", "NSBluetoothPeripheralUsageDescription", "NSCalendarsUsageDescription", "NSRemindersUsageDescription", "NSCameraUsageDescription", "NSMicrophoneUsageDescription", "NSContactsUsageDescription", "NSFaceIDUsageDescription", "NSDesktopFolderUsageDescription", "NSDocumentsFolderUsageDescription", "NSDownloadsFolderUsageDescription", "NSNetworkVolumesUsageDescription", "NSRemovableVolumesUsageDescription", "NSFileProviderPresenceUsageDescription", "NSFileProviderDomainUsageDescription", "NSHealthClinicalHealthRecordsShareUsageDescription", "NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription", "NSHealthRequiredReadAuthorizationTypeIdentifiers", "NSHomeKitUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription", "NSLocationUsageDescription", "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysUsageDescription", "NSAppleMusicUsageDescription", "NSMotionUsageDescription", "NFCReaderUsageDescription", "NSPhotoLibraryAddUsageDescription", "NSPhotoLibraryUsageDescription", "NSAppleScriptEnabled", "NSAppleEventsUsageDescription", "NSSystemAdministrationUsageDescription", "ITSAppUsesNonExemptEncryption", "ITSEncryptionExportComplianceCode", "NSSiriUsageDescription", "NSSpeechRecognitionUsageDescription", "NSVideoSubscriberAccountUsageDescription", "UIRequiresPersistentWiFi"]
var permissionListNameDict = {
    "NSBluetoothAlwaysUsageDescription": "Privacy - Bluetooth Always Usage Description",
    "NSBluetoothPeripheralUsageDescription": "Privacy - Bluetooth Peripheral Usage Description",
    "NSCalendarsUsageDescription": "Privacy - Calendars Usage Description",
    "NSRemindersUsageDescription": "Privacy - Reminders Usage Description",
    "NSCameraUsageDescription": "Privacy - Camera Usage Description",
    "NSMicrophoneUsageDescription": "Privacy - Microphone Usage Description",
    "NSContactsUsageDescription": "Privacy - Contacts Usage Description",
    "NSFaceIDUsageDescription": "Privacy - Face ID Usage Description",
    "NSDesktopFolderUsageDescription": "Privacy - Desktop Folder Usage Description",
    "NSDocumentsFolderUsageDescription": "Privacy - Documents Folder Usage Description",
    "NSDownloadsFolderUsageDescription": "Privacy - Downloads Folder Usage Description",
    "NSNetworkVolumesUsageDescription": "Privacy - Network Volumes Usage Description",
    "NSRemovableVolumesUsageDescription": "Privacy - Removable Volumes Usage Description",
    "NSFileProviderPresenceUsageDescription": "Privacy - File Provider Presence Usage Description",
    "NSFileProviderDomainUsageDescription": "Privacy - Access to a File Provider Domain Usage Description",
    "NSHealthClinicalHealthRecordsShareUsageDescription": "Privacy - Health Records Usage Description",
    "NSHealthShareUsageDescription": "Privacy - Health Share Usage Description",
    "NSHealthUpdateUsageDescription": "Privacy - Health Update Usage Description",
    "NSHealthRequiredReadAuthorizationTypeIdentifiers": "The clinical record data types that your app must get permission to read.",
    "NSHomeKitUsageDescription": "Privacy - HomeKit Usage Description",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Privacy - Location Always and When In Use Usage Description",
    "NSLocationUsageDescription": "Privacy - Location Usage Description",
    "NSLocationWhenInUseUsageDescription": "Privacy - Location When In Use Usage Description",
    "NSLocationAlwaysUsageDescription": "Privacy - Location Always Usage Description",
    "NSAppleMusicUsageDescription": "Privacy - Media Library Usage Description",
    "NSMotionUsageDescription": "Privacy - Motion Usage Description",
    "NFCReaderUsageDescription": "Privacy - NFC Scan Usage Description",
    "NSPhotoLibraryAddUsageDescription": "Privacy - Photo Library Additions Usage Description",
    "NSPhotoLibraryUsageDescription": "Privacy - Photo Library Usage Description",
    "NSAppleScriptEnabled": "Scriptable",
    "NSAppleEventsUsageDescription": "Privacy - AppleEvents Sending Usage Description",
    "NSSystemAdministrationUsageDescription": "Privacy - System Administration Usage Description",
    "ITSAppUsesNonExemptEncryption": "App Uses Non-Exempt Encryption",
    "ITSEncryptionExportComplianceCode": "App Encryption Export Compliance Code",
    "NSSiriUsageDescription": "Privacy - Siri Usage Description",
    "NSSpeechRecognitionUsageDescription": "Privacy - Speech Recognition Usage Description",
    "NSVideoSubscriberAccountUsageDescription": "Privacy - Video Subscriber Account Usage Description",
    "UIRequiresPersistentWiFi": "Application uses Wi-Fi"
};
var permissionListDetailDict = {
    "NSBluetoothAlwaysUsageDescription": "A message that tells the user why the app needs access to Bluetooth",
    "NSBluetoothPeripheralUsageDescription": "A message that tells the user why the app is requesting the ability to connect to Bluetooth peripherals",
    "NSCalendarsUsageDescription": "A message that tells the user why the app is requesting access to the user’s calendar data",
    "NSRemindersUsageDescription": "A message that tells the user why the app is requesting access to the user’s reminders",
    "NSCameraUsageDescription": "A message that tells the user why the app is requesting access to the device’s camera",
    "NSMicrophoneUsageDescription": "A message that tells the user why the app is requesting access to the device’s microphone",
    "NSContactsUsageDescription": "A message that tells the user why the app is requesting access to the user’s contacts",
    "NSFaceIDUsageDescription": "A message that tells the user why the app is requesting the ability to authenticate with Face ID",
    "NSDesktopFolderUsageDescription": "A message that tells the user why the app needs access to the user’s Desktop folder",
    "NSDocumentsFolderUsageDescription": "A message that tells the user why the app needs access to the user’s Documents folder",
    "NSDownloadsFolderUsageDescription": "A message that tells the user why the app needs access to the user’s Downloads folder",
    "NSNetworkVolumesUsageDescription": "A message that tells the user why the app needs access to files on a network volume",
    "NSRemovableVolumesUsageDescription": "A message that tells the user why the app needs access to files on a removable volume",
    "NSFileProviderPresenceUsageDescription": "A message that tells the user why the app needs to be informed when other apps access files that it manages",
    "NSFileProviderDomainUsageDescription": "A message that tells the user why the app needs access to files managed by a file provider",
    "NSHealthClinicalHealthRecordsShareUsageDescription": "A message to the user that explains why the app requested permission to read clinical records",
    "NSHealthShareUsageDescription": "A message to the user that explains why the app requested permission to read samples from the HealthKit store",
    "NSHealthUpdateUsageDescription": "A message to the user that explains why the app requested permission to save samples to the HealthKit store",
    "NSHealthRequiredReadAuthorizationTypeIdentifiers": "The clinical record data types that your app must get permission to read",
    "NSHomeKitUsageDescription": "A message that tells the user why the app is requesting access to the user’s HomeKit configuration data",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "A message that tells the user why the app is requesting access to the user’s location information at all times",
    "NSLocationUsageDescription": "A message that tells the user why the app is requesting access to the user’s location information",
    "NSLocationWhenInUseUsageDescription": "A message that tells the user why the app is requesting access to the user’s location information while the app is running in the foreground",
    "NSLocationAlwaysUsageDescription": "A message that tells the user why the app is requesting access to the user's location at all times",
    "NSAppleMusicUsageDescription": "A message that tells the user why the app is requesting access to the user’s media library",
    "NSMotionUsageDescription": "A message that tells the user why the app is requesting access to the device’s accelerometer",
    "NFCReaderUsageDescription": "A message that tells the user why the app is requesting access to the device’s NFC hardware",
    "NSPhotoLibraryAddUsageDescription": "A message that tells the user why the app is requesting write-only access to the user’s photo library",
    "NSPhotoLibraryUsageDescription": "A message that tells the user why the app is requesting access to the user’s photo library",
    "NSAppleScriptEnabled": "A Boolean value indicating whether AppleScript is enabled",
    "NSAppleEventsUsageDescription": "A message that tells the user why the app is requesting the ability to s=s+Apple events",
    "NSSystemAdministrationUsageDescription": "A message in macOS that tells the user why the app is requesting to manipulate the system configuration",
    "ITSAppUsesNonExemptEncryption": "A Boolean value indicating whether the app uses encryption",
    "ITSEncryptionExportComplianceCode": "The export compliance code provided by App Store Connect for apps that require it",
    "NSSiriUsageDescription": "A message that tells the user why the app is requesting to s=s+user data to Siri",
    "NSSpeechRecognitionUsageDescription": "A message that tells the user why the app is requesting to s=s+user data to Apple’s speech recognition servers",
    "NSVideoSubscriberAccountUsageDescription": "A message that tells the user why the app is requesting access to the user’s TV provider account",
    "UIRequiresPersistentWiFi": "A Boolean value indicating whether the app requires a Wi-Fi connection"
}
for (var i = 0; i < permissionListArray.length; i++) {
    try {
        if (dictKeys.containsObject_(permissionListArray[i])) {
            s=s+"\nResource : " + permissionListArray[i]
            s=s+"\nName     : " + permissionListNameDict[permissionListArray[i]]
            s=s+"\nDetails  : " + permissionListDetailDict[permissionListArray[i]]
            s=s+"\nValue    : " + ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_(permissionListArray[i]).toString()
            s=s+"\n"
        }
    } catch (err) {
        if (DEBUG) {
            console.error("[!] Error: " + err.message);
        }
    }
}

s=s+"\n"
s=s+"\n-----------------------------------"
s=s+"\n| App Transport Security Settings |"
s=s+"\n-----------------------------------"
s=s+"\nSource: https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity"
var dictKeys = ObjC.classes.NSBundle.mainBundle().infoDictionary().allKeys();
if (dictKeys.containsObject_("NSAppTransportSecurity")) {
    s=s+"\n[*] Issue: Found 'NSAppTransportSecurity' defined in Info.plist file"
    s=s+"\n[*] Detail: A description of changes made to the default security for HTTP connections"
    s=s+"\n"
    var atsDictKeys = ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").allKeys();
    for (var i = 0; i < atsDictKeys.count(); i++) {
        if (atsDictKeys.objectAtIndex_(i) == "NSAllowsArbitraryLoads") {
            if (ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").objectForKey_("NSAllowsArbitraryLoads").toString() == "1") {
                s=s+"\n[*] Issue: ATS restrictions dsiabled for all network connections by setting 'NSAllowsArbitraryLoads' to True"
                s=s+"\n[*] Detail: A Boolean value indicating whether App Transport Security restrictions are disabled for all network connections"
                s=s+"\n[*] Description: Setting this key's value to YES disables App Transport Security (ATS) restrictions for all domains not specified in the NSExceptionDomains dictionary. Disabling ATS means that unsecured HTTP connections are allowed. HTTPS connections are also allowed, and are still subject to default server trust evaluation. However, extended security checks—like requiring a minimum Transport Layer Security (TLS) protocol version—are disabled. In iOS 10 and later, the value of the NSAllowsArbitraryLoads key is ignored and the default value of NO is used instead — if any of the following keys are present in app's Information Property List file: NSAllowsArbitraryLoadsForMedia, NSAllowsArbitraryLoadsInWebContent, NSAllowsLocalNetworking."
                s=s+"\n"
            }
        }
        if (atsDictKeys.objectAtIndex_(i) == "NSAllowsArbitraryLoadsForMedia") {
            if (ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").objectForKey_("NSAllowsArbitraryLoadsForMedia").toString() == "1") {
                s=s+"\n[*] Issue: ATS restrictions disabled for requests made using the AV Foundation framework by setting 'NSAllowsArbitraryLoadsForMedia' to True"
                s=s+"\n[*] Detail: A Boolean value indicating whether all App Transport Security restrictions are disabled for requests made using the AV Foundation framework"
                s=s+"\n[*] Description: Setting this key's value to disables App Transport Security restrictions for media loaded using the AVFoundation framework, without affecting URLSession connections. Domains specified in the NSExceptionDomains dictionary aren't affected by this key's value. In iOS 10 and later, if this key is included with any value, then App Transport Security ignores the value of the NSAllowsArbitraryLoads key, instead using that key's default value of NO."
                s=s+"\n"
            }
        }
        if (atsDictKeys.objectAtIndex_(i) == "NSAllowsArbitraryLoadsInWebContent") {
            if (ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").objectForKey_("NSAllowsArbitraryLoadsInWebContent").toString() == "1") {
                s=s+"\n[*] Issue: ATS restrictions disabled for requests made from webviews by setting 'NSAllowsArbitraryLoadsInWebContent' to True"
                s=s+"\n[*] Detail: A Boolean value indicating whether all App Transport Security restrictions are disabled for requests made from web views"
                s=s+"\n[*] Description: Setting this key's value to YES to exempt app's web views from App Transport Security restrictions without affecting URLSession connections. Domains specified in the NSExceptionDomains dictionary aren't affected by this key's value. A web view is an instance of any of the following classes: WKWebView and UIWebView. In iOS 10 and later, if this key is included with any value, then App Transport Security ignores the value of the NSAllowsArbitraryLoads key, instead using that key's default value of NO."
                s=s+"\n"
            }
        }
        if (atsDictKeys.objectAtIndex_(i) == "NSAllowsLocalNetworking") {
            if (ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").objectForKey_("NSAllowsLocalNetworking").toString() == "1") {
                s=s+"\n[*] Issue: Allowed Loading of Local Resources by setting 'NSAllowsLocalNetworking' to True"
                s=s+"\n[*] Detail: A Boolean value indicating whether to allow loading of local resources."
                s=s+"\n[*] Description: In iOS 9, App Transport Security (ATS) disallows connections to unqualified domains, .local domains, and IP addresses. Exceptions can be added for unqualified domains and .local domains in the NSExceptionDomains dictionary, but can’t add numerical IP addresses. Instead use NSAllowsArbitraryLoads when you want to load directly from an IP address. In iOS 10 later, ATS allows all three of these connections by default, so an exception is no longer needed for any of them. However, if compatibility with older versions of the OS is to be maintained, set both of the NSAllowsArbitraryLoads and NSAllowsLocalNetworking keys to YES."
                s=s+"\n"
            }
        }
        if (atsDictKeys.objectAtIndex_(i) == "NSExceptionDomains") {
            s=s+"\n[*] Issue: Found 'NSExceptionDomains' defined inside 'NSAppTransportSecurity' in Info.plist file"
            s=s+"\n[*] Detail: Custom configurations for App Transport Security named domains"
            s=s+"\n"
            /*var atsExceptionDomainsDict = ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").objectForKey_("NSExceptionDomains");
            var atsExceptionDomainsDictKeys = ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").objectForKey_("NSExceptionDomains").allKeys();
            for( var i = 0; i<atsExceptionDomainsDictKeys.count(); i++)
            {
                s=s+"\nDomain Name : " + atsExceptionDomainsDict);
                if(ObjC.classes.NSBundle.mainBundle().infoDictionary().objectForKey_("NSAppTransportSecurity").objectForKey_("NSAllowsArbitraryLoads").toString() == "1")
                {
                    s=s+"\n[*] Issue: ")
                    s=s+"\n[*] Detail: ")
                    s=s+"\n[*] Description: ")
                    s=s+"\n")
                }
            }*/
        }
    }
}

s=s+"\n"
s=s+"\n---------------------------------------------"
s=s+"\n| Classes for potential jailbreak detection |"
s=s+"\n---------------------------------------------"
for (var className in ObjC.classes) {
    if (ObjC.classes.hasOwnProperty(className)) {
        var classNameLower = className.toLowerCase();
        if (classNameLower.indexOf("jailbreak") != -1 || classNameLower.indexOf("jailbroke") != -1) {
            s=s+"\n"+className;
            var methods = ObjC.classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++) {
                s=s+"\n\t" + methods[i];
            }
            s=s+"\n"
        }
    }
}

s=s+"\n"
s=s+"\n---------------------------------------------"
s=s+"\n| Methods for potential jailbreak detection |"
s=s+"\n---------------------------------------------"
for (var className in ObjC.classes) {
    if (ObjC.classes.hasOwnProperty(className)) {
        var foundMethods = [];
        var j = 0;
        var methods = ObjC.classes[className].$ownMethods;
        for (var i = 0; i < methods.length; i++) {
            var methodNameLowerCase = methods[i].toLowerCase();
            if (methodNameLowerCase.indexOf("jailbreak") != -1 || methodNameLowerCase.indexOf("jailbroke") != -1) {
                foundMethods[j] = methods[i];
                j++;
            }
        }
        if (foundMethods.length > 0) {
            s=s+"\n"+className
            for (var i = 0; i < foundMethods.length; i++) {
                s=s+"\n\t" + foundMethods[i]
            }
            s=s+"\n"
        }
    }
}

send(s)