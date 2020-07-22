/************************************************************************
 * Name: iOS App Environment
 * OS: iOS
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info: 
    * BundlePath
    * CachesDirectory
    * codeCacheDirectory
    * DocumentDirectory
    * LibraryDirectory
*************************************************************************/

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

send("************************************** App Environment Info **************************************")
send("mainDirectory: "+env.mainDirectory);
send("BundlePath: "+env.BundlePath);
send("CachesDirectory: "+env.CachesDirectory);
send("DocumentDirectory: "+env.DocumentDirectory);
send("LibraryDirectory: "+env.LibraryDirectory);
send("**************************************************************************************************")