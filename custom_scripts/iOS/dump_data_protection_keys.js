/********************************************************************************
 * Name: Dump iOS Data Protection Keys
 * OS: iOS
 * Author: @ay-kay
 * Source: https://codeshare.frida.re/@ay-kay/ios-dataprotection/
 * Info: List iOS file data protection classes (NSFileProtectionKey) of an app
 *********************************************************************************/

function listDirectoryContentsAtPath(path) {
    var fileManager = ObjC.classes.NSFileManager.defaultManager();
    var enumerator = fileManager.enumeratorAtPath_(path);
    var file;
    var paths = [];

    while ((file = enumerator.nextObject()) !== null) {
        paths.push(path + '/' + file);
    }

    return paths;
}

function listHomeDirectoryContents() {
    var homePath = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString();
    var paths = listDirectoryContentsAtPath(homePath);
    return paths;
}

function getDataProtectionKeyForPath(path) {
    var fileManager = ObjC.classes.NSFileManager.defaultManager();
    var urlPath = ObjC.classes.NSURL.fileURLWithPath_(path);
    var attributeDict = dictFromNSDictionary(fileManager.attributesOfItemAtPath_error_(urlPath.path(), NULL));
    return attributeDict.NSFileProtectionKey;
}

// helper function available at https://codeshare.frida.re/@dki/ios-app-info/
function dictFromNSDictionary(nsDict) {
    var jsDict = {};
    var keys = nsDict.allKeys();
    var count = keys.count();

    for (var i = 0; i < count; i++) {
        var key = keys.objectAtIndex_(i);
        var value = nsDict.objectForKey_(key);
        jsDict[key.toString()] = value.toString();
    }

    return jsDict;
}

var fileManager = ObjC.classes.NSFileManager.defaultManager();
var dict = [];
var paths = listHomeDirectoryContents();

var isDir = Memory.alloc(Process.pointerSize);
Memory.writePointer(isDir, NULL);

for (var i = 0; i < paths.length; i++) {
    fileManager.fileExistsAtPath_isDirectory_(paths[i], isDir);

    if (Memory.readPointer(isDir) == 0) {
        dict.push({
            path: paths[i],
            fileProtectionKey: getDataProtectionKeyForPath(paths[i])
        });
    }
}

send("**** Files with Data Protection ****");
var k;
for (k in dict) {
    send("\tFile " + k);
    send("\tPath: " + dict[k]['path']);
    send("\tFile protection key: " + dict[k]['fileProtectionKey']);
    send("");
}
send("**** END Files with Data Protection ****");