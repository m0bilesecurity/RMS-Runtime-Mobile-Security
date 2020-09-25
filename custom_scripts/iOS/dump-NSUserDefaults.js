/************************************************************************
 * Name: Dump NSUserDefaults
 * OS: iOS
 * Author: @noobpk
 * Source: https://github.com/noobpk/frida-ios-hook
*************************************************************************/

send("[*] Started: Read NSUserDefaults PLIST file");

try {
  var NSUserDefaults = ObjC.classes.NSUserDefaults;
  var NSDictionary = NSUserDefaults.alloc().init().dictionaryRepresentation();
  send(NSDictionary.toString())
} catch (err) {
  send("[!] Exception: " + err.message);
}

send("[*] Completed: Read NSUserDefaults PLIST file");