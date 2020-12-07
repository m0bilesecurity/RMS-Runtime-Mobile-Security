/************************************************************************
 * Name: Dump UI
 * OS: iOS
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
*************************************************************************/

send("[*] Dumping UI - script loaded")

var current_window = ObjC.classes.UIWindow.keyWindow()
send(current_window.recursiveDescription().toString());

send("[*] Dumping UI - completed")