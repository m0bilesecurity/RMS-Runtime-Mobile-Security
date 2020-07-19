/********************************************************************************
 * Name: Dump Cookies
 * OS: iOS
 * Author: @iddoeldor
 * Source: https://github.com/iddoeldor/frida-snippets
 *********************************************************************************/

var cookieJar = {};
var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
for (var i = 0, l = cookies.count(); i < l; i++) {
  var cookie = cookies['- objectAtIndex:'](i);
  cookieJar[cookie.Name()] = cookie.Value().toString(); // ["- expiresDate"]().toString()
}
send(JSON.stringify(cookieJar, null, 2));