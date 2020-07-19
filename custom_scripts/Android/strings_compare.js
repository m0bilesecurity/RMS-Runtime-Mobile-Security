/************************************************************************
 * Name: Strings Compare
 * OS: Android
 * Author: iddoeldor
 * Source: https://github.com/iddoeldor/frida-snippets#string-comparison
 *************************************************************************/

Java.perform(function() {

    var str = Java.use('java.lang.String');
    str.equals.overload('java.lang.Object').implementation = function(obj) {
        var result = str.equals.overload('java.lang.Object').call(this, obj);
        if (obj) {
            if (obj.toString().length > 8) {
                send(str.toString.call(this)+" == "+obj.toString()+" ? "+ result);
            }
        }
        return result;
    }
    
});