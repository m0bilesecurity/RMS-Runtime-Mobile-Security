/************************************************************************
 * Name: Native Hook Template
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info: 
    * {native_library} = e.g. libc.so
    * {native_function} = e.g. open
    * args is an array containing arguments passed to native function
    * retval contains return value
*************************************************************************/

var native_library="{native_library}"
var native_function="{native_function}"

Interceptor.attach(
    Module.findExportByName(native_library, native_function), {
        onEnter: function (args) {
            send(native_library + " - " + native_function);
            send("arg0 "+Memory.readCString(args[0]));
            
        },
        onLeave: function (retval) {
            send("Return Value: "+Memory.readCString(retval));
            //retval.replace(0);
        }
    }
);
