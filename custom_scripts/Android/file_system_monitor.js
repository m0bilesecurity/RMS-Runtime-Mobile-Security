/************************************************************************
 * Name: File System Monitor
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info: (libc.so - open, close, read, write, unlink, remove)
*************************************************************************/

Java.perform(function () {
Interceptor.attach(
    Process.getModuleByName("libc.so").findExportByName("open"), {
        onEnter: function (args) {
            var file = ptr(args[0]).readCString();
            if(!file.includes("/dev/ashmem") && !file.includes("/proc/"))
            print("open",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Process.getModuleByName("libc.so").findExportByName("close"), {
        onEnter: function (args) {
            var file = ptr(args[0]).readCString();
            print("close",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Process.getModuleByName("libc.so").findExportByName("read"), {
        onEnter: function (args) {
            var file = ptr(args[0]).readCString();
            print("read",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Process.getModuleByName("libc.so").findExportByName("write"), {
        onEnter: function (args) {
            var file = ptr(args[0]).readCString();
            print("write",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Process.getModuleByName("libc.so").findExportByName("unlink"), {
        onEnter: function (args) {
            var file = ptr(args[0]).readCString();
            print("remove",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Process.getModuleByName("libc.so").findExportByName("remove"), {
        onEnter: function (args) {
            var file = ptr(args[0]).readCString();
            print("remove",file);
        },
        onLeave: function (retval) {

        }
    }
);


function print(method,file){
    send("API Monitor | "+
         "FileSystem" + " | " +
         method + " - " +
         file
        );
  }
});