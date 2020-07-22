/************************************************************************
 * Name: File System Monitor
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info: (libc.so - open, close, read, write, unlink, remove)
*************************************************************************/

Java.perform(function () {
Interceptor.attach(
    Module.findExportByName("libc.so", "open"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            if(!file.includes("/dev/ashmem") && !file.includes("/proc/"))
            print("open",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "close"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            print("close",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "read"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            print("read",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "write"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            print("write",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "unlink"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            print("remove",file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "remove"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
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