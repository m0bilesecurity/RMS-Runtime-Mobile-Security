/************************************************************************
 * Name: File System Monitor
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
*************************************************************************/

Interceptor.attach(
    Module.findExportByName("libc.so", "open"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            if(!file.includes("/dev/ashmem") && !file.includes("/proc/"))
            send("FS Monitor |   action: open   | file: " + file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "close"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            send("FS Monitor |   action: close  | file: " + file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "read"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            send("FS Monitor |   action: read   | file: " + file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "write"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            send("FS Monitor |   action: write  | write: " + file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "unlink"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            send("FS Monitor |   action: unlink | file: " + file);
        },
        onLeave: function (retval) {

        }
    }
);

Interceptor.attach(
    Module.findExportByName("libc.so", "remove"), {
        onEnter: function (args) {
            var file = Memory.readCString(args[0]);
            send("FS Monitor |   action: remove | file: " + file);
        },
        onLeave: function (retval) {

        }
    }
);

