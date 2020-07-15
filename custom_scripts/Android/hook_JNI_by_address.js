/********************************************************************************
 * Name: Hook JNI by address
 * OS: Android
 * Author: iddoeldor
 * Source: https://github.com/iddoeldor/frida-snippets#hook-jni-by-address
 * Info: Hook native method by module name and method address and print arguments
 *********************************************************************************/

var moduleName = "libfoo.so"; 
var nativeFuncAddr = 0x1234; // $ nm --demangle --dynamic libfoo.so | grep "Class::method("

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        send("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.endsWith(moduleName)) {
            send("ret: " + retval);
            var baseAddr = Module.findBaseAddress(moduleName);
            Interceptor.attach(baseAddr.add(nativeFuncAddr), {
                onEnter: function(args) {
                    send("[-] hook invoked");
                    send(JSON.stringify({
                        a1: args[1].toInt32(),
                        a2: Memory.readUtf8String(Memory.readPointer(args[2])),
                        a3: Boolean(args[3])
                    }, null, '\t'));
                }
            });
        }
    }
});