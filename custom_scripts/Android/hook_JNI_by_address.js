/********************************************************************************
 * Name: Hook JNI by address
 * OS: Android
 * Author: iddoeldor
 * Source: https://github.com/iddoeldor/frida-snippets#hook-jni-by-address
 * Info: Hook native method by module name and method address and print arguments
 *********************************************************************************/

var moduleName = "libfoo.so"; 
var nativeFuncAddr = 0x1234; // $ nm --demangle --dynamic libfoo.so | grep "Class::method("

Interceptor.attach(Module.getGlobalExportByName("dlopen"), {
    onEnter: function(args) {
        this.lib = ptr(args[0]).readUtf8String();
        send("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.endsWith(moduleName)) {
            send("ret: " + retval);
            var baseAddr = Process.getModuleByName(moduleName).base;
            Interceptor.attach(baseAddr.add(nativeFuncAddr), {
                onEnter: function(args) {
                    send("[-] hook invoked");
                    send(JSON.stringify({
                        a1: args[1].toInt32(),
                        a2: ptr(args[2]).readPointer().readUtf8String(),
                        a3: Boolean(args[3])
                    }, null, '\t'));
                }
            });
        }
    }
});