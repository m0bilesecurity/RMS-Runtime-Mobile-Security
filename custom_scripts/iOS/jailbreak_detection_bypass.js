/************************************************************************
 * Name: Jailbreak Detection Bypass
 * OS: iOS
 * Author: @chaitin
 * Source: https://github.com/chaitin/passionfruit
*************************************************************************/

const paths = [ '/Applications/Cydia.app',
'/Applications/FakeCarrier.app',
'/Applications/Icy.app',
'/Applications/IntelliScreen.app',
'/Applications/MxTube.app',
'/Applications/RockApp.app',
'/Applications/SBSettings.app',
'/Applications/WinterBoard.app',
'/Applications/blackra1n.app',
'/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist',
'/Library/MobileSubstrate/DynamicLibraries/Veency.plist',
'/Library/MobileSubstrate/MobileSubstrate.dylib',
'/System/Library/LaunchDaemons/com.ikey.bbot.plist',
'/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
'/bin/bash',
'/bin/sh',
'/etc/apt',
'/etc/ssh/sshd_config',
'/private/var/lib/apt',
'/private/var/lib/cydia',
'/private/var/mobile/Library/SBSettings/Themes',
'/private/var/stash',
'/private/var/tmp/cydia.log',
'/usr/bin/sshd',
'/usr/libexec/sftp-server',
'/usr/libexec/ssh-keysign',
'/usr/sbin/sshd',
'/var/cache/apt',
'/var/lib/apt',
'/private/jailbreak.txt',
'/var/lib/cydia' ];

const subject = 'jailbreak'

if(ObjC.available) {
//function bypassJailbreak() {
    /* eslint no-param-reassign: 0, camelcase: 0, prefer-destructuring: 0 */
    Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter(args) {
        if (!args[0])
        return

        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; }).join("\n\t\t");
        //e => e.name)

        //const path = Memory.readUtf8String(args[0])
        const path = args[0].readUtf8String()

        if (paths.indexOf(path) > -1) {

        var newPath = "/QZQZ" + path.substring(5)
        //send(newPath)

        send("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
        send("\tMethod: open");
        send("\tPath: " + path);
        send("\tTime: " + new Date().getTime());
        send("\tBacktrace: " + backtrace);
        send("*** END Jailbrek check detected")
        
        //args[0] = NULL
        args[0].writeUtf8String(newPath)


        }
    }
    })

    const statHandler = {
    onEnter(args) {
        if (!args[0])
        return

        //const path = Memory.readUtf8String(args[0])
        const path = args[0].readUtf8String()
        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t");
        // e => e.name

        if (paths.indexOf(path) > -1) {    

        var newPath = "/QZQZ" + path.substring(5)
        
        send("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
        send("\tMethod: stat");
        send("\tPath: " + path);
        send("\tTime: " + new Date().getTime());
        send("\tBacktrace: " + backtrace);
        send("*** END Jailbrek check detected")

        args[0].writeUtf8String(newPath)
        //args[0] = NULL
        }
    }
    }
    Interceptor.attach(Module.findExportByName(null, 'stat'), statHandler)
    Interceptor.attach(Module.findExportByName(null, 'stat64'), statHandler)

    Interceptor.attach(Module.findExportByName(null, 'getenv'), {
    onEnter(args) {
        //const key = Memory.readUtf8String(args[0])
        const key = args[0].readUtf8String()
        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t");
        // e => e.name

        this.print_ret = false

        if (key === 'DYLD_INSERT_LIBRARIES') {

        this.print_ret = true

        send("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
        send("\tenv: DYLD_INSERT_LIBRARIES");
        send("\tTime: " + new Date().getTime());
        send("\tBacktrace: " + backtrace);
        send("*** END Jailbrek check detected")

        //args[0] = NULL

        }
    },
    onLeave(retVal) {

        if(this.print_ret == true) {
        //send(retVal);
        retVal.replace(ptr(0));
        }
    }
    })

    Interceptor.attach(Module.findExportByName(null, '_dyld_get_image_name'), {
    onLeave(retVal) {
        if (Memory.readUtf8String(retVal).indexOf('MobileSubstrate') > -1)
        retVal.replace(ptr(0x00))
    }
    })

    Interceptor.attach(Module.findExportByName(null, 'fork'), {
    onLeave(retVal) {
        retVal.replace(ptr(-1))
        // todo: send
    }
    })

    //const { UIApplication, NSURL, NSFileManager } = ObjC.classes
    const UIApplication = ObjC.classes.UIApplication
    const NSURL = ObjC.classes.NSURL
    const NSFileManager = ObjC.classes.NSFileManager

    const canOpenURL_publicURLsOnly_ = UIApplication['- _canOpenURL:publicURLsOnly:']
    Interceptor.attach(canOpenURL_publicURLsOnly_.implementation, {
    onEnter(args) {
        if (args[2].isNull())
        return

        const url = ObjC.Object(args[2]).toString()
        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t")
        // e => e.name

        if (/^cydia:\/\//i.exec(url)) {
        args[2] = NSURL.URLWithString_('invalid://')
        this.shouldOverride = true

        send("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
        send("\turl: " + url);
        send("\tTime: " + new Date().getTime());
        send("\tBacktrace: " + backtrace);
        send("*** END Jailbrek check detected")

        
        }
    },
    onLeave(retVal) {
        if (this.shouldOverride)
        retVal.replace(ptr(0))
    }
    })

    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter(args) {
        if (args[2].isNull())
        return

        const path = new ObjC.Object(args[2]).toString()
        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t")
        // e => e.name

        if (paths.indexOf(path) > -1) {

        send("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
        send("\tpath: " + path);
        send("\tTime: " + new Date().getTime());
        send("\tBacktrace: " + backtrace);
        send("*** END Jailbrek check detected")

        this.shouldOverride = true
        }
    },
    onLeave(retVal) {
        if (this.shouldOverride)
        retVal.replace(ptr('0x00'))
    }
    })
}
