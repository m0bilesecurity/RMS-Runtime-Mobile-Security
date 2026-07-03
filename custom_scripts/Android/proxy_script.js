// proxy-script.js
function addColor(text) {
    var colors = [
        '\x1b[31m',  // red
        '\x1b[32m',  // green
        '\x1b[33m',  // yellow
        '\x1b[34m',  // blue
        '\x1b[35m',  // magenta
        '\x1b[36m',  // cyan
        '\x1b[37m'   // white
    ];

    var randomColor = colors[Math.floor(Math.random() * colors.length)];

    return randomColor + text + '\x1b[0m';  // reset color
}

// Set the provided text in the logoText variable
var logoText =
    " __  __ _______ _______ _______ _______ _______      _______ _______ ______ _______ _____   _______ ___ ___ _______ \n" +
    "|  |/  |_     _|     __|   |   |   _   |    |  |    |   _   |   |   |   __ \\   _   |     |_|_     _|   |   |   _   |\n" +
    "|     < _|   |_|__     |       |       |       |    |       |       |   __ <       |       |_|   |_ \\     /|       |\n" +
    "|__|\\__|_______|_______|___|___|___|___|__|____|    |___|___|__|_|__|______/___|___|_______|_______| |___| |___|___|\n" +
    "                                     K I S H A N    A M B A L I Y A                          ";

// Generate and print the logo-like text with a random color
console.log(addColor(logoText));

const proxyIp = "159.223.117.14";
const proxyPort = 24006;

function setHttpProxy() {
    try {
        var System = Java.use("java.lang.System");
        var Proxy = Java.use("java.net.Proxy");
        var InetSocketAddress = Java.use("java.net.InetSocketAddress");
        var String = Java.use("java.lang.String");

        if (System) {
            // Set HTTP proxy
            System.setProperty("http.proxySet", "true");
            System.setProperty("http.proxyHost", proxyIp);
            System.setProperty("http.proxyPort", "" + proxyPort);

            // Set HTTPS proxy
            System.setProperty("https.proxyHost", proxyIp);
            System.setProperty("https.proxyPort", "" + proxyPort);

            console.log("HTTP proxy set: " + proxyIp + ":" + proxyPort);
        }

        if (Proxy && InetSocketAddress && String) {
            var addr = InetSocketAddress.$new(String.$new(proxyIp), proxyPort);
            var proxyAddr = Proxy.$new(java.net.Proxy.Type.HTTP, addr);

            console.log("Set up proxy: " + proxyAddr);

            // Modify OkHttpClient to use the proxy
            Java.choose("okhttp3.OkHttpClient$Builder", {
                onMatch: function (instance) {
                    instance.build.overload().implementation = function () {
                        this.proxy(proxyAddr);
                        return this.build();
                    };
                },
                onComplete: function () {}
            });
        } else {
            console.error("Required classes not found.");
        }
    } catch (error) {
        console.error("Error in setHttpProxy: " + error);
    }
}

function hookApplication() {
    try {
        var Application = Java.use("android.app.Application");
        Application.onCreate.implementation = function () {
            this.onCreate();
            console.log("Hooking application...");
            setHttpProxy();
        };
    } catch (e) {
        console.error("Error hooking application: " + e);
    }
}

Java.perform(hookApplication);
