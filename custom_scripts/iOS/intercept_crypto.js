/*************************************************************************************
 * Name: Intercepts Crypto Operations
 * OS: iOS
 * Author: @federicodotta
 * Source: https://github.com/federicodotta/Brida
 **************************************************************************************/

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCrypt"),
    {
    onEnter: function(args) {

        send("*** ENTER CCCrypt ****");
        send("CCOperation: " + parseInt(args[0]));
        send("CCAlgorithm: " + parseInt(args[1]));
        send("CCOptions: " + parseInt(args[2]));
        
        if(ptr(args[3]) != 0 ) {
            send("Key:");
            send(base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4]))));
        } else {
            send("Key: 0");
        }

        if(ptr(args[5]) != 0 ) {
            send("IV:");
            send(base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16)));
        } else {
            send("IV: 0");
        }

        this.dataInLength = parseInt(args[7]);

        if(ptr(args[6]) != 0 ) {

            send("Data in ****:");
            send(base64ArrayBuffer(Memory.readByteArray(ptr(args[6]),this.dataInLength)));

        } else {
            send("Data in: null");
        }

        this.dataOut = args[8];
        this.dataOutLength = args[10];

    },

    onLeave: function(retval) {

        if(ptr(this.dataOut) != 0 ) {
            send("Data out");
            send(base64ArrayBuffer(Memory.readByteArray(this.dataOut,parseInt(ptr(Memory.readU32(ptr(this.dataOutLength),4))))));

        } else {
            send("Data out: null");
        }

        send("*** EXIT CCCrypt ****");
        
    }

});

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorCreate"),
    {
    onEnter: function(args) {

        send("*** CCCryptorCreate ENTER ****");
        send("CCOperation: " + parseInt(args[0]));
        send("CCAlgorithm: " + parseInt(args[1]));
        send("CCOptions: " + parseInt(args[2]));

        if(ptr(args[3]) != 0 ) {
            send("Key:");
            send(base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4]))));

        } else {
            send("Key: 0");
        }

        if(ptr(args[5]) != 0 ) {
            send("IV:");
            send(base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16)));
        } else {
            send("IV: 0");
        }

    },
    onLeave: function(retval) {
        send("*** CCCryptorCreate EXIT ****");
    }

});


Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorUpdate"),
    {
    onEnter: function(args) {
        send("*** CCCryptorUpdate ENTER ****");
        if(ptr(args[1]) != 0) {
            send("Data in:");
            send(base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2]))));

        } else {
            send("Data in: null");
        }

        //this.len = args[4];
        this.len = args[5];
        this.out = args[3];

    },

    onLeave: function(retval) {

        if(ptr(this.out) != 0) {
            send("Data out CCUpdate:");
            send(base64ArrayBuffer(Memory.readByteArray(this.out,parseInt(ptr(Memory.readU32(ptr(this.len),4))))));

        } else {
            send("Data out: null");
        }
        send("*** CCCryptorUpdate EXIT ****");
    }

});

Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorFinal"),
    {
    onEnter: function(args) {
        send("*** CCCryptorFinal ENTER ****");
        //this.len2 = args[2];
        this.len2 = args[3];
        this.out2 = args[1];
    },
    onLeave: function(retval) {
        if(ptr(this.out2) != 0) {
            send("Data out CCCryptorFinal:");
            send(base64ArrayBuffer(Memory.readByteArray(this.out2,parseInt(ptr(Memory.readU32(ptr(this.len2),4))))));

        } else {
            send("Data out: null")
        }
        send("*** CCCryptorFinal EXIT ****");
    }

});

//CC_SHA1_Init(CC_SHA1_CTX *c);
Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Init"),
{
    onEnter: function(args) {
    send("*** CC_SHA1_Init ENTER ****");	  	
    send("Context address: " + args[0]);	   
    }
});

//CC_SHA1_Update(CC_SHA1_CTX *c, const void *data, CC_LONG len);
Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Update"),
{
    onEnter: function(args) {
    send("*** CC_SHA1_Update ENTER ****");
    send("Context address: " + args[0]);
    if(ptr(args[1]) != 0) {
        send("data:");
        send(base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2]))));
    } else {
        send("data: null");
    }
    }
});

//CC_SHA1_Final(unsigned char *md, CC_SHA1_CTX *c);
Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Final"),
{
    onEnter: function(args) {
    this.mdSha = args[0];
    this.ctxSha = args[1];
    },
    onLeave: function(retval) {
    send("*** CC_SHA1_Final ENTER ****");
    send("Context address: " + this.ctxSha);
    if(ptr(this.mdSha) != 0) {
        send("Hash:");
        send(base64ArrayBuffer(Memory.readByteArray(ptr(this.mdSha),20)));

    } else {
        send("Hash: null");
    }	
    }
});

// Native ArrayBuffer to Base64
// https://gist.github.com/jonleighton/958841
function base64ArrayBuffer(arrayBuffer) {
    var base64    = ''
    var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    var bytes         = new Uint8Array(arrayBuffer)
    var byteLength    = bytes.byteLength
    var byteRemainder = byteLength % 3
    var mainLength    = byteLength - byteRemainder

    var a, b, c, d
    var chunk

    // Main loop deals with bytes in chunks of 3
    for (var i = 0; i < mainLength; i = i + 3) {
    // Combine the three bytes into a single integer
    chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

    // Use bitmasks to extract 6-bit segments from the triplet
    a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
    b = (chunk & 258048)   >> 12 // 258048   = (2^6 - 1) << 12
    c = (chunk & 4032)     >>  6 // 4032     = (2^6 - 1) << 6
    d = chunk & 63               // 63       = 2^6 - 1

    // Convert the raw binary segments to the appropriate ASCII encoding
    base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
    }

    // Deal with the remaining bytes and padding
    if (byteRemainder == 1) {
    chunk = bytes[mainLength]

    a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

    // Set the 4 least significant bits to zero
    b = (chunk & 3)   << 4 // 3   = 2^2 - 1

    base64 += encodings[a] + encodings[b] + '=='
    } else if (byteRemainder == 2) {
    chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

    a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
    b = (chunk & 1008)  >>  4 // 1008  = (2^6 - 1) << 4

    // Set the 2 least significant bits to zero
    c = (chunk & 15)    <<  2 // 15    = 2^4 - 1

    base64 += encodings[a] + encodings[b] + encodings[c] + '='
    }
    
    return base64
}