/******************************************************************************
 * Exported APIs

 Base APIs set - same of RMS_core.js
 ____________________________________________________________________________
 1. loadclasses()
 2. loadclasseswithfilter([filters], isRegex, isCase, isWhole)
 3. loadmethods([loaded_classes])
 4. loadcustomfridascript(frida_script)
 5. hookclassesandmethods([loaded_classes], [loaded_methods], template)
 6. generatehooktemplate([loaded_classes], [loaded_methods], template)
 7. heapsearchtemplate([loaded_classes], [loaded_methods], template)
 8. apimonitor([api_to_monitor])
 9. getappenvinfo()
 10. listfilesatpath(path)
 ____________________________________________________________________________

 BETA APIs set 
 ____________________________________________________________________________
 11. downloadfileatpath(path)
 ____________________________________________________________________________
 ******************************************************************************/

//import frida-fs
const fs = require('frida-fs');

rpc.exports = {
  checkmobileos: function(){
    if (Java.available) return "Android"
    if (ObjC.available) return "iOS"
    return "N/A"
  },
  loadclasses: function () {
    if (Java.available)
      return load_classes_Android()
    else 
      return load_classes_iOS()
  },
  loadclasseswithfilter: function (filter, isRegex, isCase, isWhole) {
    if (Java.available)
      return load_classes_with_filter_Android(filter, isRegex, isCase, isWhole)
    else 
      return load_classes_with_filter_iOS(filter, isRegex, isCase, isWhole)
  },
  loadmethods: function (loaded_classes) {
      if (Java.available)
        return load_methods_Android(loaded_classes)
      else 
        return load_methods_iOS(loaded_classes)
  },
  loadcustomfridascript: function (frida_script) {
    if (Java.available)
      load_frida_custom_script_Android(frida_script)
    else 
      load_frida_custom_script_iOS(frida_script)
  },
  hookclassesandmethods: function (loaded_classes, loaded_methods, template) {
    if (Java.available)
      hook_classes_and_methods_Android(loaded_classes, loaded_methods, template)
    else 
      hook_classes_and_methods_iOS(loaded_classes, loaded_methods, template)
  },
  generatehooktemplate: function (loaded_classes, loaded_methods, template) {
    if (Java.available)
      return generate_hook_template_Android(loaded_classes, loaded_methods, template)
    else 
      return generate_hook_template_iOS(loaded_classes, loaded_methods, template)
  },
  heapsearchtemplate: function (loaded_classes, loaded_methods, template) {
    if (Java.available)
      return heap_search_template_Android(loaded_classes, loaded_methods, template)
    else 
      return heap_search_template_iOS(loaded_classes, loaded_methods, template)
  },
  getappenvinfo: function () {
    if (Java.available)
      return get_app_env_info_Android()
    else 
      return get_app_env_info_iOS()
  },
  listfilesatpath: function (path) {
    if (Java.available)
      return list_files_at_path_Android(path)
    else 
      return list_files_at_path_iOS(path)
  },
  downloadfileatpath: function (path) {
    if (Java.available)
      download_file_at_path_Android(path)
    else 
      download_file_at_path_iOS(path)
  },
  apimonitor: function (api_to_monitor) {
    if (Java.available)
      api_monitor_Android(api_to_monitor)
    else 
      api_monitor_iOS(api_to_monitor)
  }
};

/*
***********************************************************************
*************************** Android - Stuff ***************************
***********************************************************************             
*/

function load_classes_Android()
{
  var loaded_classes = []
  Java.perform(function () {
    Java.enumerateLoadedClasses({
      onMatch: function (className) 
      {
        //Remove too generics
        if (
          className.length > 5 &&
          //skip androidx stuff
          !className.includes("androidx")
        )
          loaded_classes.push(className)
      }

    });
  });
  return loaded_classes;
}

function load_classes_with_filter_Android(filter, isRegex, isCase, isWhole)
{
  var loaded_classes = []
  Java.perform(function () {
    Java.enumerateLoadedClasses({
      onMatch: function (className) {

        //lowercase if not case sensitive
        var originalClassName = className
        className = isCase ? className : className.toLowerCase()
        filter = isCase ? filter : filter.toLowerCase()

        //check if a filter exists
        if (filter != null) 
        {
          //Regex
          if (isRegex) 
          {
            if (className.search(filter) > -1) 
            {
              loaded_classes.push(originalClassName)
            }
            //Not regex
          } else 
          {
            //check if we have multiple filters (comma separated list)
            var filter_array = filter.split(",");
            filter_array.forEach(function (f) 
            {
              if (isWhole) 
              { //f.trim() is needed to remove possibile spaces after the comma
                if (className == f.trim()) {
                  loaded_classes.push(originalClassName)
                }
              } else 
              { //f.trim() is needed to remove possibile spaces after the comma
                if (className.startsWith(f.trim())) 
                {
                  loaded_classes.push(originalClassName)
                }
              }
            });
          }
        }
      }
    });
  });
  return loaded_classes;
}

function load_methods_Android(loaded_classes){
  var loaded_methods = {};
  Java.perform(function () {
    loaded_classes.forEach(function (className, index) {
      var jClass;
      var classMethods_dirty;
      var classMethods = []
    
      //catch possible issues
      try {
        jClass = Java.use(className);
        classMethods_dirty = jClass.class.getDeclaredMethods();
      } catch (err) {
        send("Exception while loading methods for " + className);
        //skip current loop
        loaded_methods[className] = classMethods //is empty
        return;
      }
    
      classMethods_dirty.forEach(function (m) {
        var method_and_args = {};
        //Cleaning up
        m = m.toString();
        //add info for the UI
        method_and_args["ui_name"] = m.replace(className + ".", "")
        // Remove generics from the method
        while (m.includes("<")) {
          m = m.replace(/<.*?>/g, "");
        }
        // remove "Throws" 
        if (m.indexOf(" throws ") !== -1) {
          m = m.substring(0, m.indexOf(" throws "));
        }
        // remove scope and return type declarations 
        m = m.slice(m.lastIndexOf(" "));
        // remove the class name
        m = m.replace(className + ".", "");
    
        // remove the signature (args) 
        method_and_args["name"] = m.split("(")[0].trim()
    
        // get the args 
        var args_dirty = ((/\((.*?)\)/.exec(m)[1]).trim())
    
        // add quotes between every arg
        var args_array = args_dirty.split(",")
        var args_srt = ""
        for (var i = 0; i < args_array.length; i++) {
    
          // check if the current arg is an array
          var arg = args_array[i]
          if (arg.includes("[]")) {
            // arg is an array --> smali notation conversion
            if (arg.includes(".")) arg = "L" + arg + ";"
            else if ((/boolean/i).test(arg)) arg = "Z" + arg.replace(/boolean/i, "");
            else if ((/byte/i).test(arg)) arg = "B" + arg.replace(/byte/i, "");
            else if ((/char/i).test(arg)) arg = "C" + arg.replace(/char/i, "");
            else if ((/double/i).test(arg)) arg = "D" + arg.replace(/double/i, "");
            else if ((/float/i).test(arg)) arg = "F" + arg.replace(/float/i, "");
            else if ((/int/i).test(arg)) arg = "I" + arg.replace(/int/i, "");
            else if ((/long/i).test(arg)) arg = "J" + arg.replace(/long/i, "");
            else if ((/short/i).test(arg)) arg = "S" + arg.replace(/short/i, "");
            else arg = "L" + arg + ";"
          }
          while (arg.includes("[]")) {
            arg = arg.replace("[]", "")
            arg = "[" + arg
          }
    
          args_srt = args_srt + ("\"" + arg + "\"")
          //add a comma if the current item is not the last one
          if (i + 1 < args_array.length) args_srt = args_srt + ",";
        }
    
        method_and_args["args"] = args_srt
        classMethods.push(method_and_args);
    
      });
    
      loaded_methods[className] = classMethods;
    });
  });
  //DEBUG console.log("loaded_classes.length: " + loaded_classes.length)
  //DEBUG console.log("loaded_methods.length: " + Object.keys(loaded_methods).length)
  return loaded_methods;
}

function load_frida_custom_script_Android(frida_script)
{
  Java.perform(function () {
    console.log("FRIDA script LOADED")
    eval(frida_script)
  })
}

function hook_classes_and_methods_Android(loaded_classes, loaded_methods, template)
{ 
  Java.perform(function () {

    console.log("Hook Template setup")

    loaded_classes.forEach(function (clazz) {
      loaded_methods[clazz].forEach(function (dict) {
        var t = template //template1

        // replace className
        t = t.replace("{className}", clazz);
        // replace classMethod x3
        t = t.replace("{classMethod}", dict["name"]);
        t = t.replace("{classMethod}", dict["name"]);
        t = t.replace("{classMethod}", dict["name"]);
        // replace methodSignature 
        t = t.replace("{methodSignature}", dict["ui_name"]);

        //check if the method has args 
        if (dict["args"] != "\"\"") {
          //check if the method has overloads
          t = t.replace("{overload}", "overload(" + dict["args"] + ").");
          // Check args length
          var args_len = (dict["args"].split(",")).length

          //args creation (method inputs) - v[i] to N
          var args = "";
          for (var i = 0; i < args_len; i++) {
            if (i + 1 == args_len) args = args + "v" + i;
            else args = args + "v" + i + ",";
          }

          //replace args x2
          t = t.replace("{args}", args);
          t = t.replace("{args}", args);

        } else {
          //Current methods has NO args 
          // no need to overload
          t = t.replace("{overload}", "overload().");
          //replace args x2 
          t = t.replace("{args}", "");
          t = t.replace("{args}", "");
        }

        //Debug - print FRIDA template
        //send(t);

        console.log(clazz+" "+dict["name"]+" hooked!")
        // ready to eval!
        eval(t);
      });
    });

  })
}

function generate_hook_template_Android (loaded_classes, loaded_methods, template) {
  var hto = "" //hto stands for hooks template output
  Java.perform(function () {
    loaded_classes.forEach(function (clazz) {
      loaded_methods[clazz].forEach(function (dict) {
        var t = template //template2

        // replace className
        t = t.replace("{className}", clazz);
        // replace classMethod x3
        t = t.replace("{classMethod}", dict["name"]);
        t = t.replace("{classMethod}", dict["name"]);
        t = t.replace("{classMethod}", dict["name"]);
        // replace methodSignature x2
        t = t.replace("{methodSignature}", dict["ui_name"]);
        t = t.replace("{methodSignature}", dict["ui_name"]);

        //check if the method has args 
        if (dict["args"] != "\"\"") {
          //check if the method has overloads
          t = t.replace("{overload}", "overload(" + dict["args"] + ").");
          // Check args length
          var args_len = (dict["args"].split(",")).length

          //args creation (method inputs) - v[i] to N
          var args = "";
          for (var i = 0; i < args_len; i++) {
            if (i + 1 == args_len) args = args + "v" + i;
            else args = args + "v" + i + ",";
          }

          //replace args x3
          t = t.replace("{args}", args);
          t = t.replace("{args}", args);
          t = t.replace("{args}", args);
        } else {
          //Current methods has NO args 
          // no need to overload
          t = t.replace("{overload}", "overload().");
          //replace args x3
          t = t.replace("{args}", "");
          t = t.replace("{args}", "");
          t = t.replace("{args}", "\"\"");
        }

        //Debug - print FRIDA template
        //send(t);

        // hooks concat
        hto = hto + t;
      });
    });

  })
  // return HOOK template
  return hto;
}

function heap_search_template_Android(loaded_classes, loaded_methods, template)
{
  var hto = "" //hto stands for heap template output
  Java.perform(function () {
    loaded_classes.forEach(function (clazz) {
      loaded_methods[clazz].forEach(function (dict) {
        var t = template //template2

        // replace className
        t = t.replace("{className}", clazz);
        // replace classMethod x2
        t = t.replace("{classMethod}", dict["name"]);
        t = t.replace("{classMethod}", dict["name"]);
        // replace methodSignature x2
        t = t.replace("{methodSignature}", dict["ui_name"]);
        t = t.replace("{methodSignature}", dict["ui_name"]);

        //check if the method has args 
        if (dict["args"] != "\"\"") {

          // Check args length
          var args_len = (dict["args"].split(",")).length

          //args creation (method inputs) - v[i] to N
          var args = "";
          for (var i = 0; i < args_len; i++) {
            if (i + 1 == args_len) args = args + "v" + i;
            else args = args + "v" + i + ",";
          }

          //replace args
          t = t.replace("{args}", args);

        } else {
          //Current methods has NO args 

          //replace args
          t = t.replace("{args}", "");

        }

        //Debug - print FRIDA template
        //send(t);

        // heap search templates concat
        hto = hto + t;
      });
    });

  })
  // return Heap Search template
  return hto;
}

function get_app_env_info_Android()
{
  var env;
  Java.perform(function (){
    var context = null
    var ActivityThread = Java.use('android.app.ActivityThread');
    var targetApp = ActivityThread.currentApplication();

    if (targetApp != null) {
        context = targetApp.getApplicationContext();
        env = 
        {   mainDirectory: context.getFilesDir().getParent(),
            filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
            cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
            externalCacheDirectory: context.getExternalCacheDir().getAbsolutePath().toString(),
            codeCacheDirectory: 
                'getCodeCacheDir' in context ? 
                context.getCodeCacheDir().getAbsolutePath().toString() : 'N/A',
            obbDir: context.getObbDir().getAbsolutePath().toString(),
            packageCodePath: context.getPackageCodePath().toString().replace("/base.apk",""),
        };
    } else env=null
  })
  return env;
}

function list_files_at_path_Android(path)
{
  var listResult;
  Java.perform(function (){
    var file = Java.use("java.io.File");
    var currentPath = file.$new(path);
    var files;

    listResult= {
      files: {},
      path: path,
      readable: currentPath.canRead(),
      writable: currentPath.canWrite(),
    };

    files = currentPath.listFiles();
    files.forEach(function (f) {
      listResult.files[f.getName()] = {
        attributes: {
          isDirectory: f.isDirectory(),
          isFile: f.isFile(),
          isHidden: f.isHidden(),
          lastModified: new Date(f.lastModified()).toISOString().replace(/T/, ' ').replace(/\..+/, ''),
          size: f.length()
        },
        fileName: f.getName(),
        readable: f.canRead(),
        writable: f.canWrite()
      };
    })
    //console.log(JSON.stringify(listResult))
  })
  return listResult;
}

function download_file_at_path_Android(path)
{
  var file;
  Java.perform(function (){
    file=fs.readFileSync(path)
  })
  return file;
}

function api_monitor_Android(api_to_monitor) 
{
  Java.perform(function () {
    /* DEBUG
    api_to_monitor.forEach(function (e) {
      console.log(e["Category"]);
      e["hooks"].forEach(function (hook) {
        console.log("--> "+hook["clazz"]+" - "+hook["method"]);
      });
    });
    */
    api_to_monitor.forEach(function (e) {
      e["hooks"].forEach(function (hook) {
        // Java or Native Hook?

        // Native - File System only at the moment
        if (e["HookType"] == "Native") {
          nativedynamichook(hook, e["Category"]);
        }

        // Java 
        if (e["HookType"] == "Java") {
          javadynamichook(hook, e["Category"], function (realRetval, to_print) {

            send('[API_Monitor]\n' + 
            JSON.stringify(to_print,function(k,v)
            {
              if(v instanceof Array)
                 return JSON.stringify(v);
              return v;
            },2)
            +"\n");
            
            return realRetval;
          });
        } // end javadynamichook

      });

    });

  })
}

function nativedynamichook(hook, category) {
  // File System monitor only - libc.so
  Interceptor.attach(
    Module.findExportByName(hook["clazz"], hook["method"]), {
      onEnter: function (args) {
        var file = Memory.readCString(args[0]);
        //bypass ashem and prod if libc.so - open
        if (hook["clazz"] == "libc.so" &&
          hook["method"] == "open" &&
          !file.includes("/dev/ashmem") &&
          !file.includes("/proc/"))
          send("[API_Monitor] - " + category + " - " + hook["clazz"] + " - " + hook["method"] + " - " + file+"\n");
      }
    }
  );
}

function javadynamichook(hook, category, callback) {
  var Exception = Java.use('java.lang.Exception');
  var toHook;
  try {
    var clazz = hook.clazz;
    var method = hook.method;

    try {
      if (hook.target &&
        parseInt(Java.androidVersion, 10) < hook.target) {
        send('[API_Monitor] - Android Version not supported - Cannot hook - ' + clazz + '.' + method)
        return
      }
      // Check if class and method is available
      toHook = Java.use(clazz)[method];
      if (!toHook) {
        send('[API_Monitor] - Cannot find ' + clazz + '.' + method);
        return
      }
    } catch (err) {
      send('[API_Monitor] - Cannot find ' + clazz + '.' + method);
      return
    }
    for (var i = 0; i < toHook.overloads.length; i++) {
      toHook.overloads[i].implementation = function () {
        var args = [].slice.call(arguments);
        // Call original method
        var retval = this[method].apply(this, arguments);
        
        if (callback) {
          var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
          var to_print = {
            category: category,
            class: clazz,
            method: method,
            args: args,
            returnValue: retval ? retval.toString() : "N/A",
            calledFrom: calledFrom
          };
          retval = callback(retval, to_print);
        }
        return retval;
      }
    }
  } catch (err) {
    send('[API_Monitor] - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
  }
}

/*
***********************************************************************
***************************** iOS - Stuff *****************************
***********************************************************************             
*/

function load_classes_iOS()
{
  var loaded_classes = []
  for (var className in ObjC.classes) {
    if (
        ObjC.classes.hasOwnProperty(className) &&
        className.length > 5
      )
        loaded_classes.push(className)
  }
  
  return loaded_classes;
}

function load_classes_with_filter_iOS(filter, isRegex, isCase, isWhole)
{
  var loaded_classes = []

  for (var className in ObjC.classes) {
      //lowercase if not case sensitive
      var originalClassName = className
      className = isCase ? className : className.toLowerCase()
      filter = isCase ? filter : filter.toLowerCase()

      //check if a filter exists
      if (filter != null) 
      {
        //Regex
        if (isRegex) 
        {
          if (className.search(filter) > -1) 
          {
            loaded_classes.push(originalClassName)
          }
          //Not regex
        } else 
        {
          //check if we have multiple filters (comma separated list)
          var filter_array = filter.split(",");
          filter_array.forEach(function (f) 
          {
            if (isWhole) 
            { //f.trim() is needed to remove possibile spaces after the comma
              if (className == f.trim()) {
                loaded_classes.push(originalClassName)
              }
            } else 
            { //f.trim() is needed to remove possibile spaces after the comma
              if (className.startsWith(f.trim())) 
              {
                loaded_classes.push(originalClassName)
              }
            }
          });
        }
      }
    }

  return loaded_classes;
}

function load_methods_iOS(loaded_classes){
  var loaded_methods = {};
  loaded_classes.forEach(function (className, index) {

    var classMethods_dirty;
    var classMethods = []

    try{
      if (ObjC.classes.hasOwnProperty(className))
        classMethods_dirty=ObjC.classes[className].$ownMethods;
      
    } catch (err) {
      send("Exception while loading methods for " + className);
      //skip current loop
      loaded_methods[className] = classMethods //is empty
      return;
    }

    classMethods_dirty.forEach(function (m) {
      var method_and_args = {};
      var retValue=null;
      var args=null;
      try{
        retValue=ObjC.classes[className][m].returnType
      }
      catch(err){
        retValue=null
      }
      try{
        args=(ObjC.classes[className][m].argumentTypes)
        //remove args[0] = self, args[1] = selector
        args.shift() 
        args.shift()
      }
      catch(err){
        args=null
      }
      
      method_and_args["ui_name"]="("+retValue+") "+m+"("+args+")";
      method_and_args["name"]=m;
      method_and_args["args"]=args;
      classMethods.push(method_and_args);
    })
    loaded_methods[className] = classMethods;
  }); 
  
  //DEBUG console.log("loaded_classes.length: " + loaded_classes.length)
  //DEBUG console.log("loaded_methods.length: " + Object.keys(loaded_methods).length)
  return loaded_methods;
}

function load_frida_custom_script_iOS(frida_script)
{
    console.log("FRIDA script LOADED")
    eval(frida_script)
}

function hook_classes_and_methods_iOS(loaded_classes, loaded_methods, template)
{
  loaded_classes.forEach(function (clazz) {
    loaded_methods[clazz].forEach(function (dict) {
      var t = template 

      // replace className
      t = t.replace("{className}", clazz);
      // replace classMethod 
      t = t.replace("{classMethod}", dict["name"]);
      // replace methodSignature 
      t = t.replace("{methodSignature}", dict["ui_name"]);

      console.log(clazz+" "+dict["name"]+" hooked!")
      eval(t)
    });
  });
}


function generate_hook_template_iOS (loaded_classes, loaded_methods, template) 
{
  var hto = "" //hto stands for hooks template output
  loaded_classes.forEach(function (clazz) {
    loaded_methods[clazz].forEach(function (dict) {
      var t = template //template2

      // replace className
      t = t.replace("{className}", clazz);
      // replace classMethod 
      t = t.replace("{classMethod}", dict["name"]);
      // replace methodSignature x3
      t = t.replace("{methodSignature}", dict["ui_name"]);
      t = t.replace("{methodSignature}", dict["ui_name"]);
      t = t.replace("{methodSignature}", dict["ui_name"]);

      //hook templates concat
      hto = hto + t;
    });
  });
  // return HOOK template
  return hto;
}

function heap_search_template_iOS(loaded_classes, loaded_methods, template)
{
  var hto = "" //hto stands for heap template output
  loaded_classes.forEach(function (clazz) {
    loaded_methods[clazz].forEach(function (dict) {
      var t = template //template2

      // replace className
      t = t.replace("{className}", clazz);
      // replace classMethod x1
      t = t.replace("{classMethod}", dict["name"]);
      // replace methodSignature x2
      t = t.replace("{methodSignature}", dict["ui_name"]);
      t = t.replace("{methodSignature}", dict["ui_name"]);
      
      //heap search templates concat
      hto = hto + t;
    });
  });
  // return Heap Search template
  return hto;
}

function get_app_env_info_iOS()
{
  var env;
  const NSUserDomainMask = 1
  const NSLibraryDirectory = 5
  const NSDocumentDirectory = 9
  const NSCachesDirectory = 13
  
  var NSBundle = ObjC.classes.NSBundle.mainBundle()
  var NSFileManager = ObjC.classes.NSFileManager.defaultManager();
  
  var env = {
      mainDirectory: (NSFileManager.URLsForDirectory_inDomains_(NSLibraryDirectory, NSUserDomainMask).lastObject().path().toString()).replace("Library",""),
      BundlePath: NSBundle.bundlePath().toString(),
      CachesDirectory: NSFileManager.URLsForDirectory_inDomains_(NSCachesDirectory, NSUserDomainMask).lastObject().path().toString(),
      DocumentDirectory: NSFileManager.URLsForDirectory_inDomains_(NSDocumentDirectory, NSUserDomainMask).lastObject().path().toString(),
      LibraryDirectory: NSFileManager.URLsForDirectory_inDomains_(NSLibraryDirectory, NSUserDomainMask).lastObject().path().toString()
  };
  return env;
}

function list_files_at_path_iOS(path)
{
    var NSFileManager = ObjC.classes.NSFileManager.defaultManager(); 
    var currentPath = ObjC.classes.NSString.stringWithString_(path); 

    var listResult= {
        files: {},
        path: path,
        readable: NSFileManager.isReadableFileAtPath_(currentPath),
        writable: NSFileManager.isWritableFileAtPath_(currentPath),
      };

    if (!listResult.readable) { return listResult; }

    var pathContents = NSFileManager.contentsOfDirectoryAtPath_error_(path, NULL);
    var fileCount = pathContents.count();

    for (var i = 0; i < fileCount; i++) {
      const file = pathContents.objectAtIndex_(i);

      var files = {
        attributes: {},
        fileName: file.toString(),
        readable: undefined,
        writable: undefined,
      };      

      const filePath = [path, "/", file].join("");
      const currentFilePath = ObjC.classes.NSString.stringWithString_(filePath);

      files.readable = NSFileManager.isReadableFileAtPath_(currentFilePath);
      files.writable = NSFileManager.isWritableFileAtPath_(currentFilePath);

      // obtain attributes
      const attributes = NSFileManager.attributesOfItemAtPath_error_(currentFilePath, NULL);

      if (attributes) {
        const enumerator = attributes.keyEnumerator();
        var key;
        while ((key = enumerator.nextObject()) !== null) {
          const value = attributes.objectForKey_(key);
          if (key=="NSFileExtensionHidden")
            files.attributes["isHidden"] = value.toString();
          if (key=="NSFileModificationDate")
            files.attributes["lastModified"] = value.toString();
          if (key=="NSFileSize")
            files.attributes["size"] = value.toString();
          if (key=="NSFileType")
            if(value.toString()=="NSFileTypeDirectory"){
              files.attributes["isDirectory"] = true
              files.attributes["isFile"] = false
            }
            else{
              files.attributes["isDirectory"] = false
              files.attributes["isFile"] = true
            }
        }
      }
      // add current file to the listResult
      listResult.files[file] = files;
    }
    //DEBUG console.log(JSON.stringify(listResult))
    return listResult;
}

function download_file_at_path_iOS(path)
{
  var file;
  file=fs.readFileSync(path)
  return file;
}

function api_monitor_iOS(api_to_monitor) 
{
  //STUB
}