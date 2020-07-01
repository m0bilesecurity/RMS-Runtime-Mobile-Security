/******************************************************************************
 * Exported APIs
 1. loadclasses
 2. loadclasseswithfilter([filters], isRegex, isCase, isWhole)
 3. loadmethods([loaded_classes])
 4. loadcustomfridascript(frida_script)
 5. hookclassesandmethods([loaded_classes], [loaded_methods], template)
 6. generatehooktemplate([loaded_classes], [loaded_methods], template)
 7. heapsearchtemplate([loaded_classes], [loaded_methods], template)
 8. getappenvinfo()
 9. listfilesatpath(path)
 10. downloadfileatpath(path)
 11. apimonitor([api_to_monitor])
 ******************************************************************************/

const fs = require('frida-fs');

rpc.exports = {
  loadclasses: function () {
    var loaded_classes = []

    Java.perform(function () {
      Java.enumerateLoadedClasses({
        onMatch: function (className) {
          //Remove too generics
          if (
            className.length > 5 &&
            //skip androidx stuff
            !className.includes("androidx")
          )
            loaded_classes.push(className)
        },
        onComplete: function () {
          //sort is managed python side
          //loaded_classes.sort()
        }
      });
    })
    return loaded_classes;
  },
  loadclasseswithfilter: function (filter, isRegex, isCase, isWhole) {
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
        },
        onComplete: function () {
          //sort is managed python side
          //loaded_classes.sort()
        }
      });
    })
    return loaded_classes;
  },
  loadmethods: function (loaded_classes) {
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

    })
    //DEBUG console.log("loaded_classes.length: " + loaded_classes.length)
    //DEBUG console.log("loaded_methods.length: " + Object.keys(loaded_methods).length)
    return loaded_methods;
  },
  loadcustomfridascript: function (frida_script) {
    Java.perform(function () {
      console.log("FRIDA script LOADED")
      eval(frida_script)
    })
  },
  hookclassesandmethods: function (loaded_classes, loaded_methods, template) {
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

          // ready to eval!
          eval(t);
        });
      });

    })
  },
  generatehooktemplate: function (loaded_classes, loaded_methods, template) {
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
  },
  heapsearchtemplate: function (loaded_classes, loaded_methods, template) {
    var hto = "" //hto stands for hooks template output
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

          // hooks concat
          hto = hto + t;
        });
      });

    })
    // return HOOK template
    return hto;
  },
  getappenvinfo: function () {
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
  },
  listfilesatpath: function (path) {
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
  },
  downloadfileatpath: function (path) {
    var file;
    Java.perform(function (){
      file=fs.readFileSync(path)
    })
    return file;
  },
  apimonitor: function (api_to_monitor) {
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
              to_print.returnValue = realRetval

              //check if type object if yes convert it to string
              if (realRetval && typeof realRetval === 'object') {
                var retval_string = [];
                for (var k = 0, l = realRetval.length; k < l; k++) {
                  retval_string.push(realRetval[k]);
                }
                to_print.returnValue = '' + retval_string.join('');
              }
              if (!to_print.result) to_print.result = undefined
              if (!to_print.returnValue) to_print.returnValue = undefined

              send('[API_Monitor] - ' + JSON.stringify(to_print)+"\n");
              return realRetval;
            });
          } // end javadynamichook

        });

      });

    })
  }
};

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
            calledFrom: calledFrom
            //result: retval ? retval.toString() : null,
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