/******************************************************************************
 * Exported APIs
 1. loadclasses
 2. loadclasseswithfilter([filters])
 3. loadcustomfridascript(frida_script)
 4. loadmethods([loaded_classes])
 5. hookclassesandmethods([loaded_classes], [loaded_methods], template)
 6. generatehooktemplate([loaded_classes], [loaded_methods], template)
 ******************************************************************************/

rpc.exports = {
  loadclasses: function () {
    var loaded_classes = []

    Java.perform(function () {
      Java.enumerateLoadedClasses({
        onMatch: function (className) {

          //Remove too generics
          if (className.length > 5)
            loaded_classes.push(className)

        },
        onComplete: function () {
          loaded_classes.sort()
        }
      });
    })
    return loaded_classes;
  },
  loadclasseswithfilter: function (filter) {
    var loaded_classes = []
    Java.perform(function () {
      Java.enumerateLoadedClasses({
        onMatch: function (className) {

          //check if a filter exists
          if (filter != null) {
            //check if we have multiple filters (comma separated list)
            var filter_array = filter.split(",");
            filter_array.forEach(function (f) {
              //f.trim() is needed to remove possibile spaces after the comma
              if (className.startsWith(f.trim())) {
                loaded_classes.push(className)
              }
            });
          }
        },
        onComplete: function () {
          loaded_classes.sort()
        }
      });
    })
    return loaded_classes;
  },
  loadcustomfridascript: function (frida_script) {
    Java.perform(function () {
      console.log("FRIDA script LOADED")
      eval(frida_script)
    })
  },
  loadmethods: function (loaded_classes) {
    var loaded_methods = {};
    Java.perform(function () {
      loaded_classes.forEach(function (className, index) {

        var jClass = Java.use(className);
        var classMethods_dirty = jClass.class.getDeclaredMethods();
        var classMethods = []

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
            args_srt = args_srt + ("\"" + args_array[i] + "\"")
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

            //replace x2
            t = t.replace("{args}", args);
            t = t.replace("{args}", args);

          } else {
            //Current methods has NO args 
            // no need to overload
            t = t.replace("{overload}", "overload().");
            //replace x2 and no args
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

            //replace x3
            t = t.replace("{args}", args);
            t = t.replace("{args}", args);
            t = t.replace("{args}", args);
          } else {
            //Current methods has NO args 
            // no need to overload
            t = t.replace("{overload}", "overload().");
            //replace x3
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

            //replace
            t = t.replace("{args}", args);

          } else {
            //Current methods has NO args 

            //replace
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
};