const express = require("express")
const nunjucks = require('nunjucks')
const bodyParser = require('body-parser');
const frida = require('frida');
const load = require('frida-load');
const fs = require('fs');
const io = require('socket.io');

 
const FRIDA_DEVICE_OPTIONS=["USB","Remote","ID"]
const FRIDA_DEVICE_ARGS_OPTIONS={'host': 'IP:PORT','id': 'Device’s serial number'}
//PATH files
const FRIDA_AGENT_PATH = "./agent/compiled_RMS_core.js"
const CONFIG_FILE_PATH = "config/config.json"
const API_MONITOR_FILE_PATH ="config/api_monitor.json"
const CUSTOM_SCRIPTS_PATH = "custom_scripts/"

//Global variables
var api = null //contains agent export
var loaded_classes = []
var system_classes = []
var loaded_methods = {}

var target_package = ""
var system_package = ""
var no_system_package=false //TODO needed?

var packages = [] //apps installed on the device
var mobile_OS="N/A"
var app_env_info = {} //app env info


//Global variables - diff analysis
var current_loaded_classes = []
var new_loaded_classes = []

//Global variables - console output
var calls_console_output = ""
var hooks_console_output = ""
var heap_console_output = ""
var global_console_output = ""
var api_monitor_console_output = ""
var static_analysis_console_output = ""

//Global variables - call stack 
var call_count = 0
var call_count_stack={}
var methods_hooked_and_executed = []


const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.static('views/static/'))


nunjucks.configure('views/templates', {
    autoescape: true,
    express: app
});

//{{stacktrace}} placeholder is managed nodejs side
template_massive_hook_Android = `
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var methodsignature = "{methodSignature}";
    var hookclass = Java.use(classname);
    
    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("[Call_Stack]\\nClass: " +classname+"\\nMethod: "+methodsignature+"\\n");
        var ret = this.{classMethod}({args});

        var s="";
        s=s+"[Hook_Stack]\\n"
        s=s+"Class: "+classname+"\\n"
        s=s+"Method: "+methodsignature+"\\n"
        s=s+"Called by: "+Java.use('java.lang.Exception').$new().getStackTrace().toString().split(',')[1]+"\\n"
        s=s+"Input: "+eval(args)+"\\n"
        s=s+"Output: "+ret+"\\n"
        {{stacktrace}}
        send(s);
                
        return ret;
    };
});
`

template_massive_hook_iOS = `
var classname = "{className}";
var classmethod = "{classMethod}";
var methodsignature = "{methodSignature}";
try {
  var hook = eval('ObjC.classes.' + classname + '["' + classmethod + '"]');

  Interceptor.attach(hook.implementation, {
    onEnter: function (args) {
      send("[Call_Stack]\\nClass: " + classname + "\\nMethod: " + methodsignature + "\\n");
      this.s = ""
      this.s = this.s + "[Hook_Stack]\\n"
      this.s = this.s + "Class: " + classname + "\\n"
      this.s = this.s + "Method: " + methodsignature + "\\n"
      if (classmethod.indexOf(":") !== -1) {
        var params = classmethod.split(":");
        params[0] = params[0].split(" ")[1];
        for (var i = 0; i < params.length - 1; i++) {
          try {
            this.s = this.s + "Input: " + params[i] + ": " + new ObjC.Object(args[2 + i]).toString() + "\\n";
          } catch (e) {
            this.s = this.s + "Input: " + params[i] + ": " + args[2 + i].toString() + "\\n";
          }
        }
      }
    },

    onLeave: function (retval) {
      this.s = this.s + "Output: " + retval.toString() + "\\n";
      {{stacktrace}}
      send(this.s);
    }
  });
} catch (err) {
  send("[!] Exception: " + err.message);
  send("Not able to hook \\nClass: " + classname + "\\nMethod: " + methodsignature + "\\n");
}
`

template_hook_lab_Android = `
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var methodsignature = "{methodSignature}";
    var hookclass = Java.use(classname);
    
    //{methodSignature}
    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("[Call_Stack]\\nClass: " +classname+"\\nMethod: "+methodsignature+"\\n");
        var ret = this.{classMethod}({args});
        
        var s="";
        s=s+"[Hook_Stack]\\n"
        s=s+"Class: " +classname+"\\n"
        s=s+"Method: " +methodsignature+"\\n"
        s=s+"Called by: "+Java.use('java.lang.Exception').$new().getStackTrace().toString().split(',')[1]+"\\n"
        s=s+"Input: "+eval({args})+"\\n";
        s=s+"Output: "+ret+"\\n";
        //uncomment the line below to print StackTrace
        //s=s+"StackTrace: "+Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()).replace('java.lang.Exception','') +"\\n";

        send(s);
                
        return ret;
    };
});
`

template_hook_lab_iOS = `
var classname = "{className}";
var classmethod = "{classMethod}";
var methodsignature = "{methodSignature}";
try {
  var hook = eval('ObjC.classes.' + classname + '["' + classmethod + '"]');
 
  //{methodSignature}
  Interceptor.attach(hook.implementation, {
    onEnter: function (args) {
      send("[Call_Stack]\\nClass: " + classname + "\\nMethod: " + methodsignature + "\\n");
      this.s = ""
      this.s = this.s + "[Hook_Stack]\\n"
      this.s = this.s + "Class: " + classname + "\\n"
      this.s = this.s + "Method: " + methodsignature + "\\n"
      if (classmethod.indexOf(":") !== -1) {
        var params = classmethod.split(":");
        params[0] = params[0].split(" ")[1];
        for (var i = 0; i < params.length - 1; i++) {
          try {
            this.s = this.s + "Input: " + params[i] + ": " + new ObjC.Object(args[2 + i]).toString() + "\\n";
          } catch (e) {
            this.s = this.s + "Input: " + params[i] + ": " + args[2 + i].toString() + "\\n";
          }
        }
      }
    },

    //{methodSignature}
    onLeave: function (retval) {
      this.s = this.s + "Output: " + retval.toString() + "\\n";
      //uncomment the lines below to replace retvalue
      //retval.replace(0);  

      //uncomment the line below to print StackTrace
      //this.s = this.s + "StackTrace: \\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + "\\n";
      send(this.s);
    }
  });
} catch (err) {
  send("[!] Exception: " + err.message);
  send("Not able to hook \\nClass: " + classname + "\\nMethod: " + methodsignature + "\\n");
}
`

template_heap_search_Android = `
Java.performNow(function () {
    var classname = "{className}"
    var classmethod = "{classMethod}";
    var methodsignature = "{methodSignature}";

    Java.choose(classname, {
        onMatch: function (instance) {
            try 
            {
                var returnValue;
                //{methodSignature}
                returnValue = instance.{classMethod}({args}); //<-- replace v[i] with the value that you want to pass

                //Output
                var s = "";
                s=s+"[Heap_Search]\\n"
                s=s + "[*] Heap Search - START\\n"

                s=s + "Instance Found: " + instance.toString() + "\\n";
                s=s + "Calling method: \\n";
                s=s + "   Class: " + classname + "\\n"
                s=s + "   Method: " + methodsignature + "\\n"
                s=s + "-->Output: " + returnValue + "\\n";

                s = s + "[*] Heap Search - END\\n"

                send(s);
            } 
            catch (err) 
            {
                var s = "";
                s=s+"[Heap_Search]\\n"
                s=s + "[*] Heap Search - START\\n"
                s=s + "Instance NOT Found or Exception while calling the method\\n";
                s=s + "   Class: " + classname + "\\n"
                s=s + "   Method: " + methodsignature + "\\n"
                s=s + "-->Exception: " + err + "\\n"
                s=s + "[*] Heap Search - END\\n"
                send(s)
            }

        }
    });

});
`


template_heap_search_iOS = `
var classname = "{className}";
var classmethod = "{classMethod}";
var methodsignature = "{methodSignature}";

ObjC.choose(ObjC.classes[classname], {
  onMatch: function (instance) {
    try
    {   
        var returnValue;
        //{methodSignature}
        returnValue = instance[classmethod](); //<-- insert args if needed

        var s=""
        s=s+"[Heap_Search]\\n"
        s=s + "[*] Heap Search - START\\n"
        s=s+"Instance Found: " + instance.toString() + "\\n";
        s=s+"Calling method: \\n";
        s=s+"   Class: " + classname + "\\n"
        s=s+"   Method: " + methodsignature + "\\n"
        s=s+"-->Output: " + returnValue + "\\n";

        s=s+"[*] Heap Search - END\\n"
        send(s);
        
    }catch(err)
    {
        var s = "";
        s=s+"[Heap_Search]\\n"
        s=s + "[*] Heap Search - START\\n"
        s=s + "Instance NOT Found or Exception while calling the method\\n";
        s=s + "   Class: " + classname + "\\n"
        s=s + "   Method: " + methodsignature + "\\n"
        s=s + "-->Exception: " + err + "\\n"
        s=s + "[*] Heap Search - END\\n"
        send(s)
    }
  },
  onComplete: function () {
  }
});
`


/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Device - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/", async function(req, res){
    /*
    const mgr = await frida.getDeviceManager();
    const list = await mgr.enumerateDevices();
    */
   let custom_scripts_Android = []
   let custom_scripts_iOS = []

    //get device
    const device = await frida.getUsbDevice()
    const device_info=device.name+" | "+device.id+" | "+device.type

    //get app list
    const app_list = await device.enumerateApplications()

    //read config file
    const config = read_json_file(CONFIG_FILE_PATH)

    //load FRIDA custom scripts list
    fs.readdirSync(CUSTOM_SCRIPTS_PATH+"Android").forEach(file => {
      if (file.endsWith(".js"))
        custom_scripts_Android.push(file)
    })
    fs.readdirSync(CUSTOM_SCRIPTS_PATH+"iOS").forEach(file => {
      if (file.endsWith(".js"))
      custom_scripts_iOS.push(file)
    })

    //load API Monitors list
    const api_monitor = read_json_file(API_MONITOR_FILE_PATH)

    let template = {
      device_info: device_info,
      app_list: app_list,
      api_monitor: api_monitor,
      system_package_Android: config.system_package_Android,
      system_package_iOS: config.system_package_iOS,
      device_mode: config.device_type,
      custom_scripts_Android: custom_scripts_Android,
      custom_scripts_iOS: custom_scripts_iOS,
    }
    res.render("device.html", template)
})


app.post("/", async function(req, res){

  //output reset
  reset_variables_and_output()

  //read config file
  const config = read_json_file(CONFIG_FILE_PATH)

  //obtain device OS
  mobile_OS = req.body.mobile_OS

  //set the proper system package 
  if(mobile_OS=="Android")
    system_package=config.system_package_Android
  else
    system_package=config.system_package_iOS

  //set the target package
  target_package = req.body.package

  //Frida Gadget support
  if (target_package=="re.frida.Gadget")
    target_package="Gadget"

  //setup the RMS run
  const mode = req.body.mode
  const frida_script = req.body.frida_startup_script 
  const api_selected = req.body.api_selected

  //RMS overview - print run options
  console.log()
  if(target_package)
    console.log("Package Name: " + target_package)
  if(mode)
    console.log("Mode: " + mode)
  if(frida_script) 
    console.log("Frida Startup Script: \n" + frida_script)
  else 
    console.log("Frida Startup Script: None")

  if(api_selected)
    console.log("APIs Monitors: \n" + " - ".join(api_selected))
  else
    console.log("APIs Monitors: None")
  console.log

let session, script;
try {
  const device = await frida.getUsbDevice();
  
  const pid = await device.spawn(target_package);
  session = await device.attach(pid);
  const frida_agent = await	load(require.resolve(FRIDA_AGENT_PATH));	
  script = await session.createScript(frida_agent);
  script.message.connect(onMessage);
  await script.load()

  api = await script.exports
  console.log('[*] API Test - checkmobileos() =>', await api.checkmobileos());


  await device.resume(pid);
}
catch (err) {
    console.log(err);
  }

  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    loaded_classes: loaded_classes,
    loaded_methods: loaded_methods,
    system_package: system_package,
  }
  res.render("dump.html",template)
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Static Analysis - TAB (iOS only)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/static_analysis", async function(req, res){

  //obtain static analysis script path
  static_analysis_script_path="/custom_scripts/"+ mobile_OS +"/static_analysis.js"
  //read the script
  static_analysis_script = fs.readFileSync(static_analysis_script_path, 'utf8')
  //run it via the loadcustomfridascript api
  await api.loadcustomfridascript(static_analysis_script)

  let template = {
    mobile_OS: mobile_OS,
    static_analysis_console_output: static_analysis_console_output,
    target_package: target_package,
    system_package: system_package,
    no_system_package: no_system_package
  }
  res.render("static_analysis.html", template);

})


/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Dump Classes and Methods - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/dump", async function(req, res){

  //# check what the user is triyng to do
  const choice = req.query.choice
  if (choice == 1){
    // --> Dump Loaded Classes (w/o filters)

    //clean up the array
    loaded_classes = []
    loaded_methods = []
    //check if the user is trying to filter loaded classes
    filter = req.query.filter
    //Checking options
    regex=0
    case_sensitive=0
    whole_world=0

    if(req.query.regex==1) regex=1
    if(req.query.case==1) case_sensitive=1
    if(req.query.whole==1) whole_world=1

    if (filter){
      hooked_classes = await api.loadclasseswithfilter(filter, 
                                                 regex, 
                                                 case_sensitive, 
                                                 whole_world)
      loaded_classes = hooked_classes
    }
    else{
      loaded_classes = await api.loadclasses()
      //differences between class loaded after and before the app launch
      //TODO 
      //loaded_classes = list(set(loaded_classes) - set(system_classes))
    }

    //sort loaded_classes alphabetically
    loaded_classes.sort()
    console.log(loaded_classes)
  }

  if (choice == 2){
    // --> Dump all methods [Loaded Classes]
    // NOTE: Load methods for more than 500 classes can crash the app
    try{
      loaded_methods = await api.loadmethods(loaded_classes)
      console.log(loaded_methods)
    }
    catch (err) {
      console.log(err)
      /* TODO
      msg="FRIDA crashed while loading methods for one or more classes selected. Try to exclude them from your search!"
      console.log(msg)
      return redirect(url_for("device_management", frida_crash=True, frida_crash_message=msg))
      */
    }
  }
 
  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    loaded_classes: loaded_classes,
    loaded_methods: loaded_methods,
    system_package: system_package,
    methods_hooked_and_executed: methods_hooked_and_executed
  }
  res.render("dump.html",template)
})


/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Diff Classess - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/diff_classes", async function(req, res){
  //# check what the user is triyng to do
  const choice = req.query.choice
  if (choice == 1)
  {
    //Checking current loaded classes
    /*
    perform --> loaded classes - 
                system classes =
                ______________________
                current_loaded_classes
    */
    current_loaded_classes = (await api.loadclasses()).filter(
      function(x) 
      { 
        return system_classes.indexOf(x) < 0;
      });

    //sort list alphabetically
    current_loaded_classes.sort()
    console.log(current_loaded_classes)
  }
  if (choice == 2)
  {
    //Checking NEW loaded classes
    /*
    perform --> new loaded classes - 
                old loaded classes - 
                system classes     =
                _____________________
                new_loaded_classes
    */
    new_loaded_classes = (await api.loadclasses()).filter(
      function(x) 
      { 
        return current_loaded_classes.indexOf(x) < 0;
      }
    );
    new_loaded_classes = new_loaded_classes.filter(
      function(x) 
      { 
        return system_classes.indexOf(x) < 0;
      }
    );

    //sort list alphabetically
    new_loaded_classes.sort()
  }

  let template = {
    mobile_OS: mobile_OS,
    current_loaded_classes: current_loaded_classes,
    new_loaded_classes: new_loaded_classes,
    target_package: target_package,
    system_package: system_package
  }
  res.render("diff_classes.html",template)
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Hook LAB - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

function get_hook_lab_template(mobile_OS){
  if (mobile_OS=="Android")
    return template_hook_lab_Android
  else
    return template_hook_lab_iOS
}


app.get("/hook_lab", async function(req, res){

  var hook_template = ""
  var selected_class = ""

  //class_index contains the index of the loaded class selected by the user
  class_index = req.query.class_index 
  //get methods of the selected class
  selected_class = loaded_classes[class_index]
  //check if methods are loaded or not
  if(!loaded_methods)
  {
    try{
      loaded_methods = await api.loadmethods(loaded_classes)
    }
    catch(err){
      console.log(err)
      const msg="FRIDA crashed while loading methods for one or more classes selected. Try to exclude them from your search!"
      console.log(msg)
      //TODO
      //return redirect(url_for("device_management", frida_crash=True, frida_crash_message=msg))
    }
  }
      
  //method_index contains the index of the loaded method selected by the user
  method_index = req.query.method_index 
  //Only class selected - load heap search template for all the methods
  if (!method_index)
  {
    //hook template generation
    hook_template = await api.generatehooktemplate(
      [selected_class], 
      loaded_methods, 
      get_hook_lab_template(mobile_OS)
    )
  }
  //class and method selected - load heap search template for selected method only
  else
  {
    var selected_method={}
    //get method of the selected class
    selected_method[selected_class] = 
      [(loaded_methods[selected_class])[method_index]]

    //hook template generation
    hook_template = await api.generatehooktemplate(
        [selected_class], 
        selected_method, 
        get_hook_lab_template(mobile_OS)
    )
  }

  //print hook template
  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    system_package: system_package,
    no_system_package: no_system_package,
    loaded_classes: loaded_classes,
    loaded_methods: loaded_methods,
    selected_class: selected_class,
    methods_hooked_and_executed: methods_hooked_and_executed,
    hook_template_str: hook_template
  }
  res.render("hook_lab.html",template);
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Heap Search - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

function get_heap_search_template(mobile_OS){
  if (mobile_OS=="Android")
    return template_heap_search_Android
  else
    return template_heap_search_iOS
}


app.get("/heap_search", async function(req, res){

  var heap_template = ""
  var selected_class = ""

  //lass_index contains the index of the loaded class selected by the user
  class_index = req.query.class_index 
  //get methods of the selected class
  selected_class = loaded_classes[class_index]
  //check if methods are loaded or not
  if(!loaded_methods)
  {
    try{
      loaded_methods = await api.loadmethods(loaded_classes)
    }
    catch(err){
      console.log(err)
      const msg="FRIDA crashed while loading methods for one or more classes selected. Try to exclude them from your search!"
      console.log(msg)
      //TODO
      //return redirect(url_for("device_management", frida_crash=True, frida_crash_message=msg))
    }
  }
      
  //method_index contains the index of the loaded method selected by the user
  method_index = req.query.method_index 
  //Only class selected - load heap search template for all the methods
  if (!method_index)
  {
    //heap template generation
    heap_template = await api.heapsearchtemplate(
        [selected_class], 
        loaded_methods, 
        get_heap_search_template(mobile_OS)
    )
  }
  //class and method selected - load heap search template for selected method only
  else
  {
    var selected_method={}
    //get method of the selected class
    selected_method[selected_class] = 
      [(loaded_methods[selected_class])[method_index]]
    //heap template generation
    heap_template = await api.heapsearchtemplate(
        [selected_class], 
        selected_method, 
        get_heap_search_template(mobile_OS)
    )
  }
  //print hook template
  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    system_package: system_package,
    no_system_package: no_system_package,
    loaded_classes: loaded_classes,
    loaded_methods: loaded_methods,
    selected_class: selected_class,
    methods_hooked_and_executed: methods_hooked_and_executed,
    heap_template_str: heap_template,
    heap_search_console_output_str: heap_console_output
  }

  res.render("heap_search.html", template);
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
API Monitor - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/api_monitor", async function(req, res){
  res.render("api_monitor.html");
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
File Manager - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/file_manager", async function(req, res){
  res.render("file_manager.html");
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Load Frida Script - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/load_frida_script", async function(req, res){

  //Load frida custom scripts inside "custom_scripts" folder
  var custom_scripts = []

  fs.readdirSync(CUSTOM_SCRIPTS_PATH+mobile_OS).forEach(file => 
    {
    if (file.endsWith(".js"))
    custom_scripts.push(file)
    }
  )

  //sort custom_scripts alphabetically
  custom_scripts.sort()

  //open the custom script selected by the user
  const cs_name = req.query.cs
  var cs_file=""

  //check if a custom script has been selected
  if(cs_name){
    cs_path="custom_scripts/"+mobile_OS+"/"+ cs_name
    cs_file=fs.readFileSync(cs_path, 'utf8')
  }


  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    system_package: system_package,
    custom_scripts: custom_scripts,
    custom_script_loaded: cs_file,
    no_system_package: no_system_package
  }
  res.render("load_frida_script.html",template);
  
})

app.post("/load_frida_script", async function(req, res){
  script = req.body.frida_custom_script
  await api.loadcustomfridascript(script)
  //auto redirect the user to the console output page
  res.redirect('/console_output');
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Console Output - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/console_output", async function(req, res){
  let template = {
    mobile_OS: mobile_OS,
    called_console_output_str: calls_console_output,
    hooked_console_output_str: hooks_console_output,
    global_console_output_str: global_console_output,
    target_package: target_package,
    system_package: system_package,
    no_system_package: no_system_package
  }
  res.render("console_output.html",template)
})

/* 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Config File - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.all("/config", async function(req, res){
  /*
  |POST!
  */
  if (req.method == "POST"){
      //read new values
      const device_type = req.body.device_type
      const system_package_Android = req.body.system_package_Android.trim()
      const system_package_iOS = req.body.system_package_iOS.trim()
      let device_arg_host = req.body.host_value
      let device_arg_id = req.body.id_value
      
      if(!device_arg_host) device_arg_host=""
      if(!device_arg_id) device_arg_id=""

      device_args={
        host:device_arg_host,
        id:device_arg_id
      }

      new_config = {}
      new_config.device_type=device_type
      new_config.system_package_Android=system_package_Android
      new_config.system_package_iOS=system_package_iOS
      new_config.device_args=device_args

      console.log("NEW CONFIG")
      console.log(new_config)

      //write new config to config.js
      fs.writeFileSync(CONFIG_FILE_PATH, 
                       JSON.stringify(new_config,null,4));
  }

  /*
  |GET!
  */

  //read config file
  const config = read_json_file(CONFIG_FILE_PATH)
  let template = {
    system_package_Android: config.system_package_Android,
    system_package_iOS: config.system_package_iOS,
    device_type_selected: config.device_type,
    device_type_options: FRIDA_DEVICE_OPTIONS,
    device_args: config.device_args,
    device_args_options: FRIDA_DEVICE_ARGS_OPTIONS
  }
  res.render("config.html", template);
})


/* 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
API - eval frida script and redirect
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.post("/eval_script_and_redirect", async function(req, res){
  script = req.body.frida_custom_script
  redirect_url = req.body.redirect 
  await api.loadcustomfridascript(script)
  //auto redirect the user to the console output page
  res.redirect(redirect_url);
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
API - get frida custom script as text (Device Page)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/get_frida_custom_script", async function(req, res){
  const mobile_os_get = req.query.os;
  const custom_script_get = req.query.cs;
  const cs_file_path = CUSTOM_SCRIPTS_PATH+mobile_os_get+"/"+custom_script_get

  let custom_script = ""

  if(mobile_os_get && custom_script_get){
    custom_script=fs.readFileSync(cs_file_path, 'utf8')
  }
  res.send(custom_script)
});

/* 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
on_message stuff
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

function onMessage(message, data) {
  //TODO check what's wrong with loadclasses
  if(message.type!="error"){
    console.log('[*] onMessage() message:', message, 'data:', data);
  }

  if (message.type == 'send'){
    if(message.payload.includes("[Call_Stack]"))
      log_handler("call_stack",message.payload)
    if(message.payload.includes("[Hook_Stack]"))
      log_handler("hook_stack",message.payload)
    if(message.payload.includes("[Heap_Search]"))
      log_handler("heap_search",message.payload)
    if(message.payload.includes("[API_Monitor]"))
      log_handler("api_monitor",message.payload)
    if(message.payload.includes("[Static_Analysis]"))
      log_handler("static_analysis",message.payload) 
    if(!(message.payload.includes("[Call_Stack]")) &&
       !(message.payload.includes("[Hook_Stack]")) &&
       !(message.payload.includes("[Heap_Search]")) &&
       !(message.payload.includes("[API_Monitor]")) &&
       !(message.payload.includes("[Static_Analysis]"))
      ) 
      log_handler("global_stack",message.payload)
  }   
}

function log_handler(level, text){
  console.log('[*] log_handler() level:', level, 'text:', text);
}

/* 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Supplementary functions
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

function read_json_file(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
} 

function reset_variables_and_output(){
  mobile_OS="N/A"
  //output reset
  calls_console_output = ""
  hooks_console_output = ""
  heap_console_output = ""
  global_console_output = ""
  api_monitor_console_output = ""
  static_analysis_console_output = ""
  // call stack
  call_count = 0
  call_count_stack = {}
  methods_hooked_and_executed = []
  //variable reset
  loaded_classes = []
  system_classes = []
  loaded_methods = {}
  //file manager
  app_env_info = {}
  //diff classes variables
  current_loaded_classes = []
  new_loaded_classes = []
  //package reset
  target_package=""
  system_package=""
  //error reset //TODO remove?
  //no_system_package=false
}

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Server startup
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.listen(5000, () => {

  console.log("")
  console.log("_________________________________________________________")
  console.log("RMS - Runtime Mobile Security")
  console.log("Version: 1.4.2")
  console.log("by @mobilesecurity_")
  console.log("Twitter Profile: https://twitter.com/mobilesecurity_")
  console.log("_________________________________________________________")
  console.log("")

  
  console.log("Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)");
  
});

