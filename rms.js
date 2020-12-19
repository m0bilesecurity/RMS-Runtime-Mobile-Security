#!/usr/bin/env node

const http = require('http');
const express = require("express")
const nunjucks = require('nunjucks')
const bodyParser = require('body-parser');
const frida = require('frida');
const load = require('frida-load');
const fs = require('fs');
const socket_io = require('socket.io');
const datetime = require('node-datetime');
 
const BETA = false
const FRIDA_DEVICE_OPTIONS=["USB","Remote","ID"]
const FRIDA_DEVICE_ARGS_OPTIONS=
{
  'host': 'IP:PORT',
  'id': 'Device’s serial number'                                
}
//PATH files
const FRIDA_AGENT_PATH = __dirname+"/agent/compiled_RMS_core.js"
const CONFIG_FILE_PATH = __dirname+"/config/config.json"
const API_MONITOR_FILE_PATH = __dirname+"/config/api_monitor.json"
const CUSTOM_SCRIPTS_PATH = __dirname+"/custom_scripts/"
const CONSOLE_LOGS_PATH = "./console_logs"
const PACKAGE_JSON_PATH = __dirname+"/package.json"

const STATIC_PATH = __dirname+"/views/static/"
const TEMPLATE_PATH =__dirname+"/views/templates"


//Global variables
var api = null //contains agent export
var loaded_classes = []
var system_classes = []
var loaded_methods = {}

var target_package = ""
var system_package = ""
var no_system_package=false 

var app_list = [] //apps installed on the device
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

//app instance
const app = express();
// server instance
const server = http.createServer(app);
// socket listen
const io=socket_io(server);

//bind socket_io to app
app.set('socket_io', io);

//express post config
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
//express static path
app.use(express.static(STATIC_PATH))
//nunjucks config
nunjucks.configure(TEMPLATE_PATH, {
    autoescape: true,
    express: app
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Server startup
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

server.listen(5000, () => {

  console.log("")
  console.log("_________________________________________________________")
  console.log("RMS - Runtime Mobile Security")
  console.log("Version: "+(require(PACKAGE_JSON_PATH).version))
  console.log("by @mobilesecurity_")
  console.log("Twitter Profile: https://twitter.com/mobilesecurity_")
  console.log("_________________________________________________________")
  console.log("")

  console.log("Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)");
  
});

io.on('connection', (socket) => {
  console.log('Socket connected');

  socket.on('disconnect', () => {
    console.log('Socket disconnected');
  });
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Templates
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

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
  var hook = eval('ObjC.classes["' + classname + '"]["' + classmethod + '"]');

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
  var hook = eval('ObjC.classes["' + classname + '"]["' + classmethod + '"]');
 
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
  const config = read_json_file(CONFIG_FILE_PATH)

  let custom_scripts_Android = []
  let custom_scripts_iOS = []

  //#exception handling - frida crash
  var frida_crash=req.query.frida_crash || "False"
  var frida_crash_message=req.query.frida_crash_message

  var device=null
  app_list=null
  //get device
  try
  {
    const device_manager = await frida.getDeviceManager()
    switch(config.device_type)
    {
      case "USB":
        device = await frida.getUsbDevice()
        break;
      case "Remote":
        device = await device_manager.addRemoteDevice(config.device_args.host)        
        break;
      case "ID":
        device= await device_manager.getDevice(config.device_args.id)
        break;
      default:
        device = await frida.getUsbDevice()
        break;
    }

    //get app list
    app_list = await device.enumerateApplications()
    if (app_list.length == 0)
      return res.redirect('/config?error=True');
  }
  catch(err)
  {
    console.log(err)
    return res.redirect('/config?error=True');
  }

  const device_info="name: "+device.name+" | id: "+device.id+" | mode: "+device.type

  //load FRIDA custom scripts list
  fs.readdirSync(CUSTOM_SCRIPTS_PATH+"Android").forEach(file => {
    if (file.endsWith(".js"))
      custom_scripts_Android.push(file)
  })
  fs.readdirSync(CUSTOM_SCRIPTS_PATH+"iOS").forEach(file => {
    if (file.endsWith(".js"))
    custom_scripts_iOS.push(file)
  })

  //sort custom_scripts alphabetically
  custom_scripts_Android.sort()
  custom_scripts_iOS.sort()

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
    frida_crash: frida_crash,
    frida_crash_message: frida_crash_message,
    no_system_package: no_system_package,
    target_package: target_package,
    system_package: system_package
  }
  res.render("device.html", template)
})


app.post("/", async function(req, res){

  //output reset
  reset_variables_and_output()

  //check if RMS agent exist
  if(!fs.existsSync(FRIDA_AGENT_PATH))
  {
    console.log("")
    console.log("RMS agent does not exist at path: "+FRIDA_AGENT_PATH)
    console.log("in order to compile it, please run the following command:")
    console.log("npm install -g rms-runtime-mobile-security")
    console.log("***")
    console.log("For Development mode ONLY --> check the readme on Github")
    console.log("You can compile the agent via the following command:")
    console.log("npm install or npm run compile")
    console.log("***")
    console.log("")
    //RMS exit - important file is missing
    process.kill(process.pid, 'SIGTERM')
  }

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
    console.log("APIs Monitors: \n" + api_selected)
  else
    console.log("APIs Monitors: None")
  
  var device=null
  //get device
  try
  {
    const device_manager = await frida.getDeviceManager()
    switch(config.device_type)
    {
      case "USB":
        device = await frida.getUsbDevice()
        break;
      case "Remote":
        device = await device_manager.addRemoteDevice(config.device_args.host)
        break;
      case "ID":
        device= await device_manager.getDevice(config.device_args.id)
        break;
      default:
        device = await frida.getUsbDevice()
        break;
    }
  }
  catch(err)
  {
    console.log(err)
    return res.redirect('/config?error=True');
  }

  //spawn/attach the app/gadget
  let session, script;
  try 
  {
    //attaching a persistent process to get enumerateLoadedClasses() result before starting the target app 
    //default process are com.android.systemui/SpringBoard
    session = await device.attach(system_package)
    const frida_agent = await	load(require.resolve(FRIDA_AGENT_PATH));
    script = await session.createScript(frida_agent)
    await script.load()
    api = await script.exports
    system_classes = await api.loadclasses()
    //sort list alphabetically
    system_classes.sort()
  }
  catch(err)
  {
    console.log("Exception: "+err)
    if (system_classes.length==0)
      no_system_package=true
    if (target_package!="Gadget")
      console.log(system_package+" is NOT available on your device or a wrong OS has been selected. For a better RE experience, change it via the Config TAB!");
  }

  session = null
  pid=null
  try
  {
    if (mode == "Spawn" && target_package!="Gadget")
    {
      pid= await device.spawn([target_package])
      session = await device.attach(pid)
      console.log('[*] Process Spawned')
    }
    if (mode == "Attach" || target_package=="Gadget")
    {
      //on iOS device "attach" is performd via package.name instead of identifier
      if(mobile_OS=="iOS" && target_package!="Gadget")
      {
        app_list.forEach(function(p) {
          if(p.identifier==target_package)
            target_package=p.name
        });
      }        
      session = await device.attach(target_package)
      console.log('[*] Process Attached')
    }

    const frida_agent = await	load(require.resolve(FRIDA_AGENT_PATH));
    script = await session.createScript(frida_agent)

    //crash handling 
    device.processCrashed.connect(onProcessCrashed);
    session.detached.connect(onSessionDetached);

    //onMessage 
    script.message.connect(onMessage);

    await script.load()

    //API export
    api = script.exports

    if (mode == "Spawn" && target_package!="Gadget")
      device.resume(pid)
    
    //loading FRIDA startup script if selected by the user
    if (frida_script)
      await api.loadcustomfridascript(frida_script)

    //loading APIs Monitors if selected by the user
    if(api_selected)
    {
      //load API Monitors list
      const api_monitor = read_json_file(API_MONITOR_FILE_PATH)
      var api_to_hook=[]
    
      api_monitor.forEach(function(e) {
        if(api_selected.includes(e.Category))
        api_to_hook.push(e)
      });
      
      //load APIs monitors
      try
      {
        await api.apimonitor(api_to_hook)
      }
      catch(err)
      {
        console.log("Excpetion: "+err)
      }
    }
  
  }//end try
  catch(err)
  {
    console.log("Excpetion: "+err)
    return res.redirect('/?frida_crash=True&frida_crash_message='+err);
  }

  //automatically redirect the user to the dump classes and methods tab
  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    loaded_classes: loaded_classes,
    loaded_methods: loaded_methods,
    system_package: system_package,
    no_system_package: no_system_package
  }
  res.render("dump.html",template)
})

function onProcessCrashed(crash) {
  console.log('[*] onProcessCrashed() crash:', crash);
  console.log(crash.report);
}

function onSessionDetached(reason, crash) {
  console.log('[*] onDetached() reason:', reason, 'crash:', crash);
}

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Static Analysis - TAB (iOS only)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/static_analysis", async function(req, res){

  //obtain static analysis script path
  static_analysis_script_path=CUSTOM_SCRIPTS_PATH+ mobile_OS +"/static_analysis.js"
  //read the script
  static_analysis_script = fs.readFileSync(static_analysis_script_path, 'utf8')
  //run it via the loadcustomfridascript api
  try
  {
    await api.loadcustomfridascript(static_analysis_script)
  }
  catch(err)
  {
    console.log(err)
  }
  

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

    if (filter)
    {
      hooked_classes = await api.loadclasseswithfilter(filter, 
                                                 regex, 
                                                 case_sensitive, 
                                                 whole_world)
      loaded_classes = hooked_classes
    }
    else
    {
      loaded_classes = await api.loadclasses()
      //Checking current loaded classes
      /*
      perform --> loaded classes - 
                  system classes =
                  ______________________
                  current_loaded_classes
      */
     loaded_classes=loaded_classes.filter(function(x) 
      { 
        return system_classes.indexOf(x) < 0;
      });
    }

    //sort loaded_classes alphabetically
    loaded_classes.sort()
    //console.log(loaded_classes)
  }

  if (choice == 2){
    // --> Dump all methods [Loaded Classes]
    // NOTE: Load methods for more than 500 classes can crash the app
    try
    {
      loaded_methods = await api.loadmethods(loaded_classes)
      //console.log(loaded_methods)
    }
    catch (err) {
      console.log("Excpetion: "+err)
      
      msg="FRIDA crashed while loading methods for one or more classes selected. Try to exclude them from your search!"
      console.log(msg)

      return res.redirect('/?frida_crash=True&frida_crash_message='+err);
    }
  }
  if (choice == 3)
  {
    //--> Hook all loaded classes and methods

    current_template=""
    if (mobile_OS=="Android")
        current_template=template_massive_hook_Android
    else
        current_template=template_massive_hook_iOS
  
    const stacktrace = req.query.stacktrace
    if (stacktrace == "yes")
    {
      if (mobile_OS=="Android")
        current_template=current_template.replace("{{stacktrace}}", "s=s+\"StackTrace: \"+Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()).replace('java.lang.Exception','') +\"\\n\";")
      else
        current_template=current_template.replace("{{stacktrace}}", "this.s=this.s+\"StackTrace: \\n\"+Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') +\"\\n\";")
    }
    else
      current_template=current_template.replace("{{stacktrace}}", "")
    try
    {
      await api.hookclassesandmethods(loaded_classes, 
                                      loaded_methods, 
                                      current_template)
    }
    catch(err)
    {
      console.log("Excpetion: "+err)
      
      msg="FRIDA crashed while hooking methods for one or more classes selected. Try to exclude them from your search!"
      console.log(msg)

      return res.redirect('/?frida_crash=True&frida_crash_message='+err);
    }

    //redirect the user to the console output
    return res.redirect('/console_output');
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


app.post("/dump", async function(req, res){
  //tohook contains class (index) selected by the user (hooking purposes)
  array_to_hook = req.body.tohook
  if(!Array.isArray(array_to_hook))
    array_to_hook=[array_to_hook]

  if (array_to_hook)
  {
    hooked_classes = []
    array_to_hook.forEach(function(index) 
    {
      //hooked classes
      hooked_classes.push(loaded_classes[Number(index)])
    })
    loaded_classes = hooked_classes
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
  
  //check if methods are loaded or not
  if (loaded_methods === undefined || loaded_methods.length == 0) 
  {
    try{
      loaded_methods = await api.loadmethods(loaded_classes)
      return res.redirect("/hook_lab")
    }
    catch(err){
      console.log("Excpetion: "+err)
      
      const msg="FRIDA crashed while loading methods for one or more classes selected. Try to exclude them from your search!"
      console.log(msg)

      return res.redirect('/?frida_crash=True&frida_crash_message='+err);
    }
  }

  var hook_template = ""
  var selected_class = ""

  //class_index contains the index of the loaded class selected by the user
  class_index = req.query.class_index 
  if(class_index)
  {
    //get methods of the selected class
    selected_class = loaded_classes[class_index]        
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

  //check if methods are loaded or not
  if (loaded_methods === undefined || loaded_methods.length == 0) 
  {
    try{
      loaded_methods = await api.loadmethods(loaded_classes)
      return res.redirect("/heap_search")
    }
    catch(err){
      console.log("Excpetion: "+err)
      
      const msg="FRIDA crashed while loading methods for one or more classes selected. Try to exclude them from your search!"
      console.log(msg)

      return redirect('/?frida_crash=True&frida_crash_message='+err);
    }
  }

  var heap_template = ""
  var selected_class = ""

  //lass_index contains the index of the loaded class selected by the user
  class_index = req.query.class_index 
  if(class_index)
  {
    //get methods of the selected class
    selected_class = loaded_classes[class_index]        
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
  const api_monitor = read_json_file(API_MONITOR_FILE_PATH)

  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    system_package: system_package,
    no_system_package: no_system_package,
    api_monitor: api_monitor,
    api_monitor_console_output_str: api_monitor_console_output
  }
  res.render("api_monitor.html",template);
})

app.post("/api_monitor", async function(req, res){

  const api_monitor = read_json_file(API_MONITOR_FILE_PATH)
  const api_selected = req.body.api_selected
  var api_to_hook=[]

  api_monitor.forEach(function(e) {
    if(api_selected.includes(e.Category))
    api_to_hook.push(e)
  });

  try
  {
    await api.apimonitor(api_to_hook)
  }
  catch(err)
  {
    console.log("Excpetion: "+err)
    return res.redirect('/?frida_crash=True&frida_crash_message='+err);
  }
 
  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    system_package: system_package,
    no_system_package: no_system_package,
    api_monitor: api_monitor,
    api_monitor_console_output_str: api_monitor_console_output
  }
  res.render("api_monitor.html",template);
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
File Manager - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/file_manager", async function(req, res){

  const path=req.query.path 
  const download=req.query.download 
  var files_at_path=""
  var file=""

  //check is app_env_info is not loaded yet
  if (Object.keys(app_env_info).length === 0) 
    app_env_info=await api.getappenvinfo()
  
  if(path)
  {
    files_at_path=await api.listfilesatpath(path)
    //console.log(files_at_path)
  }
  if(download)
  {
    file=await api.downloadfileatpath(download)
    /*
    if(file)
    {
      file=''.join(map(chr, (file)["data"])) 
      filename=os.path.basename(os.path.normpath(download))
      //console.log(filename)
      return Response(file,
                      headers={
                      "Content-disposition":
                      "attachment; filename="+filename}
                     )
    }
    */

  }

  let template = {
    mobile_OS: mobile_OS,
    target_package: target_package,
    system_package: system_package,
    no_system_package: no_system_package,
    env: app_env_info,
    files_at_path: files_at_path,
    currentPath: path,
    BETA: BETA
  }
  res.render("file_manager.html",template);
})

app.post("/file_manager", async function(req, res){

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
    cs_path=CUSTOM_SCRIPTS_PATH+mobile_OS+"/"+ cs_name
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
  try
  {
    await api.loadcustomfridascript(script)
  }
  catch(err){
    console.log("Exception: "+err)
  }
  //auto redirect the user to the console output page
  return res.redirect('/console_output');
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
API - Print Console logs to a File
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/save_console_logs", async function(req, res){
  try
  {
    //check if console_logs exists
    if (!fs.existsSync(CONSOLE_LOGS_PATH))
      fs.mkdirSync("console_logs")

    //create new directory for current logs package_timestamp
    const dt = datetime.create().format('Ymd-HMS')
    out_path=CONSOLE_LOGS_PATH+"/"+target_package+"_"+dt
    fs.mkdirSync(out_path)

    //save calls_console_output
    fs.writeFile(out_path+"/calls_console_output.txt", 
                 calls_console_output, 
                 function(err){
                  if(err)
                    console.log(err);
                  console.log("calls_console_output.txt saved");
    });
    //save hooks_console_output
    fs.writeFile(out_path+"/hooks_console_output.txt", 
                 hooks_console_output, 
                 function(err)
                 {
                  if(err)
                   console.log(err);
                  console.log("hooks_console_output.txt saved");
                 });
    //save global_console_output
    fs.writeFile(out_path+"/global_console_output.txt", 
                 global_console_output, 
                 function(err)
                 {
                  if(err)
                    console.log(err);
                  console.log("global_console_output.txt saved");
                 });
    //save api_monitor_console_output - not available on iOS
    if(mobile_OS=="Android")
    {
      fs.writeFile(out_path+"/api_monitor_console_output.txt", 
                   api_monitor_console_output, 
                   function(err)
                   {
                    if(err)
                      console.log(err);
                    console.log("api_monitor_console_output.txt saved");
                   });
    }
    out_path=out_path.replace("./",process.cwd()+"/")
    res.send("print_done - "+out_path)
  }
  catch(err){
    res.send("print_error: "+err)
  }
})

/* 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
API - Reset Console Output
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/reset_console_logs", async function(req, res){
  calls_console_output = ""
  hooks_console_output = ""
  heap_console_output = ""
  global_console_output = ""
  api_monitor_console_output = ""
  static_analysis_console_output = ""

  call_count = 0
  call_count_stack = {}
  methods_hooked_and_executed = []

  redirect_url = req.query.redirect
  //auto redirect the user to the console output page
  return res.redirect(redirect_url);
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
  if (req.method == "POST")
  {
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

  error = false
  if (req.query.error)
      error = true

  let template = {
    system_package_Android: config.system_package_Android,
    system_package_iOS: config.system_package_iOS,
    device_type_selected: config.device_type,
    device_type_options: FRIDA_DEVICE_OPTIONS,
    device_args: config.device_args,
    device_args_options: FRIDA_DEVICE_ARGS_OPTIONS,
    error: error
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
  console.log(script)
  console.log(redirect_url)
  try
  {
    await api.loadcustomfridascript(script)
  }
  catch(err){
    console.log("Exception: "+err)
  }
  
  //auto redirect the user to the console output page
  return res.redirect(redirect_url);
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
  /*
  if(message.type!="error"){
    console.log('[*] onMessage() message:', message, 'data:', data);
  }
  */

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
  if(!text) return //needed?

  switch (level) 
  {
    case "call_stack":
      //clean up the string
      text=text.replace("[Call_Stack]\n","")
      //method hooked has been executed by the app
      var new_m_executed=text //text contains Class and Method info
      //remove duplicates
      if (!methods_hooked_and_executed.includes(new_m_executed))
          methods_hooked_and_executed.push(new_m_executed)
      //add the current call (method) to the call stack
      call_count_stack[new_m_executed]=call_count
      //creating string for the console output by adding INDEX info
      text = "-->INDEX: [" + call_count + "]\n" + text
      calls_console_output = calls_console_output + "\n" + text
      //increase the counter
      call_count += 1

      io.emit(
      'call_stack', 
      {
          'data': "\n"+text, 
          'level': level
      }, 
      namespace='/console'
      )
      break;
    case "hook_stack":
      //clean up the string
      text=text.replace("[Hook_Stack]\n","")
      //obtain current method info - first 2 lines contain Class and Method info
      var current_method=(text.split("\n").splice(0,2)).join('\n')+'\n'
      //check the call order by looking at the stack call
      var out_index=-1 //default value if for some reasons current method is not in the stack
      try
      {
        out_index=call_count_stack[current_method]
      }
      catch(err)
      {
        console.log("Not able to assign: \n"+current_method+"to its index")
      }
      //assign the correct index (stack call) to the current hooked method and relative info (IN/OUT)
      text="INFO for INDEX: ["+out_index+"]\n"+text
      hooks_console_output = hooks_console_output + "\n" + text

      io.emit(
      'hook_stack', 
      {
          'data': "\n"+text, 
          'level': level
      }, 
      namespace='/console'
      )
      break;
    case "heap_search":
      text=text.replace("[Heap_Search]\n","")
      heap_console_output = heap_console_output + "\n" + text
      io.emit(
      'heap_search', 
      {
          'data': "\n"+text, 
          'level': level
      }, 
      namespace='/console'
      )
      break;
    case "api_monitor":
      api_monitor_console_output = api_monitor_console_output + "\n" + text
      io.emit(
      'api_monitor', 
      {
          'data': "\n"+text, 
          'level': level
      }, 
      namespace='/console'
      )
      break;
    case "static_analysis":
      text=text.replace("[Static_Analysis]\n","")
      static_analysis_console_output=text
    default:
      break;
  }

  //always executed
  global_console_output = global_console_output + "\n" + text
  io.emit(
  'global_console', 
  {
      'data': "\n"+text, 
      'level': level
  }, 
  namespace='/console'
  )
  //print text
  console.log(text)
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
  //error reset
  no_system_package=false
}
