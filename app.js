const express = require("express")
const nunjucks = require('nunjucks')
const bodyParser = require('body-parser');
const frida = require('frida');
const load = require('frida-load');
const fs = require('fs');

 
const FRIDA_DEVICE_OPTIONS=["USB","Remote","ID"]
const FRIDA_DEVICE_ARGS_OPTIONS={'host': 'IP:PORT','id': 'Device’s serial number'}
//PATH files
const FRIDA_AGENT_PATH = "./agent/compiled_RMS_core.js"
const CONFIG_FILE_PATH = "config/config.json"
const API_MONITOR_FILE_PATH ="config/api_monitor.json"
const CUSTOM_SCRIPTS_PATH = "custom_scripts/"

var api;
var loaded_classes = [];
var loaded_methods = [];

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.static('views/static/'))


nunjucks.configure('views/templates', {
    autoescape: true,
    express: app
});


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

  const mobile_OS = req.body.mobile_OS
  const mode = req.body.mode
  const target_package = req.body.package
  const frida_script = req.body.frida_startup_script 
  const api_selected = req.body.api_selected

  // print info on the console
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
catch (e) {
    console.log("entering catch block");
    console.log(e);
    console.log("leaving catch block");
  }

  res.render("dump.html")
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Static Analysis - TAB (iOS only)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/static_analysis", async function(req, res){
  res.render("static_analysis.html");
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
 
  res.render("dump.html")
})


/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Diff Classess - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/diff_classes", async function(req, res){
  res.render("diff_classes.html");
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Hook LAB - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/hook_lab", async function(req, res){
  res.render("hook_lab.html");
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Heap Search - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/heap_search", async function(req, res){
  res.render("heap_search.html");
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
  res.render("load_frida_script.html");
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Console Output - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/console_output", async function(req, res){
  res.render("console_output.html")
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
API - get frida custom script as text (Device Page)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/get_frida_custom_script", (req, res) => {
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
    if("[Call_Stack]" in message.payload)
      log_handler("call_stack",message.payload)
    if("[Hook_Stack]" in message.payload)
      log_handler("hook_stack",message.payload)
    if("[Heap_Search]" in message.payload)
      log_handler("heap_search",message.payload)
    if("[API_Monitor]" in message.payload)
      log_handler("api_monitor",message.payload)
    if("[Static_Analysis]" in message.payload)
      log_handler("static_analysis",message.payload) 
    if(!("[Call_Stack]" in message.payload) &&
       !("[Hook_Stack]" in message.payload) &&
       !("[Heap_Search]" in message.payload) &&
       !("[API_Monitor]" in message.payload) &&
       !("[Static_Analysis]" in message.payload)
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

