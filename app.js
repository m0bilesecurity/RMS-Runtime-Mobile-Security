const express = require("express")
const nunjucks = require('nunjucks')
const bodyParser = require('body-parser');
const frida = require('frida');
const fs = require('fs');

//PATH files
const CONFIG_FILE_PATH = "config/config.json"
const API_MONITOR_FILE_PATH ="config/api_monitor.json"
const CUSTOM_SCRIPTS_PATH = "custom_scripts/"


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

  res.render("device.html")
})

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Static Analysis - TAB (iOS only)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/static_analysis", (req, res) => {
  res.render("static_analysis.html");
});


/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Dump Classes and Methods - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/diff_classes", (req, res) => {
  res.render("diff_classes.html");
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Hook LAB - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/hook_lab", (req, res) => {
  res.render("hook_lab.html");
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Heap Search - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/heap_search", (req, res) => {
  res.render("heap_search.html");
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
API Monitor - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
app.get("/api_monitor", (req, res) => {
  res.render("api_monitor.html");
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Diff Classess - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/dump", (req, res) => {
  res.render("dump.html");
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
File Manager - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/file_manager", (req, res) => {
  res.render("file_manager.html");
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Load Frida Script - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/load_frida_script", (req, res) => {
  res.render("load_frida_script.html");
});

/*
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Console Output - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/console_output", (req, res) => {
  res.render("console_output.html");
});

/* 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Config File - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

app.get("/config", async function(req, res){
  res.render("config.html");
});


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

  
  console.log("Running on http://127.0.0.1:5000/ (Press CTRL+C to quit");
  
});

