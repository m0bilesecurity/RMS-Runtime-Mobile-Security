import os
import sys
import json
import frida
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO, emit
from flask import Flask, request, render_template, redirect, url_for
import logging

app = Flask(__name__)
socket_io = SocketIO(app)

# Global variables
loaded_classes = []
system_classes = []
loaded_methods = {}

# Global variables - diff analysis
current_loaded_classes = []
new_loaded_classes = []

# Global variables - console output
calls_console_output = ""
hooks_console_output = ""
global_console_output = ""
api_monitor_console_output = ""
calls_count = 0

api = None

target_package = ""
system_package = ""
no_system_package=False

template_massive_hook = """
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var hookclass = Java.use(classname);

    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("CALLED: " + classname + "." + classmethod + "()\\n");
        var ret = this.{classMethod}({args});

        var s="";
        s=s+"HOOK: " + classname + "." + classmethod + "()\\n";
        s=s+"IN: "+eval(args)+"\\n";
        s=s+"OUT: "+ret+"\\n";
        send(s);
                
        return ret;
    };
});
"""

template_hook_lab = """
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var hookclass = Java.use(classname);
    
    //{methodSignature}

    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("CALLED: " + classname + "." + classmethod + "()\\n");
        var ret = this.{classMethod}({args});

        var s="";
        s=s+"HOOK: " + classname + "." + classmethod + "()\\n";
        s=s+"IN: "+eval({args})+"\\n";
        s=s+"OUT: "+ret+"\\n";
        //uncomment the line below to print StackTrace
        //s=s+"StackTrace: "+Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()) +"\\n";
        send(s);
                
        return ret;
    };
});
"""

template_heap_search = """
    Java.performNow(function () {
      var classname = "{className}"
      var classmethod = "{classMethod}";

      send("Heap Search - START ("+classname+")\\n");

      Java.choose(classname, {
        onMatch: function (instance) {
          
          var s="";
          s=s+"[*] Instance Found: " +instance.toString()+"\\n";
          s=s+"Calling method: " +classmethod+"\\n";
          
          //{methodSignature}
          var ret = instance.{classMethod}({args}); //<-- replace v[i] with the value that you want to pass
          s=s+"Output: "+ ret + "\\n";
          send(s);

        }
      });
      send("Heap Search - END ("+classname+")");
    });
"""

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Device - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

@app.route('/', methods=['GET', 'POST'])
def device_management():
    global api
    global system_classes
    global target_package
    global system_package
    global no_system_package

    cs_file = ""
    custom_scripts = []
    packages = []
    config = read_config_file()
    system_package=config["system_package"];
    no_system_package=False

    conn_args = ""
    if config['device_type'] == 'remote':
        conn_args = config['device_args']['host']
    elif config['device_type'] == 'id':
        conn_args = config['device_args']['id']

    try:
        device = get_device(device_type=config["device_type"], device_args=config['device_args'])
    except:
        return redirect(url_for('edit_config_file', error=True))

    if request.method == 'GET':
        try:
            for package in device.enumerate_applications():
                packages.append(package.identifier)
        except Exception:
            return redirect(url_for('edit_config_file', error=True))
        
        if len(packages) == 0:
            return redirect(url_for('edit_config_file', error=True))

        # Load frida custom scripts inside "custom_scripts" folder
        for f in os.listdir(os.path.dirname(os.path.realpath(__file__)) + "/custom_scripts"):
            if f.endswith(".js"):
                custom_scripts.append(f)

        cs = request.args.get('cs')
        if cs is not None:
            with open(os.path.dirname(os.path.realpath(__file__)) + "/custom_scripts/" + cs) as f:
                cs_file = f.read()

    if request.method == 'POST':

        #output reset
        reset_variables_and_output()

        target_package = request.values.get('package')
        #Frida Gadget support
        if target_package=="re.frida.Gadget":
            target_package="Gadget"

        mode = request.values.get('mode')
        frida_script = request.values.get('fridastartupscript')

        if target_package: rms_print("Package Name: " + target_package)
        if mode: rms_print("Mode: " + mode)
        if frida_script: rms_print("Frida Startup Script: \n" + frida_script)

        # main JS file
        with open(os.path.dirname(os.path.realpath(__file__)) + '/default.js') as f:
            frida_code = f.read()

        session = None
        try:
            # attaching a persistent process to get enumerateLoadedClasses() result
            # before starting the target app - default process is com.android.systemui
            session = device.attach(system_package)
            script = session.create_script(frida_code)
            #script.set_log_handler(log_handler)
            script.load()
            api = script.exports
            system_classes = api.loadclasses()
        except:
            if (len(system_classes)==0):
                no_system_package=True
            rms_print(system_package+" is NOT available on your device. For a better RE experience, change it via the Config TAB!");
            pass

        session = None
        if mode == "Spawn" and target_package!="Gadget":
            pid = device.spawn([target_package])
            session = device.attach(pid)
            rms_print('[*] Process Spawned')
        if mode == "Attach" or target_package=="Gadget":
            session = device.attach(target_package)
            rms_print('[*] Process Attached')

        script = session.create_script(frida_code)
        #script.set_log_handler(log_handler)
        script.on('message', on_message)
        script.load()

        # loading js api
        api = script.exports

        if mode == "Spawn" and target_package!="Gadget":
            device.resume(pid)

        # loading FRIDA startup script if exists
        if frida_script:
            api.loadcustomfridascript(frida_script)
            # DEBUG rms_print(frida_script)

        # automatically redirect the user to the dump classes and methods tab
        return printwebpage()
    
    return render_template(
        "device.html",
        custom_script_loaded=cs_file,
        custom_scripts=custom_scripts,
        system_package_str=config["system_package"],
        device_type_str=config["device_type"],
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package,
        packages=packages,
        conn_args_str=conn_args
    )

def get_device(device_type="usb", device_args=None):
    device_type = device_type.lower()
    device_args = device_args or {}
    device_manager = frida.get_device_manager()
    if device_type == "id":
        device_id = device_args['id']
        device_args.clear()
        return device_manager.get_device(device_id, **device_args)
    if device_type == "usb":
        device_args.clear()
        return device_manager.get_usb_device(**device_args)
    elif device_type == "local":
        device_args.clear()
        return device_manager.get_local_device(**device_args)
    elif device_type == "remote":
        device_host = device_args['host']
        if device_host:
            return device_manager.add_remote_device(device_host)
        device_args.clear()
        return device_manager.get_remote_device(**device_args)

    return device_manager.enumerate_devices()[0]

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Dump Classes and Methods - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/dump', methods=['GET', 'POST'])
def home():
    global loaded_classes
    global loaded_methods
    global system_classes

    # tohook contains class selected by the user (hooking purposes)
    if request.method == 'POST':
        array_to_hook = request.values.getlist('tohook')
        if array_to_hook is not None:
            hooked_classes = []
            for index in array_to_hook:
                # hooked classes
                hooked_classes.append(loaded_classes[int(index)])
            loaded_classes = hooked_classes
        return printwebpage()

    # check what the user is triyng to do
    choice = request.args.get('choice')
    if choice is not None:
        choice = int(request.args.get('choice'))

    # ***** MENU *****
    if choice == 1:
        # --> Dump Loaded Classes (w/o filters)

        # clean up the array
        loaded_classes.clear()
        loaded_methods.clear()
        # check if the user is trying to filter loaded classes
        filter = request.args.get('filter')

        # Checking options
        regex = 1 if 'regex' in request.args else 0
        case = 1 if 'case' in request.args else 0
        whole = 1 if 'whole' in request.args else 0

        if filter:
            hooked_classes = api.loadclasseswithfilter(filter, regex, case, whole)
            loaded_classes.clear()
            loaded_classes = hooked_classes
        else:
            loaded_classes = api.loadclasses()
            # differences between class loaded after and before the app launch
            loaded_classes = list(set(loaded_classes) - set(system_classes))
        return printwebpage()

    if choice == 2:
        # --> Dump all methods [Loaded Classes]
        # NOTE: Load methods for more than 500 classes can crash the app
        loaded_methods = api.loadmethods(loaded_classes)
        return printwebpage()

    if choice == 3:
        # --> Hook all loaded classes and methods

        global calls_count
        global template_massive_hook
        calls_count = 0
        className = ""
        classMethod = ""

        api.hookclassesandmethods(loaded_classes, loaded_methods, template_massive_hook)
        # redirect the user to the console output
        return redirect(url_for('console_output_loader'))

    # Default template
    return printwebpage()


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Diff Classess - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/diff_classes', methods=['GET', 'POST'])
def diff_analysis():
    global current_loaded_classes
    global new_loaded_classes
    global target_package
    global system_package
    global no_system_package

    choice = request.args.get('choice')
    if choice is not None:
        choice = int(choice)
        if (choice == 1):
            # rms_print("Check current Loaded Classes")
            current_loaded_classes = list(
                set(api.loadclasses()) -
                set(system_classes)
            )
            # rms_print(len(current_loaded_classes))
        if (choice == 2):
            # rms_print("check NEW Loaded Classes")
            new_loaded_classes = list(
                set(api.loadclasses()) -
                set(current_loaded_classes) -
                set(system_classes)
            )
            # rms_print(len(new_loaded_classes))

    temp_str_1 = ""
    temp_str_2 = ""

    for i, c in enumerate(current_loaded_classes):
        temp_str_1 = temp_str_1 + "\n" + str(i) + " - " + str(c)

    for i, c in enumerate(new_loaded_classes):
        temp_str_2 = temp_str_2 + "\n" + str(i) + " - " + str(c)


    return render_template(
        "diff_classes.html",
        current_loaded_classes=temp_str_1,
        new_loaded_classes=temp_str_2,
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package
        )


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Hook LAB - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/hook_lab', methods=['GET', 'POST'])
def hook_lab():
    global template_hook_lab
    global loaded_methods
    global loaded_classes
    global target_package
    global system_package
    global no_system_package
    hook_template = ""
    selected_class = ""

    # class_index contains the index of the loaded class selected by the user
    class_index = request.args.get('class_index')
    if class_index is not None:
        class_index = int(class_index)
        # get methods of the selected class
        selected_class = [loaded_classes[class_index]]
        # check if methods are loaded or not
        if not loaded_methods:
            loaded_methods = api.loadmethods(loaded_classes)
        # template generation
        hook_template = api.generatehooktemplate(selected_class, loaded_methods, template_hook_lab)

    if selected_class != "":
        selected_class = selected_class[0]

    # print hook template
    return render_template(
        "hook_lab.html",
        loaded_classes=loaded_classes,
        selected_class=selected_class,
        hook_template_str=hook_template,
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package

    )


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Heap Search - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/heap_search', methods=['GET', 'POST'])
def heap_search():
    global template_heap_search
    global loaded_methods
    global loaded_classes
    global target_package
    global system_package
    global no_system_package
    heap_template = ""
    selected_class = ""

    # class_index contains the index of the loaded class selected by the user
    class_index = request.args.get('class_index')
    if class_index is not None:
        class_index = int(class_index)
        # get methods of the selected class
        selected_class = [loaded_classes[class_index]]
        # check if methods are loaded or not
        if not loaded_methods:
            loaded_methods = api.loadmethods(loaded_classes)
        # heap template generation
        heap_template = api.heapsearchtemplate(selected_class, loaded_methods, template_heap_search)

    if selected_class != "":
        selected_class = selected_class[0]

    # print hook template
    return render_template(
        "heap_search.html",
        loaded_classes=loaded_classes,
        selected_class=selected_class,
        heap_template_str=heap_template,
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package
    )

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
API Monitor - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

@app.route('/api_monitor', methods=['GET', 'POST'])
def api_monitor():

    global target_package
    global system_package
    global no_system_package

    api_monitor = {}
    api_selected=[]

    with open(os.path.dirname(os.path.realpath(__file__)) + "/api_monitor.json") as f:
        api_monitor = json.load(f)


    if request.method == 'POST':
        api_selected = request.values.getlist('api_selected')
        api_filter = [e for e in api_monitor if e['Category'] in api_selected]
        api_to_hook = json.loads(json.dumps(api_filter))
        api.apimonitor(api_to_hook);

        ''' DEBUG
        rms_print("\nAPI Selected")
        rms_print(api_selected)

        rms_print("\nAPI Monitor")
        for e in api_monitor:
            rms_print(e["Category"])

        rms_print("\nAPI to Hook")
        for c in api_to_hook:
            rms_print(c["Category"])
        '''

    return render_template(
        "api_monitor.html",
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package,
        api_monitor=api_monitor,
        api_monitor_console_output_str=api_monitor_console_output
    )

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Load Frida Script - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/load_frida_script', methods=['GET', 'POST'])
def frida_script_loader():
    global target_package
    global system_package
    global no_system_package

    if request.method == 'POST':
        script = request.values.get('frida_custom_script')
        api.loadcustomfridascript(script)
        # auto redirect the user to the console output page
        return redirect(url_for('console_output_loader'))

    # Load frida custom scripts inside "custom_scripts" folder
    custom_scripts = []
    for f in os.listdir(os.path.dirname(os.path.realpath(__file__)) + "/custom_scripts"):
        if f.endswith(".js"):
            custom_scripts.append(f)
    cs_file = ""
    if request.method == 'GET':
        cs = request.args.get('cs')
        if cs is not None:
            with open(os.path.dirname(os.path.realpath(__file__)) + "/custom_scripts/" + cs) as f:
                cs_file = f.read()

    return render_template(
        "load_frida_script.html",
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package,
        custom_scripts=custom_scripts,
        custom_script_loaded=cs_file
    )


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Console Output - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/console_output', methods=['GET', 'POST'])
def console_output_loader():
    global target_package
    global system_package
    global no_system_package
    return render_template(
        "console_output.html",
        called_console_output_str=calls_console_output,
        hooked_console_output_str=hooks_console_output,
        global_console_output_str=global_console_output,
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package
    )

''' Socket LOG
@socket_io.on('connect', namespace='/console')
def ws_connect():
    rms_print('Client connected')


@socket_io.on('disconnect', namespace='/console')
def ws_disconnect():
    rms_print('Client disconnected')
'''


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Config File - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/config', methods=['GET', 'POST'])
def edit_config_file():
    global target_package
    global system_package
    global no_system_package

    config = read_config_file()
    placeholder = {
        'host': 'IP:PORT',
        'id': 'Device’s serial number'
    }

    error = False
    if request.values.get('error'):
        error = True

    if request.method == 'POST':
        new_config = {}

        device_type = request.values.get('device-type')
        system_package = request.values.get('package')
        device_args_keys = request.values.getlist('key[]')
        device_args_values = request.values.getlist('value[]')

        device_args = dict(zip(device_args_keys, device_args_values))

        if device_type: new_config['device_type'] = device_type.lower()
        if system_package: new_config['system_package'] = system_package.strip()
        if device_args: new_config['device_args'] = device_args

        with open(os.path.dirname(os.path.realpath(__file__)) + "/config.json", "w") as f:
            json.dump(new_config, f, indent=4)

        return redirect(url_for('device_management'))

    return render_template(
        "config.html",
        system_package_str=config['system_package'],
        device_type_str=config['device_type'],
        args=config['device_args'],
        placeholder_str=placeholder,
        is_hide=is_hide,
        printOptions=printOptions(),
        error=error,
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package
    )


# Support show arguments in config tab
def is_hide(device_type, key):
    correlation = {
        'usb': '',
        'remote': 'host',
        'id': 'id',
        'local': ''
    }
    return correlation[device_type.lower()] != key


# Support init with correct device type selected
def printOptions():
    devices = ['USB', 'Remote', 'Local', 'ID']
    config = read_config_file()
    temp_str = ""

    for device_type in devices:
        if device_type.lower() == config['device_type']:
            temp_str = temp_str + "<option selected>" + str(device_type) + "</option>"
        else:
            temp_str = temp_str + "<option>" + str(device_type) + "</option>"
    return temp_str


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Read config.json file
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

def read_config_file():
    with open(os.path.dirname(os.path.realpath(__file__)) + "/config.json") as f:
        config = json.load(f)
    return config


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Render Template Function - used for the sidebar and dump page
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

def printwebpage():
    global target_package
    global system_package
    global no_system_package
    global loaded_classes
    global loaded_methods
    
    return render_template(
        "dump.html",
        loaded_classes=loaded_classes,
        loaded_methods=loaded_methods,
        target_package=target_package,
        system_package=system_package,
        no_system_package=no_system_package 
    )


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
on_message stuff
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

def on_message(message, data):


    if message['type'] == 'send':
        if "CALLED" in message['payload']:
            log_handler("calls_stack",message['payload'])
        if "HOOK" in message['payload']:
            log_handler("hooks_stack",message['payload'])
        if "API Monitor" in message['payload']:
            log_handler("api_monitor",message['payload'])
        if ("CALLED" not in message['payload'] and
            "HOOK" not in message['payload'] and
            "API Monitor" not in message['payload']):
            log_handler("global_stack",message['payload'])

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Supplementary functions
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

def rms_print(msg):
    print(msg, file=sys.stdout);

def reset_variables_and_output():
    global calls_count
    global calls_console_output
    global hooks_console_output
    global global_console_output
    global api_monitor_console_output
    global loaded_classes
    global system_classes
    global loaded_methods
    global current_loaded_classes
    global new_loaded_classes


    #output reset
    calls_console_output = ""
    hooks_console_output = ""
    global_console_output = ""
    api_monitor_console_output = ""
    calls_count = 0
    #variable reset
    loaded_classes = []
    system_classes = []
    loaded_methods = {}
    #diff classes variables
    current_loaded_classes = []
    new_loaded_classes = []
    #package reset
    target_package=""
    system_package=""

def log_handler(level, text):
    global calls_count
    global calls_console_output
    global hooks_console_output
    global global_console_output
    global api_monitor_console_output

    if not text:
        return
    '''
    if level == 'info':
        rms_print(text)
    else:
        rms_print(text)
    '''
    if level == 'calls_stack':
        text = "[" + str(calls_count) + "] " + text
        calls_console_output = calls_console_output + "\n" + text
        calls_count += 1
        socket_io.emit(
        'calls_stack', 
        {
            'data': "\n"+text, 
            'level': level
        }, 
        namespace='/console'
        )
    if level == 'hooks_stack':
        hooks_console_output = hooks_console_output + "\n" + text
        socket_io.emit(
        'hooks_stack', 
        {
            'data': "\n"+text, 
            'level': level
        }, 
        namespace='/console'
        )
    if level == 'api_monitor':
        api_monitor_console_output = api_monitor_console_output + "\n" + text
        socket_io.emit(
        'api_monitor', 
        {
            'data': "\n"+text, 
            'level': level
        }, 
        namespace='/console'
        )
    global_console_output = global_console_output + "\n" + text
    socket_io.emit(
    'global_console', 
    {
        'data': "\n"+text, 
        'level': level
    }, 
    namespace='/console'
    )
    rms_print(text)

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
MAIN
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

if __name__ == '__main__':
    print("")
    print("_________________________________________________________")
    print("RMS - Runtime Mobile Security")
    print("Version: 1.1")
    print("by @mobilesecurity_")
    print("Twitter Profile: https://twitter.com/mobilesecurity_")
    print("_________________________________________________________")
    print("")


    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    # run Flask
    socket_io.run(app)
