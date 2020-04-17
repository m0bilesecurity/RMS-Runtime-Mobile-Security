import os
import sys
import json
import frida
from flask_bootstrap import Bootstrap
from flask_socketio import SocketIO, emit
from flask import Flask, request, render_template, redirect, url_for

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
calls_count = 0

api = None

package_name = ""

template_massive_hook = """
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var hookclass = Java.use(classname);

    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("CALLED: " + classname + "." + classmethod + "()");
        var ret = this.{classMethod}({args});

        var s="";
        s=s+("\\nHOOK: " + classname + "." + classmethod + "()");
        s=s+"\\nInput: "+eval(args);
        s=s+"\\nOutput: "+ret;
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
        send("CALLED: " + classname + "." + classmethod + "()");
        var ret = this.{classMethod}({args});

        var s="";
        s=s+"\\nHOOK: " + classname + "." + classmethod + "()";
        s=s+"\\nIN: "+{args};
        s=s+"\\nOUT: "+ret;
        send(s);
                
        return ret;
    };
});
"""

template_heap_search = """
    Java.performNow(function () {
      var classname = "{className}"
      var classmethod = "{classMethod}";

      send("Heap Search - START ("+classname+")");

      Java.choose(classname, {
        onMatch: function (instance) {
          
          var s="";
          s=s+"Instance Found: " +instance.toString();
          s=s+"\\nCalling method: " +classmethod;
          
          //{methodSignature}
          var ret = instance.{classMethod}({args}); //<-- replace v[i] with the value that you want to pass
          s=s+"\\nOutput: "+ ret;
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


def log_handler(level, text):
    if not text:
        return

    if level == 'info':
        print(text, file=sys.stdout)
    else:
        print(text, file=sys.stderr)

    global hooks_console_output
    hooks_console_output += text + '\n'
    socket_io.emit('console_output', {'data': hooks_console_output, 'level': level}, namespace='/console')


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


@app.route('/', methods=['GET', 'POST'])
def device_management():
    global api
    global system_classes
    global package_name

    cs_file = ""
    custom_scripts = []
    packages = []
    config = read_config_file()

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
            pass

        # Load frida custom scripts inside "custom_scripts" folder
        for f in os.listdir(os.path.dirname(os.path.realpath(__file__)) + "/custom_scripts"):
            if f.endswith(".js"):
                custom_scripts.append(f)

        cs = request.args.get('cs')
        if cs is not None:
            with open(os.path.dirname(os.path.realpath(__file__)) + "/custom_scripts/" + cs) as f:
                cs_file = f.read()

    if request.method == 'POST':
        package_name = request.values.get('package')
        mode = request.values.get('mode')
        frida_script = request.values.get('fridastartupscript')

        if package_name: print("Package Name: " + package_name, file=sys.stdout)
        if mode: print("Mode: " + mode, file=sys.stdout)
        if frida_script: print("Frida Startup Script: \n" + frida_script, file=sys.stdout)

        # main JS file
        with open(os.path.dirname(os.path.realpath(__file__)) + '/default.js') as f:
            frida_code = f.read()

        # attaching a persistent process to get enumerateLoadedClasses() result
        # before starting the target app - default process is com.android.systemui
        session = device.attach(config["system_package"])
        script = session.create_script(frida_code)
        script.set_log_handler(log_handler)
        script.load()
        api = script.exports
        system_classes = api.loadclasses()

        session = None
        if mode == "Spawn":
            pid = device.spawn([package_name])
            session = device.attach(pid)
            print('[*] Process Spawned')
        if mode == "Attach":
            session = device.attach(package_name)
            print('[*] Process Attached')

        script = session.create_script(frida_code)
        script.set_log_handler(log_handler)
        script.on('message', on_message)
        script.load()

        # loading js api
        api = script.exports

        if mode == "Spawn":
            device.resume(pid)

        # loading FRIDA startup script if exists
        if frida_script:
            api.loadcustomfridascript(frida_script)
            # DEBUG print(frida_script, file=sys.stdout)

        # automatically redirect the user to the dump classes and methods tab
        return printwebpage()

    return render_template(
        "device.html",
        custom_script_loaded=cs_file,
        custom_scripts=custom_scripts,
        system_package_str=config["system_package"],
        device_type_str=config["device_type"],
        package_name_str=package_name,
        packages=packages,
        conn_args_str=conn_args
    )


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
        if filter:
            hooked_classes = api.loadclasseswithfilter(filter)
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

    choice = request.args.get('choice')
    if choice is not None:
        choice = int(choice)
        if (choice == 1):
            # print("Check current Loaded Classes", file=sys.stdout)
            current_loaded_classes = list(
                set(api.loadclasses()) -
                set(system_classes)
            )
            # print(len(current_loaded_classes), file=sys.stdout)
        if (choice == 2):
            # print("check NEW Loaded Classes", file=sys.stdout)
            new_loaded_classes = list(
                set(api.loadclasses()) -
                set(current_loaded_classes) -
                set(system_classes)
            )
            # print(len(new_loaded_classes), file=sys.stdout)

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
        package_name_str=package_name)


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
        package_name_str=package_name
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
        package_name_str=package_name
    )


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Custom Frida Script - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/custom_frida_script', methods=['GET', 'POST'])
def frida_script_loader():
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
        "custom_frida_script.html",
        package_name_str=package_name,
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
    return render_template(
        "console_output.html",
        called_console_output_str=calls_console_output,
        hooked_console_output_str=hooks_console_output,
        package_name_str=package_name
    )


@socket_io.on('connect', namespace='/console')
def ws_connect():
    print('Client connected')
    emit('console_output', {'data': hooks_console_output})


@socket_io.on('disconnect', namespace='/console')
def ws_disconnect():
    print('Client disconnected')


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Config File - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


@app.route('/config', methods=['GET', 'POST'])
def edit_config_file():
    config = read_config_file()
    placeholder = {
        'host': 'IP:PORT',
        'id': 'Device’s serial number'
    }

    error = False
    if request.values.get('error'):
        error = "Device not connected. Please, modify the settings and try again."

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
        error_str=error
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
    return render_template(
        "dump.html",
        loaded_classes_str=printClassesMethods(),
        package_name_str=package_name,
        loaded_classes=loaded_classes
    )


# Support print function
def printClassesMethods():
    temp_str = ""
    for index, class_name in enumerate(loaded_classes):
        temp_str = temp_str + "<tr><td><center>[" + str(index) + "]</center></td>" + "<td>" + class_name + "</td>"
        # print(str(index)+" Class: "+class_name, file=sys.stdout);
        temp_str = temp_str + "<td><pre><code class=Java>"
        if loaded_methods:
            # if(class_name in loaded_methods):
            for index, method_name in enumerate(loaded_methods[class_name]):
                m = method_name
                temp_str = temp_str + m["ui_name"] + ";<br>"
        temp_str = temp_str + "</code></pre></td></tr>"
    return temp_str


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
on_message stuff
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''


def on_message(message, data):
    global calls_count
    global calls_console_output
    global hooks_console_output
    if message['type'] == 'send':
        if "CALLED" in message['payload']:
            to_print = "[" + str(calls_count) + "] " + message['payload']
            print(to_print, file=sys.stdout)
            calls_console_output = calls_console_output + "\n" + to_print
            calls_count += 1
        else:
            hooks_console_output = hooks_console_output + "\n" + message['payload']
            print("[*] {0}".format(message['payload']), file=sys.stdout)


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
MAIN
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

if __name__ == '__main__':
    print("")
    print("_________________________________________________________")
    print("RMS - Runtime Mobile Security")
    print("Version: 1.0")
    print("by @mobilesecurity_")
    print("Twitter Profile: https://twitter.com/mobilesecurity_")
    print("_________________________________________________________")
    print("")

    # run Flask
    socket_io.run(app)
