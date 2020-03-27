from flask import Flask, request, render_template
from flask_bootstrap import Bootstrap
import frida, sys, os
import json

app = Flask(__name__)

# Global variables 
loaded_classes = []
system_classes = []
loaded_methods = {}

# Global variables - diff analysis
current_loaded_classes = []
new_loaded_classes = []

# Global variables - console output
calls_console_output=""
hooks_console_output=""
calls_count=0

api = None

package_name=""


template1="""
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var hookclass = Java.use(classname);

    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("CALLED: " + classname + "." + classmethod + "()");
        var ret = this.{classMethod}({args});

        var s="";
        s=s+("\\nHOOK: " + classname + "." + classmethod + "()");
        s=s+"\\nIN: "+eval(args);
        s=s+"\\nOUT: "+ret;
        send(s);
                
        return ret;
    };
});
"""
template2="""
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var hookclass = Java.use(classname);

    //{methodSignature}

    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("CALLED: " + classname + "." + classmethod + "()");
        var ret = this.{classMethod}({args});

        var s="";
        s=s+("\\nHOOK: " + classname + "." + classmethod + "()");
        s=s+"\\nIN: "+{args};
        s=s+"\\nOUT: "+ret;
        send(s);
                
        return ret;
    };
});
"""

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Device - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

@app.route('/', methods=['GET','POST'])

def device_management():
    global api
    global system_classes
    global package_name
    
    cs_file=""
    custom_scripts=[]

    #Read config.json file
    with open(os.path.dirname(os.path.realpath(__file__)) +"/config.json") as f:
        config = json.load(f)

    if request.method == 'GET':
        #Load frida custom scripts inside "custom_scripts" folder
        for f in os.listdir(os.path.dirname(os.path.realpath(__file__)) +"/custom_scripts"):
            if f.endswith(".js"):
                custom_scripts.append(f)

        cs=request.args.get('cs')
        if cs!=None:
            with open(os.path.dirname(os.path.realpath(__file__)) +"/custom_scripts/"+cs) as f: 
                cs_file = f.read()
    
    if request.method == 'POST':
        package_name=request.values.get('package')
        mode=request.values.get('mode')
        frida_script=request.values.get('fridastartupscript')

        if package_name: print("Package Name: "+package_name, file=sys.stdout)
        if mode: print("Mode: "+mode, file=sys.stdout)
        if frida_script: print("Frida Startup Script: \n"+frida_script, file=sys.stdout)

        # main JS file
        with open(os.path.dirname(os.path.realpath(__file__)) + '/default.js') as f: 
            frida_code = f.read()

        device = frida.get_usb_device()

        # attaching a persistent process to get enumerateLoadedClasses() result 
        # before starting the target app - default process is com.android.systemui
        session = device.attach(config["system_package"])
        script = session.create_script(frida_code)
        script.load()
        api = script.exports
        system_classes=api.loadclasses()

        session=None
        if(mode=="Spawn"):
            pid = device.spawn([package_name])
            session = device.attach(pid)
            print('[*] Process Spawned')
        if(mode=="Attach"):
            session = device.attach(package_name)
            print('[*] Process Attached')

        script = session.create_script(frida_code)
        script.on('message', on_message)
        script.load()

        # loading js api
        api = script.exports  

        if(mode=="Spawn"):
            device.resume(pid)
 

        # loading FRIDA startup script if exists
        if frida_script:
            api.loadcustomfridascript(frida_script)
            #DEBUG print(frida_script, file=sys.stdout)

        # automatically redirect the user to the dump classes and methods tab  
        return printwebpage()


    return render_template(
        "device.html",
        custom_script_loaded=cs_file,
        custom_scripts=custom_scripts,
        system_package_str=config["system_package"],
        package_name_str=package_name
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
        array_to_hook=request.values.getlist('tohook')
        if array_to_hook != None:
            hooked_classes=[]
            for index in array_to_hook: 
                # hooked classes 
                hooked_classes.append(loaded_classes[int(index)])
            loaded_classes=hooked_classes
        return printwebpage()

    # check what the user is triyng to do
    choice=request.args.get('choice') 
    if choice != None:
        choice = int(request.args.get('choice'))

    # ***** MENU ***** 
    if choice==1: 
        # --> Dump Loaded Classes (w/o filters)

        #clean up the array
        loaded_classes.clear()
        loaded_methods.clear()
        # check if the user is trying to filter loaded classes 
        filter = request.args.get('filter')
        if filter:
            hooked_classes=api.loadclasseswithfilter(filter)
            loaded_classes.clear()
            loaded_classes=hooked_classes
        else:
            loaded_classes=api.loadclasses()
            #differences between class loaded after and before the app launch
            loaded_classes=list(set(loaded_classes)-set(system_classes))
        return printwebpage()


    if choice==2: 
        # --> Dump all methods [Loaded Classes]
        #NOTE: Load methods for more than 500 classes can crash the app
        loaded_methods=api.loadmethods(loaded_classes)
        return printwebpage()
  
    if choice==3: 
        # --> Hook all loaded classes and methods

        global calls_count
        global template1
        calls_count=0
        className=""
        classMethod=""

        api.hookclassesandmethods(loaded_classes,loaded_methods,template1)
        return printwebpage()


    # Default template
    return printwebpage();


''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Diff Classess - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

@app.route('/diff_classes', methods=['GET', 'POST'])
def diff_analysis():
    global current_loaded_classes 
    global new_loaded_classes 

    choice=request.args.get('choice')
    if choice != None:
        choice=int(choice)
        if(choice==1):
            #print("Check current Loaded Classes", file=sys.stdout)
            current_loaded_classes=list(
                set(api.loadclasses())-
                set(system_classes)
                )
            #print(len(current_loaded_classes), file=sys.stdout)
        if(choice==2):
            #print("check NEW Loaded Classes", file=sys.stdout)
            new_loaded_classes=list(
                set(api.loadclasses())-
                set(current_loaded_classes)-
                set(system_classes)
                )
            #print(len(new_loaded_classes), file=sys.stdout)

    temp_str_1=""
    temp_str_2=""

    for i,c in enumerate(current_loaded_classes):
        temp_str_1=temp_str_1+"\n"+str(i)+" - "+str(c);

    for i,c in enumerate(new_loaded_classes):
        temp_str_2=temp_str_2+"\n"+str(i)+" - "+str(c);

    return render_template(
        "diff_classes.html",
        current_loaded_classes=temp_str_1,
        new_loaded_classes=temp_str_2,
        package_name_str=package_name)

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
        package_name_str=package_name)

''' 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Hook LAB - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

@app.route('/hook_lab', methods=['GET', 'POST'])
def hook_lab():
    global template2
    global loaded_methods
    global loaded_classes
    hook_template=""
    selected_class=""

    # class_index contains the index of the loaded class selected by the user
    class_index=request.args.get('class_index')
    if class_index != None:
        class_index = int(class_index) 
        # get methods of the selected class
        selected_class=[loaded_classes[class_index]]
        #check if methods are loaded or not
        if not loaded_methods:
            loaded_methods=api.loadmethods(loaded_classes)
        # template generation
        hook_template=api.generatehooktemplate(selected_class,loaded_methods,template2)

    if selected_class!="":
        selected_class=selected_class[0]

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
Custom Frida Script - TAB
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''

@app.route('/custom_frida_script', methods=['GET', 'POST'])
def frida_script_loader():
    if request.method == 'POST':
        script=request.values.get('frida_custom_script')
        api.loadcustomfridascript(script)
        # auto redirect the user to the dump classes and methods page
        return printwebpage()

    #Load frida custom scripts inside "custom_scripts" folder
    custom_scripts=[]
    for f in os.listdir(os.path.dirname(os.path.realpath(__file__)) +"/custom_scripts"):
        if f.endswith(".js"):
            custom_scripts.append(f)
    cs_file=""
    if request.method == 'GET':
        cs=request.args.get('cs')
        if cs!=None:
            with open(os.path.dirname(os.path.realpath(__file__)) +"/custom_scripts/"+cs) as f: 
                cs_file = f.read()

            
    return render_template(
        "custom_frida_script.html", 
        package_name_str=package_name,
        custom_scripts=custom_scripts,
        custom_script_loaded=cs_file
        )

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

    temp_str=""
    for index, class_name in enumerate(loaded_classes):
        temp_str=temp_str+"<tr><td><center>["+str(index)+"]</center></td>"+"<td>"+class_name+"</td>"
        #print(str(index)+" Class: "+class_name, file=sys.stdout); 
        temp_str=temp_str+"<td><pre><code class=Java>"
        if loaded_methods:
            #if(class_name in loaded_methods): 
            for index, method_name in enumerate(loaded_methods[class_name]): 
                m=method_name
                temp_str=temp_str+m["ui_name"]+";<br>"
        temp_str=temp_str+"</code></pre></td></tr>"
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
            to_print="["+str(calls_count)+"] "+message['payload']
            print(to_print, file=sys.stdout)
            calls_console_output=calls_console_output+"\n"+to_print
            calls_count+=1
        else:
            hooks_console_output=hooks_console_output+"\n"+message['payload']
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
    app.run()
