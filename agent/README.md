# RMS Core - Frida Agent Script

**RMS_Core_BETA.js** differs from the default **RMS_Core.js** script only for the implementation of [frida-fs](https://github.com/nowsecure/frida-fs) which is required in order to download files directly from the Web Browser (File Manager TAB). This feature is currently in **BETA** and needs to be enabled.

If you want to enable files download, **RMS_Core_BETA.js** needs to be compiled via [frida-compile](https://github.com/frida/frida-compile).

Just run 
<p><code>npm install</code></p>
directly from this folder to generate the "<b>_RMS_Core_BETA.js</b>" compiled script.

**Step by step instructions**
1. Open the file called "**mobilesecurity.py**" and set the **BETA** variable to **True**
2. Compile the "**RMS_Core.js**" agent via frida-compile! Just run the command ```npm install``` directly from this folder (**agent** folder). A file called "**_RMS_Core_BETA.js**" will be generated.
3. Restart RMS!