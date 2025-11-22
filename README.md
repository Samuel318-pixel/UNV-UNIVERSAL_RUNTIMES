# UNV-UNIVERSAL_RUNTIMES
UNV IS A UNIVERSAL EXECUTABLE THAT WORKS ON LITERALLY ANY OPERATING SYSTEM, I MADE THE REPOSITORY AVAILABLE FOR ANYONE TO MODIFY TO TURN THEIR SCRIPTS OR APPS INTO UNIVERSAL-RUNTIME. YOU NEED TO CREATE A FOLDER AND PUT IN IT THIS EXAMPLE CONTENT

my_app.unv (it's a renamed ZIP file)
│
├── manifest.json
├── main.py ← default entrypoint
├── /assets ← (optional) images, sounds, fonts...
├── /modules ← (optional) extra Python modules
└── any_file... ← (optional)

manifest.json (REQUIRED)
This file is the heart of the .unv. Complete example:
{
  "name": "My App",
  "version": "1.0.0",
  "entry": "main",
  "description": "My application using UNV Runtime",
  "permissions": {
    "network": false,
    "filesystem": true
  },
  "icon": "assets/icon.png"
}

2. main
Your main code here. Simple example:
print("Hello from UNV!") but practically any language can be turned into Python, I just used it as an example


after that, you turn the folder into a ZIP and change the extension to .unv, then you can run it on any operating system.
