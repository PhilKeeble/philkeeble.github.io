---
layout: single
classes: wide
title: "Setting Up For iOS Hacking"
excerpt: "A guide on how to set up an environment for testing iOS devices."
categories: 
  - iOS
---
<h1>Intro</h1>

So for work I need to start testing iOS applications and it's a nice shiny new thing to learn, so I obviously took up the opportunity. This blog series will detail things I find in my journey into it, mainly so I can refer back later on and remember what I did.

Note: I will be using a Mac and an iPhone SE (the old one, not the new 2020 one) for this. Results may vary, especially not on apple hardware as they are notoriously a pain to work with. 

DISCLAIMER: DO NOT DO THIS ON YOUR PERSONAL PHONE!!!! WE WILL WEAKEN ITS SECURITY SIGNIFICANTLY! 

<h1>Initial</h1>

So the first thing to do I suppose is make sure that you can connect your iPhone to your computer. Make sure the computer, phone and cable are all working. After that I will assume that this is a test device and not a personal one. 

Connect the phone to the computer and make sure a pop-up comes up to trust the computer. For me, I had to go into the finder application on the mac then go into the phone through Finder, then hit the trust button. This forced the popup on my phone. Initially I had some issues with this and had to factory reset the phone beforehand. 

If you have to factory reset then make sure you set it up as a new device and either use a new icloud account or use an old one, but i don't recommend using any backups as we want to make 100% sure that no personal data exists on this phone. 

If your trust is ok and you can connect ok between computer and iPhone then move on.

<h1>Jailbreak</h1>

For our testing we are going to want root privileges on our phone. This can be achieved through `jailbreaks` which are techniques to get you root essentially. The one you use will depend on the hardware of the iOS device and the version. I am using the old SE on iOS 13.5.1. For this I can use CheckRa1n. 

Checkra1n can be used on any old iOS device since its a hardware exploit. Download CheckRa1n on to your computer from their site (you may want to use a VM, but you may experience issues if you do). Once you have it and run it (I think it only works on Mac and Linux), you should see a popup talking about checkra1n with an options button. 

Plug in the iOS to the USB now and you should see the device version and the iOS version appear in the checkra1n box. Since 13.5.1 is outside of the tested range at the time of writing, I needed to go into options on checkra1n and click on the top option to enable untested versions. Then hit back. Then I could hit start.

Follow the on screen instructions and if it all goes well you should be jailbroken within a couple minutes! 

This is a semi-tethered jailbreak, which means it will last until you reboot the device. After reboot you will need to repeat this process. 

<h1>Installing Tools on iOS</h1>

Now that you are jailbroken, you should see the Cydia application on your phone. This is a package manager for the device and apps that you can't get without root. Go through these steps: 

<h2>SSH</h2>

* Open Cydia 
* If it says you are missing packages, hit on upgrade all
* Click on search at the bottom
* Search for and install `OpenSSH`

To check this worked ok, open up Settings > General > WiFi > Tap on your connected Wifi network > take note of the IP Address. Then open your terminal and use:
`ssh root@iphoneIP` with the password `alpine` and you should connect. (I recommend changing the password with the command `passwd` after you connect).

<h2>AppSync Unified</h2>

* Click on the Sources button at the bottom 
* Click on edit at the top right 
* Click on add in the top left 
* Add `https://cydia.angelxwind.net/`
* Tap Return to Cydia 
* Click on Search 
* Search for and install `AppSync Unified`

<h2>Frida</h2>

* Go back to Adding a Source 
* Add `https://build.frida.re`
* Search and install `Frida` (for me I chose the pre-A12 iOS option)

<h2>iRET (Currently not working, will update if I get it working. Ignore for now.)</h2>

* SSH into the iOS device
* Run the command below 

```
wget --no-check-certificate https://www.veracode.com/sites/default/files/Resources/Tools/iRETTool.zip
```

* Run `apt-get install unzip`
* Run  `unzip iRETTool.zip`
* Run `cd iRET-Tool/`
* Run `dpkg -i iRET.deb`
* Run `killall SpringBoard`
* Reconnect over SSH if needed
* Run `uicache`
* You should now see iRET in the iPhone. I can't open it yet, I think i'm missing some dependencies but will update this when I can. 

I will update this list as I need to add more for testing.

<h1>Installing Tools on Mac</h1>

<h2>Xcode</h2>
Install xcode from the Apple Store. This is the official way to develop iOS applications and has iOS simulation capabilities and some helpful utilities to aid us with loading applications onto the iphone. This took ages to download for me. 

<h2>Frida</h2>
Make sure you have Python3 on your device. Linux and Mac should have this by default. If you don't install it.

Make sure you have pip3 installed on your device. If you don't then you can install it through Python3. 

Install Frida:

`pip3 install frida-tools` 

You should now be able to run the following in the terminal (plug in your iOS device over USB first)

`frida-ps -U`

You should see some application names that relate to things on the iOS device. 

<h2>iFunBox</h2>

iFunBox is a useful tool for managing the file system. It's old but seems to still work ok. Google it and download it from their site. Once its installed, make sure you can see your iOS device over USB with it and look at files. 

I will update these as I find more I need for testing! 

<h2>Ghidra</h2>

Ghidra isn't necessary, but we may need to reverse engineer applications. I recommend using whatever you are comfortable with. I have been using Ghidra a lot lately so I will use this. 

You will need to go to the Ghidra website and download the zip file they have. It's just a self contained Java file so there is no installation needed. You will then need to google for a JDK and download the latest JDK. This will need to be installed.

Once you have the JDK installed, you should be able to go to the Ghidra directory in the terminal and use `ghidrarun` to run Ghidra. For Ghidra basics you can check out my Minesweeper hacking post. 

To load an application, you will need to follow these steps:

* Find the .ipa file you want to analyse
* Rename it to a .zip file 
* unzip the contents
* look inside the contents and go into the Payload folder
* You should be able to see a .app file. This is the application and will be named the same as the application
* Load the .app file into the Reversing tool (for ghidra you will need to make a new project, then import the file)

<h2>Objection</h2>

Objection will be helpful for injecting into apps and a useful addition to Frida. It can be installed in the same way with pip. 

`pip3 install objection`

Using the command `objection` should show help menu.

<h2>KeyChain Dumper</h2>

Dumping data from the keychain will be important. This can be done with a dedicated tool, however I will be doing it through other tools (Passionfruit seems to work well for keychain access).

<h2>Passionfruit</h2>

Passionfruit is a GUI application that allows us to conveniently view data about the application. To install this we will need to get node.

`brew install node`

Then we will need to use node package manager (npm) to download Passionfruit.

`npm install -g passionfruit`

Now we should just be able to run it! 

`passionfruit`

This should show a URL (localhost:31337 by default). Browse to this URL in your browser and you should see the Passionfruit home page. Connect your device over USB and you should see your device there as well! 

Note: this will require Frida and will often crash, but is easy to reboot. 

<h2>GrapeFruit</h2>

Dev version of new Passionfruit, it will be more stable but doesn't show some information currently that is in Passionfruit (such as Keychain values). The link below has the steps needed to install and get running. 

<a href="https://github.com/ChiChou/Grapefruit/blob/master/README.md">https://github.com/ChiChou/Grapefruit/blob/master/README.md</a>

<h2>SQLite Browser</h2>

Googling for SQLite Browser and downloading should work well. Installation is same as a normal mac app. 

<h2>Realm Browser</h2>

This can be retrieved from Apple Store. Search for Realm Browser and install and you should be good to go.

<h2>Others</h2>

There are other tools that can be helpful. A list of useful ones can be found at the link below:

<a href="https://github.com/ansjdnakjdnajkd/iOS">https://github.com/ansjdnakjdnajkd/iOS</a>

<h1>Install DVIA</h1>

DVIA is Damn Vulnerable IOS App and is a training ground for hacking. There are two. Version 1 is older and in Objective-C. The Version 2 is newer and written in SWIFT. I have opted to get the second one. 

Head to the github page for the project and download the .ipa file included in the Github project. 

If you have follow the above and have Xcode and AppSync Unified installed then follow below: 

* Connect the iOS device over USB 
* Open xcode
* Click on window (in the very top of the screen, not in the app) 
* Click on Organizer
* You should see your device in the left hand side, click on it 
* scroll so you can see the application section 
* Click on the + button and select the .ipa file you downloaded 
* It should now be installed! 

You can now launch DVIA-v2 on the iOS device as with any other app and take a look around. I recommend clicking into all the options to see what they do and input fake data all over for you to find later. 

My next posts will be on exploring DVIA-v2 for vulnerabilities. I will likely come back to this post to update it on tools I find useful to install. 