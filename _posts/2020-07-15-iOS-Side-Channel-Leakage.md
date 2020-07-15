---
layout: single
classes: wide
title: "iOS Side Channel Data Leakage - DVIAv2 Part 6"
excerpt: "A guide on how to find data leaked by iOS applications through side channels."
categories: 
  - iOS
---
<h1>Intro</h1>

As a user interacts with an application, it may store various pieces of data around the system. These pieces of data can be things typed on the keyboard, things copied, screenshots of sensitive information, cookies and device logs. All of these pieces of information can be found by users with jailbroken devices. If a device is jailbroken, other applications may be able to interact with these as well and they could be used to steal information about the user. This is varying in severity depending on the sensitivity of the application. 

DVIA-v2 has various challenges for finding sensitive data in these storage locations. For most of the challenges the sensitive data is typically credit card details, mimicking something like a banking application where you definitely don't want data leaked. 

<h1>Device Logs</h1>

Whenever I fill out the form and submit it, my application crashes. This means I may not be able to do this first one. I will come back and update this if I get the function working on my device.

<h1>App Screenshot</h1>

When a phone application is backgrounded, you can still 'see' the screen when you go into the menu to select between open applications. This is actually just a screenshot. The app takes the screenshot when it is being backgrounded, then keeps it on the device and that is what you see. Then when you open the application again, it keeps that screenshot whilst it loads the app, this provides a more seamless experience. However, if you background the application whilst entering bank information, that means the screenshot includes sensitive data. 

The screenshots are saved at the location:

```
/var/mobile/Containers/Data/Application/$APP_ID/Library/SplashBoard/Snapshots
```

You will need to know the $APP_ID and if you have a lot of applications on the device this can be tedious. Let's do this a quick way by loading up Passionfruit.

```
Passionfruit
```

Go to `localhost:31337` in your browser, select your iPhone, select DVIA-v2. You should now be able to see the directory.

<p align="center"><a href="/images/iOS6-1.png"><img src="/images/iOS6-1.png"></a></p>

For me it is as below:

```
/private/var/mobile/Containers/Data/Application/B93C0B16-206B-4C86-B436-886B4716D29B
```

Yours will be different, but you want the Data Directory. Now you need to add in the data on the application to be stored. This is the security question you need to answer on the `App Screenshot` screen. With the answer filled in, go home on the device so that the application is backgrounded. If you are an iPhone, double tap the home button to see that you can see the application in the reel and that it shows your answer.

Now SSH into your device.

```
SSH root@IPHONE_IP_ADDRESS
```

Now cd into the data directory path and have a look around. I ended up finding a `.jpeg` with the path below:

```
/private/var/mobile/Containers/Data/Application/B93C0B16-206B-4C86-B436-886B4716D29B/Library/SplashBoard/Snapshots/sceneID:com.highaltitudehacks.DVIAswiftv2-default/E349742F-08F3-4886-A4B1-A56733A08664\@2x.jpeg
```

I then used SCP to copy it over from my phone. To do this, exit SSH, then use a command such as below:

```
scp root@IPHONE_IP_ADDRESS:/private/var/mobile/Containers/Data/Application/B93C0B16-206B-4C86-B436-886B4716D29B/Library/SplashBoard/Snapshots/sceneID:com.highaltitudehacks.DVIAswiftv2-default/E349742F-08F3-4886-A4B1-A56733A08664\@2x.jpeg .
```

This copies it from the device to the current directory on the mac. Now go there in finder and take a look at the screenshot.

<p align="center"><a href="/images/iOS6-2.png"><img src="/images/iOS6-2.png"></a></p>

You can see it saved the `secretname` value I put in the text field before backgrounding the application! 

<h1>Pasteboard</h1>

When text is copied in iOS it goes inside the 'pasteboard'. So this is the same as a Windows Clipboard. This stores things for pasting later on. This could include usernames, passwords and any other sensitive information. The challenge here is to enter a Name, Credit Card Number and CVV value, copy them and then see them on the pasteboard. It say's we should create a separate app to do it, but I will use Objection.

Starting Objection:

```
objection --gadget DVIA-v2 explore
```

Start monitoring the pasteboard:

```
ios pasteboard monitor
```

Now go into the application, fill out the values and then copy them all one at a time. We should see them appear in the console as we copy them!

<p align="center"><a href="/images/iOS6-3.png"><img src="/images/iOS6-3.png"></a></p>

<h1>Keystroke Logging</h1>

When going through the application, the device is logging the keystrokes on every input by default. It doesn't do this if the input field is marked as `secure` in the application. Developers should also disable autocorrect on sensitive fields to prevent this. Phones collect this information so that they can use predictive text and suggestions for autocorrect. Since they are values stored on the device, we (or a malicious app) can find them on a jailbroken device and read the contents!

By default the location is:

```
/private/var/mobile/Library/Keyboard/
```

Type some values into the input field on the `keystoke logging` screen. Then SSH into the device and go to this directory.

```
SSH root@IPHONE_IP_ADDRESS

cd /private/var/mobile/Library/Keyboard/
```

Online I was seeing that the location should be `en_GB-dynamic-text.dat` within this folder. This did not exist for me. However, looking through the folders and other `.dat` files I found the following file:

`/private/var/mobile/Library/Keyboard/en-dynamic.lm/dynamic-lexicon.dat`

I copied this over to my mac with SCP (you will need to exit the SSH session first or use another terminal):

```
scp root@IPHONE_IP_ADDRESS:/private/var/mobile/Library/Keyboard/en-dynamic.lm/dynamic-lexicon.dat .
```

I then read the file on my mac with the built-in tools xxd and less:

```
xxd dynamic-lexicon.dat | less
```

Now hitting enter you can scroll through the hex and look at the bytes (to exit press `q`). You should be able to see something like the below: 

<p align="center"><a href="/images/iOS6-4.png"><img src="/images/iOS6-4.png"></a></p>

In the bytes we can see various strings like `hellokeychain` and other `hello...` strings that I have used around the application. The `hellologger` string is the one I used on the `Keystroke logging` screen input field! 

Now press `q` to leave the view of `less`. 

If you don't have this file it may be one of the other `.dat` files. Try pulling them all down with SCP and then reading them all with xxd and seeing which one contains the words you have entered to the application.

<h1>Cookies</h1>

Some applications create cookies and store them on the device to allow persistance within the application (remaining logged in so users don't need to enter authentication every time). Whilst convenient, this may allow credentials to be on the device. 

The challenge here is to find the cookies on the device and find the username and password and enter them in the login boxes. You can actually also reverse engineer it and see the credentials in Ghidra, but we won't do that now.

Let's start Objection (With DVIA-v2 already running).

```
objection --gadget DVIA-v2 explore
```

We can now list the cookies within the application sandbox through Objection.

```
ios cookies get
```

<p align="center"><a href="/images/iOS6-5.png"><img src="/images/iOS6-5.png"></a></p>

As you can see above, we can now see the username is `admin123` and the password is `dvpassword`. Entering those values in the application shows us they are correct! 

The application does mention that if you don't see the cookies, you may need to restart the app and come to the screen again.