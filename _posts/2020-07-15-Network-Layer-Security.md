---
layout: single
classes: wide
title: "iOS Network Layer Security - DVIAv2 Part 7"
excerpt: "A guide on how to intercept web traffic from iOS devices."
categories: 
  - iOS
---
<h1>Intro</h1>

So far we have only looked at mobile applications and their interaction with the device. However, almost every application I can think of talks to some server somewhere. This could be to get information like a web browser, or to communicate through some API like getting the weather, or it could be saving points in a game. This presents an interesting opportunity because like a web application assessment, we control the client. This means we can manipulate data in ways the developers may not have thought of and we may be able to attack the server, or develop an attack against someone else using the application. 

This challenge of DVIAv2 has three input fields for name and credit card numbers. Once they are filled out you can send the traffic through HTTP (unencrypted), HTTPS (encrypted) and you also have the choice to apply `Certificate Pinning` or `SSL Pinning`. These are both methods to prevent traffic interception and to prevent Man in the Middle (MitM) attacks.

<h1>HTTP</h1>

I will assume you have already got `BurpSuite` on your computer. If you have not then go and download the community version of that (it's free). This is the de facto tool for web traffic interception in pentesting and this is no exception. 

Open up BurpSuite on your computer and choose the default options. When it is launched first go to the `Proxy` tab at the top. Under that make sure you are on the `Intercept` tab. Now click on the `Intercept is on` button so that it says `Intercept is off`. This is on whenever you open up Burp and it will stop all traffic going through until you allow it. I prefer to have this off until I need it for something specific.

Now stay under the `Proxy` tab and go to the `Options` tab located under it. You should see the below:

<p align="center"><a href="/images/iOS7-1.png"><img src="/images/iOS7-1.png"></a></p>
<img>

Now click on the `Add` button for a Proxy Listener. Add in the port `8081` and click on the button for it to be `All interfaces`, like below:

<p align="center"><a href="/images/iOS7-2.png"><img src="/images/iOS7-2.png"></a></p>
<img>

Click on `OK`. It will give you an error since you are listening to remote connections. Click `OK` again and you should see the listener has been added. 

Now on your iPhone go into `Settings` > `WiFi` > Click on your currently connected WiFi (must be same as computer) > Scroll to the bottom > `Configure Proxy` > `Manual` > Add your computer IP into the `Server` field and `8081` into the `Port` field > Save > Now go back home.

All being well you should now be intercepting traffic. 

Go back into DVIA-v2 and enter some details in on the input fields for the `Network Layer Security` view. Now click `Send over HTTP`. You should see the below in Burp.

<p align="center"><a href="/images/iOS7-3.png"><img src="/images/iOS7-3.png"></a></p>
<img>

This will contain the data you just entered! 

<h1>HTTPS</h1>

If we try to send the HTTPS now we should get an error that the host isn't trusted. This is because it can see we are intercepting it and it doesn't yet trust Burp. 

On your iPhone, launch the web browser and go to `http://burp`. Click on the `CA Certificate` button in the top right of the view and allow the download. 

Now go back into `Settings` > `General` > `Profile` > `PortSwigger CA` > `Install`. This should install the CA certificate to your phone so that it trusts Burp. 

Now go back into DVIA-v2 and click on the `Send over HTTPS` button. 

You should see the below in Burp:

<p align="center"><a href="/images/iOS7-4.png"><img src="/images/iOS7-4.png"></a></p>
<img>

Note that the host is now `https://example.com` rather than `http://example.com` but we can still see the data. It is essentially encrypting it to us and then Burp is encrypting it to the server, completing the MitM scenario. 

<h1>Certificate/SSL Pinning</h1>

Despite intercepting HTTPS, it is not the certificate expected by the application. SSL and Certificate pinning can be used to try make sure that they are talking to the right server and aren't being intercepted. However, if we control the device then we can again bypass this. 

If you tap on either the `Send using Certificate Pinning` or the `Send using Public Key Pinning` buttons you should get a popup telling you that `Certificate Validation failed`.

There are multiple ways to bypass this such as SSL Killswitch, but I will be using Objection.

Load Objection into DVIA-v2.

```
objection --gadget DVIA-v2 explore
```

Now disable SSL pinning:

```
ios sslpinning disable
```

This hooks the low level functions that check the certificates and returns that they are true. Now if we click on either the `Send using certificate pinning` or the `send using public key pinning` it will not popup at all. But in Burp we will see the requests! 

<p align="center"><a href="/images/iOS7-5.png"><img src="/images/iOS7-5.png"></a></p>
<img>

Both of these requests look the same and are GET requests. This means they do not include POST data from the application, so we cannot see the sensitive data. 

However since we have bypassed the certificate validation, we are done and now fully a MitM! 