---
layout: single
classes: wide
title: "Insecure iOS Storage - DVIAv2 Part 1 "
excerpt: "A guide on how to abuse insecure iOS storage configurations."
categories: 
  - iOS
---
<h1>Intro</h1>

Mobile applications store a lot of data about the users and things for it to function. The mobile model of security is in general pretty good at stopping users from accessing this data (as long as they don't root or jailbreak their device). 

With DVIAv2 there are several pieces of information to show how an application could store data insecurely. If you load up DVIAv2 on the iOS device you can click on the `Local Data Storage` option. This will show you all the places it stores bad data. 

The list is as follows: 
* Plist
* UserDefaults
* Keychain
* Core Data
* Webkit Caching
* Realm
* Couchbase Lite 
* YapDatabase

For each of these options you should click into them and see what it says. For most you will need to inject some data. For most I have just used a string such as `helloplist` where plist is replaced for each category. This will help to identify what you are seeing and why. Save all of these and then begin hunting! 

<h1>Plist</h1>

Opening up Grapefruit, (cd into install directory and use npm start) we can see our device connected over USB with its apps.

<p align="center"><a href="/images/iOS1-1.png"><img src="/images/iOS1-1.png"></a></p>

Clicking into DVIA-v2 we can see some basic information 

<p align="center"><a href="/images/iOS1-2.png"><img src="/images/iOS1-2.png"></a></p>

We can see a plist file being displayed, but it doesn't have the information we want in it. Looking on the DVIAv2 app, it says our task is to find where this value is stored in the App sandbox. 

We are within the app sandbox with Grapefruit, so lets click on the finder icon on the left hand side. Within this panel we can browse all the files (double click on the folders to expand them).

Clicking on Documents and then opening the `userInfo.plist` file shows us our string! 

<p align="center"><a href="/images/iOS1-3.png"><img src="/images/iOS1-3.png"></a></p>

<h1>UserDefaults</h1>

Staying in Grapefruit, we can see a NsUserDefaults Panel. 

Clicking on the NsUserDefaults panel, we can see the string `DemoValue:"hellouserdefaults"`, which is the one we entered earlier.

<p align="center"><a href="/images/iOS1-4.png"><img src="/images/iOS1-4.png"></a></p>

<h1>Keychain</h1>

We can see the keychain in Grapefruit, however at the time of writing this post it doesn't seem to be giving me the values correctly. 

So opening up Passionfruit (Close DVIA-v2 on your device, then run `passionfruit`) we can now go to Storage > Keychain and see our value in the Keychain that has been dumped! We can also go back and see the other flags in Passionfruit.

<p align="center"><a href="/images/iOS1-5.png"><img src="/images/iOS1-5.png"></a></p>

Passionfruit can be a bit buggy and crashes often, so you may need to switch between the two, or keep closing and re-opening passionfruit when it starts timing out. 

<h1>Core Data</h1>

So looking around the sandbox within Passionfruit, I ended up going to the following directory: 

`Data > Library > Application Support`

<p align="center"><a href="/images/iOS1-6.png"><img src="/images/iOS1-6.png"></a></p>

Click on the file `Model.sqlite` and it should open a SQL viewer. In the top left select the table `ZUSER` and you should see the data you stored for core data, in this case `hellocoredata`!

<p align="center"><a href="/images/iOS1-7.png"><img src="/images/iOS1-7.png"></a></p>

<h1>Webkit Caching</h1>

In Passionfruit we can see:

`Data > Library > Caches` 

This has a couple folders of interest. One is the `WebKit` folder that links to the same name as the challenge. The other is the `com.highaltitudehacks.DVIAswiftv2`.

If we look at `com.highaltitudehacks.DVIAswiftv2` first, we can see a `Cache.db` file inside. Opening it in the SQL browser doesn't show much but does show us tables starting with `cf_url` which DVIA-v2 tells us is the right table. 

<p align="center"><a href="/images/iOS1-8.png"><img src="/images/iOS1-8.png"></a></p>

If we look at `WebKit` we can go into `NetworkCache > Version 16 > Records > GUID > Resource`

The GUID will likely change between devices, but may correlate to DVIA-v2. I am unsure on that. 

You should see several files though. If we click on some of them and open them in the text editor, then hit the `Hex View` button at the top, we can see clearly that what we are seeing is cached web responses for pages that I have never visited and has been stored through the App. 

<p align="center"><a href="/images/iOS1-9.png"><img src="/images/iOS1-9.png"></a></p>

So it seems like we have found the table and the data that we needed to find. We didn't store a string for this challenge so I will assume we are done. If any of these responses had sensitive information such as banking information, then we could see them as well since they were cached through the application. 

It will only save data viewed from within the app. You may need to go to the front page of the iOS app and hit the link there for the DVIA website. This will open the website within the app and will hopefully cache data to show the vulnerability.

<h1>Realm</h1>

In Passionfruit got to: 

`Documents`

In Documents you can see the `default.realm` file. This is the file that should store our realm data. 

I got Realm Browser from the Apple Store, downloaded the file and then opened it with the Realm Browser. It's empty but I can see that every time I enter more data on the app, the number of entries in this table increases. 

<p align="center"><a href="/images/iOS1-10.png"><img src="/images/iOS1-10.png"></a></p>

I don't know why its showing as empty. If I view it within a text editor the values can't be read. I know it's storing here, so I assume I am either on the wrong path or the application is storing it weirdly as it did with the YapDatabase. 

<h1>Couchbase Lite</h1>

In Passionfruit, go to the following directory:

`Data > Library > Application Support > CouchbaseLite > dvcouchbasedb.cblite2`

You should see the `db.sqlite3` file. Let's download that.

<p align="center"><a href="/images/iOS1-11.png"><img src="/images/iOS1-11.png"></a></p>

Now lets open it up in a SQLite browser and locate some data. 

Click on `Browse Data` and then select the `revs` database and we can see the string `hellocouchbase` and the password stored!

<p align="center"><a href="/images/iOS1-12.png"><img src="/images/iOS1-12.png"></a></p>

<h1>YapDatabase</h1>

In Passionfruit, use the file explorer to go to: 

`Data > Library > Application Support`

A file named `YapDatabase.sqlite` can be seen here. If I open this with the sqlite view in Passionfruit it shows me no information.

<p align="center"><a href="/images/iOS1-13.png"><img src="/images/iOS1-13.png"></a></p>

However, you can use the buttons on the right hand side to either view it as text or to download the file and then open it on your computer in a SQL browser. 

I have clicked on the download button and then opened SQLite browser. You can click on the tables and then click on browse data at the top to look for the data. 

<p align="center"><a href="/images/iOS1-14.png"><img src="/images/iOS1-14.png"></a></p>

We can't see the values yet, but we can see that there are blobs stored in the DB. If we click on the blobs we can see text in the right hand side, and can locate our string! 

<p align="center"><a href="/images/iOS1-15.png"><img src="/images/iOS1-15.png"></a></p>

Highlighted is the string `helloyap`. 

<h1>Summary</h1>

Having found the data DVIA wanted us to find, I will move on. The next section on the application is jailbreak detection, so I will likely try that next!