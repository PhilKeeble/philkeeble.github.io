---
layout: single
classes: wide
title: "Getting Started With Hacking - From Beginner to Junior Pentester"
excerpt: "A guide on how to go from no experience to getting your first job within the offensive security field."
categories: 
  - Career
---
<h1>Why Make This?</h1>

Lots of people have asked me lately on LinkedIn about how to get started with hacking. It's an interesting field with a lot of interesting topics and diversity, making it very attractive for people that like to learn and have constant challenge (also the money is a plus). When starting out, it is extremely daunting. There are so many courses and books and different people giving different advise and it is all confusing. I wanted to make this post to give my opinion on how you can go from zero experience to getting a junior job in cybersecurity. 

At the bottom of this post I have put links for all the resources mentioned here. 

<h1>My Story</h1>

I won't go into too much depth here, but I want to give you an idea of where I was and how I moved into cyber security. 

Being a pentester is the first job I got out of University. At University I got my degree in Forensic Science, which was mostly chemistry, and then got my Masters in Forensic Chemistry. This involved nothing to do with hacking and did not contribute to my job. During my time at Uni, I spent many evenings and weekends suffering in hacking labs at home. I did various courses online and I even got my CEH qualification (which I regret very much, I do not recommend it at all! Way better to spend your money on other courses mentioned below). I also set up a blog to detail things I exploited, walkthroughs for challenges etc. It was all basic but useful. I spent a lot of time watching talks from DefCon and other conferences to learn more about the world of hacking and I spent a lot of time playing around with Vulnerable Virtual Machines on my own laptop. I also followed lots and lots of walkthroughs and also had a VIP HackTheBox membership so I could do retired machines with walkthroughs which helped a lot! 

All the time spent was frustrating and confusing, but I remained curious and persistent, and after uni I managed to get a job as a junior Security Consultant and it was a set career from then onwards! I didn't know how to code, I had no formal training, I had no previous experience, I had no-one coaching me, I had no CVEs at the time etc. I hope this lets you know that it is possible, despite what some people and elitist pentesters may say! 

<h1>Myth Busting</h1>

There are lots of common myths within cyber security. The common ones I see are: 

* You need to have studied computer science or something related at Uni.
* You need to be able to code.
* You need to have lots of years experience before going offensive.
* You need to have developer experience or blue team experience. 

I had none of these things when I started my career as a pentester, so I know you do not need these. These are all things that people say but at the end of the day you just need the skills to do the job and an understanding of the fundamentals. 

<h1>Starting Point</h1>

Getting a job in cyber security will take a lot of effort and frustration. I will detail several helpful resources below, but ultimately you need to put the time in above all else. There will be lots of times where you don't understand something and that is ok, you need to just accept it for now and as you do more your understanding will start to form more. 

The best place to start is to get familiar with the common toolset that you will see everyone using in walkthroughs. For hacking this is Kali Linux. It's not necessary, but knowing Kali will make it so much easier to follow guides which you will be doing for some time. This essentially is an Operating System (OS) that gives you all the tools you need. 

To install Kali you will need to get a virtualisation software. I recommend VirtualBox to start with as it is free and works really well. (On macs it may be a bit slow but at this point it's not worth paying for licenses just yet). So download and install VirtualBox, then install Kali Linux. There are several guides online on how to do this. 

Now that kali is installed, you need to learn the basics of using a Linux OS. To do this I recommend playing the Bandit wargame here: 
<a href="https://overthewire.org/wargames/bandit/">https://overthewire.org/wargames/bandit/</a>

This wargame will teach you various Linux utilities and tricks. Follow a walkthrough like the one below for all the levels: 
<a href="https://jhalon.github.io/over-the-wire-bandit1/">https://jhalon.github.io/over-the-wire-bandit1/</a>

I highly recommend keeping your own private GitBook (gitbook.com) to store notes of all the commands you learn and a little sentence about what they do. This will be invaluable later on as you will need to come back and reference things that you have forgotten. 

<h1>The Fun Stuff</h1>

So now you should have the toolkit and you should know the basics of navigating it. Now we can move on to some more interesting stuff.

Hacking can be broken down into some large fields such as Infrastructure (hacking machines), Web Application (hacking websites), Mobile (hacking mobile apps and systems), Cloud (hacking cloud systems and networks) etc. When starting out it's best not to spread yourself too thin. For most junior pentesting positions, they will be looking for basic Infrastructure and Web Application skills, although as Cloud is becoming so relevant, they will probably soon want the basics of that as well. 

You can do these really in any order that interests you, but I think it is best to do both Web Applications and Infrastructure at the same time. This way you can mix things up when things get a bit dry or you want a new challenge. 

<h2>Web Basics</h2>

There are so many places to learn web security now that it is hard to find great ones. However with all the ones I have tried, I will give you what I feel is the best combo. 

Start with Burp Academy here: 
<a href="https://portswigger.net/web-security">https://portswigger.net/web-security</a>

Burp is the number 1 tool for assessing web applications and you will become very familiar with it as a pentester. The Academy is completely free and has amazing guides and labs for all the types of vulnerabilities you will likely find. Some of these are harder to grasp than others (such as HTTP smuggling), but all of them are exceptionally useful and things you will encounter in the real world! Take the time to work through all of the labs here. 

If you get stuck either try and find a walkthrough or go back to the learning section on the Academy. I would also recommend picking up a copy of this book: 
<a target="_blank" href="https://www.amazon.co.uk/gp/product/1118026470/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1118026470&linkCode=as2&tag=philkeeble-21&linkId=4fa4c1857e96dbc38d2c5f14a14cac7c">The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1118026470" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" /> 

This is essentially the bible of Web security. If you get stuck on a Burp lab, read the relating chapter within the book and you will have a much better idea of how to tackle the problem. You could also look at walkthroughs for other labs that have the same vulnerability to see how other people handled it. 

After you have cleared Burp Academy, you will be in a solid position. I would then move on to OWASP Juice Shop: 
<a href="https://owasp.org/www-project-juice-shop/">https://owasp.org/www-project-juice-shop/</a>

This is a real challenge and takes you from beginner level to some pretty advanced attacks. The huge bonus of Juice Shop is that it functions like a modern application that you would be attacking as a pentester, something that very few of these training sites manage. 

There is a detailed guide on OWASP Juice Shop made by the creator which has hints and solutions and descriptions of various challenges. I would also recommend finding walkthroughs online if they exist.

If you complete both Juice Shop and Burp Academy, you are golden for Application Security in my opinion as a beginner. You will have a good range of knowledge and experience with finding and exploiting a good range of vulnerabilities. 

Again keep good notes in your GitBook!! This is all invaluable knowledge that you get from challenges and you will forget it! 

If you are aching for more web challenges then check out the web challenges on <a href="https://www.hackthissite.org">https://www.hackthissite.org</a>, <a href="https://www.enigmagroup.org">https://www.enigmagroup.org</a> and the web applications available on the Metasploitable 2 Virtual Machine.

Another valuable resource is HackerOne's training environment, <a href="https://www.hacker101.com">https://www.hacker101.com</a>. This is meant to get you from zero to finding real world example bugs in applications and is a great way to see real world vulnerabilities and how they manifest in modern applications.

<h2>Infrastructure Basics</h2>

When learning Infrastructure hacking, it can be hard to find good resources. Essentially the easiest and cheapest way is to download Vulnerable Virtual Machines (VMs) and hack them on your own computer. 

You should know the basics as you have installed Kali Linux. Downloading Vulnerable VMs is similar, however most will just be a case of downloaded and booting. Note: when doing this you should put your Kali and the target machine either in its own network, or both on Bridged Mode (In the networking settings of whatever virtualisation software you are using). 

I recommend starting with <a href="https://metasploit.help.rapid7.com/docs/metasploitable-2">https://metasploit.help.rapid7.com/docs/metasploitable-2</a> as the first target machine. This machine is made to show a bunch of different attack paths using Metasploit, which is a hacking framework that can be used to automate lots of tasks. I would recommend also learning how to exploit things manually, as you won't be able to rely on Metasploit as a pentester a lot of the time, but its a fine starting point. 

There are several walkthroughs on different ways you can own Metasploitable 2 so I would follow those. Essentially everything on there is vulnerable to something and you should see how many different paths you can find onto the system. 

It also hosts some vulnerable web applications on port 80 which you can hack and practise your web application skills against. 

After you have done Metasploitable, there are a whole host of other machines to try. There is <a href="https://blog.rapid7.com/2016/11/15/test-your-might-with-the-shiny-new-metasploitable3/">Metasploitable 3</a>, which is a Windows machine. There is also all the machines on:
<a href="http://vulnhub.com/">http://vulnhub.com/</a>

Vulnhub is great for downloading and hacking VMs (called boot to roots typically). The goal is to get onto the target and then to gain administrative or root privileges on it. Usually this is proven by reading a file like `/root/flag.txt` for Linux or `C:\Users\Administrator\Desktop\flag.txt` for Windows. 

Once you have done a selection of these, I recommend trying out some rooms on <a href="https://tryhackme.com/">https://tryhackme.com/</a>. This is a relatively new website on the scene, but for free you can try a bunch of rooms and learn a bunch of community uploaded stuff which is helpful.

If you really want a challenge then try <a href="https://www.hackthebox.eu">https://www.hackthebox.eu</a> (Note: the signup page is in itself a challenge, so if you are new and curious, you may need to look for a walkthrough. Hopefully you have done the above and have no issues with it! &#x1F609;) This is the best for vulnerable VMs in my opinion, however be warned, the active machines will be hard!! Generally for beginners I say to only do HackTheBox if you can first get the VIP membership. Get the VIP Membership for a year and then just work through all the retired machines and follow the videos for all of them made by Ippsec. By the time you have done all the retired machines you will have a great understanding of how it works and you will be in a great place to start doing active machines. 

<h2>Cloud Security</h2>

At the moment, I have never seen a company require cloud hacking skills for a junior position, however I think that will change. I certainly think that if you have it, you will stand out and be in a better position. 

I recommend doing <a href="http://flaws.cloud">http://flaws.cloud</a> first, then <a href="http://flaws2.cloud">http://flaws2.cloud</a> as an attacker and defender. I then recommend doing <a href="https://github.com/RhinoSecurityLabs/cloudgoat">https://github.com/RhinoSecurityLabs/cloudgoat</a> by RhinoSecurity. 

After these you will have an understanding of AWS security, which fundamentally will help you with assessing other cloud providers as well. 

Again I recommend following walkthroughs and taking notes. 

<h1>Courses</h1>

So now if you have done all the above, you should be have a pretty good grasp on the basics across the board for the general skills needed as a junior pentester. However, what you wont have is the fundamental knowledge of computers and networking. 

For understanding the fundamentals (and showing it on your CV), I recommend getting <a href="https://www.comptia.org/certifications/network">CompTIA Network+</a> and then <a href="https://www.comptia.org/certifications/security">CompTIA Security+</a>. This will give you the fundamental knowledge and will show an employer that you understand how things piece together. 

Generally the only Udemy course I recommend are the ones by TheCyberMentor. They are good and include practical challenges. I would heavily advise against using any others, all the others I have seen on there are terrible quality in the content they teach and not useful at all for getting a job. 

If you can afford it, then check out eLearnSecurity's PenTest Student (PTS) Course <a href="https://www.elearnsecurity.com/course/penetration_testing_student/">here</a>. This is a great way to go to get your first practical certification in hacking which will give you more of an edge on your CV. 

If you have done all the above and PTS, then check out <a href="https://www.offensive-security.com/pwk-oscp/">OSCP by Offensive Security</a> and do that. It will be intense, but with persistance you will make it through. OSCP is the number 1 certification to have for your CV for pentesting. It will definitely get you a Junior pentest position. However, it is not necessary (I don't have it), so don't use it as an excuse to say that you need to spend a lot of money to become a pentester and you can't afford it. 

<h1>Books</h1>

There are several helpful books for hacking, but finding good ones can be hard.

* The Hackers Playbook 2 and 3 are good resources that walk you through Infrastructure testing and a basic example of Red Teaming. This is handy context to know. 
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1512214566/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1512214566&linkCode=as2&tag=philkeeble-21&linkId=dd5c042124b769c902d31545f2043875">The Hacker Playbook 2: Practical Guide To Penetration Testing</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1512214566" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1980901759/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1980901759&linkCode=as2&tag=philkeeble-21&linkId=639ba5e38f27cb7ecb20b26e9cad4433">The Hacker Playbook 3: Practical Guide To Penetration Testing</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1980901759" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* The Web Application Hackers Handbook is another great resource already spoken about. 
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1118026470/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1118026470&linkCode=as2&tag=philkeeble-21&linkId=4fa4c1857e96dbc38d2c5f14a14cac7c">The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1118026470" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Advanced Penetration Testing is also really good for more red team focused work and understanding how that comes together.
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1119367689/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1119367689&linkCode=as2&tag=philkeeble-21&linkId=f9553cb34000d91b3dc01cf3b6093c42">Advanced Penetration Testing: Hacking the World's Most Secure Networks</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1119367689" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Hacking; The Art of Exploitation is great for learning the basics of binary exploitation and understanding how code brings in vulnerabilties in software. Don't pick this up first as it is very in depth.
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1593271441/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1593271441&linkCode=as2&tag=philkeeble-21&linkId=8dc4b012a07da07ae7a6c4f06e307402">Hacking: The Art of Exploitation</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1593271441" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Kevin Mitnicks books are good stories about hacking but won't contain the technical knowledge to perform the techniques. Interesting reads though. 
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0316212180/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0316212180&linkCode=as2&tag=philkeeble-21&linkId=c498e4c66d62967cf08cbde5f71043ee">Ghost In The Wires: My Adventures as the World's Most Wanted Hacker</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0316212180" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0471782661/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0471782661&linkCode=as2&tag=philkeeble-21&linkId=69b7aa99b5bb193ecbfe7db90e27bc88">The Art of Intrusion: The Real Stories Behind the Exploits of Hackers, Intruders and Deceivers</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0471782661" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/076454280X/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=076454280X&linkCode=as2&tag=philkeeble-21&linkId=eb24c597727f1887d70b0a5902847344">The Art of Deception: Controlling the Human Element of Security</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=076454280X" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0316554545/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0316554545&linkCode=as2&tag=philkeeble-21&linkId=572e6a94e30a17ebfc19102091577d89">The Art of Invisibility: The World's Most Famous Hacker Teaches You How to Be Safe in the Age of Big Brother and Big Data</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0316554545" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Christopher Hagnady Books on Social Engineering are exceptional and very helpful for anyone looking to go into a role including red teaming. 
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0470639539/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0470639539&linkCode=as2&tag=philkeeble-21&linkId=f9db3eb891eebf647884c4ce7a356b83">Social Engineering</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0470639539" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/111943338X/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=111943338X&linkCode=as2&tag=philkeeble-21&linkId=732377828318b04218064f024eec32c4">Social Engineering: The Science of Human Hacking, 2nd Edition</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=111943338X" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1118608577/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1118608577&linkCode=as2&tag=philkeeble-21&linkId=a189a887feaf8b152b6272ca25237ecb">Unmasking the Social Engineer: The Human Element of Security</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1118608577" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1118958470/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1118958470&linkCode=as2&tag=philkeeble-21&linkId=ae240beb30ab1c998aa096b2572cf0f2">Phishing Dark Waters: The Offensive and Defensive Sides of Malicious Emails</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1118958470" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Network Security Assessment 3rd Edition is very dry but very good for understanding networks and how it fits together.
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/149191095X/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=149191095X&linkCode=as2&tag=philkeeble-21&linkId=46b87670eefbc8ba5c7684f2251685d2">Network Security Assessment: Know Your Network</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=149191095X" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Real-World Bug Hunting is a good book for understanding some basic web app concepts and how bugs are found. 
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1593278616/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1593278616&linkCode=as2&tag=philkeeble-21&linkId=a9be0c5cc3a06de95c6fd542e97f943c">Real-World Web Hacking: A Field Guide to Bug Hunting</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1593278616" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />

<h1>Getting the Job</h1>

At this point you should have a good direction on where to go to get the skills you need. Realistically, this is only half the battle. The other half is actually showing to employers that you know this stuff. 

I heavily recommend a blog. You can host a blog for free like this one on GitPages. It doesn't have to be fancy, but it does have to look professional and have a decent format. On the blog upload walkthroughs of challenges you have solved, upload tutorials on different basic techniques, upload things that you got stuck on and solved for the next beginner. 

It doesn't matter about traffic you get or anything, it's just something the employer can look at to see what you know, how you write, how well you can explain the concepts and how well you know it. 

I would also recommend working a lot on your CV, as that will be the first thing employers see. You want to show them that you have passion for it and that you have done all this in your free time. They will appreciate that if they are technical. This combined with a blog to show off skills and you should be in a good place. I don't want to go into a lot of depth on CVs as I am certainly not a pro on it, but I would recommend putting the things you really want them to focus on (such as home labs and things you have done in free time) at the top of the CV. All the other stuff that is irrelevant should either not be there or at the bottom. 

It's important to remember that if a pentester is reviewing your CV, then they won't have much time. Pentesting is a very busy job no matter where you work and they won't spend long looking at your CV. You need to make the important stuff easy to find and at the start to ensure that it gets through and is seen. 

I would also recommend dedicating time to looking up CV advise online and working on it. This should be treated as if its your best piece of work. A report you are handing to a client for example. Reports are all pentesters have to show clients that they did something worth paying for, so they need to be damn good. Showing you can write clearly is very important. 

If you have done all of this then you should be in a really good place to get a job as a junior and shouldn't have much issue. It may take time to get your first job and that is ok. Once you have it you will be set for your career, just keep learning and growing. 

<h1>Resources</h1>

<h2>Linux</h2>

* Kali Linux: <a href="https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/#1572305786534-030ce714-cc3b">Download Page</a>
* VirtualBox: <a href="https://www.virtualbox.org">Download</a>
* OverTheWire Bandit Wargame: <a href="https://overthewire.org/wargames/bandit/">https://overthewire.org/wargames/bandit/</a>

<h2>Web</h2>

* BurpAcademy: <a href="https://portswigger.net/web-security">https://portswigger.net/web-security</a>
* OWASP Juice Shop: <a href="https://owasp.org/www-project-juice-shop/">https://owasp.org/www-project-juice-shop/</a>
* Juice Shop Book: <a href="https://bkimminich.gitbooks.io/pwning-owasp-juice-shop/content/">https://bkimminich.gitbooks.io/pwning-owasp-juice-shop/content/</a>
* Hacker101: <a href="https://www.hacker101.com">https://www.hacker101.com</a>
* Web Application Hackers Handbook: <a target="_blank" href="https://www.amazon.co.uk/gp/product/1118026470/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1118026470&linkCode=as2&tag=philkeeble-21&linkId=4fa4c1857e96dbc38d2c5f14a14cac7c">The Web Application Hacker's Handbook: * Finding and Exploiting Security Flaws</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1118026470" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Hackthissite: <a href="https://www.hackthissite.org">https://www.hackthissite.org</a>
* Enigmagroup: <a href="https://www.enigmagroup.org">https://www.enigmagroup.org</a>

<h2>Infrastructure</h2>

* Metasploitable 2: <a href="https://metasploit.help.rapid7.com/docs/metasploitable-2">https://metasploit.help.rapid7.com/docs/metasploitable-2</a>
* Metasploitable 3: <a href="https://blog.rapid7.com/2016/11/15/test-your-might-with-the-shiny-new-metasploitable3/">https://blog.rapid7.com/2016/11/15/test-your-might-with-the-shiny-new-metasploitable3/</a>
* Vulnhub: <a href="https://www.vulnhub.com">https://www.vulnhub.com</a>
* HackTheBox: <a href="https://www.hackthebox.eu">https://www.hackthebox.eu</a> (Note: the signup is a challenge, you may need a walkthrough if new to it.)
* TryHackMe: <a href="https://tryhackme.com/">https://tryhackme.com/</a>

<h2>Cloud</h2>

* Flaws: <a href="http://flaws.cloud">http://flaws.cloud</a>
* Flaws2: <a href="http://flaws2.cloud">http://flaws2.cloud</a>
* CloudGoat: <a href="https://github.com/RhinoSecurityLabs/cloudgoat">https://github.com/RhinoSecurityLabs/cloudgoat</a>

<h2>Courses</h2>

* CompTIA Network+: <a href="https://www.comptia.org/certifications/network">CompTIA Network+</a>
* CompTIA Security+: <a href="https://www.comptia.org/certifications/security">CompTIA Security+</a>
* eLearnSecurity PTS: <a href="https://www.elearnsecurity.com/course/penetration_testing_student/">https://www.elearnsecurity.com/course/penetration_testing_student/</a>
* Offensive Security OSCP: <a href="https://www.offensive-security.com/pwk-oscp/">https://www.offensive-security.com/pwk-oscp/</a> 

<h2>Books</h2>

* The Hackers Playbook 2: <a target="_blank" href="https://www.amazon.co.uk/gp/product/1512214566/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1512214566&linkCode=as2&tag=philkeeble-21&linkId=dd5c042124b769c902d31545f2043875">The Hacker Playbook 2: Practical Guide To Penetration Testing</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1512214566" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* The Hackers Playbook 3: <a target="_blank" href="https://www.amazon.co.uk/gp/product/1980901759/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1980901759&linkCode=as2&tag=philkeeble-21&linkId=639ba5e38f27cb7ecb20b26e9cad4433">The Hacker Playbook 3: Practical Guide To Penetration Testing</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1980901759" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Advanced Penetration Testing: <a target="_blank" href="https://www.amazon.co.uk/gp/product/1119367689/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1119367689&linkCode=as2&tag=philkeeble-21&linkId=f9553cb34000d91b3dc01cf3b6093c42">Advanced Penetration Testing: Hacking the World's Most Secure Networks</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1119367689" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Hacking - The Art of Exploitation: <a target="_blank" href="https://www.amazon.co.uk/gp/product/1593271441/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1593271441&linkCode=as2&tag=philkeeble-21&linkId=8dc4b012a07da07ae7a6c4f06e307402">Hacking: The Art of Exploitation</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1593271441" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Kevin Mitnicks books:
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0316212180/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0316212180&linkCode=as2&tag=philkeeble-21&linkId=c498e4c66d62967cf08cbde5f71043ee">Ghost In The Wires: My Adventures as the World's Most Wanted Hacker</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0316212180" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0471782661/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0471782661&linkCode=as2&tag=philkeeble-21&linkId=69b7aa99b5bb193ecbfe7db90e27bc88">The Art of Intrusion: The Real Stories Behind the Exploits of Hackers, Intruders and Deceivers</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0471782661" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/076454280X/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=076454280X&linkCode=as2&tag=philkeeble-21&linkId=eb24c597727f1887d70b0a5902847344">The Art of Deception: Controlling the Human Element of Security</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=076454280X" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0316554545/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0316554545&linkCode=as2&tag=philkeeble-21&linkId=572e6a94e30a17ebfc19102091577d89">The Art of Invisibility: The World's Most Famous Hacker Teaches You How to Be Safe in the Age of Big Brother and Big Data</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0316554545" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Christopher Hadnagy Books on Social Engineering:
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/0470639539/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=0470639539&linkCode=as2&tag=philkeeble-21&linkId=f9db3eb891eebf647884c4ce7a356b83">Social Engineering</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=0470639539" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/111943338X/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=111943338X&linkCode=as2&tag=philkeeble-21&linkId=732377828318b04218064f024eec32c4">Social Engineering: The Science of Human Hacking, 2nd Edition</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=111943338X" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1118608577/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1118608577&linkCode=as2&tag=philkeeble-21&linkId=a189a887feaf8b152b6272ca25237ecb">Unmasking the Social Engineer: The Human Element of Security</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1118608577" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
    - <a target="_blank" href="https://www.amazon.co.uk/gp/product/1118958470/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1118958470&linkCode=as2&tag=philkeeble-21&linkId=ae240beb30ab1c998aa096b2572cf0f2">Phishing Dark Waters: The Offensive and Defensive Sides of Malicious Emails</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1118958470" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Network Security Assessment 3rd Edition: <a target="_blank" href="https://www.amazon.co.uk/gp/product/149191095X/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=149191095X&linkCode=as2&tag=philkeeble-21&linkId=46b87670eefbc8ba5c7684f2251685d2">Network Security Assessment: Know Your Network</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=149191095X" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />
* Real-World Bug Hunting: <a target="_blank" href="https://www.amazon.co.uk/gp/product/1593278616/ref=as_li_tl?ie=UTF8&camp=1634&creative=6738&creativeASIN=1593278616&linkCode=as2&tag=philkeeble-21&linkId=a9be0c5cc3a06de95c6fd542e97f943c">Real-World Web Hacking: A Field Guide to Bug Hunting</a><img src="//ir-uk.amazon-adsystem.com/e/ir?t=philkeeble-21&l=am2&o=2&a=1593278616" width="1" height="1" border="0" alt="" style="border:none !important; margin:0px !important;" />