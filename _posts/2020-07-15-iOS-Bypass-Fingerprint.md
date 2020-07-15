---
layout: single
classes: wide
title: "Bypassing Biometrics - DVIAv2 Part 5"
excerpt: "A guide on how to manipulate iOS applications to bypass biometric authentication."
categories: 
  - iOS
---
<h1>Intro</h1>

To some, biometrics are seen as the pinnacle of authentication. After all, the chances of someone else having the same fingerprint as us is so slim that it has never happened (that we know of). Due to this, many people feel more secure with an application asking for a fingerprint rather than a code, as it's more secure. However, this decision assumes that the implementation of both are equally secure. 

To bypass biometrics, we may not need to actually be able to have the same fingerprint / face as the target. We could just abuse the mechanism that checks the fingerprint. If it is insecurely implemented, then we can bypass the check. 

You will see with this bypass that the iPhone correctly says that the fingerprint is wrong, but after we hook it the application will show us the success anyway, because the application thinks the fingerprint was a success when it failed. The actual function that handles the fingerprint reading is not included in the application and is a native function on the device. Our aim is to hook the response that the native fingerprint read function gives the application and altering it's value so that the application thinks we succeeded. 

<h1>Easy Win</h1>

If you open DVIA-v2 and go into the panel, you will see a section labelled `Touch/Face ID Bypass`. Clicking on that takes us to a challenge with two fingerprint readers. The first is written in Swift, the second is written in Objective-C. This allows us to work on a method for them both.

Thanks to Objection, there is a very easy way to solve these challenges. First, load up Objection into DVIA-v2.

```
objection --gadget DVIA-v2 explore
```

Now use the pre-built Objection script for fingerprint bypasses.

```
ios ui biometrics_bypass 
```

Now click on the fingerprint on the screen for Swift or Objective-C. It will prompt you to put your fingerprint in. Put the wrong finger on the fingerprint sensor (you need to have it set up on your device before you do this. If you don't then go set it in your settings). With the wrong fingerprint it should say that it was wrong and tell you to try again. Just his the `cancel` button instead of trying again. Now you will see a new popup from within the application telling us the the fingerprint was successful! 

This works for both Swift and Objective-C functions without any modification! 

<h1>Explanation</h1>

In the Objection wiki, a post was put up to explain what this does. The post can be found <a href="https://github.com/sensepost/objection/wiki/Understanding-the-iOS-Biometrics-Bypass">here</a>. 

In summary, the class `LAContext` is responsible for local authentication. It does not do any external checks and relies on iOS to present the relevant dialogue and confirmation. 

The `evaluatePolicy` method within the `LAContext` class gives iOS a chance to present the relevant dialog (fingerprint, face scan, login password, passcode) and authenticate the user. Depending on the results of the check, a `reply` block is invoked from the method and is sent back to the application. This contains a boolean value dictating whether it was successful or not. 

When `ios ui biometrics_bypass` is executed in Objection, it creates a hook on `-[LAContext evaluatePolicy:localizedReason:reply:]`. In this it can be seen it's the `LAContext` class, `evaluatePolicy` method and `reply` block. It will change it from false to true, meaning it was a success. 

This won't work in cases where further checks are needed. In those cases you could use this to bypass the first part, then you would need to manually hook the subsequent checks. This would also not work if it validated remotely as its a local authentication mechanism. This also won't work in cases where keychain items are protected with access control flags such as `kSecAccessControlTouchIDAny` or `kSecAccessControlTouchIDCurrentSet`. 

Interestingly if I try it manually using the command below, it will fail and will not bypass the check.

```
ios hooking set return_value "-[LAContext evaluatePolicy:localizedReason:reply:]" true
```

This leads me to believe it is doing more under the hood than meets the eye, but I can't find the relevant piece of source code for it. At some point I will come back and do this all manually to figure it out, but for now I will leave it here and continue on with the challenges since we do have a solution for these ones that seems reliable. 
