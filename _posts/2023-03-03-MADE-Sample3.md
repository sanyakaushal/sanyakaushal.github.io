---
title: Dynamic Analysis - Sample 3
date: 2023-03-03 20:47:56+/-TTTT  
categories: [Malware Analysis and Detection Engineering Labs]
tags: [malware analysis, dynamic analysis, static analysis, tools, write-up]     # TAG names should always be lowercase
---
> Click on the images below to expand and view them in larger size. 
{: .prompt-tip }
<span style="font-size: smaller;">*The following exercise is from Chapter 13 of the book "Malware Analysis and Detection Engineering" by Abhijit Mohanta and Anoop Saldanha.*</span>

## Static Analysis

```
MD5 - 51f032aaf7579439c4c4c555310d468c
SHA1 - 17adda042d375f132e0cc1d0b5204d313662357f
SHA256 - 34d768b9953b4a2ea55f2b11bafbbac12a3a4639d8de97ee062c1be1c2a332ac
VirusTotal - 46/73 detections
```
![screenshot 1](https://github.com/sanyakaushal/images/blob/main/sa3-2.PNG?raw=true){: .left w="200" h="200" } 
<br>
triDNET identified this sample as a CIL Executable. 
<br>
![screenshot 2](https://github.com/sanyakaushal/images/blob/main/sa3-3.PNG?raw=true){: .left w="200" h="200" } 
<br>
PEid indicated that the file is packed with *7.62* rating in entropy.
<br>
![screenshot 3](https://github.com/sanyakaushal/images/blob/main/sa3-4.PNG?raw=true){: .left w="200" h="200" } 
<br>
File properties revealed that the file is copyrighted by
*tjsDecDiilmP PzzBzbmMm*, which does not appear reputable.

![screenshot 4](https://github.com/sanyakaushal/images/blob/main/sa3-5.PNG?raw=true)_BinText_
BinText reveals mostly obfuscated strings, and the readable ones correspond to functions or APIs. However, these do not provide much information about the nature of the file.

## Running the sample
![screenshot 5](https://github.com/sanyakaushal/images/blob/main/sa3-6.PNG?raw=true)_Process Hacker_

Executing the sample resulted in the creation of a new process named ``coherence.exe``, described as ``qeNCVcE``. However, no online results were found for this description. 
Autoruns did not reveal any new additions.

## Analyzing with API miner
![screenshot 6](https://github.com/sanyakaushal/images/blob/main/sa3-7.PNG?raw=true)_APIminer traces_
Microsoft Windows provides the ``EncodePointer()`` and ``DecodePointer()`` functions, which encrypt and decrypt pointers using a process-specific secret. 
These can be used by malwares for anti-debugging purposes.

## Malware family classification 
It's difficult to classify the malware solelt by examining the API logs for this sample due to the encoding of pointers. 
We would have to look at strings dynamically to gain further insight. 

## Dynamic String Analysis
![screenshot 7](https://github.com/sanyakaushal/images/blob/main/sa3-9.PNG?raw=true){: .left w="450" h="450"} 
![screenshot 8](https://github.com/sanyakaushal/images/blob/main/sa3-10.PNG?raw=true){: .right w="300" h="300" }

APIs and functions that were not visible in APIminer logs because of encryption, became apparent here. <br>
Presence of strings like ``username`` and ``password``, along with protocols like ``IMAP`` and ``SMTP``, suggests that this malware might be attempting to steal passwords and gather information from user accounts. 

![screenshot 9](https://github.com/sanyakaushal/images/blob/main/sa3-11.PNG?raw=true)

Searching the highlighted strings on Google revealed that the malware belongs to the [``Pony Loader``](https://www.acunetix.com/blog/articles/pony-malware-credential-theft/) family. 

## Analyzing with ProcMon
![screenshot 10](https://github.com/sanyakaushal/images/blob/main/sa3-12.PNG?raw=true)

We observe that the sample creates a file named ``coherence.exe`` and copies both itself and the contents of the ``$Directory``. Dynamic string analysis using *Process Hacker* reveals that the files from the ``Downloads`` directory are involved, providing an explanation for their presence. 
It seems that the sample is traversing through all directories and copying its data into ``coherence.exe``.