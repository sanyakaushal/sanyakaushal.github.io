---
title: Dynamic Analysis - Sample 1
date: 2023-02-20 20:47:56+/-TTTT  
categories: [Malware Analysis and Detection Engineering Labs]
tags: [malware analysis, dynamic analysis, static analysis, tools, write-up]     # TAG names should always be lowercase
---
> Click on the images below to expand and view them in larger size. 
{: .prompt-tip }
<span style="font-size: smaller;">*The following exercise is from Chapter 13 of the book "Malware Analysis and Detection Engineering" by Abhijit Mohanta and Anoop Saldanha.*</span>

## Static Analysis

```
MD5 - 47da511c59512062e7dbdb2bb66a9fde
SHA1 - dcf5a684cc8b5095b6b9a7237b8ff7c751fe0017
SHA256 - B02352D9777D7AA82C69F0F9A16A61D8E9EE00BC383C6781E3B6DEB59CC72BCA
VirusTotal - 57/70 detections
```
![screenshot 1](https://github.com/sanyakaushal/images/blob/main/sa1-1.PNG?raw=true){: .left w="200" h="200" } 
<br>
triDNET identified this sample as a ``Win32 Executable`` supported by ``MS Visual C++``. 
<br>
![screenshot 2](https://github.com/sanyakaushal/images/blob/main/sa1-2.PNG?raw=true){: .left w="200" h="200" } 
<br>
PEid indicated that the file is packed with ``7.38`` rating in entropy.
<br>
![screenshot 3](https://github.com/sanyakaushal/images/blob/main/sa1-3.PNG?raw=true){: .left w="200" h="200" } 
<br>
File properties revealed that there is no Digital Signature tab, indicating that the file is not signed. 

![screenshot 4](https://github.com/sanyakaushal/images/blob/main/sa1-one.PNG?raw=true) _Thumbnail Faking_
Furthermore, the file is engaging in *thumbnail faking*, displaying a thumbnail of a Word document while being an executable. 
![screenshot 5](https://github.com/sanyakaushal/images/blob/main/sa1-4.PNG?raw=true) _Fig.5: BinText_
BinText analysis revealed that the majority of the strings are obfuscated. However, the highlighted portions contain functions and APIs that malware can utilize, such as ``CreateMuxtexA`` and
``GetModuleHandlew``, which can be used for API hooking and process hallowing. Additionally, the presence of ``LoadLibraryW`` suggests the potential for *DLL injection*. 
Based on these findings, it is challenging to determine the specific type of malware solely from this information. Dynamic analysis is required to gain further insight. 

## Running the sample
![screenshot 6](https://github.com/sanyakaushal/images/blob/main/sa1-5.PNG?raw=true){: w="400" h="300" } _Windows Explorer Pop-up_
![screenshot 7](https://github.com/sanyakaushal/images/blob/main/sa1-6.PNG?raw=true) _Autoruns_
![screenshot 8](https://github.com/sanyakaushal/images/blob/main/sa1-7.PNG?raw=true){: w="400" h="300" } _Newly created file_
When running the sample, a pop-up message appears indicating that Windows cannot open the file.
Autoruns reveals the addition of a new Rule Key, with its value being the path to the newly created malware file in the Local folder. This entry ensures persistence by running the malware at logon. 
![screenshot 9](https://github.com/sanyakaushal/images/blob/main/sa1-8.PNG?raw=true) _HashMyFiles_
Comparing the hash of the sample file with the newly created file confirms that they are the same.
![screenshot 10](https://github.com/sanyakaushal/images/blob/main/sa1-9.PNG?raw=true) _Process Hacker_
Process Hacker detected a suspiocus svchost.exe process without a parent, originating from the user account - ``IE8WIN7/IEUSER``.
## Analyzing with API miner
![screenshot 11](https://github.com/sanyakaushal/images/blob/main/sa1-10.PNG?raw=true) _APIminer traces-1_
The sequence reveals the utilization of *process hallowing*. It begins with the creation of a suspended ``svchost.exe`` process, denoted by the [creation_flag] value of 4.
Next, ``NtReadVirtualMemory`` API is employed to read memory from the remote process, and followed by the usage of the ``NtMapViewOfSection`` API to create a section and map a view of it into the remote process.
Finally, the ``NtResumeThread`` API is invoked to resume the suspended thread.
![screenshot 12](https://github.com/sanyakaushal/images/blob/main/sa1-11.PNG?raw=true) _APIminer traces-2_
This section indicates the occurrence of process injection.
![screenshot 13](https://github.com/sanyakaushal/images/blob/main/sa1-12.PNG?raw=true) _APIminer traces-3_
These network APIs suggest the possible establishment of connections with CnC servers.
## Malware family classification 
![screenshot 14](https://github.com/sanyakaushal/images/blob/main/sa1-13.PNG?raw=true) _Mutant name:2GVWNQJz1_
In addition to the logs mentioned above, a Win32 API related to this mutant was detected with the name ``2GVWNQJz1``. 
A Google search reveals its association with [``KULUOZ``](https://antimalwarelab.blogspot.com/2014/04/dissecting-kuluoz.html), a Trojan botnet commmonly distributed through spam emails. This finding provides an explanation for the network APIs observed earlier. 
## Dynamic String Analysis
![screenshot 15](https://github.com/sanyakaushal/images/blob/main/sa1-14.PNG?raw=true){: .left w="200" h="200" } 
![screenshot 16](https://github.com/sanyakaushal/images/blob/main/sa1-15.PNG?raw=true){: .normal w="200" h="300" } 
![screenshot 17](https://github.com/sanyakaushal/images/blob/main/sa1-16.PNG?raw=true){: .right w="200" h="300" } 
<br><br><br><br><br>
Reviewing the strings in Process Hacker shows some of the APIs we saw in BinText and through API Miner logs.
We also notice a list of applications like *Wireshark, IPTools, ProcessHacker* and others, that the malware searches for in the environment, likely for anti-analysis purposes, which explains the observed pop-up.

Furthermore, we come across strings like ``“YOU FAG!!!”`` and numerous IP addresses belonging to various countries. 
In a [blog](https://antimalwarelab.blogspot.com/2014/04/dissecting-kuluoz.html)   dissecting the ``KULUOZ`` malware, it was explained that each time the malware initiates a network request to a CnC sever, it compares the enumerated and decrypted key values found in ``HKEY_CURRENT_USER/Software`` to the string *'YOU FAG!!!!!!"*. If they match, the data following the *'YOU FAG'* string is translated as an  ``in_addr`` struct. 
## Analyzing with ProcMon
![screenshot 18](https://github.com/sanyakaushal/images/blob/main/sa1-17.PNG?raw=true) _Mutant name:2GVWNQJz1_
We observe in this samoke that it creates a ``svchost.exe`` process, and the ``QuerySecurityFile`` function indicates that it is the Owner. 
![screenshot 19](https://github.com/sanyakaushal/images/blob/main/sa1-18.PNG?raw=true) _Mutant name:2GVWNQJz1_
The ``Svchost`` host is then observed creating a copy of the sample in the ``Local`` folder. 