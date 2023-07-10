---
title: Dynamic Analysis - Sample 2
date: 2023-03-02 20:47:56+/-TTTT  
categories: [Malware Analysis and Detection Engineering Labs]
tags: [malware analysis, dynamic analysis, static analysis, tools, write-up]     # TAG names should always be lowercase
---
> Click on the images below to expand and view them in larger size. 
{: .prompt-tip }
<span style="font-size: smaller;">*The following exercise is from Chapter 13 of the book "Malware Analysis and Detection Engineering" by Abhijit Mohanta and Anoop Saldanha.*</span>

## Static Analysis
```
MD5 - a048795fdaf5b6d844960e1c45c3a442
SHA1 - 8a0e147897b62398a6e9bcabcfa87a088ee76a3b
SHA256 - 40c5ec744bcf776a3e885a2a88e49ff092155211e8e08ea9576fc98f781f6fc5
VirusTotal - 60/71 detections
```
![screenshot 1](https://github.com/sanyakaushal/images/blob/main/sa2-2.PNG?raw=true){: .left w="200" h="200" } 
<br>
triDNET identified this sample as a ``Win32 Executable``. 
<br>
![screenshot 2](https://github.com/sanyakaushal/images/blob/main/sa2-3.PNG?raw=true){: .left w="200" h="200" } 
<br>
PEid indicated that the file is packed with ``7.89`` rating in entropy.
<br>
![screenshot 3](https://github.com/sanyakaushal/images/blob/main/sa2-4.PNG?raw=true){: .left w="200" h="200" } 
<br>
File properties revealed that there is no Digital Signature tab, indicating that the file is not signed. 

![screenshot 4](https://github.com/sanyakaushal/images/blob/main/sa2-5.PNG?raw=true) _BinText_
BinText analysis indicated that the strings within the file were mostly obfuscated. However, the presence of ``LoadLibraryA`` and ``GetProcAddress``
suggests that *DLL injection* could be taking place.

## Running the sample
![screenshot 5](https://github.com/sanyakaushal/images/blob/main/sa2-6.PNG?raw=true) _Before and after execution_
We observe that the file is thumbnail faking, pretending to be an image. When we run the sample as an admin, we notice it get deleted by itself.  
![screenshot 6](https://github.com/sanyakaushal/images/blob/main/sa2-7.PNG?raw=true) _Autoruns_
Autoruns reveals that a new *Run Key* has been added, with its value being the path to the newly created malware file ``SVOHOST.exe``, serving the purpose of persistence.
![screenshot 7](https://github.com/sanyakaushal/images/blob/main/sa2-8.PNG?raw=true) _Process Hacker_
In Process Hacker, we see a new process ``SVOHOST.exe``. It is engaged in thumbnail faking and has no parent. This is highly suspicious.

## Analyzing with API miner
![screenshot 8](https://github.com/sanyakaushal/images/blob/main/sa2-9.PNG?raw=true) _APIminer traces - 1_
![screenshot 9](https://github.com/sanyakaushal/images/blob/main/sa2-10.PNG?raw=true) _APIminer traces - 2_
Highlighted APIs at different points indicate the usage of *API hooking*. For instance, APIs such as ``FindFirstFileA`` and ``DeleteFileA`` have been hooked to enable file deletion, as observed during the execution of the file. 
![screenshot 10](https://github.com/sanyakaushal/images/blob/main/sa2-11.PNG?raw=true) _APIminer traces - 3_
Additionally, ``NtAllocateVirtualMemory`` API represents the NT API version invoked by ``VirtualAllocEx``. This implies that the malware is allocating virtual memory with the Windows NT environment using this API. 
## Malware family classification 
![screenshot 11](https://github.com/sanyakaushal/images/blob/main/sa2-12.PNG?raw=true) 
![screenshot 12](https://github.com/sanyakaushal/images/blob/main/sa2-13.PNG?raw=true) 
In addition to the APIs and functions mentioned earlier, the highlighted functions from the ``user32.dll`` are commonly associated with *password stealer malware*.

## Dynamic String Analysis
![screenshot 13](https://github.com/sanyakaushal/images/blob/main/sa2-14.PNG?raw=true){: .left w="450" h="450"} 
![screenshot 14](https://github.com/sanyakaushal/images/blob/main/sa2-15.PNG?raw=true){: .right w="300" h="300" }


The software ``software\borland\delphi\rtl`` appears to be commonly associated with malwares.
However, the specific email, ``lijieliang1990@163.com`` did yield any results. Additonally, ``63`` is a Chinese domain and has no hits on VirusTotal.<br>
Despite my inability to de-obfuscate the string ``ujj25whrs*400$...``, considering the surrounding strings, I assume its related to
establishing a ``SMTP`` connection. 
We have information from *APIminer* logs that confirms this as a password stealer, indicating that it is used for exfiltration. 
<br>

## Analyzing with ProcMon
![screenshot 15](https://github.com/sanyakaushal/images/blob/main/sa2-16.PNG?raw=true)_ProcMon_
We observe that the sample creates a new file in ``Windows\System32`` named ``SVOHOST.exe``, resembling the name ``svchost.exe``.
Furthermore, We notice it copying its content into the OS system folder, which raises high suspicious.

