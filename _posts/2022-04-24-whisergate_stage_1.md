---
layout: post
title: "Whispergate Stage 1"
date: 2022-04-24 02:10:00 -0000
tags: Malware Russia Ukraine MBR
---

While the kinetic war between Russia and Ukraine began in earnest on the 24th of Febuary of this year, the cyberwar between the two countries began long before that point.
Indeed one could argue that it started as early as 2013, just prior to the annexation of Crimea and that it was continued unabated ever since, albeit with varying degrees of intensity. 
On the 13th January of this year just after the failed NATO-Russia talks regarding the future status of Ukraine a number of cyberattacks were launched against numerous targets within Ukraine.
While these attacks where supplemented by targeted defacements of 70 Ukrainian government websites the most worrying aspect of the attacks was the use of a novel strain of destructive malware dubbed by the Microsoft Threat Intelligence Centre (MTIC), the team who first discovered it, with the moniker WhisperGate.<sup>[1]</sup>

WhisperGate was assessed by the MTIC to be a 2 stage piece of malware.

The first stage being a MBR wiper & pseudo-ransomware executable and is the subject of this article.
MBR wipers are paces of malware designed to effectively destroy the operating system present on a computer by corrupting the master boot record (MBR) on the systems primary hard drive.
On systems the employ a MBR, it contains critical data and executable code used by the system to start the operating system.
Without a functional MBR it is impossible to start the system.
The stage 1 binary was observed to overwrite the MBR with the following fake ransom message:
```
Your hard drive has been corrupted.
In case you want to recover all hard drives
of your organization,
You should pay us $10k via bitcoin wallet
1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv and send message via
tox ID 8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C057ECED5496F65
with your organization name.
We will contact you to give further instructions.
```

This ransom warning is completely empty, the malware makes no back up and simply overwrites the MBR with this message.
The malware authors could not restore the contents of the MBR even if they wanted to.

The second stage was observed to be a dropper for a file corrupter should the first stage fail.
We will explore it's functionality and internals in a follow up post to this.

# Technical Analysis

The sample of WhisperGate stage 1 used in this analysis was sourced form "The Malware Bazzar" hosted by abuse.ch a research project at the Bern University of Applied Sciences which makes malware samples publicly available for security researchers to investigate.<sup>[2]</sup>
The SHA256 sum of the file was computed and was verified to match the hash of the sample used by the US CISA in their analysis of the WhisperGate malware<sup>[3]</sup>

```bash
$ sha256sum ./whispergate.bin 
a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92  ./whispergate.bin
```

Having established that we are dealing with the correct binary we proceeded to load it into Ghidra for analysis.
The examining each of the functions detected by Ghidra in tern we see that majority of the functionality of the malware is contained within its main function. 

The malware begins by copying a large number of copies of the ransom message into a 2050 byte buffer.

![Ransom message Messaged Copied](/images/decompilation1.png)

Following this WhisperGate performs a call to CreateFileW, specifying `PhysicalDrive0` as the target.

![Opening a handle to disk 0](/images/decompilation2.png)

Parsing this into a more readable this can be seen to be equivalent to the following function call:

```C++
HANDLE drive0 = CreateFileW( L"\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
```

CreateFileW creates or opens a file or in this case I/O device and returns a handle to the file or device.
`PhysicalDrive0` is a I/O device which allows for the direct reading a writing of bytes to the primary physical hard drive.<sup>[4]</sup>
If the malware is able to successfully open a handle to this device then it will be able to write bytes to arbitrary locations on disk, including to the MBR. 
It should be noted however that since Windows Vista/Windows Server 2008, this method of directly accessing physical drives has been restricted, likely due malware exhibiting exactly this kind of behaviour.

Having opened a handle to `PhysicalDrive0` the malware simply call the `WriteFile` API function writes the buffer containing the ransom message to the initial 512 bytes of the disk.

![Overwriting the MBR](/images/decompilation3.png)

Once again here is a tidier version than that offered by the Ghidra decompiler:

```C++
WriteFile(drive0, buffer, 512, NULL, NULL);
```

With this call to `WriteFile` (assuming it was successful) the MBR has been completely destroyed and replaced with the malware authors pseudo-ransom note.
Next time the system is power cycled it will fail to boot and instead the attackers unscrupulous demands  will be presented to the user.

The Malware finishes up by considerately closing the handle to `PhysicalDrive0` that it opened.

![Cleaning up](/images/decompilation4.png)

# Summary and Thoughts

I must say I was somewhat disappointed by how dated and rudimentary this malware was.
The technique of directly opening a handle to `PhysicalDrive0` and using that to overwrite the MBR is very old and is ineffective against modern systems.
Indeed almost any modern system with UEFI the primary drive will be partitioned using GPT and as a result will not even have a MBR.
That being said however I doubt that having half a kilobyte of random data scribbled at the start of your hard drive will do much for your systems stability. 

It's possible that the attacker who deployed this malware selectively deployed  it against systems they knew to be vulnerable to it.
Indeed the prevalence of machines running out dated version of Windows is likely fairly high in Ukraine so that doesn't seem an unreasonable notion.

In my next post I will analyse the second stage of this malware and see if is of greater sophistication.

# Sources 
1. https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/ 
2. https://bazaar.abuse.ch/sample/dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78/
3. https://www.cisa.gov/uscert/ncas/alerts/aa22-057a
4. https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew 
