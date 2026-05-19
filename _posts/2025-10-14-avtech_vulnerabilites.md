---
layout: post
title: "5 Vulnerabilities in Dozens of Models of AvTech Devices"
date: 2025-10-13 09:30:00 -0000
tags: CVE AvTech IoT
---

# Background 

AvTech is a Taiwanese manufacturer of security cameras and DVR devices.
They have quite a poor history with the security of their devices, with a plethora of vulnerabilities having been found over the years[1].
In March of 2024 researchers at Akamai discovered another vulnerability allowing for RCE on a number of AvTech devices[2].
This inspired me to obtain my own device to try and reproduce their vulnerability.
Sadly it transpired that the vulnerability had been patched for my device, but in the process of reverse engineering the firmware I discovered 5 novel vulnerabilities in a variety of AvTech devices, including 4 post-auth RCE vulnerabilities and 1 XSS vulnerability.

# Protecting Yourself

These vulnerabilities affect a lot of different AvTech devices, particularly EOL ones.
Along with this blog post I am releasing PoCs for all of these vulnerabilities so that, should you own any AvTech devices, you can check if you are vulnerable.
I have strong reason to believe that some or all of these vulnerabilities have been exploited as 0-days for some time.
Most of these devices are EOL and as a result are unlikely to be patched and should be decommissioned.
If you cannot decommission any of these devices, make sure that you set a long and complex password as these vulnerabilities are all post-auth.

I reached out to AvTech to inform them of these vulnerabilities but they did not respond.

# Obtaining the Firmware

After obtaining an AvTech DGM1104 camera from eBay I began considering methods for obtaining a firmware image for it.
My first thought was to open it up and try to dump the SPI flash, as this is an approach that I had taken for previous cameras that I'd looked at.
But it turns out that AvTech is very generous with their firmware images, particularly for their older devices, and almost all of their out-of-support devices, as well as some of their in-support devices, have firmware images available from their website.[3][4]

With the firmware in hand I was able to begin reverse engineering and looking for bugs.


# The vulnerabilities

## FTP Test (CVE-2025-57198)

In the `cgibox` binary there is a function for testing the FTP settings of the camera to make sure that the camera can reach the remote FTP server that it can send files to in the course of its operation.
This function reads previously saved FTP configuration settings from the camera's flash memory, and then without performing sanitization integrates them into a string which is then handed directly to `system()`.
This can be trivially exploited to achieve command injection and remote code execution.

```c
undefined4 test_ftp(void)

{
  int iVar1;
  void *value_read;
  char ftp_test_command [520];
  
  value_read = (void *)0x0;
  strcpy(ftp_test_command,"FtpClient -T /tmp/HTM_AV718/images/ftp_test.png ");
  iVar1 = readFlashDBValue("Network.FTP.Server",&value_read);
  if (0 < iVar1) {
    cgi_remove_char(value_read,0x22);
    cgi_safe_snprintf(ftp_test_command,0x200,"%s-S \"%s\" ",ftp_test_command,value_read);
    free(value_read);
    iVar1 = readFlashDBValue("Network.FTP.Username",&value_read);
    if (0 < iVar1) {
      cgi_remove_char(value_read,0x22);
      cgi_safe_snprintf(ftp_test_command,0x200,"%s-u \"%s\" ",ftp_test_command,value_read);
      free(value_read);
      iVar1 = readFlashDBValue("Network.FTP.Password",&value_read);
      if (0 < iVar1) {
        cgi_remove_char(value_read,0x22);
        cgi_safe_snprintf(ftp_test_command,0x200,"%s-p \"%s\" ",ftp_test_command,value_read);
        free(value_read);
        iVar1 = readFlashDBValue("Network.FTP.Port",&value_read);
        if (0 < iVar1) {
          cgi_remove_char(value_read,0x22);
          cgi_safe_snprintf(ftp_test_command,0x200,"%s-P \"%s\" ",ftp_test_command,value_read);
          free(value_read);
          iVar1 = readFlashDBValue("Network.FTP.Directory",&value_read);
          if (0 < iVar1) {
            cgi_remove_char(value_read,0x22);
            cgi_safe_snprintf(ftp_test_command,0x200,&DAT_00056fa7,ftp_test_command,value_read);
            free(value_read);
          }
          iVar1 = readFlashDBValue("Network.FTP.Mode",&value_read);
          if (0 < iVar1) {
            cgi_remove_char(value_read,0x22);
            cgi_safe_snprintf(ftp_test_command,0x200,"%s-m \"%s\" ",ftp_test_command,value_read);
            free(value_read);
          }
          strcat(ftp_test_command,"-n ftp_test.png ");
          system(ftp_test_command);
          return 0;
        }
      }
    }
  }
  return 0xffffffed;
}
```

## SMTP Test (CVE-2025-57200)

In the `cgibox` binary there is a function for testing the SMTP settings of the camera to make sure that the camera is able to send an email to a system administrator in the event of any issues.
This function reads previously saved SMTP configuration settings from the camera's flash memory, and then without performing sanitization integrates them into a string which is then handed directly to `system()`.
This can be trivially exploited to achieve command injection and remote code execution.

```c

/* This function is vulnerable to command injection in a similar way to test_ftp. */

undefined4 test_mail(void)

{
  int flash_read_successful;
  char *flash_value;
  char *local_20c;
  char command [512];
  char *smtp_encryption;
  char *smtp_ssl;
  
  flash_value = (char *)0x0;
  local_20c = (char *)0x0;
  strcpy(command,"SmtpClient -T ");
  flash_read_successful = readFlashDBValue("Network.SMTP.Encryption",&flash_value);
  smtp_encryption = flash_value;
  if (flash_read_successful < 1) {
    flash_read_successful = readFlashDBValue("Network.SMTP.SSL",&flash_value);
    smtp_encryption = flash_value;
    if (0 < flash_read_successful) {
      flash_read_successful = strcasecmp("YES",flash_value);
      if (flash_read_successful == 0) {
        strcat(command,"-e ");
      }
      goto LAB_0003bcfe;
    }
  }
  else {
    flash_read_successful = strcasecmp("TLS",flash_value);
    if (flash_read_successful == 0) {
      smtp_encryption = "-E ";
    }
    else {
      flash_read_successful = strcasecmp("SSL",smtp_encryption);
      if (flash_read_successful != 0) {
        flash_read_successful = readFlashDBValue("Network.SMTP.SSL",&local_20c);
        smtp_ssl = local_20c;
        smtp_encryption = flash_value;
        if (0 < flash_read_successful) {
          flash_read_successful = strcasecmp("YES",local_20c);
          if (flash_read_successful == 0) {
            strcat(command,"-e ");
          }
          free(smtp_ssl);
          smtp_encryption = flash_value;
        }
        goto LAB_0003bcfe;
      }
      smtp_encryption = "-e ";
    }
    strcat(command,smtp_encryption);
    smtp_encryption = flash_value;
LAB_0003bcfe:
    free(smtp_encryption);
  }
  flash_read_successful = readFlashDBValue("Network.SMTP.MailServer",&flash_value);
  if (flash_read_successful < 1) {
    return 0xffffffed;
  }
  cgi_remove_char(flash_value,0x22);
  cgi_safe_snprintf(command,0x200,"%s-S \"%s\" ",command,flash_value);
  free(flash_value);
  flash_read_successful = readFlashDBValue("Network.SMTP.Authentication.Enabled",&flash_value);
  if (0 < flash_read_successful) {
    flash_read_successful = strcasecmp("YES",flash_value);
    if (flash_read_successful == 0) {
      cgi_remove_char(local_20c,0x22);
      flash_read_successful = readFlashDBValue("Network.SMTP.Authentication.Username",&local_20c);
      if (flash_read_successful < 1) {
LAB_0003bd86:
        free(flash_value);
        return 0xffffffed;
      }
      cgi_safe_snprintf(command,0x200,"%s-u \"%s\" ",command,local_20c);
      free(local_20c);
      cgi_remove_char(local_20c,0x22);
      flash_read_successful = readFlashDBValue("Network.SMTP.Authentication.Password",&local_20c);
      if (flash_read_successful < 1) goto LAB_0003bd86;
      cgi_safe_snprintf(command,0x200,"%s-p \"%s\" ",command,local_20c);
      free(local_20c);
    }
    free(flash_value);
  }
  strcat(command,"-s \'Test Mail\' ");
  flash_read_successful = readFlashDBValue("Network.SMTP.Sender",&flash_value);
  if (flash_read_successful < 1) {
    strcat(command,"-f smtp_test ");
  }
  else {
    cgi_remove_char(flash_value,0x22);
    cgi_safe_snprintf(command,0x200,"%s-f \"%s\" ",command,flash_value);
    free(flash_value);
  }
  flash_read_successful = readFlashDBValue("Network.SMTP.Receivers",&flash_value);
  if (flash_read_successful < 1) {
    return 0xffffffed;
  }
  cgi_remove_char(flash_value,0x22);
  cgi_safe_snprintf(command,0x200,"%s-t \"%s\" ",command,flash_value);
  free(flash_value);
  system(command);
  return 0;
}
```

## Mount SMB (CVE-2025-57201)

In the `cgibox` binary there is a function for mounting SMB shares, which is run automatically to mount a share if such an SMB share is configured.
This function reads previously saved SMB configuration settings from the camera's flash memory, and then without performing sanitization integrates them into a string which is then handed directly to `system()`.
This can be trivially exploited to achieve command injection and remote code execution.

```c
void mount_smb_share(void)

{
  int result;
  char *pcVar1;
  char *pcVar2;
  char *smb_path_ptr;
  char *flash_value;
  undefined username [32];
  undefined password [32];
  undefined smb_version [32];
  char smb_address [128];
  char smb_path;
  char acStack_297 [127];
  char command [512];
  
  system("umount /mnt/samba/");
  smb_version[0] = 0;
  password[0] = 0;
  username[0] = 0;
  smb_path = '\0';
  smb_address[0] = '\0';
  command[0] = '\0';
  result = readFlashDBValue("Network.NetworkShare.Address",&flash_value);
  if (0 < result) {
    cgi_safe_strncpy(smb_address,flash_value,0x80);
    free(flash_value);
  }
  result = readFlashDBValue("Network.NetworkShare.Path",&flash_value);
  if (result < 1) {
    pcVar2 = (char *)0x0;
    smb_path_ptr = (char *)0x0;
  }
  else {
    cgi_safe_strncpy(&smb_path,flash_value,0x80);
    if (smb_path == '/') {
      smb_path_ptr = acStack_297;
    }
    else {
      smb_path_ptr = &smb_path;
    }
    pcVar1 = strchr(acStack_297,0x2f);
    pcVar2 = pcVar1;
    if (pcVar1 != (char *)0x0) {
      pcVar2 = pcVar1 + 1;
      *pcVar1 = '\0';
    }
    free(flash_value);
  }
  result = readFlashDBValue("Network.NetworkShare.Username",&flash_value);
  if (0 < result) {
    cgi_safe_strncpy(username,flash_value,0x20);
    free(flash_value);
  }
  result = readFlashDBValue("Network.NetworkShare.Password",&flash_value);
  if (0 < result) {
    cgi_safe_strncpy(password,flash_value,0x20);
    free(flash_value);
  }
  result = readFlashDBValue("Network.NetworkShare.SMBVersion",&flash_value);
  if (0 < result) {
    cgi_safe_snprintf(smb_version,0x20,"vers=%s,",flash_value);
    free(flash_value);
  }
  if ((smb_address[0] != '\0') && (smb_path != '\0')) {
    result = readFlashDBValue("Network.NetworkShare.Enabled",&flash_value);
    if (0 < result) {
      result = strcasecmp(flash_value,"YES");
      if (result == 0) {
        if (pcVar2 == (char *)0x0) {
          cgi_safe_snprintf(command,0x200,
                            "mount -t cifs -o %susername=%s,password=%s,nounix,sec=ntlm //%s/%s /mnt /samba/"
                            ,smb_version,username,password,smb_address,smb_path_ptr);
        }
        else {
          cgi_safe_snprintf(command,0x200,
                            "mount -t cifs -o %susername=%s,password=%s,nounix,sec=ntlm,prefixpath=% s //%s/%s /mnt/samba/"
                            ,smb_version,username,password,pcVar2,smb_address,smb_path_ptr);
        }
      }
      free(flash_value);
    }
    if (command[0] != '\0') {
      av_systemc(command);
    }
  }
  return;
}
```

## Network Failure Check (CVE-2025-57199)

`NetFailDetectD` is a daemon that runs on the camera to detect whether it has network access; the way that it does this is by regularly pinging a specified host address and checking that a response is received.
If it fails to get a ping back from the host it knows that there is some kind of network issue and it then attempts to alert the administrator about this via SMTP.


I won't give the full disassembly for this one as the logic isn't as clean as for the others.
Suffice it to say that the config value `Network.NetworkFailureDetection.Address` is read from the camera's flash memory into `local_4c8`; they then filter `"` (0x22) and `` ` `` (0x60) characters to try and prevent command injection, but this does nothing to stop us from using `$()`-based command injection.
The filtered string is then integrated into a ping command used to check if the host at the address specified by `Network.NetworkFailureDetection.Address` is up, and then passed to `popen`.
```c
cgi_remove_char(local_4c8,0x22);
cgi_remove_char(local_4c8,0x60);
sprintf(acStack_ac8,"ping -w 5 \"%s\"",local_4c8);
pFVar2 = popen(acStack_ac8,"r");
```

While not a call to `system`, `popen` also results in a call to the system shell and is consequently vulnerable to command injection; see the Linux man pages:
> The popen() function opens a process by creating a pipe, forking,
> and invoking the shell.

## Username XSS (CVE-2025-57202)

When creating a new user for the admin console you can add arbitrary HTML characters to the name of the new user.
This allows for XSS payloads to be injected which will be triggered whenever a user visits the user list page.


## Core issue

All of these vulnerabilities rely on being able to write arbitrary data to the system config, which is possible via the `/cgi-bin/user/Config.cgi` endpoint.
This endpoint, however, requires you to be authenticated to the device, hence all of these vulnerabilities are post-auth.


# References

1. [A collection of previously discovered AvTech vulnerabilities](https://www.exploit-db.com/exploits/40500)
2. [Akamai blog post](https://www.akamai.com/blog/security-research/corona-mirai-botnet-infects-zero-day-sirt)
3. [In support camera firmware](https://www.avtech.com.tw/NetworkCamera.aspx)
4. [EOL firmware](https://www.avtech.com.tw/EOL.aspx)
