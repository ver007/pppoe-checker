#!/usr/bin/env python
import socket
#import cgi
#from BeautifulSoup import BeautifulSoup
#from selenium import webdriver
import json
import re
from scapy.all import get_if_raw_hwaddr, Ether
from scapy.contrib import igmp
import subprocess as sp
import logging
import os
from Modules.pppinit import *


try:    
    import thread 
except ImportError:
    import thread as thread #Py3K changed it.

class Polserv(object):
    def __init__(self):
        self.numthreads = 0
        self.tidcount   = 0
        self.port       = 8000
        self.sock       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen(5)
        self.inituser = "Sgdsl-testload-344"
        self.initpass = "123456"
        self.initmac = "ca:64:16:40:11:26"
        self.initvlanid = "1036"
        self.pppSession = pppoed(account={"userName": self.inituser,
                                "password": self.initpass,
                                "mac": self.initmac,
                                "vlanID": self.initvlanid},
                                iface="eth0")

        self.pppSession.setInterface()
        time.sleep(0.5)
        while not self.pppSession.pppoed_session:
            self.pppSession.setPPPoED()
            time.sleep(5)

    def run(self):
        while True:
            thread.start_new_thread(self.handle, self.sock.accept())
            if self.pppSession.pppoed_session:
                self.pppSession.keepAlive()
                continue
            else:
                self.pppSession.setPPPoED()


    def handle(self, conn, addr):
        self.numthreads += 1
        self.tidcount   += 1
        tid = self.tidcount

        while True:
            data = conn.recv(2048)
            if not data:
                conn.close()
                self.numthreads -= 1
                break
            else:
                #conn.sendall("received data %s " % data + "\r\n")
                #conn.sendall("received json data %s" % matches.group(1) + "\r\n")
                try:
                    # get data as form-field request
                    #form = cgi.parse_multipart(data)
                    #run_ppp(userName=form.getfirst("username", "Sgdsl-testload-355"),
                    #        password=form.getfirst("password", "123456"),
                    #        vlanID=form.getfirst("vlanID", "100"))
                    #get data as json data request
                    JSON = re.compile('({.*?})', re.DOTALL)
                    matches = json.loads(JSON.search(data).group(1))
                    #json data for test
                    # PPPoE :{"command": "testPPPoE", "userName": "...", "password": "...", "vlanID": "..."}
                    if matches["command"] == "testPPPoE":
                        run_ppp(userName=matches["userName"],
                                password=matches["password"],
                                vlanID=matches["vlanID"])
                        conn.sendall(json.dumps({"Result": "Success"}))
                        conn.close()
                        self.numthreads -= 1
                        break
                    # run syscall command:{"command": "shell", "shellcommand": "..." , "args": ["args1", "args2", "args3"]}
                    elif matches["command"] == "shell":
                        carg = [matches["shellcommand"]]
                        for arg in matches["args"]:
                            carg.append(arg)
                        try:
                            conn.sendall("Run shell command: %s " % matches)
                            ps = sp.Popen(carg,stdout=sp.PIPE)
                            stdout_value = ps.communicate()[0]
                            conn.sendall(json.dumps({"Result": "Success", "value": repr(stdout_value)}))
                            ps.kill()
                        except:
                            conn.sendall(json.dumps({"Result": "False", "value": "error in request body"}))
                        conn.close()
                        self.numthreads -=1
                    # drop current background inited PPPoE Session
                    elif matches["command"] == "dropPPPoE":
                        with self.pppSession:
                            try:
                                out_value = {"PPPoESession": self.pppSession.pppoed_session.ip, "status" : "Down"}
                                self.pppSession.stopPPPoED()
                                conn.sendall(json.dumps(out_value))
                            except:
                                conn.sendall(json.dumps({"Result": "Success", "value": "error in request body"}))
                        conn.close()
                        self.numthreads -=1
                        break
                except:
                    conn.sendall("there error in request data")
                    conn.close()
                    self.numthreads -= 1
                    break
                #conn.sendall(b"<?xml version='1.0'?><cross-domain-policy><allow-access-from domain='*' to-ports='*'/></cross-domain-policy>")
                #conn.close()
                #self.numthreads -= 1
                #break
        #conn.sendall(b"[#%d (%d running)] %s" % (tid,self.numthreads,data) )
Polserv().run()
