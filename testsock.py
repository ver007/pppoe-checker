#!/usr/bin/env python
import socket
try:    
    import thread 
except ImportError:
    import _thread as thread #Py3K changed it.
class Polserv(object):
    def __init__(self):
        self.numthreads = 0
        self.tidcount   = 0
        self.port       = 8000
        self.sock       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen(5)
    def run(self):
        while True:
            thread.start_new_thread(self.handle, self.sock.accept()) 
    def handle(self,conn,addr):
        self.numthreads += 1
        self.tidcount   += 1
        tid=self.tidcount
        while True:
            data=conn.recv(2048)
            if not data:
                conn.close()
                self.numthreads-=1
                break
            #if "<policy-file-request/>\0" in data:
            conn.sendall(b"<?xml version='1.0'?><cross-domain-policy><allow-access-from domain='*' to-ports='*'/></cross-domain-policy>")
            conn.close()
            self.numthreads-=1
            break
        #conn.sendall(b"[#%d (%d running)] %s" % (tid,self.numthreads,data) )
Polserv().run()