#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
from logger import getHandler
from daemon import runner
import subprocess

class App():
    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = '/var/run/pppoe_worker.pid'
        self.pidfile_timeout = 5

    def run(self):
        while True:
            try:
                p = subprocess.Popen(["python", "/opt/pppoe-checker/testsock.py"],
                                     stdout=subprocess.PIPE,
                                     )  # we don't want to change pppoed file right away, so temporary absolute path
                time_wait = 15*60  # 15mins
                #stdout_value = p.communicate()[0] # default value
                while time_wait > 0:  # normally we'd do some checks here
                    time_wait -= 1
                    time.sleep(1)
                    #print '\tstdout:', repr(stdout_value) # print out p processing data
                p.kill()  # always kill, just in case
            except:
                continue


if __name__ == '__main__':
    app = App()
    daemon_runner = runner.DaemonRunner(app)
    daemon_runner.daemon_context.files_preserve = [getHandler().stream]
    daemon_runner.do_action()
