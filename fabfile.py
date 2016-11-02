from fabric.api import *
import json
import datetime
from collections import defaultdict
import getpass
env.hosts = ["118.69.163.2", "118.69.163.6", "118.69.163.10", "118.69.163.14", "118.69.163.18", "118.69.163.34", "118.69.163.38", "118.69.163.42", "118.69.163.46"]
env.user = "congnt3"
env.skip_bad_hosts = True
env.warn_only = True
env.always_use_pty = False
env.password = getpass.getpass()
m = defaultdict(defaultdict)


def update_pppoe():
    with cd("/opt/pppoe-checker/"):
        sudo("git checkout pppdaemon.py logger.py")
        sudo("git pull")


def stop():
    sudo("/etc/init.d/pppoed stop")


def start():
    sudo("/etc/init.d/pppoed start")


def killall():
    sudo("ps -ef | grep pppcheck.py | grep -v grep | awk '{print $2}' | xargs kill -9")


def save_aopt_password():
    run("echo machine review.rad.fpt.net login aopt password rad@fpt123 > ~/.netrc")


def status():
    m[env.host_string]["name"] = 'null'
    with hide("output", "running"):
        name = run("hostname")
        id = run("ps -ef | grep pppdaemon | grep -v grep | awk '{print $2}'")
        d, t = run("tail -n 1 /var/log/pppoe/pppoe_worker.log | awk '{print $1}{print $2}'").split("\n")
        d = d+" " + t
        d = d[:d.index(",")]
        t = datetime.datetime.strptime(d, "%Y-%m-%d %H:%M:%S")
        res = sudo("lsof | wc -l")
    cur_t = datetime.datetime.now()
    if cur_t - t > datetime.timedelta(hours=4):
        m[env.host_string]["running"] = False
    else:
        m[env.host_string]["running"] = True
    m[env.host_string]["name"] = name
    m[env.host_string]["pid"] = id
    m[env.host_string]["fd"] = res


def count_fd():
    with hide("output", "running"):
        name = run("hostname")
        res = sudo("lsof | wc -l")
    m[name]["fd"] = res


@hosts('')
def output():
    print json.dumps(m, sort_keys=True, indent=4)

