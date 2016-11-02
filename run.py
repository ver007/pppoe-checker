#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pppoe import *
import time
import signal
from logger import setupLog
import logging
import requests
import json
import os
from multiprocessing import Pool
from scapy.all import get_if_raw_hwaddr
from subprocess import call
import random


DB_URI = 'http://118.69.190.9/pppoe/{0}'
TRIES = 3


def signal_handler(signal, frame):
    print 'You pressed Ctrl+C!'
    sys.exit(0)


def get_env(env):
    try:
        return os.environ[env]
    except KeyError:
        return None


def read_env():
    global AREA
    global IFACE
    if get_env('PPPOE_AREA') != None and get_env('PPPOE_IFACE') != None:
        AREA = get_env('PPPOE_AREA')
        IFACE = get_env('PPPOE_IFACE')
        IFACE = IFACE.split()
    else:
        raise ValueError("We need to export PPPOE_AREA and PPPOE_IFACE")


signal.signal(signal.SIGINT, signal_handler)
log = logging.getLogger("main")
setupLog(log)
read_env()
# r = redis.StrictRedis(host='localhost', port=6379, db=0)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = False
#conf.verb = 0
# conf.sniff_promisc = 0
account_status = {}
# STATUS
# 0 : success
# 1 : Cannot connect PPPOE - Timed out waiting for PADO
# 2 : Cannot connect PPPOE - Timed out waiting for auth response
# 3 : Cannot connect PPPOE - Permission denied
# 4 : Cannot connect PPPOE - Insufficient resource
# 5 : Connected but no return IP or GW
# 6 : Received IP/GW but cannot ping GW
# 7 : Received IP/GW but cannot ping internet (IP 8.8.8.8)
# 8 : Cannot send/receive DNS


def init_worker():
    '''
    When system send Break/KeyboardInterrupt or SIGTERM, the subprocess
    hanged and doesn't cleanup properly for the main program to terminate
    Ignore SIGINT so the subprocess can do the cleanup to the parent
    '''
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def isDNS(pkt, domain):
    if pkt.proto != 17 or DNS not in pkt:
        return False
    if domain not in pkt[DNS].qd.qname:
        return False
    if not pkt[DNS].an:
        return False
    return True


def isICMP(pkt, src, dst):
    # print pkt.summary()
    if pkt.proto != 1:
        return False
    if pkt.type != 0 and pkt.type != 8:
        return False
    if pkt.src != src or pkt.dst != dst:
        return False
    return True


def ping(p, src, dst):
    for _ in range(TRIES):
        p.send_packet(IP(src=src, dst=dst)/ICMP())
        time.sleep(1)
        while p.recv_queuelen() != 0:
            if isICMP(p.recv_packet(), dst, src):
                return True
    return False


def dns(p, domain, server):
    for _ in range(TRIES):
        p.send_packet(IP(src=p.ip(), dst=server)/UDP()/DNS(rd=1, qd=DNSQR(qname=domain)))
        time.sleep(1)
        while p.recv_queuelen() != 0:
            if isDNS(p.recv_packet(), domain):
                return True
    return False


def doCheck(account):
    # try:
    #     pid = multiprocessing.current_process()._identity[0]
    # except IndexError:
    #     pid = 1
    # tries = len(IFACE)
    status = 0
    bras_name = None
    for iface in random.sample(IFACE, len(IFACE)):
        with PPPoESession(username=account['userName'], password=account['password'],
                          iface=iface, mac=account['mac'], vlan=account['vlanID']) as p:
            log.info('Checking %s %s', p.username, p.iface, extra=p.extra_log)
            p.runbg()  # run pppoe in background
            #let pppoe connect for 5s then check
            pppoe_tried = 10
            while (not p.connected) and pppoe_tried > 0:
                time.sleep(1)
                pppoe_tried -= 1
            if p.bras_name:
                bras_name = p.bras_name
            if not p.connected:
                log.error('PPPoE session error: Cannot Connect', extra=p.extra_log)
                status = p.error_id
                p.terminate()
                continue
            try:
                p.ip()
                p.gw()
            except TypeError:
                log.error('PPPoE session error: No IP/Gateway', extra=p.extra_log)
                status = 5
                break
            time.sleep(1)
            if ping(p, p.ip(), p.gw()):
                log.info('Successful pinging GW %s', p.gw(), extra=p.extra_log)
            else:
                log.error('Pinging GW failed', extra=p.extra_log)
                status = 6
                break

            if ping(p, p.ip(), '8.8.8.8'):
                log.info('Successful pinging internet', extra=p.extra_log)
            else:
                log.error('Pinging internet failed', extra=p.extra_log)
                status = 7
                break

            if dns(p, "fpt.com.vn", "8.8.8.8"):
                log.info('Successful asking DNS', extra=p.extra_log)
            else:
                log.error('DNS failed', extra=p.extra_log)
                status = 8
                break
            # if PPPOE session is success
            return account['userName'], bras_name, 0
    return account['userName'], bras_name, status


def getAccount():
    try:
        r = requests.get(DB_URI.format(AREA), auth=('admin', 'Esdaemon'))
        if r.status_code == 200:
            result = r.json()['results']
            for index, account in enumerate(result):
                account['mac'] = '00:16:3e:{0:02}:{1:02d}:{2:02d}'.format(1, index//100, index % 100)
            return result
        else:
            return None
    except:
        return None


def setResult(result):
    account_id, bras_name, status = result
    account_status[account_id] = [status, bras_name]


def main():
    interfaces = []
    while True:
        # GET lastest account list
        accounts = getAccount()
        if not accounts:
            time.sleep(10)
            continue
        for account in accounts:
            for iface in IFACE:
                inf = iface + '.' + str(account['vlanID'])
                if inf not in interfaces:
                    try:
                        get_if_raw_hwaddr(inf)
                        interfaces.append(inf)
                    except IOError:
                        call(["vconfig", "add", iface, str(account['vlanID'])])
                        call(["ifconfig", inf, "up"])
                        get_if_raw_hwaddr(inf)
                        interfaces.append(inf)
        try:
            pool = Pool(10, init_worker)
            random.shuffle(accounts)
            for account in accounts:
                pool.apply_async(doCheck, (account, ), callback=setResult)
                time.sleep(0.1)
            pool.close()
            pool.join()
            time.sleep(10)

            pool = Pool(5, init_worker)
            for account in accounts:
                if not (account['userName'] in account_status) or account_status[account['userName']][0] != 0:
                    pool.apply_async(doCheck, (account, ), callback=setResult)
                    time.sleep(0.5)
            pool.close()
            pool.join()
            log.info('STATUS account: %s' % account_status, extra={'user': 'root'})
            log.info('FINISHED', extra={'user': 'root'})

            # send account info to server
            result = []
            for account in accounts:
                data = account_status[account['userName']]
                result.append({'id': account['id'], 'status': data[0], 'nasName': data[1]})
            try:
                r = requests.post(DB_URI.format(AREA), data={"data": json.dumps({"results": result})}, auth=('admin', 'Esdaemon'))
                if r.status_code == 200 and 'OK' in r.text:
                    log.info('Sent account status to DB server Successful', extra={'user': 'root'})
                else:
                    log.info('Sent account status to DB server Failed', extra={'user': 'root'})
            except:
                log.info('Sent account status to DB server Failed with exception', extra={'user': 'root'})
                pass
            time.sleep(600)
        except KeyboardInterrupt:
            pool.terminate()
            pool.wait()
            return

if __name__ == '__main__':
    main()
