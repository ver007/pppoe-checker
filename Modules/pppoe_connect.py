from multiprocessing import Pool, Manager
from pppoe import *  # noqa
from scapy.all import get_if_raw_hwaddr, get_if_list, Ether
from scapy.contrib import igmp
from subprocess import call
import json
import logging
import os
import random
import requests
import time
import re
import sys
from optparse import *


DB_URI = 'http://118.69.190.9/pppoe/{0}'
PACKET_RETRIES = 3

PPP_TRIES = 3
PPPOED_TRIES = 15  # time PPPOE wait in seconds
TIMEOUT = 3

# Define common parser
parser = OptionParser()
# Define Parsing login group1
group1 = OptionGroup(parser, "PPPoE Common", "argument nescessary for using to request PPPoE")
# Define group 1 Parsing arguments

group1.add_option("-u", dest="username", type="string",
                  help="request pppoe username", metavar=' ')

group1.add_option("-p", "--password", dest="password", type="string",
                  help="request pppoe password", metavar=' ')

group1.add_option("-v","--vlan", dest="vlan", type="string",
                  help="request pppoen vlan id", metavar=' ')

group1.add_option("-i","--interface", dest="interface", type="string",
                  help="request pppoe on ethernet interface ", metavar=' ')

parser.add_option_group(group1)
(options, args) = parser.parse_args()

for option in ('username', 'password', 'vlan', 'interface'):
    if not getattr(options, option):
        print 'Option %s not specified' % option
        parser.print_help()
        sys.exit()

def get_env(env):
    try:
        return os.environ[env]
    except KeyError:
        return None


def read_env():
    global AREA
    global IFACE
    if get_env('PPPOE_AREA') is not None and get_env('PPPOE_IFACE') is not None:
        AREA = get_env('PPPOE_AREA')
        IFACE = get_env('PPPOE_IFACE')
        IFACE = IFACE.split()
    else:
        AREA = "HCM"
        IFACE = []
        for ifaces in get_if_list():
            if re.match(r'%s' % options.interface , ifaces, re.IGNORECASE ):
                IFACE.append(options.interface)
                break
            else:
                continue
        return
        raise ValueError("We need to export PPPOE_AREA and PPPOE_IFACE")


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("main")
read_env()
# r = redis.StrictRedis(host='localhost', port=6379, db=0)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = False
conf.verb = 0
# conf.sniff_promisc = 0
manager = Manager()
account_status = manager.dict()

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


def clearBuff(p):
    while p.recv_queuelen() != 0:
        p.recv_packet()


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
    for _ in range(PACKET_RETRIES):
        p.send_packet(IP(src=src, dst=dst) / ICMP())
        time.sleep(TIMEOUT)
        while p.recv_queuelen() != 0:
            if isICMP(p.recv_packet(), dst, src):
                return True
    return False


def isDNS(pkt, domain):
    if pkt.proto != 17 or DNS not in pkt:
        return False
    if domain not in pkt[DNS].qd.qname:
        return False
    if not pkt[DNS].an:
        return False
    return True


def dns(p, domain, server):
    for _ in range(PACKET_RETRIES):
        p.send_packet(IP(src=p.ip(), dst=server) / UDP() / DNS(rd=1, qd=DNSQR(qname=domain)))
        time.sleep(TIMEOUT)
        while p.recv_queuelen() != 0:
            if isDNS(p.recv_packet(), domain):
                return True
    return False


def isTCPSyn(pkt, sport):
    if TCP in pkt:
        if pkt[TCP].sport == 80 and pkt[TCP].dport == sport:
            return pkt
    return False


def http(p, domain):
    clearBuff(p)
    ip = IP(src=p.ip(), dst=domain)
    sport = 31234
    p.send_packet(ip / TCP(sport=sport, dport=80, flags='S'))
    time.sleep(TIMEOUT)
    while p.recv_queuelen() != 0:
        pkt = isTCPSyn(p.recv_packet(), sport)
        if pkt:
            clearBuff(p)
            getStr = 'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(domain)
            request = ip / TCP(dport=80,
                               sport=pkt.dport,
                               seq=pkt.ack,
                               ack=pkt.seq + 1,
                               flags='A') / getStr
            p.send_packet(request)
            time.sleep(TIMEOUT)
            while p.recv_queuelen() != 0:
                pkt = p.recv_packet()
                if pkt.dport == sport and pkt.sport == 80:
                    if TCP in pkt and Raw in pkt:  # http data packet
                        return True
    return False


def check_igmp(p):
    clearBuff(p)
    log.info("IMGP test")
    ip = IP(src=p.ip())
    c = igmp.IGMP(type=0x11, gaddr="0.0.0.0")
    c.adjust_ip(ip)
    p.send_packet(ip/c, vlan=99)
    time.sleep(1)
    while p.recv_queuelen() != 0:
        pkt = p.recv_packet()
        print pkt.summary()


def doCheck(account, iface):
    # try:
    #     pid = multiprocessing.current_process()._identity[0]
    # except IndexError:
    #     pid = 1
    # tries = len(IFACE)
    status = 0
    my_parent = os.getppid()
    bras_name = None
    try:
        if account_status[account['userName']][0] == 0:
            return 0
    except:
        pass
    with PPPoESession(username=account['userName'],
                      password=account['password'],
                      iface=iface,
                      mac=account['mac'][iface],
                      vlan=account['vlanID']) as p:
        log.info('Checking %s %s', p.username, p.iface, extra=p.extra_log)
        p.runbg()  # run pppoe in background
        # let pppoe connect for 5s then check
        pppoe_tried = PPPOED_TRIES
        while (not p.connected) and pppoe_tried > 0:
            try:
                if my_parent != os.getppid():
                    log.info('Parent died, suiciding', extra=p.extra_log)
                    sys.exit(0)
            except:
                pass
            time.sleep(1)
            pppoe_tried -= 1
        time.sleep(1)
        if p.bras_name:
            bras_name = p.bras_name
        if not p.connected:
            log.error('PPPoE session error: Cannot Connect', extra=p.extra_log)
            status = p.error_id
            p.terminate()
        else:
            # check connection status
            try:
                p.ip()
                p.gw()
                time.sleep(1)
                status = 0
                if ping(p, p.ip(), p.gw()):
                    log.info('Successful pinging GW %s', p.gw(), extra=p.extra_log)
                else:
                    log.error('Pinging GW failed', extra=p.extra_log)
                    status = 6

                if status == 0 and ping(p, p.ip(), '8.8.8.8'):
                    log.info('Successful pinging internet', extra=p.extra_log)
                else:
                    log.error('Pinging internet failed', extra=p.extra_log)
                    status = 7

                if status == 0 and dns(p, "fpt.com.vn", "8.8.8.8"):
                    log.info('Successful asking DNS', extra=p.extra_log)
                else:
                    log.error('DNS failed', extra=p.extra_log)
                    status = 8

                if status == 0 and http(p, "www.google.com"):
                    log.info("Successful visit google.com", extra=p.extra_log)
                else:
                    log.error("HTTP to google.com failed", extra=p.extra_log)
                    status = 9
                if status == 0:
                    # if PPPOE session is success
                    account_status[account['userName']] = [0, bras_name]
                    p.stop()
                    return 0
            except TypeError:
                log.exception('PPPoE session error', extra=p.extra_log)
                status = 5
        p.stop()

    try:
        if account_status[account['userName']][0] > status:
            return status
    except:
        pass
    account_status[account['userName']] = [status, bras_name]
    return status


def getAccount():
    try:
        log.debug('Getting account from external server', extra={'user': 'root'})
        return [{
            'userName': 'Sgdsl-testload-344',
            'mac': {'eth0': '00:16:3e:05:05:05'},
            'password': '123456',
            'vlanID': '1038'
        }]
    except:
        log.error(traceback.format_exc(), extra={'user': 'root'})
        return None


def getFailedAccount(accounts):
    failed_account = []
    for account in accounts:
        try:
            if not (account['userName'] in account_status
                    ) or account_status[account['userName']][0] != 0:
                acc = {}
                acc['userName'] = account['userName']
                acc['mac'] = account['mac']
                acc['vlanID'] = account['vlanID']
                failed_account.append(acc)
        except:
            pass
    return failed_account


def run_ppp():
    interfaces = []
    # GET lastest account list
    accounts = [{
            'userName': options.username,
            'mac': {'eth0': '00:16:3e:05:05:05'},
            'password': options.password,
            'vlanID': options.vlan}]
    for account in accounts:
        # reset account status
        account_status[account['userName']] = None
        for iface in IFACE:
            inf = iface + '.' + str(account['vlanID'])
            #inf = 'vlan' + str(account['vlanID'])
            if inf not in interfaces:
                try:
                    get_if_raw_hwaddr(inf)
                    interfaces.append(inf)
                except IOError:
                    print 'Calling', ["vconfig", "add", iface, str(account['vlanID'])]
                    call(["vconfig", "set_name_type", "DEV_PLUS_VID_NO_PAD"])
                    call(["vconfig", "add", iface, str(account['vlanID'])])
                    call(["ifconfig", inf, "up"])
                    get_if_raw_hwaddr(inf)
                    interfaces.append(inf)
    try:
        # pool = Pool(8)
        random.shuffle(accounts)
        for iface in random.sample(IFACE, len(IFACE)):
            for account in accounts:
                print 'Checking', account, iface
                res = doCheck(account, iface)
                if res != 0:
                    doCheck(account, iface)
                # pool.apply_async(doCheck, (account, iface, ))
                time.sleep(0.1)
        return

        pool.close()
        pool.join()

        for i in range(1, PPP_TRIES):
            log.debug('Account with not-0 status: %s' % getFailedAccount(accounts),
                      extra={'user': 'root'})
            log.info('Waiting for try #{0}'.format(i), extra={'user': 'root'})
            time.sleep(120)
            pool = Pool(PPP_TRIES + 2 - i)
            for iface in random.sample(IFACE, len(IFACE)):
                for account in accounts:
                    if not (account['userName'] in account_status
                            ) or account_status[account['userName']][0] != 0:
                        pool.apply_async(doCheck, (account,
                                                   iface, ))
                        time.sleep(0.5)
            pool.close()
            pool.join()

# final try with sequencing
        log.info("Waiting for final sequence try", extra={'user': 'root'})
        time.sleep(300)
        for iface in random.sample(IFACE, len(IFACE)):
            for account in accounts:
                if not (account['userName'] in account_status
                        ) or account_status[account['userName']][0] != 0:
                    doCheck(account, iface)
                    time.sleep(2)
        log.info('Final account with not-0 status: %s' % getFailedAccount(accounts),
                 extra={'user': 'root'})
        # send account info to server
        result = []
        for account in accounts:
            data = account_status[account['userName']]
            result.append({'id': account['id'], 'status': data[0], 'nasName': data[1]})

# log.info("Final status all account: %s" % result, extra={'user': 'root'})

        try:
            r = requests.post(
                DB_URI.format(AREA),
                data={"data": json.dumps({"results": result})},
                auth=('admin', 'Esdaemon'))
            if r.status_code == 200 and 'OK' in r.text:
                log.info('Sent account status to DB server Successful', extra={'user': 'root'})
            else:
                log.info('Sent account status to DB server Failed', extra={'user': 'root'})
        except:
            log.info('Sent account status to DB server Failed with exception',
                     extra={'user': 'root'})
            pass

    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
        return
    except:
        log.error(traceback.format_exc(), extra={'user': 'root'})
        return

if __name__ == '__main__':
    run_ppp()
