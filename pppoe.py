#!/usr/bin/env python
import hashlib
md5 = hashlib.md5()
import os
import time
import random
from logger import setupLog
import logging
from scapy.all import *
conf.verb = 0
# Some human-readable versions of hex type numbers
Service_Name = '\x01\x01'
Host_Unique = '\x01\x03'
Generic_Error = '\x02\x03'
AC_Cookie = '\x01\x04'
LCP = 49185
CHAP = 49699
IPCP = 32801
IPv4 = 33
PADI = 9
PADO = 7
PADR = 25
PADS = 101
PADT = 167
ConfReq = '\x01'
ConfAck = '\x02'
ConfNak = '\x03'
ConfRej = '\x04'
TermReq = '\x05'
TermAck = '\x06'
EchoReq = '\x09'
EchoRep = '\x0a'
MTU = '\x01\x04'
MAGIC = '\x05\x06'
Challenge = '\x01'
Response = '\x02'
Success = '\x03'
Reject = '\x04'
Address = '\x03\x06'
lastpkt = IP()
PAPRequest = '\x01'

PAPProto = '\x03'
PAPLength = '\x04'
PAPHex = '\xc0\x23'
PAP = 49187


def do_build(payload):
    return str(payload)


def word(value):
    # Generates a two byte representation of the provided number
    return (chr((value / 256) % 256) + chr(value % 256))


def TLV(type, value):
    # Generates a TLV for a variable length string
    return (type + word(len(value)) + value)


def confreq(payload, id='\x01'):
    # Generates a TLV for a variable length string
    return (ConfReq + id + word(len(payload) + 4) + payload)


def parseconfreq(payload):
    # Returns a tuple containing the IP address plus any additional junk from a ConfReq
    ip = ''
    other = ''
    if (len(payload) > 4 and payload[0:1] == ConfReq):
        i = 4
        while (i < len(payload) and i < ord(payload[3:4]) + (256 * ord(payload[2:3]))):
            type = payload[i:i + 1]
            length = payload[i + 1:i + 2]
            value = payload[i + 2:i + ord(length)]
            if (type + length == Address):
                ip = value
            else:
                other += type + length + value
            i = i + ord(length)
    return ([ip, other])


class PPPoESession(Automaton):
    # A class providing a PPPoE and PPP state machine
    randomcookie = False
    retries = 100
    mac = "00:00:00:00:00:00"
    hu = "\x7a\x00\x00\x00"
    ac_cookie = ""
    our_magic = "\x01\x23\x45\x67"
    their_magic = "\x00\x00\x00\x00"
    sess_id = 0
    servicename = ""
    username = ""
    password = ""
    chal_id = ""
    challenge = ""
    ipaddress = chr(0) + chr(0) + chr(0) + chr(0)
    gwipaddress = ''
    recvbuff = []
    maxrecv = 1000

    def __init__(self, username, password, iface, mac=None, vlan=None):
        if not vlan is None:
            self.iface = iface + '.' + str(vlan)
        else:
            self.iface = iface
        super(PPPoESession, self).__init__(iface=self.iface)
        self.connected = False
        self.username = username
        self.password = password
        self.blacklist = []
        self.ac_mac = "ff:ff:ff:ff:ff:ff"
        self.bras_name = None
        self.log = setupLog(logging.getLogger('pppoe'))
        self.error_id = 1
        # 0 : success
        # 1 : Cannot connect PPPOE - Timed out waiting for PADO
        # 2 : Cannot connect PPPOE - Timed out waiting for auth response
        # 3 : Cannot connect PPPOE - Permission denied
        # 4 : Cannot connect PPPOE - Insufficient resource
        if mac:
            self.mac = mac
            mac = mac.split(':')
            self.hu = "\x7a{0}{1}{2}".format(
                chr(int('0x' + mac[3], 16) % 30), chr(int('0x' + mac[4], 16) % 30),
                chr(int('0x' + mac[5], 16) % 30))
            # self.hu="\x7a{0}{1}{2}".format(chr(random.randint(1, 30)),chr(random.randint(1, 30)),chr(random.randint(1, 30)))
        else:
            self.mac = get_if_hwaddr(self.iface)
            self.hu = "\x7a{0}{1}{2}".format(
                chr(random.randint(1, 30)), chr(random.randint(1, 30)), chr(random.randint(1, 30)))

        self.extra_log = {'user': self.username, 'iface': self.iface}

# Method to check whether packets are queued

    def recv_queuelen(self):
        return (len(self.recvbuff))

# Method to get the first packet in the receive queue

    def recv_packet(self):
        if (len(self.recvbuff) > 0):
            return (self.recvbuff.pop())
        else:
            return (None)

# Method to send an IP packet through the PPP session

    def send_packet(self, payload, vlan=None):
        if vlan is None:
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                PPP(proto=IPv4) / payload,
                iface=self.iface,
                verbose=False)
        else:
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / Dot1Q(vlan=vlan) /
                PPPoE(sessionid=self.sess_id) / PPP(proto=IPv4) / payload,
                iface=self.iface,
                verbose=False)

    def ip(self):
        # Method to find the current IP address
        return (str(ord(self.ipaddress[0:1])) + "." + str(ord(self.ipaddress[1:2])) + "." +
                str(ord(self.ipaddress[2:3])) + "." + str(ord(self.ipaddress[3:4])))

    def gw(self):
        # Method to find the current IP address
        return (str(ord(self.gwipaddress[0:1])) + "." + str(ord(self.gwipaddress[1:2])) + "." +
                str(ord(self.gwipaddress[2:3])) + "." + str(ord(self.gwipaddress[3:4])))

    def get_bras_name(self, payload):
        loc = 0
        while (loc < len(payload)):
            att_type = payload[loc:loc + 2]
            att_len = (256 * ord(payload[loc + 2:loc + 3])) + ord(payload[loc + 3:loc + 4])
            if att_type == "\x01\x02":
                self.bras_name = payload[loc + 4:loc + 4 + att_len]
                break
            loc = loc + att_len + 4

    def getcookie(self, payload):
        # Method to recover an AC-Cookie from PPPoE tags
        loc = 0
        while (loc < len(payload)):
            att_type = payload[loc:loc + 2]
            att_len = (256 * ord(payload[loc + 2:loc + 3])) + ord(payload[loc + 3:loc + 4])
            if att_type == "\x01\x04":
                self.ac_cookie = payload[loc + 4:loc + 4 + att_len]
                break
            loc = loc + att_len + 4

    def master_filter(self, pkt):
        # Filter out anything that's not PPPoE as our automaton won't be interested
        if pkt[Ether].dst != self.mac:
            return False
        # return (PPPoED in pkt) or (PPPoE in pkt)
        if (PPPoED not in pkt) and (PPPoE not in pkt):
            return False
        if (PPPoED in pkt) and (Raw not in pkt) and (self.hu not in pkt[Raw].load):
            return False
        if self.ac_mac != "ff:ff:ff:ff:ff:ff":
            if (pkt[Ether].src != self.ac_mac):
                return False
        if PPPoE in pkt:
            if self.sess_id != 0:
                return pkt[PPPoE].sessionid == self.sess_id
        return True
        # if (PPPoED in pkt) and (Raw not in pkt) and (self.hu not in pkt[Raw].load):
        #     return False
        # if self.ac_mac != "ff:ff:ff:ff:ff:ff":
        #     if (pkt[Ether].src!=self.ac_mac) or (pkt[Ether].dst!=self.mac):
        #         return False
        # if PPPoE in pkt:
        #     if self.sess_id != 0:
        #         return pkt[PPPoE].sessionid==self.sess_id
        # return True

        # Define possible states
    @ATMT.state(initial=1)
    def START(self):
        pass

    @ATMT.state()
    def WAIT_PADO(self):
        pass

    @ATMT.state()
    def GOT_PADO(self):
        pass

    @ATMT.state()
    def WAIT_PADS(self):
        pass

    @ATMT.state()
    def START_LCP(self):
        pass

    @ATMT.state()
    def LCP_Request_Sent(self):
        pass

    @ATMT.state()
    def LCP_Ack_Received(self):
        pass

    @ATMT.state()
    def LCP_Ack_Sent(self):
        pass

    @ATMT.state()
    def LCP_OPEN(self):
        pass

    @ATMT.state()
    def CHAP_AUTHENTICATING(self):
        pass

    @ATMT.state()
    def PAP_AUTHENTICATING(self):
        pass

    @ATMT.state()
    def WAIT_AUTH_RESPONSE(self):
        pass

    @ATMT.state()
    def START_IPCP(self):
        pass

    @ATMT.state()
    def IPCP_Request_Sent(self):
        pass

    @ATMT.state()
    def IPCP_Ack_Received(self):
        pass

    @ATMT.state()
    def IPCP_BOTH_PEND(self):
        pass

    @ATMT.state()
    def IPCP_Ack_Sent(self):
        pass

    @ATMT.state()
    def IPCP_OPEN(self):
        pass

    @ATMT.state()
    def START_PADT(self):
        pass

    @ATMT.state(error=1)
    def ERROR(self):
        pass

    @ATMT.state(final=1)
    def END(self):
        pass

# Define transitions
# Transitions from START

    @ATMT.condition(START)
    def send_padi(self):
        self.retries_auth = 0
        self.retries_pad = 0
        self.log.debug("Starting PPPoED %s %s", self.mac, self.iface, extra=self.extra_log)
        sendp(
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") / PPPoED() /
            Raw(load=TLV(Service_Name, self.servicename) + TLV(Host_Unique, self.hu)),
            iface=self.iface,
            verbose=False)
        raise self.WAIT_PADO()

# Transitions from WAIT_PADO

    @ATMT.timeout(WAIT_PADO, 5)
    def timeout_pado(self):
        self.log.warning("Timed out waiting for PADO", extra=self.extra_log)
        self.retries -= 1
        if (self.retries < 0):
            self.log.warning("Timed out waiting for PADO, trying another peer",
                             extra=self.extra_log)
            self.error_id = 1
            #self.blacklist.append(self.ac_mac)
            raise self.ERROR()
        raise self.START()

    @ATMT.receive_condition(WAIT_PADO)
    def receive_pado(self, pkt):
        if (PPPoED in pkt) and (pkt[PPPoED].code == PADO):
            if self.hu in pkt[Raw].load:
                if pkt[Ether].src not in self.blacklist:
                    self.ac_mac = pkt[Ether].src
                    self.log.debug('Received PADO, mac:%s', self.ac_mac, extra=self.extra_log)
                    self.get_bras_name(pkt[Raw].load)
                    self.getcookie(pkt[Raw].load)
                    raise self.GOT_PADO()

# Transitions from GOT_PADO

    @ATMT.condition(GOT_PADO)
    def send_padr(self):
        if (self.randomcookie):
            self.log.warning("Random cookie being used", extra=self.extra_log)
            self.ac_cookie = os.urandom(16)
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoED(code=PADR) /
            Raw(load=TLV(Service_Name, self.servicename) + TLV(Host_Unique, self.hu) + TLV(
                AC_Cookie, self.ac_cookie)),
            iface=self.iface,
            verbose=False)
        raise self.WAIT_PADS()

# Transitions from WAIT_PADS

    @ATMT.timeout(WAIT_PADS, 3)
    def timeout_pads(self):
        self.log.warning("Timed out waiting for PADS", extra=self.extra_log)
        self.retries_pad += 1
        if (self.retries_pad >= 2):
            self.blacklist.append(self.ac_mac)
            self.ac_mac = "ff:ff:ff:ff:ff:ff"
            self.log.warning('Timed out PADS, trying another peer', extra=self.extra_log)
            raise self.START()
        raise self.GOT_PADO()

    @ATMT.receive_condition(WAIT_PADS)
    def receive_pads(self, pkt):
        # check mac of src and dst
        if (PPPoED in pkt) and (pkt[PPPoED].code == PADS):
            # print self.iface, 'got PADS', pkt.summary()
            if pkt[Raw].load[8:12] == self.hu:
                self.sess_id = pkt[PPPoED].sessionid
                raise self.START_LCP()

    @ATMT.receive_condition(WAIT_PADS)
    def receive_padt(self, pkt):
        if (PPPoED in pkt) and (pkt[PPPoED].code == PADT):
            self.log.error("Received PADT", extra=self.extra_log)
            raise self.ERROR()

# Transitions from START_LCP

    @ATMT.condition(START_LCP)
    def lcp_send_confreq(self):
        self.log.debug("Starting LCP Session %s", self.sess_id, extra=self.extra_log)
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=LCP) /
            Raw(load=confreq(MTU + word(1492) + MAGIC + self.our_magic)),
            iface=self.iface,
            verbose=False)
        raise self.LCP_Request_Sent()

# Transitions from LCP_Request_Sent

    @ATMT.timeout(LCP_Request_Sent, 3)
    def lcp_req_sent_timeout(self):
        self.log.warning("Timed out waiting for LCP from peer", extra=self.extra_log)
        self.retries -= 1
        if (self.retries < 0):
            self.log.error("Too many retries, aborting.", extra=self.extra_log)
            self.error_id = 2
            raise self.ERROR()
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=LCP) /
            Raw(load=confreq(MTU + word(1492) + MAGIC + self.our_magic)),
            iface=self.iface,
            verbose=False)
        raise self.LCP_Request_Sent()

    @ATMT.receive_condition(LCP_Request_Sent, prio=1)
    def lcp_req_sent_rx_confreq(self, pkt):
        # We received a ConfReq from the peer. Nak is not implemented, we just Ack anything we are sent.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == ConfReq):
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                PPP(proto=LCP) / Raw(load=ConfAck + pkt[Raw].load[1:]),
                iface=self.iface,
                verbose=False)
            if pkt[Raw].load[8] == PAPProto and pkt[Raw].load[9] == PAPLength and pkt[Raw].load[
                    10:12] == PAPHex:
                self.log.debug('Got PAP Authentication', extra=self.extra_log)
                self.pap = True
            raise self.LCP_Ack_Sent()

    @ATMT.receive_condition(LCP_Request_Sent, prio=2)
    def lcp_req_sent_rx_confack(self, pkt):
        # We received a ConfAck from the peer. Now we must wait for their ConfReq.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == ConfAck):
            raise self.LCP_Ack_Received()

    @ATMT.receive_condition(LCP_Request_Sent, prio=3)
    def lcp_req_sent_rx_confnakrej(self, pkt):
        # We received a ConfNak or a ConfRej from the peer. In theory we could negotiate but we have no parameters to fall back on so just error.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == ConfNak or
                                                       pkt[Raw].load[0:1] == ConfRej):
            raise self.ERROR()

## Transitions from LCP_Ack_Sent

    @ATMT.timeout(LCP_Ack_Sent, 3)
    def lcp_ack_sent_timeout(self):
        self.log.warning("Timed out waiting for LCP from peer", extra=self.extra_log)
        self.retries -= 1
        if (self.retries < 0):
            self.log.error("Too many retries, aborting.", extra=self.extra_log)
            self.error_id = 2
            raise self.ERROR()
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=LCP) /
            Raw(load=confreq(MTU + word(1492) + MAGIC + self.our_magic)),
            iface=self.iface,
            verbose=False)
        raise self.LCP_Ack_Sent()

    @ATMT.receive_condition(LCP_Ack_Sent, prio=1)
    def lcp_ack_sent_rx_confack(self, pkt):
        # We received a ConfAck from the peer, so we are ready to play.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == ConfAck):
            self.chal_id = pkt[Raw].load[1]
            if self.pap:
                raise self.PAP_AUTHENTICATING()
            raise self.LCP_OPEN()

    @ATMT.receive_condition(LCP_Ack_Sent, prio=2)
    def lcp_ack_sent_rx_confreq(self, pkt):
        # We received a ConfReq from the peer. Nak is not implemented, we just Ack anything we are sent.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == ConfReq):
            if self.pap:
                raise self.LCP_Ack_Sent()
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                PPP(proto=LCP) / Raw(load=ConfAck + pkt[Raw].load[1:]),
                iface=self.iface,
                verbose=False)
            raise self.LCP_Ack_Sent()

    @ATMT.receive_condition(LCP_Ack_Sent, prio=3)
    def lcp_ack_sent_rx_confnakrej(self, pkt):
        # We received a ConfNak or a ConfRej from the peer. In theory we could negotiate but we have no parameters to fall back on so just error.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == ConfNak or
                                                       pkt[Raw].load[0:1] == ConfRej):
            raise self.ERROR()

# Transitions from LCP_Ack_Received

    @ATMT.timeout(LCP_Ack_Received, 3)
    def lcp_ack_recv_timeout(self):
        self.log.warning("Timed out waiting for LCP from peer", extra=self.extra_log)
        self.retries -= 1
        if (self.retries < 0):
            self.log.error("Too many retries, aborting.", extra=self.extra_log)
            self.error_id = 2
            raise self.ERROR()
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=LCP) /
            Raw(load=confreq(MTU + word(1492) + MAGIC + self.our_magic)),
            iface=self.iface,
            verbose=False)
        raise self.LCP_Req_Sent()

    @ATMT.receive_condition(LCP_Ack_Received)
    def lcp_ack_recv_rx_confreq(self, pkt):
        # We received a ConfReq from the peer. Nak is not implemented, we just Ack anything we are sent.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == ConfReq):
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                PPP(proto=LCP) / Raw(load=ConfAck + pkt[Raw].load[1:]),
                iface=self.iface,
                verbose=False)
            # if self.pap:
            #     raise self.PAP_AUTHENTICATING()
            raise self.LCP_OPEN()

# Transitions from LCP_OPEN

    @ATMT.timeout(LCP_OPEN, 3)
    def auth_or_ipcp_timeout(self):
        self.log.warning("Timed out waiting for authentication challenge or IPCP from peer",
                         extra=self.extra_log)
        self.retries -= 1
        if (self.retries < 0):
            self.log.error("Too many retries, aborting.", extra=self.extra_log)
            self.error_id = 2
            raise self.ERROR()
        raise self.LCP_OPEN()

    @ATMT.receive_condition(LCP_OPEN, prio=1)
    def get_challenge(self, pkt):
        # We received a CHAP challenge from the peer so we must authenticate ourself.
        if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1] == Challenge):
            self.log.debug("Got CHAP Challenge, Authenticating", extra=self.extra_log)
            self.chal_id = pkt[Raw].load[1:2]
            chal_len = ord(pkt[Raw].load[4:5])
            self.challenge = pkt[Raw].load[5:5 + chal_len]
            raise self.CHAP_AUTHENTICATING()
        if (PPP in pkt) and pkt[PPP].proto == LCP:
            if pkt[Raw].load[8] == PAPProto and pkt[Raw].load[9] == PAPLength and pkt[Raw].load[
                    10:12] == PAPHex:
                self.log.debug("Got PAP Request, Authenticating", extra=self.extra_log)
                raise self.PAP_AUTHENTICATING()

    @ATMT.receive_condition(LCP_OPEN, prio=2)
    def lcp_open_get_IPCP(self, pkt):
        # Straight to IPCP if the peer doesn't challenge.
        if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[Raw].load[0:1] == Challenge):
            self.log.debug("Got IPCP - skipping authentication", extra=self.extra_log)
            raise self.START_IPCP()

## Transitions from AUTHENTICATING

    @ATMT.condition(CHAP_AUTHENTICATING)
    def send_chap_response(self):
        auth_hash = md5.new(self.chal_id + self.password + self.challenge).digest()
        resp_len = word(len(auth_hash + self.username) + 5)
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=CHAP) /
            Raw(load=Response + self.chal_id + resp_len + '\x10' + auth_hash + self.username),
            iface=self.iface,
            verbose=False)
        raise self.WAIT_AUTH_RESPONSE()

## Transitions from AUTHENTICATING

    @ATMT.condition(PAP_AUTHENTICATING)
    def send_pap_response(self):
        self.log.debug("Sending Username/Password", extra=self.extra_log)
        auth_hash = chr(len(self.username)) + self.username + chr(len(
            self.password)) + self.password
        resp_len = word(len(auth_hash) + 4)
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=PAP) /
            Raw(load=Challenge + self.chal_id + resp_len + auth_hash),
            iface=self.iface,
            verbose=False)
        raise self.WAIT_AUTH_RESPONSE()

## Transitions from WAIT_AUTH_RESPONSE

    @ATMT.timeout(WAIT_AUTH_RESPONSE, 3)
    def wait_auth_response_timeout(self):
        # We timed out waiting for an auth response. Re-send.
        self.log.warning('Timed out waiting for auth response, resending', extra=self.extra_log)
        self.retries_auth += 1
        if self.retries_auth >= 3:
            self.ac_mac = "ff:ff:ff:ff:ff:ff"
            self.sess_id = 0
            self.log.error('Giving up Auth, restarting', extra=self.extra_log)
            raise self.START()
        auth_hash = chr(len(self.username)) + self.username + chr(len(
            self.password)) + self.password
        resp_len = word(len(auth_hash) + 4)
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=PAP) /
            Raw(load=Challenge + self.chal_id + resp_len + auth_hash),
            iface=self.iface,
            verbose=False)
        raise self.WAIT_AUTH_RESPONSE()

    @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=1)
    def wait_auth_response_rx_success(self, pkt):
        # We received a CHAP success so we can start IPCP.
        if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1] == Success):
            self.log.debug("Authenticated OK", extra=self.extra_log)
            raise self.START_IPCP()
        if (PPP in pkt) and pkt[PPP].proto == PAP and (pkt[Raw].load[0:1] == Response):
            self.log.debug("Authenticated OK", extra=self.extra_log)
            raise self.START_IPCP()

    @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=2)
    def wait_auth_response_rx_reject(self, pkt):
        # We received a CHAP reject and must terminate.
        if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1] == Reject):
            self.log.error("Authentication failed, reason: " + pkt[Raw].load[4:],
                           extra=self.extra_log)
            raise self.ERROR()
        if (PPP in pkt) and pkt[PPP].proto == PAP and (pkt[Raw].load[0:1] == Success):
            self.log.error(
                "Authentication failed, reason: ".format(self.username) + pkt[Raw].load[5:],
                extra=self.extra_log)
            reasons = ["address allocation failure, insufficient resources", "permission denied"]
            if pkt[Raw].load[5:len(reasons[0]) + 5] == reasons[0]:
                # 4 : Cannot connect PPPOE - Insufficient resource
                self.error_id = 4
            if pkt[Raw].load[5:len(reasons[1]) + 5] == reasons[1]:
                # 3 : Cannot connect PPPOE - Permission denied
                self.error_id = 3
            # the rest, we set it to permission denied for now
            self.error_id = 3
            raise self.ERROR()

    @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=3)
    def wait_auth_response_rx_echo(self, pkt):
        # Authentication can take a while so we should reply to echoes while we wait.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == EchoReq):
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                PPP(proto=LCP) / Raw(load=EchoRep + pkt[Raw].load[1:2] + word(8) + self.our_magic),
                iface=self.iface,
                verbose=False)
            raise self.WAIT_AUTH_RESPONSE()

    @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=4)
    def wait_auth_response_rx_challenge(self, pkt):
        # We received a CHAP challenge from the peer so we must authenticate ourself.
        if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1] == Challenge):
            self.chal_id = pkt[Raw].load[1:2]
            chal_len = ord(pkt[Raw].load[4:5])
            self.challenge = pkt[Raw].load[5:5 + chal_len]
            raise self.CHAP_AUTHENTICATING()
        if (PPP in pkt) and pkt[PPP].proto == LCP:
            if pkt[Raw].load[8] == PAPProto and pkt[Raw].load[9] == PAPLength and pkt[Raw].load[
                    10:12] == PAPHex:
                raise self.PAP_AUTHENTICATING()

## Transitions from START_IPCP

    @ATMT.condition(START_IPCP)
    def start_ipcp_tx_confreq(self):
        self.log.debug("Starting IPCP", extra=self.extra_log)
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=IPCP) /
            Raw(load=confreq(Address + self.ipaddress)),
            iface=self.iface,
            verbose=False)
        raise self.IPCP_Request_Sent()

## Transitions from IPCP_Request_Sent

    @ATMT.timeout(IPCP_Request_Sent, 3)
    def ipcp_req_sent_timeout(self):
        # We timed out. Re-send Configure-Request.
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=IPCP) /
            Raw(load=confreq(Address + self.ipaddress)),
            iface=self.iface,
            verbose=False)
        raise self.IPCP_Request_Sent()

    @ATMT.receive_condition(IPCP_Request_Sent, prio=1)
    def ipcp_req_sent_rx_confack(self, pkt):
        # We received a ConfAck and can proceed with the current parameters.
        if (PPP in pkt) and pkt[PPP].proto == IPCP:
            payload = do_build(pkt[PPP].payload)
            if payload[0] == ConfAck:
                raise self.IPCP_Ack_Received()

    @ATMT.receive_condition(IPCP_Request_Sent, prio=2)
    def ipcp_req_sent_rx_confnak(self, pkt):
        # We received a ConfNak and must adjust the current parameters.
        if (PPP in pkt) and pkt[PPP].proto == IPCP:
            payload = do_build(pkt[PPP].payload)
            if payload[0:1] == ConfNak:
                suggestion = payload[6:10]
                if suggestion != self.ipaddress:
                    self.log.debug("Peer provided our IP as " + str(ord(suggestion[0:1])) + "." +
                                   str(ord(suggestion[1:2])) + "." + str(ord(suggestion[2:3])) + "."
                                   + str(ord(suggestion[3:4])),
                                   extra=self.extra_log)
                self.ipaddress = suggestion
                sendp(
                    Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                    PPP(proto=IPCP) / Raw(load=confreq(Address + self.ipaddress)),
                    iface=self.iface,
                    verbose=False)
                raise self.IPCP_Request_Sent()

    @ATMT.receive_condition(IPCP_Request_Sent, prio=3)
    def ipcp_req_sent_rx_confreq(self, pkt):
        # We received a ConfReq and must validate our peer's proposed parameters.
        if (PPP in pkt) and pkt[PPP].proto == IPCP:
            payload = do_build(pkt[PPP].payload)
            if (payload == ConfReq):
                [gwip, otherstuff] = parseconfreq(payload)
                if (len(gwip) == 4 and otherstuff == ''):
                    # If the other end just wants to negotiate its IP, we will take it.
                    sendp(
                        Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                        PPP(proto=IPCP) / Raw(load=ConfAck + payload[1:]),
                        iface=self.iface,
                        verbose=False)
                    self.gwipaddress = gwip
                    raise self.IPCP_Ack_Sent()
                else:
                    # Otherwise we ConfRej the other parameters as they are not supported.
                    sendp(
                        Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                        PPP(proto=IPCP) / Raw(
                            load=ConfRej + payload[1:2] + word(len(otherstuff) + 4) + otherstuff),
                        iface=self.iface,
                        verbose=False)
                    self.retries -= 1
                    if (self.retries < 0):
                        raise self.ERROR()
                    else:
                        raise self.IPCP_Request_Sent()

    @ATMT.receive_condition(IPCP_Request_Sent, prio=4)
    def ipcp_req_sent_rx_echo(self, pkt):
        # We received an LCP echo and need to reply.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == EchoReq):
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                PPP(proto=LCP) / Raw(load=EchoRep + pkt[Raw].load[1:2] + word(8) + self.our_magic),
                iface=self.iface,
                verbose=False)
            raise self.IPCP_Request_Sent()

## Transitions from IPCP_Ack_Received

    @ATMT.timeout(IPCP_Ack_Received, 3)
    def ipcp_ack_recv_timeout(self):
        # We timed out. Re-send Configure-Request.
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=IPCP) /
            Raw(load=confreq(Address + self.ipaddress)),
            iface=self.iface,
            verbose=False)
        raise self.IPCP_Request_Sent()

    @ATMT.receive_condition(IPCP_Ack_Received)
    def ipcp_ack_recv_got_confreq(self, pkt):
        # We received a ConfReq and must validate our peer's proposed parameters.
        if (PPP in pkt) and pkt[PPP].proto == IPCP:
            payload = do_build(pkt[PPP].payload)
            if (payload[0:1] == ConfReq):
                [gwip, otherstuff] = parseconfreq(payload)
                if (len(gwip) == 4 and otherstuff == ''):
                    # If the other end just wants to negotiate its IP, we will take it.
                    sendp(
                        Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                        PPP(proto=IPCP) / Raw(load=ConfAck + payload[1:]),
                        iface=self.iface,
                        verbose=False)
                    self.gwipaddress = gwip
                    self.log.debug(
                        "IPCP is OPEN, GW " + str(ord(self.gwipaddress[0:1])) + "." +
                        str(ord(self.gwipaddress[1:2])) + "." + str(ord(self.gwipaddress[2:3])) +
                        "." + str(ord(self.gwipaddress[3:4])),
                        extra=self.extra_log)
                    self.connected = True
                    self.error_id = 0
                    raise self.IPCP_OPEN()
                else:
                    # Otherwise we ConfRej the other parameters as they are not supported.
                    sendp(
                        Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                        PPP(proto=IPCP) / Raw(
                            load=ConfRej + payload[1:2] + word(len(otherstuff) + 4) + otherstuff),
                        iface=self.iface,
                        verbose=False)
                    self.retries -= 1
                    if (self.retries < 0):
                        raise self.ERROR()
                    else:
                        raise self.IPCP_Ack_Received()

## Transitions from IPCP_Ack_Sent

    @ATMT.timeout(IPCP_Ack_Sent, 3)
    def ipcp_ack_sent_timeout(self):
        # We timed out. Re-send Configure-Request.
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=IPCP) /
            Raw(load=confreq(Address + self.ipaddress)),
            iface=self.iface,
            verbose=False)
        raise self.IPCP_Ack_Sent()

    @ATMT.receive_condition(IPCP_Ack_Sent, prio=1)
    def ipcp_ack_sent_rx_confack(self, pkt):
        # We received a ConfAck and can proceed with the current parameters.
        if (PPP in pkt) and pkt[PPP].proto == IPCP:
            if (do_build(pkt[PPP].payload)[0:1] == ConfAck):
                raise self.IPCP_OPEN()

    @ATMT.receive_condition(IPCP_Ack_Sent, prio=2)
    def ipcp_ack_sent_rx_confnak(self, pkt):
        # We received a ConfNak and must adjust the current parameters.
        if (PPP in pkt) and pkt[PPP].proto == IPCP:
            payload = do_build(pkt[PPP].payload)
            if (payload[0:1] == ConfNak):
                suggestion = payload[6:10]
                if suggestion != self.ipaddress:
                    self.log.debug("Peer provided our IP as " + str(ord(suggestion[0:1])) + "." +
                                   str(ord(suggestion[1:2])) + "." + str(ord(suggestion[2:3])) + "."
                                   + str(ord(suggestion[3:4])),
                                   extra=self.extra_log)
                self.ipaddress = suggestion
                sendp(
                    Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                    PPP(proto=IPCP) / Raw(load=confreq(Address + self.ipaddress)),
                    iface=self.iface,
                    verbose=False)
                raise self.IPCP_Ack_Sent()

    @ATMT.receive_condition(IPCP_Ack_Sent, prio=3)
    def ipcp_ack_sent_rx_confreq(self, pkt):
        # We received a ConfReq and must re-validate our peer's proposed parameters.
        if (PPP in pkt) and pkt[PPP].proto == IPCP:
            payload = do_build(pkt[PPP].payload)
            if (payload[0:1] == ConfReq):
                [gwip, otherstuff] = parseconfreq(payload)
                if (len(gwip) == 4 and otherstuff == ''):
                    # If the other end just wants to negotiate its IP, we will take it.
                    sendp(
                        Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                        PPP(proto=IPCP) / Raw(load=ConfAck + payload[1:]),
                        iface=self.iface,
                        verbose=False)
                    self.gwipaddress = gwip
                    raise self.IPCP_Ack_Sent()
                else:
                    # Otherwise we ConfRej the other parameters as they are not supported.
                    sendp(
                        Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                        PPP(proto=IPCP) / Raw(
                            load=ConfRej + payload[1:2] + word(len(otherstuff) + 4) + otherstuff),
                        iface=self.iface,
                        verbose=False)
                    self.retries -= 1
                    if (self.retries < 0):
                        raise self.ERROR()
                    else:
                        raise self.IPCP_Request_Sent()

## Transitions from IPCP_OPEN

    @ATMT.receive_condition(IPCP_OPEN, prio=1)
    def ipcp_open_got_ip(self, pkt):
        # An IP packet came in.
        if (PPP in pkt) and pkt[PPP].proto == IPv4 and len(self.recvbuff) < self.maxrecv:
            self.recvbuff.insert(0, pkt[IP])
            raise self.IPCP_OPEN()

    @ATMT.receive_condition(IPCP_OPEN, prio=2)
    def ipcp_open_got_echo(self, pkt):
        # Automatically respond to LCP echo requests.
        if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1] == EchoReq):
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) /
                PPP(proto=LCP) / Raw(load=EchoRep + pkt[Raw].load[1:2] + word(8) + self.our_magic),
                iface=self.iface,
                verbose=False)
            raise self.IPCP_OPEN()

    @ATMT.receive_condition(IPCP_OPEN, prio=3)
    def ipcp_open_got_padt(self, pkt):
        # Shut down upon receipt of PADT.
        if (PPPoED in pkt) and (pkt[PPPoED].code == PADT):
            if not self.connected:
                self.log.debug("Received PADT, shutting down.", extra=self.extra_log)
            else:
                self.log.error("Received PADT, shutting down.", extra=self.extra_log)
            sendp(
                Ether(src=self.mac, dst=self.ac_mac) / PPPoED(code=PADT,
                                                              sessionid=self.sess_id) /
                Raw(load=TLV(Service_Name, self.servicename) + TLV(Host_Unique, self.hu) + TLV(
                    Generic_Error, "Received PADT from peer") + TLV(AC_Cookie, self.ac_cookie)),
                iface=self.iface,
                verbose=False)
            raise self.END()

    def terminate(self):
        sendp(
            Ether(src=self.mac, dst=self.ac_mac) / PPPoE(sessionid=self.sess_id) / PPP(proto=LCP) /
            Raw(load='\x05\x02' + word(len('Goodbye') + 4) + 'Goodbye'),
            iface=self.iface,
            verbose=False)
        self.connected = False
        # sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoED(code=PADT, sessionid=self.sess_id)/Raw(load=TLV(Service_Name,self.servicename)+TLV(Host_Unique, self.hu)+TLV(Generic_Error, "Received PADT from peer")+TLV(AC_Cookie,self.ac_cookie)),iface=self.iface, verbose=False)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.terminate()
        time.sleep(1)
