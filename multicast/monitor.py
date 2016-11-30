#!/usr/bin/python
import os, sys, subprocess, shlex, re, fnmatch, signal
import time
import threading
import smtplib
import MySQLdb as mdb
def db_mysql_connect(host,port,user,password,db):
	return mdb.connect(host=host,port=port,user=user,passwd=password,db=db);
def db_mysql_close(con):
	return con.close();
configfile='/monitor/config.py'
if os.path.exists(configfile):
	execfile(configfile)
else:
	print "can't read file config";
	exit(1)
from pysnmp.entity.rfc3413.oneliner import cmdgen
cmdGen = cmdgen.CommandGenerator()
errorIndication, errorStatus, errorIndex, var = cmdGen.getCmd(
    	cmdgen.CommunityData(snmp_community),
    	cmdgen.UdpTransportTarget((snmp_host, snmp_port)),
	cmdgen.MibVariable('1.3.6.1.4.1.2021.11.11.0'),
	cmdgen.MibVariable('1.3.6.1.4.1.2021.4.6.0'),
	cmdgen.MibVariable('1.3.6.1.4.1.2021.4.5.0'),
    	lookupNames=True, lookupValues=True
)
if errorIndication:
	print(errorIndication)
elif errorStatus:
    	print(errorStatus)
else:
	cpu=int(100 - int(var[0][1]))
	mem=int(100 - int(var[1][1]) * 100 / int(var[2][1]))
	session=db_mysql_connect(host,port,user,password,db);
	current=session.cursor();
	command="update agent set cpu='"+ str(cpu) +"',mem='"+ str(mem) + "',last_update=unix_timestamp() where ip='" + str(ip) +"'"
#	command="update server set cpu='"+ str(cpu) +"',mem='"+ str(mem) + "' where ip='" + str(ip) +"'"
	current.execute(command);
	session.commit()
	db_mysql_close(session)
