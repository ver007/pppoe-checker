#!/usr/bin/python
import os, sys, subprocess, shlex, re, fnmatch,signal
from subprocess import call
import smtplib
import threading
import time
import MySQLdb as mdb
def connect_mysql_db(host,port,user,password,db):
	return mdb.connect(host=host,port=port,user=user,passwd=password,db=db);
def close_mysql_db(con):
	return con.close();
def probe_file(source):
#	cmnd = ['/usr/local/bin/ffprobe', source, '-v', 'quiet' , '-show_format', '-show_streams', '-timeout', '60']
	cmnd = ['/usr/local/bin/ffprobe', source, '-v', 'quiet' , '-show_format', '-show_streams']
	p = subprocess.Popen(cmnd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	timeout = 15
	i = 0
	while p.poll() is None:
		time.sleep(1)
		i+=1
		if i > timeout:
			os.kill(p.pid, signal.SIGKILL)
	out, err = p.communicate()
#    out, err =  p.communicate()
	value=0
	for line in out.split('\n'):
		line = line.strip()
		if (line.startswith('filename=')):
			value=1
		if (line.startswith('codec_type=audio')):
			audio=1
		if (line.startswith('codec_type=video')):
			video=1
	if value == 1 and audio == 1 and video == 1:  
		return 1
	if value == 1 and audio == 1 and video == 0:
		return 2
	if value == 1 and audio == 0 and video == 1:
		return 3
	return 0
def check_probe(source,session,value,id,name,type,ip):
#	print source
	check = probe_file(source);
	if check != value:
		time.sleep(60);
		recheck = probe_file(source);
		if recheck == check:
			if check == 1:
                                status = 'up'
                        elif check == 2:
                                status = 'video error'
                        elif check == 3:
                                status = 'audio error'
			elif check == 0:
				status = 'down'
                        else:
                                status = "unknown" + str(check) + ":"
                        var=session.cursor();
#			print check
                        query="update profile_agent set status='" + str(check) + "',last_update=unix_timestamp() where id='" + str(id) + "'"
                        var.execute(query)
                        text = """
%s %s (ip:%s) status %s in host: %s
""" % ( name, type, source, status,ip)
                        query="insert into logs (host, tag, datetime, msg) values ('" + source + "', 'status' ,NOW(),'" + text + "')"
#			print query
                        var.execute(query)
                        session.commit()
        var=session.cursor();
        query="update profile_agent set `check`=0 where id='" + str(id) + "'"
#	print query
        var.execute(query);
        session.commit()
configfile='/monitor/config.py'
if os.path.exists(configfile):
	execfile(configfile)
else:
	print "can't read file config";
	exit(1)
session=connect_mysql_db(host,port,user,password,db);
cur=session.cursor();
query="select pa.id,p.ip,p.protocol,pa.status,a.thread,c.name,p.type from profile as p, agent as a, profile_agent as pa,channel as c where pa.profile_id=p.id and pa.agent_id=a.id and a.active=1 and pa.monitor=1 and p.channel_id=c.id and pa.check=1 and a.ip='" + ip +"'"
cur.execute(query);
rows = cur.fetchall();
for row in rows:
	while threading.activeCount() > row[4]:
		time.sleep(1);
	mysql=connect_mysql_db(host,port,user,password,db);
	t = threading.Thread(target=check_probe, args=(row[2]+'://'+row[1],mysql,row[3],row[0],row[5],row[6],ip,));
	t.start();
time.sleep(30);
