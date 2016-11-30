#!/bin/sh

#su - transcode -c '/transcode/service.sh &'
j=0
while [ 1 ]
do
	/usr/bin/python /monitor/agent_check.py
	if [ $j -eq 3 ]
	then
		/usr/bin/python /monitor/monitor.py
		j=0
	fi
	j=`expr $j + 1`
done
