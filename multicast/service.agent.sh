#!/bin/sh

#su - transcode -c '/transcode/service.sh &'
#j=0
while [ 1 ]
do
	/usr/bin/python /monitor/agent.py
done
