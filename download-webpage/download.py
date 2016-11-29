import requests
import sys
import time
import os
import re
import shlex
import subprocess
#from subprocess import Popen, PIPE, STDOUT

def runCommand(command):
    p = subprocess.Popen(shlex.split(command),
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return iter(p.stdout.readline, b'')
    #return Popen(shlex.split(command), stdout=PIPE, stderr=STDOUT)
    #try:
    #    return subprocess.check_output(command)
    #except subprocess.CalledProcessError, e:
    #    return "Error stdout output: ", e.output


def download(url, directory, src_ip) :
    print "fileurl: " + url + '|'
    sys.stdout.flush()
    command = 'curl -H "X-Forwarded-For: '+src_ip+'" -w "@' + os.path.join(directory, 'format.txt') + '" -o ' + os.path.join(directory, 'download.tmp') + ' -s ' + url
    for line in runCommand(command):
        sys.stdout.write(line)
    #print_(runCommand(command))
    sys.stdout.flush()

def main():
    directory = os.path.dirname(os.path.realpath(__file__))
    #print "Download complete to " + directory
    url =  str(sys.argv[1])
    included =  str(sys.argv[2])
    form_ip = str(sys.argv[3])

    download(url, directory,form_ip)

    if (included == 'true'):
        readFile = open(os.path.join(directory, 'download.tmp'))
        strText = readFile.read()

        fileList = []

        for match in re.finditer('((src)|(href))+="((.[^"\']*)\.((js)|(jpg)|(jpeg)|(png)|(gif))+?)"', strText):
            newUrl = str(match.group(4))
            if (newUrl in fileList):
                pass
            else:
                fileList.append(newUrl)
                download(newUrl, directory, form_ip)
                sys.stdout.flush()


if __name__ == "__main__" :
    main()
