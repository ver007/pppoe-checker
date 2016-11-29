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


def download(url, directory,src_ip) :
    print "fileurl: " + url + '|'
    sys.stdout.flush()
    command = 'curl --header "X-Forwarded-For: '+src_ip+'" -w "@' + os.path.join(directory, 'format.txt') + '" -o ' + os.path.join(directory, 'download.tmp') + ' -s ' + url
    for line in runCommand(command):
        sys.stdout.write(line)
    #print_(runCommand(command))
    sys.stdout.flush()

def main():
    directory = os.path.dirname(os.path.realpath(__file__))
    #print "Download complete to " + directory
    url =  str(sys.argv[1])
    included =  str(sys.argv[2])
    src_ip = print(str(sys.argv[2]))
    download(url, directory)

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
                download(newUrl, directory, src_ip="127.0.0.1")
                sys.stdout.flush()


if __name__ == "__main__" :
    main()
