# _*_ coding:utf-8 _*_

import logging
import sys
import requests

logging.basicConfig(filename='Weblogic.log',
                    format='%(asctime)s %(message)s',
                    filemode="w", level=logging.INFO)

VUL=['CVE_2018_2894']
headers = {'user-agent': 'ceshi/0.0.1'}

def islive(ur,port):
    url='http://' + str(ur)+':'+str(port)+'/ws_utc/resources/setting/options/general'
    r = requests.get(url, headers=headers)
    return r.status_code

def run(url,port,index,q):
    if islive(url,port)!=404:
        logging.info('[+]{}:{}  deserialization vulnerability:{}.'.format(url,port,VUL[index]))
        q.put('[+]{}:{}  deserialization vulnerability:{}.'.format(url,port,VUL[index]))
    else:
        logging.info('[-]{}:{} not detected {}.'.format(url,port,VUL[index]))

if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    q = sys.argv[4]
    run(url,port,0,q)
