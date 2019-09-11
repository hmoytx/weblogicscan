# _*_ coding:utf-8 _*_

import logging
import sys
import requests

logging.basicConfig(filename='Weblogic.log',
                    format='%(asctime)s %(message)s',
                    filemode="w", level=logging.INFO)

headers = {'user-agent': 'ceshi/0.0.1'}

def islive(ur,port):
    url='http://' + str(ur)+':'+str(port)+'/console/login/LoginForm.jsp'
    r = requests.get(url, headers=headers)
    return r.status_code

def run(url,port,q):
    if islive(url,port)==200:
        u='http://' + str(url)+':'+str(port)+'/console/login/LoginForm.jsp'
        logging.info("[+]{}:{} console found! path is: {} ".format(url,port,u))
        q.put["[+]{}:{} console found! path is: {} ".format(url,port,u)]
    else:
        logging.info('[-]{}:{} console not found!'.format(url,port))

if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    q = sys.argv[3]
    run(url,port,q)
