# _*_ coding:utf-8 _*_

import sys
import os
import logging
import re
from multiprocessing import Pool, Manager
import argparse
import poc.Console
import poc.CVE_2014_4210
import poc.CVE_2016_0638
import poc.CVE_2016_3510
import poc.CVE_2017_3248
import poc.CVE_2017_3506
import poc.CVE_2017_10271
import poc.CVE_2018_2628
import poc.CVE_2018_2893
import poc.CVE_2018_2894
import poc.CVE_2019_2725
import poc.CVE_2019_2729

logging.basicConfig(filename='Weblogic.log',
                    format='%(asctime)s %(message)s',
                    filemode="w", level=logging.INFO)

version = "1.0"
banner='''
__        __   _     _             _        ____                  
\ \      / /__| |__ | | ___   __ _(_) ___  / ___|  ___ __ _ _ __  
 \ \ /\ / / _ \ '_ \| |/ _ \ / _` | |/ __| \___ \ / __/ _` | '_ \ 
  \ V  V /  __/ |_) | | (_) | (_| | | (__   ___) | (_| (_| | | | |
   \_/\_/ \___|_.__/|_|\___/ \__, |_|\___| |____/ \___\__,_|_| |_|
                             |___/ 
                             
'''.format(version)

def parse_args():
    parser = argparse.ArgumentParser(prog='weblogicscan',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description='* Weblogic vulnerability Scanner. *\n'
                                                 'Modify By HMO',
                                     usage='weblogic.py [options]')

    parser.add_argument('-f', metavar='TargetFile', type=str, default='',
                        help='Load new line delimited targets from TargetFile')

    parser.add_argument('-p', metavar='ProcessNumber', type=int, default='10',
                        help='Number of prcesses,default vaule 10')
    if len(sys.argv) == 1:
        sys.argv.append('-h')

    args = parser.parse_args()
    check_args(args)
    return args

def check_args(args):
    if not args.f and not args.p:
        msg = 'Args missing! One of following args should be specified  \n           ' \
              '-f TargetFile \n           '
        print msg
        exit(-1)

    if args.f and not os.path.isfile(args.f):
        print 'TargetFile not found: %s' % args.f
        exit(-1)



def board(path,pn=10):
    print('Welcome To use WeblogicScan')
    poolmanage(path,pn)


def poolmanage(path,pn):
    pool = Pool(pn)
    queue = Manager().Queue()
    fr = open(path, 'r')
    rtar = fr.readlines()
    fr.close()
    for i in range(len(rtar)):
        ruleip=re.compile('(.*?):')
        rip =(ruleip.findall(rtar[i]))[0]
        ruleport=re.compile(':(.*)')
        rport=ruleport.findall(rtar[i])[0]
        pool.apply_async(work,args=(rip,rport,queue))
    pool.close()
    pool.join()
    print('task done\n')

def ouput(queue):
    file = open('reuslt.txt','w')
    while True:
        try:
            target = queue.get[False]
            file.write(target+'\n')
        except:
            break
    file.close()
    print('output file:result.txt')


def work(rip,rport,q):
    print ('[*]Add target，target:{}:{}\n'.format(rip,rport))
    try:
        poc.Console.run(rip, rport,q)
    except:
        logging.info ("[-]{}:{} console address not found.".format(rip,rport))

    try:
        poc.CVE_2014_4210.run(rip,rport,q)
    except:
        logging.info ("[-]{}:{} not detected CVE_2014_4210.".format(rip,rport))

    try:
        poc.CVE_2016_0638.run(rip,rport,0,q)
    except:
        logging.info ("[-]{}:{} not detected CVE_2016_0638.".format(rip,rport))

    try:
        poc.CVE_2016_3510.run(rip, rport,0,q)
    except:
        logging.info ("[-]{}:{} not detected CVE_2016_3510.".format(rip,rport))

    try:
        poc.CVE_2017_3248.run(rip, rport,0,q)
    except:
        logging.info ("[-]{}:{} not detected CVE_2017_3248.".format(rip,rport))

    try:
        poc.CVE_2017_3506.run(rip, rport,0,q)
    except:
        logging.info ("[-]{}:{} not detected CVE_2017_3506.".format(rip,rport))

    try:
        poc.CVE_2017_10271.run(rip, rport,0,q)
    except:
        logging.info("[-]{}:{} not detected CVE_2017_10271.".format(rip,rport))

    try:
        poc.CVE_2018_2628.run(rip, rport,0,q)
    except:
        logging.info("[-]{}:{} not detected CVE_2018_2628.".format(rip,rport))

    try:
        poc.CVE_2018_2893.run(rip, rport,0,q)
    except:
        logging.info("[-]{}:{} not detected CVE_2018_2893.".format(rip,rport))

    try:
        poc.CVE_2018_2894.run(rip, rport,0,q)
    except:
        logging.info("[-]{}:{} not detected CVE_2018_2894.".format(rip,rport))

    try:
        poc.CVE_2019_2725.run(rip, rport,0,q)
    except:
        logging.info("[-]{}:{} not detected CVE_2019_2725.".format(rip,rport))

    try:
        poc.CVE_2019_2729.run(rip, rport,0,q)
    except:
        logging.info("[-]{}:{} not detected CVE_2019_2729.".format(rip,rport))

    print ('[*]target done，target:{}:{}\n'.format(rip,rport))


def run(path,pn):
    board(path,pn)

if __name__ == '__main__':
    print (banner)
    args = parse_args()
    if args.f:
        input_files = [args.f]
    if args.p:
        pn = [args.p]

    run(input_files[0],pn[0])
