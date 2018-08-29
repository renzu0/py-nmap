#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Date: 2018/8/29

#!/usr/bin/python
#-*- coding:utf-8 -*-

import nmap
import re
import mytools as tool
import sys
from multiprocessing import Pool
from functools import partial
import smtplib
from email.mime.text import MIMEText

reload(sys)
sys.setdefaultencoding('utf8')

def nmScan(host,portrange,whitelist):
        p = re.compile("^(\d*)\-(\d*)$")
        # if type(hostlist) != list:
        #     help()
        portmatch = re.match(p,portrange)
        if not portmatch:
            help()

        if host == '121.42.32.172':
            whitelist = [25,]
        result = ''
        nm = nmap.PortScanner()
        tmp = nm.scan(host,portrange)
        result = result + "<h2>ip地址:%s 主机名:[%s]  ......  %s</h2><hr>" %(host,tmp['scan'][host]['hostnames'],tmp['scan'][host]['status']['state'])
        try:
            ports = tmp['scan'][host]['tcp'].keys()
            for port in ports:
                info = ''
                if port not in whitelist:
                   info = '<strong><font color=red>Alert:非预期端口</font><strong>&nbsp;&nbsp;'
                else:
                   info = '<strong><font color=green>Info:正常开放端口</font><strong>&nbsp;&nbsp;'
                portinfo = "%s <strong>port</strong> : %s &nbsp;&nbsp;<strong>state</strong> : %s &nbsp;&nbsp;<strong>product<strong/> : %s <br>" %(info,port,tmp['scan'][host]['tcp'][port]['state'],                                                                       tmp['scan'][host]['tcp'][port]['product'])
                result = result + portinfo
        except KeyError,e:
            if whitelist:
                whitestr = ','.join(whitelist)
                result = result + "未扫到开放端口!请检查%s端口对应的服务状态" %whitestr
            else:
                result = result + "扫描结果正常，无暴漏端口"
        return result

def help():
        print "Usage: nmScan(['127.0.0.1',],'0-65535')"
        return None

if __name__ == "__main__":
    hostlist = ['127.0.0.1']
    pool = Pool(5)
    nmargu = partial(nmScan,portrange='0-65535',whitelist=[])
    results = pool.map(nmargu,hostlist)
    #send email
    sender = '@163.com'
    receiver = '@qq.com'
    smtpuser = '@163.com'
    smtppass = 'a123456'
    mailcontent = '<br>'.join(results)
    msg = MIMEText(mailcontent,'html')
    msg['Subject'] = '服务器端口扫描'
    msg['From'] = sender
    msg['To'] = receiver
    s = smtplib.SMTP(host='smtp.163.com')
    s.login(smtpuser,smtppass)
    s.sendmail(sender, receiver, msg.as_string())
    s.close()