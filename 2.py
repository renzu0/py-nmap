# !/usr/bin/python
# -*- coding:utf-8 -*-

import nmap
import re
import sys
import smtplib
from email.mime.text import MIMEText

reload(sys)
sys.setdefaultencoding('utf8')


def Scan(hostlist, portrange, whitelist):
    p = re.compile("^(\d*)\-(\d*)$")


    if type(hostlist) != list:
        help()
    portmatch = re.match(p, portrange)
    if not portmatch:
        help()
    l = []
    for host in hostlist:
        result = ''
        nm = nmap.PortScanner()
        tmp = nm.scan(host, portrange)
        print tmp
        result = result + "<h2>ip地址:%s 主机名:%s  ......  %s</h2><hr>"%(host, tmp['scan'][host]['hostnames'], tmp['scan'][host]['status']['state'])
    try:
        ports = tmp['scan'][host]['tcp'].keys()
    except KeyError, e:
        if whitelist:
            whitestr = ','.join(whitelist)
            result = result + "未扫到开放端口!请检查%s端口对应的服务状态"%whitestr
        else:
            result = result + "扫描结果正常，无暴漏端口"
    for port in ports:
        info = ''
        if port not in whitelist:
            info = '<strong><font color=red>Alert:非预期端口</font><strong>&nbsp;&nbsp;'
        else:
            info = '<strong><font color=green>Info:正常开放端口</font><strong>&nbsp;&nbsp;'
        portinfo = "%s <strong>port</strong> : %s &nbsp;&nbsp;<strong>state</strong> : %s &nbsp;&nbsp;<strong>product<strong/> : %s <br>" % (
        info, port, tmp['scan'][host]['tcp'][port]['state'],
        tmp['scan'][host]['tcp'][port]['product'])
        result = result + portinfo
    l.append([host, str(result)])
    return l


def help():
    print "Usage: nmScan(['127.0.0.1',],'0-65535')"




if __name__ == "__main__":
    hostlist = ['10.15.168.39']
    portrange = '0-65535'
    whitelist = [80, 443]
    l = Scan(hostlist, portrange, whitelist)
    sender = '@163.com'
    receiver = '@qq.com'
    smtpuser = '@163.com'
    smtppass = ''
    mailcontent=''
    for i in range(len(l)):
       mailcontent = mailcontent + l[i][1]
    msg = MIMEText(mailcontent)
    msg['Subject'] = '服务器端口扫描'
    msg['From'] = sender
    msg['To'] = receiver
    s = smtplib.SMTP(host='smtp.163.com')
    s.login(smtpuser,smtppass)
    s.sendmail(sender, receiver, msg.as_string())
    s.close()
