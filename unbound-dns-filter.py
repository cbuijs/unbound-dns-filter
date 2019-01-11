#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
=========================================================================================
 dns-filter.py: v0.06-20190111 Copyright (C) 2019 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

 DNS filtering extension for the unbound DNS resolver.

=========================================================================================
'''

# Standard/Included modules
import sys, os, os.path, time
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Data
import json, struct
import configparser

# Use module regex instead of re, much faster less bugs
import regex

# Use module pytricia to find ip's in CIDR's dicts fast
import pytricia

# Use requests module for downloading lists
import requests


##########################################################################################

# Domain Regex
is_dom = regex.compile('(?=^.{1,253}[a-z][\.]*$)(^((?!-)[a-z0-9_-]{0,62}[a-z0-9]\.)*(xn--[a-z0-9-]{1,59}|[a-z]{2,63})[\.]*$)', regex.I)

# IP Regexes
ip_rx4 = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip_rx6 = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
is_ip4 = regex.compile('^' + ip_rx4 + '$', regex.I)
is_ip6 = regex.compile('^' + ip_rx6 + '$', regex.I)
is_ip = regex.compile('^(' + ip_rx4 + '|' + ip_rx6 + ')$', regex.I)

# IP Arpa Regexes
ip4arpa_rx = '([0-9]{1,3}\.){4}in-addr'
ip6arpa_rx = '([0-9a-f]\.){32}ip6'
ip4arpa = regex.compile('^' + ip4arpa_rx + '\.arpa[\.]*$', regex.I)
ip6arpa = regex.compile('^' + ip6arpa_rx + '\.arpa[\.]*$', regex.I)
iparpa = regex.compile('^(' + ip4arpa_rx + '|' + ip6arpa_rx + ')\.arpa[\.]*$', regex.I)

##########################################################################################

# Decode names/strings from response message
def decode_data(rawdata, start):
    text = ''
    remain = ord(rawdata[2])
    for c in rawdata[3+start:]:
       if remain == 0:
           text += '.'
           remain = ord(c)
           continue
       remain -= 1
       text += c
    return text.lower()

# Get config
def get_config(config, conffile):
    section = 'UNBOUND-DNS-FILTER'

    pconfig = configparser.ConfigParser()
    pconfig.sections()
    pconfig.read(conffile)

    for key in pconfig[section]:
        try:
            config[key.lower()] = json.loads(pconfig.get(section, key))
            #log_info('CONFIG-{0}: \"{1}\" = \"{2}\"'.format(str(type(config[key])).upper().split('\'')[1], key.lower(), config[key]))
        except BaseException as err:
            log_err('CONFIG-ERROR: Problem parsing \"{0}\" - {1}'.format(key.lower(), err))
            log_err('ABORT!')
            sys.exit(1)

    return config

def read_list(filenames, listname, domlst, ip4lst, ip6lst, rxlst):
    for filename in filenames:
        lines = get_lines(filename, listname)

        if lines:
            count = 0
            for line in lines:
                count += 1
                entry = regex.split('\s*#\s*', line.replace('\r', '').replace('\n', ''))[0].strip() # Strip comments and line-feeds
                if entry:
                    if is_ip4.search(entry):
                        ip4lst[entry] = entry

                    elif is_ip6.search(entry):
                        ip6lst[entry] = entry

                    elif is_dom.search(entry):
                        domlst[entry.strip('.').lower() + '.'] = entry

                    else:
                        try:
                            rx = regex.compile(entry, regex.I) # To test/validate
                            #rxlst[rx] = entry
                            rxlst.add(entry)
                        except BaseException as err:
                            log_err('LIST [#{0}]: Invalid Syntax: \"{1}\"'.format(count, line))


    log_info('LIST-TOTALS [{0}]: {1} Domains, {2} IPv4-Addresses, {3} IPv6-Addresses and {4} Regexes'.format(listname, len(domlst), len(ip4lst), len(ip6lst), len(rxlst)))
    return domlst, ip4lst, ip6lst, rxlst

def file_exist(file, isdb):
    if file:
        try:
            if os.path.isfile(file):
                fstat = os.stat(file)
                fsize = fstat.st_size
                if fsize > 0: # File-size must be greater then zero
                    mtime = int(fstat.st_mtime)
                    currenttime = int(time.time())
                    age = int(currenttime - mtime)
                    #log_info('FILE-EXIST: {0} = {1} seconds old'.format(file, age))
                    return age
                #else:
                    #log_info('FILE-EXIST: {0} is zero size'.format(file))

        except BaseException as err:
            log_err('FILE-EXIST-ERROR: {0}'.format(err))
            return False

    return False

def get_lines(filename, listname):
    log_info('READ-LIST: {0} - {1}'.format(filename, listname))
    lines = False

    if filename.startswith('http://') or filename.startswith('https://'):
        log_info('FETCH: Downloading \"{0}\" from URL \"{1}\"'.format(listname, filename))
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'}
        try:
            r = requests.get(filename, timeout=10, headers=headers, allow_redirects=True)
            if r.status_code == 200:
                lines = r.text.splitlines()
            else:
                log_err('ERROR: Unable to download from \"{0}\" ({1})'.format(filename, r.status_code))

        except BaseException as err:
            log_err('ERROR: Unable to download from \"{0}\" ({1})'.format(filename, err))

    elif file_exist(filename, False):
        log_info('FETCH: Fetching \"{0}\" from file \"{1}\"'.format(listname, filename))
        try:
            f = open(filename, 'r')
            lines = f.read().splitlines()
            f.close()

        except BaseException as err:
            log_err('ERROR: Unable to open/read/process file \"{0}\" - {1}'.format(filename, err))
            return False

    return lines

def is_blacklisted(value, valuetype, checkip):
    testvalue = regex.split('\s+', str(value))[-1]
    if testvalue in cache:
        result = cache.get(testvalue, None)
        if result is True:
            log_info('CACHE-BLACKLISTED: {0}'.format(testvalue))
        elif result is False:
            log_info('CACHE-WHITELISTED: {0}'.format(testvalue))
        return result

    result = check_blacklisted(testvalue, valuetype, checkip)
    cache[testvalue] = result
    return result

def check_blacklisted(testvalue, valuetype, checkip):
    orgtestvalue = testvalue

    # Check against domain
    if is_dom.search(testvalue):
        if check_dom(valuetype, testvalue, wl_dom, 'WHITELIST'): # Whitelisted
            return False

        elif check_dom(valuetype, testvalue, bl_dom, 'BLACKLIST'): # Blacklisted
            return True

        # Check if Domain is a rev-arpa domain, if it is, check its IP value
        ip = False
        if ip4arpa.search(testvalue):
            ip = '.'.join(testvalue.strip('.').split('.')[0:4][::-1]) # IPv4
        elif ip6arpa.search(testvalue):
            ip = ':'.join(filter(None, regex.split('(.{4,4})', ''.join(testvalue.strip('.').split('.')[0:32][::-1])))) # IPv6

        if ip:
            checkip = True
            testvalue = ip

    # Check against IP4
    if checkip and is_ip4.search(testvalue):
        # Check if IPv4 is whitelisted
        if check_ip(valuetype, testvalue, orgtestvalue, wl_ip4, 'WHITELIST', False):
            return False
        # Check if IPv4 is blacklisted
        elif check_ip(valuetype, testvalue, orgtestvalue, bl_ip4, 'BLACKLIST', True):
            return True

    # Check against IP6
    elif checkip and is_ip6.search(testvalue):
        # Check if IPv6 is whitelisted
        if check_ip(valuetype, testvalue, orgtestvalue, wl_ip6, 'WHITELIST', False):
            return False
        # Check if IPv6 is blacklisted
        elif check_ip(valuetype, testvalue, orgtestvalue, bl_ip6, 'BLACKLIST', True):
            return True

    # Check against regex
    match = wl_big_rx.search(testvalue)
    if match: # Whitelisted
        log_info('{0}-WHITELIST-RX: \"{1}\" -> \"{2}\"'.format(valuetype, testvalue, match.group(0)))
        return False
    else:
        match = bl_big_rx.search(testvalue)
        if match: # Blacklisted
            log_info('{0}-BLACKLIST-RX: \"{1}\" -> \"{2}\"'.format(valuetype, testvalue, match.group(0)))
            return True

    return None

def check_dom(valuetype, testvalue, domlist, listname):
    '''Match domain against list, works for subdomains to'''
    fqdn = False
    for label in filter(None, testvalue.split('.')[::-1]):
        if fqdn:
            fqdn = label + '.' + fqdn
        else:
            fqdn = label + '.'

        # Check if Domain Whitelisted
        if fqdn in domlist:
            log_info('{0}-{1}-DOMAIN: \"{2}\" -> \"{3}\"'.format(valuetype, listname, testvalue, fqdn))
            return fqdn

    return False

def check_ip(valuetype, testvalue, orgtestvalue, iplist, listname, rc):
    '''Check if IP is listed'''
    if testvalue in iplist:
        log_info('{0}-{1}-IP-DOMAIN: {2} -> {3}'.format(valuetype, listname, orgtestvalue, iplist.get_key(testvalue)))
        return True

    return False

def fix_cache(msg, qstate):
    msg.set_return_msg(qstate)
    if qstate.return_msg.qinfo:
        invalidateQueryInCache(qstate, qstate.return_msg.qinfo)

    qstate.no_cache_store = 0
    storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)

    qstate.return_msg.rep.security = 2

    return qstate

##########################################################################################
# UNBOUND DEFS START
##########################################################################################

# Initialization
def init(id, cfg):
    log_info('Initializing ...')

    # Global vars
    global config
    global wl_dom
    global bl_dom
    global wl_ip4
    global bl_ip4
    global wl_ip6
    global bl_ip6
    #global wl_rx
    #global bl_rx
    global wl_big_rx
    global bl_big_rx
    global cache

    # Init Lists
    config = dict()
    wl_dom = dict()
    bl_dom = dict()
    wl_ip4 = pytricia.PyTricia(32)
    bl_ip4 = pytricia.PyTricia(32)
    wl_ip6 = pytricia.PyTricia(28)
    bl_ip6 = pytricia.PyTricia(28)
    wl_rx = set()
    bl_rx = set()
    cache = dict()

    # CNAME Collapsing
    config['collapse'] = True

    # Block IP Families
    config['blockip4'] = False
    config['blockip6'] = True

    # White/Blacklists
    # See: https://github.com/cbuijs/accomplist/tree/master/standard
    config['whitelist'] = ["/opt/accomplist/standard/plain.white.domain.list", "/opt/accomplist/standard/plain.white.ip4cidr.list", "/opt/accomplist/standard/plain.white.ip6cidr.list", "/opt/accomplist/standard/plain.white.regex.list"]
    config['blacklist'] = ["/opt/accomplist/standard/plain.black.domain.list", "/opt/accomplist/standard/plain.black.ip4cidr.list", "/opt/accomplist/standard/plain.black.ip6cidr.list", "/opt/accomplist/standard/plain.black.regex.list"]

    # Get config
    config = get_config(config, '/opt/unbound-dns-filter/unbound-dns-filter.conf')

    # Read lists
    wl_dom, wl_ip4, wl_ip6, wl_rx = read_list(config['whitelist'], 'WhiteList', wl_dom, wl_ip4, wl_ip6, wl_rx)
    bl_dom, bl_ip4, bl_ip6, bl_rx = read_list(config['blacklist'], 'BlackList', bl_dom, bl_ip4, bl_ip6, bl_rx)

    # Create combined regex for speed
    try:
        wl_big_rx = regex.compile('|'.join('(?:{0})'.format(x) for x in wl_rx), regex.I)
        bl_big_rx = regex.compile('|'.join('(?:{0})'.format(x) for x in bl_rx), regex.I)
    except BaseException as err:
        log_err('BIG-REGEX-COMPILE-ERROR: {0}'.format(err))

    log_info('Initializing Finished')

    return True

# Unload/Finish-up
def deinit(id):
    log_info('Shutting down ...')
    log_info('DONE!')
    return True

# Inform_Super
def inform_super(id, qstate, superqstate, qdata):
    return True

# Main beef/process
def operate(id, event, qstate, qdata):
    # New query or new query passed by other module
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
        qname = qstate.qinfo.qname_str.lower()
        qclass = qstate.qinfo.qclass_str.upper()
        qtype = qstate.qinfo.qtype_str.upper()

        if qclass == 'IN' and qtype != 'ANY':
            result = is_blacklisted(qname, 'QNAME', False)
            if result is not True:
                qstate.ext_state[id] = MODULE_WAIT_MODULE
                return True

        qstate.return_rcode = RCODE_REFUSED
        qstate.ext_state[id] = MODULE_FINISHED 
        return True

    elif event == MODULE_EVENT_MODDONE:
        msg = qstate.return_msg
        if msg:
            rep = msg.rep
            rc = rep.flags & 0xf
            if (rc == RCODE_NOERROR) or (rep.an_numrrsets > 0):
                status = None
                rrs = list()
                for rrset in range(0, rep.an_numrrsets):
                    rk = rep.rrsets[rrset].rk
                    rdtype = rk.type_str.upper()
                    if rdtype in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV'):
                        rdname = rk.dname_str.lower()
                        status = is_blacklisted(rdname, 'CHAIN-QNAME', False)
                        if status is not None:
                           break

                        rdttl = rep.ttl
                        data = rep.rrsets[rrset].entry.data
                        countrr = 0
                        for rr in range(0, data.count):
                            answer = data.rr_data[rr]
                            rdata = False
                            if rdtype == 'A':
                                rdata = "%d.%d.%d.%d"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]))
                            elif rdtype == 'AAAA':
                                rdata = "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]),ord(answer[6]),ord(answer[7]),ord(answer[8]),ord(answer[9]),ord(answer[10]),ord(answer[11]),ord(answer[12]),ord(answer[13]),ord(answer[14]),ord(answer[15]),ord(answer[16]),ord(answer[17]))
                            elif rdtype in ('CNAME', 'NS'):
                                rdata = decode_data(answer,0)
                            elif rdtype == 'MX':
                                rdata = decode_data(answer,1)
                            elif rdtype == 'PTR':
                                rdata = decode_data(answer,0)
                            elif rdtype == 'SOA':
                                rdata = decode_data(answer,0).split(' ')[0][0]
                            elif rdtype == 'SRV':
                                rdata = decode_data(answer,5)

                            if rdata:
                                status = is_blacklisted(rdata, 'DATA', True)
                                if status is not None:
                                    break

                            rrs.append((rdname, rdttl, rdtype, rdata))

                        if status is not None: # It is White or Blacklisted
                            break

                if status is not True: # Not blacklisted
                    if rrs:
                        for rr in rrs:
                            log_info('RESPONSE: {0} {1} IN {2} {3}'.format(rr[0], rr[1], rr[2], rr[3]))

                    if config['collapse'] and rrs and rrs[0][2] == 'CNAME':
                        lastttl = rrs[-1][1]
                        firstname = rrs[0][0]

                        if rrs[-1][2] == 'A':
                            rmsg = DNSMessage(firstname, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA )
                        else:
                            rmsg = DNSMessage(firstname, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR | PKT_RA )

                        for rr in rrs:
                            if rr[2] == rrs[-1][2]:
                                rmsg.answer.append('{0} {1} IN {2} {3}'.format(firstname, lastttl, rr[2], rr[3]))

                            rmsg.set_return_msg(qstate)
                            if not rmsg.set_return_msg(qstate):
                                log_err('CNAME COLLAPSE ERROR: ' + str(rmsg.answer))
                                qstate.ext_state[id] = MODULE_ERROR
                                return True

                            # Allow changes
                            qstate.return_rcode = RCODE_NOERROR
                            if qstate.return_msg.qinfo:
                                invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                            qstate.no_cache_store = 0
                            storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)
                            qstate.return_msg.rep.security = 2

                        log_info('COLLAPSED: {0}'.format(firstname))

                    # End of processing
                    qstate.ext_state[id] = MODULE_FINISHED
                    return True

        # Block
        qstate.return_rcode = RCODE_REFUSED
        if qstate.return_msg.qinfo:
            invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
        qstate.no_cache_store = 0
        storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)
        qstate.return_msg.rep.security = 2
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    # Oops, non-supported event
    log_info('BAD Event {0}'.format(event), True)
    qstate.ext_state[id] = MODULE_ERROR

    return False

# <EOF>
