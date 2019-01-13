#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
=========================================================================================
 dns-filter.py: v0.31-20190113 Copyright (C) 2019 Chris Buijs <cbuijs@chrisbuijs.com>
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

# Use CacheTools TTLCache for cache
from cachetools import TTLCache

# Use requests module for downloading lists
import requests

# TLDExtract
import tldextract

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

# Karma regex
is_karma = regex.compile('^[a-z0-9_-]+:[0-9-]+$')

##########################################################################################

def get_data(rdtype, answer):
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
    else:
        rdata = False

    return rdata

# Decode names/strings from response message
def decode_data(rawdata, start):
    text = ''
    remain = ord(rawdata[2])
    for c in rawdata[3 + start:]:
       if remain == 0:
           text += '.'
           remain = ord(c)
           continue
       remain -= 1
       text += c
    return text.lower()

def update_cache(name, status):
    if name in cache:
        return False

    if status is True:
        log_info('UPDATE-CACHE: {0} is BLACKLISTED'.format(name))
    elif status is False:
        log_info('UPDATE-CACHE: {0} is WHITELISTED'.format(name))
    cache[name] = status

    return True

def rev_ip(ip, delimiter=None):
    revip = False
    eip = expand_ip(ip)
    prefix = False

    if '/' in eip:
        eip, prefix = regex.split('/', eip)[0:2]
    else:
        if is_ip4.search(eip):
            prefix = '32'
        elif is_ip6.search(eip):
            prefix = '128'

    if prefix:
        prefix = int(prefix)
        if is_ip4.search(eip):
            if prefix in (8, 16, 24, 32):
                revip = '.'.join(eip.split('.')[0:int(prefix / 8)][::-1]) + '.in-addr.arpa.'
            elif delimiter:
                octs = eip.split('.')[::-1]
                octs[3 - int(prefix / 8)] = octs[3 - int(prefix / 8)] + delimiter + str(prefix)
                revip = '.'.join(octs[3 - int(prefix / 8):]) + '.in-addr.arpa.'

        elif is_ip6.search(eip):
            if prefix in (4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128):
                revip = '.'.join(filter(None, regex.split('(.)', regex.sub(':', '', eip))))[0:(prefix / 4) * 2][::-1].strip('.') + '.ip6.arpa.'
            elif delimiter:
                nibs = filter(None, regex.split('(.)', regex.sub(':', '', eip)))[::-1]
                nibs[31 - int(prefix / 4)] = nibs[31 - int(prefix /4)] + delimiter + str(prefix)
                revip = '.'.join(nibs[31 - int(prefix /4):]) + '.ip6.arpa.'

    return revip

def expand_ip(ip):
    if not is_ip6.search(ip):
        return ip

    new_ip = ip

    prefix = False
    if '/' in new_ip:
        new_ip, prefix = new_ip.split('/')[0:2]
        if new_ip.endswith(':'):
            new_ip = new_ip + '0'

    if '::' in new_ip:
        padding = 9 - new_ip.count(':')
        new_ip = new_ip.replace(('::'), ':' * padding)

    parts = new_ip.split(':')
    for part in range(8):
        parts[part] = str(parts[part]).zfill(4)

    new_ip = ':'.join(parts)

    if prefix:
        new_ip = new_ip + '/' + prefix

    return new_ip

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

def get_karma(klist, wlist, blist):
    klist = karma_hits(klist, blist, False, 'BLACKLIST')
    klist = karma_hits(klist, wlist, True, 'WHITELIST')
    return klist

def karma_hits(klist, domlist, negative, name):
    log_info('KARMA: Creating {0} karmas'.format(name))
    labels = dict()
    for dom in domlist:
        cleandom = filter(None, '.'.join(tldextract.extract(dom.rstrip('.'))[:2])).strip('.')
        for label in filter(None, cleandom.split('.')):
            if len(label) > 1 and (not regex.search('^(https*|ftps*|www[a-z]*)[0-9]*$', label)):
                if label in labels:
                    labels[label] += 1
                else:
                    labels[label] = 1

            #log_info('KARMA-LABEL-{0}: {1} = {2}'.format(name, label, labels[label])) # Debugging

    maxscore = max(labels.values())
    #log_info('KARMA: Max-Score is {0}'.format(maxscore)) #Debug
    for label in labels:
        number = labels[label]
        if number > maxscore / float(100):
            score = number / float(maxscore)
            score = int(round(score * 100, 0))
            if score > 0:
                if negative:
                    score = 0 - score
                klist[label] = score
                #log_info('KARMA-LABEL [{0}]: {1} = {2}'.format(name, label, score)) # Debugging

    return klist

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
                        ip6lst[entry] = entry.lower()

                    elif is_dom.search(entry):
                        domlst[entry.strip('.').lower() + '.'] = entry.lower()
                        #if tldextract.extract(entry)[2]:
                        #    domlst[entry.strip('.').lower() + '.'] = entry
                        #else:
                        #    log_err('LIST [#{0}]: Invalid TLD: \"{1}\"'.format(count, line))

                    else:
                        try:
                            rx = regex.compile(entry, regex.I) # To test/validate
                            #rxlst[rx] = entry
                            rxlst.add(entry)
                        except BaseException as err:
                            log_err('LIST [#{0}]: Invalid Syntax: \"{1}\"'.format(count, line))
        else:
            log_err('LIST: Empty file \"{0}\"'.format(filename))

    log_info('LIST-TOTALS [{0}]: {1} Domains, {2} IPv4-Addresses, {3} IPv6-Addresses and {4} Regexes'.format(listname, len(domlst), len(ip4lst), len(ip6lst), len(rxlst)))
    return domlst, ip4lst, ip6lst, rxlst

def read_karma(filenames, listname, klist):
    for filename in filenames:
        lines = get_lines(filename, listname)
        if lines:
            count = 0
            for line in lines:
                count += 1
                entry = regex.split('\s*#\s*', line.replace('\r', '').replace('\n', ''))[0].strip() # Strip comments and line-feeds
                if entry:
                    if is_karma.search(entry):
                        elements = entry.split(':')
                        label = elements[0].lower()
                        score = elements[1]
                        #if label in klist: #DEBUG
                        #    log_info('KARMA-LIST: Overwrite score for {0}: {1} -> {2}'.format(label, klist[label], score))
                        klist[label] = int(score)
                    else:
                        log_err('KARMALIST [#{0}]: Invalid KARMA: \"{1}\"'.format(count, line))
        else:
            log_err('KARMA-LIST: Empty file \"{0}\"'.format(filename))

    return klist

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

    log_info('FILE-EXIST-ERROR: \"{0}\" file does not exist'.format(file))
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
    update_cache(testvalue, result)
    return result

def check_blacklisted(testvalue, valuetype, checkip):
    orgtestvalue = testvalue

    # Domain based checks
    if not is_ip.search(testvalue):
        # Block non-existant TLDs
        if not tldextract.extract(testvalue.rstrip('.'))[2]:
            log_info('{0}-BLACKLIST-TLD: \"{1}\"'.format(valuetype, testvalue))
            return True

        # Karma
        if config['karmaenable']:
            karmascore = 0
            if testvalue in karmacache:
                karmascore = karmacache.get(testvalue, 0)
            else:
                labels = filter(None, '.'.join(tldextract.extract(testvalue.rstrip('.'))[:2]).split('.'))
                for label in labels:
                    if len(label) > 1 and (not regex.search('^(https*|ftps*|www[a-z]*)[0-9]*$', label)):
                        score = karma.get(label, 0)
                        if score != 0:
                            #log_info('{0}-KARMA-LABEL-SCORE: {1} - {2} - {3} = {4}'.format(valuetype, testvalue, cleanlabel, label, score)) # Debug
                            if score < 0:
                                karmascore = karmascore - abs(score)
                            else:
                                karmascore = karmascore + score

                #karmascore = int(round(karmascore / len(filter(None, testvalue.split('.'))),0)) # Take average score

            if karmascore != 0:
                karmacache[testvalue] = karmascore
                if karmascore < 0: # Whitelisted
                    log_info('{0}-KARMA-DOMAIN-WHITELIST: {1} = {2}'.format(valuetype, testvalue, karmascore))
                    return False # !!! TESTING !!!
                elif karmascore > config['karmathreshold']: # Blacklisted
                    log_info('{0}-KARMA-DOMAIN-BLACKLIST: {1} = {2}'.format(valuetype, testvalue, karmascore))
                    return True # !!! TESTING !!!
                else:
                    log_info('{0}-KARMA-SCORE: {1} = {2}'.format(valuetype, testvalue, karmascore))

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
        log_info('{0}-WHITELIST-REGEX: \"{1}\" -> \"{2}\"'.format(valuetype, testvalue, match.group(0)))
        return False
    else:
        match = bl_big_rx.search(testvalue)
        if match: # Blacklisted
            log_info('{0}-BLACKLIST-REGEX: \"{1}\" -> \"{2}\"'.format(valuetype, testvalue, match.group(0)))
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
        if orgtestvalue != testvalue:
            log_info('{0}-{1}-IP: {2} -> {3} -> {4}'.format(valuetype, listname, orgtestvalue, testvalue, iplist.get_key(testvalue)))
            log_info('{0}-{1}-IP-ADD-DOMAIN: {2} ({3})'.format(valuetype, listname, orgtestvalue, testvalue))
            update_cache(orgtestvalue, rc)
        else:
            log_info('{0}-{1}-IP: {2} -> {3}'.format(valuetype, listname, orgtestvalue, iplist.get_key(testvalue)))
            iprev = rev_ip(testvalue)
            if iprev:
                log_info('{0}-{1}-IP-ADD-ARPA: {2} ({3})'.format(valuetype, listname, iprev, testvalue))
                update_cache(iprev, rc)

        return True

    return False

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
    global karma
    global karmacache

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
    karma = dict()

    # Caches
    cache = TTLCache(1024, 300) # Size and TTL
    karmacache = TTLCache(8192, 86400)

    # CNAME Collapsing
    config['collapse'] = True

    # Equalize TTLS among RRs in RRSETs
    config['equalizettl'] = True

    # Block IP Families
    config['blockip4'] = False
    config['blockip6'] = True

    # Karma
    config['karmaenable'] = False
    config['karmalist'] = ["/opt/unbound-dns-filter/karma.list"]
    config['karmathreshold'] = 15

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

    if config['karmaenable']:
        karma = get_karma(karma, wl_dom, bl_dom)
        log_info('KARMA: {0} entries'.format(len(karma)))
        karma = read_karma(config['karmalist'], 'KARMALIST', karma)
        log_info('KARMA: {0} entries'.format(len(karma)))

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
        rc = RCODE_REFUSED

        if qclass == 'IN' and qtype != 'ANY':
            if config['blockip4'] and (qtype == 'A' or (qtype == 'PTR' and qname.endswith('.in-addr.arpa.'))):
               log_info('BLOCK-IPV4: {0}/{1}'.format(qname, qtype))
            elif config['blockip6'] and (qtype == 'AAAA' or (qtype == 'PTR' and qname.endswith('.ip6.arpa.'))):
               log_info('BLOCK-IPV6: {0}/{1}'.format(qname, qtype))
               rc = RCODE_NOERROR # Search-domain workaround
            else:
               result = is_blacklisted(qname, 'QNAME', False)
               if result is not True:
                   qstate.ext_state[id] = MODULE_WAIT_MODULE
                   return True

        # REFUSE
        qstate.return_rcode = rc
        qstate.ext_state[id] = MODULE_FINISHED 
        return True

    elif event == MODULE_EVENT_MODDONE:
        msg = qstate.return_msg
        if msg:
            rep = msg.rep
            repttl = rep.ttl
            rc = rep.flags & 0xf
            status = None
            if (rc == RCODE_NOERROR) and (rep.an_numrrsets > 0):
                rrs = list()
                for rrset in range(0, rep.an_numrrsets):
                    rk = rep.rrsets[rrset].rk
                    rdtype = rk.type_str.upper()
                    if rdtype in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV'):
                        rdname = rk.dname_str.lower()
                        status = is_blacklisted(rdname, 'CHAIN-QNAME', False)
                        if status is not None:
                           break

                        data = rep.rrsets[rrset].entry.data

                        # Equalize TTLS
                        if config['equalizettl']:
                            for rr in range(0, data.count):
                                data.rr_ttl[rr] = repttl

                        # Check data
                        countrr = 0
                        for rr in range(0, data.count):
                            answer = data.rr_data[rr]
                            #rdttl = data.rr_ttl[rr]
                            rdata = get_data(rdtype, answer)
                            if rdata:
                                status = is_blacklisted(rdata, 'DATA', True)
                                if status is not None:
                                    update_cache(rdname, status)
                                    break

                            rrs.append((rdname, repttl, rdtype, rdata))

                        if status is not None: # It is White or Blacklisted
                            break

                if status is not True: # Not white/blacklisted
                    if config['collapse'] and status is None and rrs and rrs[0][2] == 'CNAME':
                        firstname = rrs[0][0]

                        if rrs[-1][2] == 'A':
                            rmsg = DNSMessage(firstname, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA )
                        else:
                            rmsg = DNSMessage(firstname, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR | PKT_RA )

                        for rr in rrs:
                            if rr[2] == rrs[-1][2]:
                                rmsg.answer.append('{0} {1} IN {2} {3}'.format(firstname, repttl, rr[2], rr[3]))

                            rmsg.set_return_msg(qstate)
                            if not rmsg.set_return_msg(qstate):
                                log_err('CNAME COLLAPSE ERROR: ' + str(rmsg.answer))
                                qstate.ext_state[id] = MODULE_ERROR
                                return True

                        log_info('COLLAPSED: {0}'.format(firstname))
            else:
                qstate.return_rcode = rc

            if status is not True:
                # Allow changes and cache
                #qstate.return_rcode = RCODE_NOERROR
                if qstate.return_msg.qinfo:
                    invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                qstate.no_cache_store = 0
                qstate.return_msg.rep.security = 2
                storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)
                qstate.ext_state[id] = MODULE_FINISHED
                return True

        else:
            log_err('NO RESPONSE MESSAGE')
            qstate.ext_state[id] = MODULE_ERROR
            return True

        # Refuse
        if qstate.return_msg.qinfo:
            invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
        qstate.no_cache_store = 1
        qstate.return_msg.rep.security = 2
        qstate.return_rcode = RCODE_REFUSED
        qstate.ext_state[id] = MODULE_FINISHED 
        return True

    # Oops, non-supported event
    log_info('BAD Event {0}'.format(event), True)
    qstate.ext_state[id] = MODULE_ERROR

    return False

# <EOF>
