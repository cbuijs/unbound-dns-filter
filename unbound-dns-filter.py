#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
=========================================================================================
 dns-filter.py: v0.01-20190111 Copyright (C) 2019 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

 DNS filtering extension for the unbound DNS resolver.

=========================================================================================
'''

# Standard/Included modules
import sys, os, os.path
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Use module regex instead of re, much faster less bugs
import regex

# Use module pytricia to find ip's in CIDR's dicts fast
import pytricia

# Use requests module for downloading lists
import requests


##########################################################################################

# Log
def log(message, iserr=False):
    if iserr:
        log_err('[DNS-FILTER-ERROR]: {0}'.format(message))
    else:
        log_info('[DNS-FILTER]: {0}'.format(message))

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

# Get DNS client IP
def client_ip(qstate):
    reply_list = qstate.mesh_info.reply_list

    while reply_list:
        if reply_list.query_reply:
            return reply_list.query_reply.addr
        reply_list = reply_list.next

    return "0.0.0.0"

##########################################################################################
# UNBOUND DEFS START
##########################################################################################

# Initialization
def init(id, cfg):
    log('Initializing ...')

    # Read Lists

    log('Initializing Finished')
    return True

# Unload/Finish-up
def deinit(id):
    log('Shutting down ...')
    log('DONE!')
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
            log('REQUEST [{0}]: {1}/{2}/{3}'.format(id, qname, qclass, qtype))

        else:
            log('REQUEST-REFUSED [{0}]: {1}/{2}/{3}'.format(id, qname, qclass, qtype))
            qstate.return_rcode = RCODE_REFUSED
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        # Pass on
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    elif event == MODULE_EVENT_MODDONE:
        msg = qstate.return_msg
        if msg:
            rep = msg.rep
            rc = rep.flags & 0xf
            if (rc == RCODE_NOERROR) or (rep.an_numrrsets > 0):
                for rrset in range(0, rep.an_numrrsets):
                    rk = rep.rrsets[rrset].rk
                    rdtype = rk.type_str.upper()
                    if rdtype in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV'):
                        rdname = rk.dname_str.lower()
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
                                log('RESPONSE [{0}]: {1}/{2}/{3}'.format(id, rdname, rdtype, rdata))

        # All done
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    # Oops, non-supported event
    log('BAD Event {0}'.format(event), True)
    qstate.ext_state[id] = MODULE_ERROR

    return False

# <EOF>
