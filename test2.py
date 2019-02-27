#!/usr/bin/env python

from binascii import hexlify
from struct import unpack
import struct
import sys

EXPECTED_LEN = 1116
EXPECTED_QUOTELEN = 1116
EXPECTED_SIGLEN = 680
EXPECTED_ENCLEN = 360

def xlf(s):
    return hexlify(s).decode('utf-8')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('usage: %s quote' % sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    if len(data) != EXPECTED_LEN: 
        print('Unexpected quote length (%d vs %d)' % (len(data),\
            EXPECTED_QUOTELEN))

    version = struct.unpack('<H',data[:2])[0]
    sign_type = struct.unpack('<H', data[2:4])[0]
    epid_group_id = data[4:8]
    isv_svn = data[8:10]
    reserved = data[10:16]
    basename = data[16:48]
    report = data[48:432]
    siglen = struct.unpack('<I', data[432:436])[0]
    if siglen != EXPECTED_SIGLEN:
        print('Unexpected siglen (%d vs. %d)' % (siglen,\
            EXPECTED_SIGLEN))

    rsaenc = data[436:692]
    keyhash = data[692:724]
    iv = data[724:736]
    enclen = struct.unpack('<I', data[736:740])[0]
    # check clen
    if enclen != EXPECTED_ENCLEN:
        print('Unexpected enclen (%d vs. %s), is RL non-empty?' % (enclen,\
            EXPECTED_ENCLEN))
    sigenc = data[740:1092]
    rl_verenc = data[1092:1096]
    n2enc = data[1096:1100]
    tag = data[1100:1116]

    # parse report
    cpu_svn = report[0:16]
    misc_select = report[16:20]
    attributes = report[48:64]
    mr_enclave = report[64:96]
    mr_signer = report[128:160]
    isv_prod_id = report[256:258]
    isv_svn = report[258:260]
    report_data = report[320:384]

    s=  '%20s\n' % ('QUOTE') +\
        '%20s\t%d\n' % ('version', version) +\
        '%20s\t%d\n' % ('sign_type', sign_type) +\
        '%20s\t%s\n' % ('epid_group_id', xlf(epid_group_id)) +\
        '%20s\t%s\n' % ('isv_svn', xlf(isv_svn)) +\
        '%20s\t%s\n' % ('reserved', xlf(reserved)) +\
        '%20s\t%s\n' % ('basename', xlf(basename)) +\
        '%20s\t%s\n' % ('report', xlf(report)) +\
        '%20s\t%d\n' % ('siglen', siglen) +\
        '%20s\t%s\n' % ('rsaenc', xlf(rsaenc)) +\
        '%20s\t%s\n' % ('keyhash', xlf(keyhash)) +\
        '%20s\t%s\n' % ('iv', xlf(iv)) +\
        '%20s\t%d\n' % ('enclen', enclen) +\
        '%20s\t%s\n' % ('sigenc', xlf(sigenc)) +\
        '%20s\t%s\n' % ('rl_verenc', xlf(rl_verenc)) +\
        '%20s\t%s\n' % ('n2enc', xlf(n2enc)) +\
        '%20s\t%s\n' % ('tag', xlf(tag))

    print(s)

    r=  '%20s\n' % ('REPORT') +\
        '%20s\t%s\n' % ('cpu_svn', xlf(cpu_svn)) +\
        '%20s\t%s\n' % ('misc_select', xlf(misc_select)) +\
        '%20s\t%s\n' % ('attributes', xlf(attributes)) +\
        '%20s\t%s\n' % ('mr_enclave', xlf(mr_enclave)) +\
        '%20s\t%s\n' % ('mr_signer', xlf(mr_signer)) +\
        '%20s\t%s\n' % ('isv_prod_id', xlf(isv_prod_id)) +\
        '%20s\t%s\n' % ('isv_svn', xlf(isv_svn)) +\
        '%20s\t%s\n' % ('report_data', xlf(report_data))

    print(r)

    attrbyte = attributes[0]
    if not isinstance(attrbyte, int):
        attrbyte = ord(attrbyte)
    debug = attrbyte>>1&1 == 1
    mode64bit = attrbyte>>2&1 == 1
    provisionkey = attrbyte>>4&1 == 1
    einittokenkey = attrbyte>>5&1 == 1
    attr =  '%20s\n' % ('ATTRIBUTES') +\
            '%20s\t%s\n' % ('debug', debug) +\
            '%20s\t%s\n' % ('mode64bit', mode64bit) +\
            '%20s\t%s\n' % ('provisionkey', provisionkey) +\
            '%20s\t%s\n' % ('einittokenkey', einittokenkey)
    print(attr)
