#!/usr/bin/env python3

import re
import random

from scapy.all import (
    Ether,
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    bind_layers,
    srp1,
    XLongField
)

from scapy.fields import Field
from scapy.utils import hexdump
import struct
import secrets

class P4calc(Packet):
    name = "P4calc"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    
                    IntField("switch1_max_pool_index", 0x04),
                    IntField("switch1_replication", 0x03),
                    XLongField("input_data",0x0000000000000000),
                    
                    IntField("replication", 0x00),
                    XLongField("res",0x00000000000000000000000000000000),
                    IntField("index", 0x00),
                    ]

bind_layers(Ether, P4calc, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

class Token:
    def __init__(self,type,value = None):
        self.type = type
        self.value = value

def num_parser(s, i, ts):
    pattern = "^\s*([0-9]+)\s*"
    match = re.match(pattern,s[i:])
    if match:
        ts.append(Token('num', match.group(1)))
        return i + match.end(), ts
    raise NumParseError('Expected number literal.')


def op_parser(s, i, ts):
    pattern = "^\s*([-+&|^])\s*"
    match = re.match(pattern,s[i:])
    if match:
        ts.append(Token('num', match.group(1)))
        return i + match.end(), ts
    raise NumParseError("Expected binary operator '-', '+', '&', '|', or '^'.")


def make_seq(p1, p2):
    def parse(s, i, ts):
        i,ts2 = p1(s,i,ts)
        return p2(s,i,ts2)
    return parse


def main():

    p = make_seq(num_parser, make_seq(op_parser,num_parser))
    s = ''
    iface = 'eth0'

    while True:
        s = input('> ')
        if s == "quit":
            break
        print(s)
        print(format(int(s), '016x'))
        try:
            pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4calc(
                switch1_max_pool_index=0x0e,
                switch1_replication=0x03,
                input_data=0x0000000000000011
                )
            pkt = pkt/' '
            pkt.show()
            resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
            print("b->",resp)
            if resp:
                p4calc=resp[P4calc]
                print("resp",resp)
                print(P4calc)
                if p4calc:
                    print(p4calc)
                    print(p4calc.res)
                    print(bin(p4calc.res).zfill(64),s)
                else:
                    print("cannot find P4calc header in the packet")
            else:
                print("Didn't receive response")
        except Exception as error:
            print("e->",error)


if __name__ == '__main__':
    main()
