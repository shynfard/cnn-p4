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

class Int40Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<Q")

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt[0] + "Q", val)[0:5]

    def getfield(self, pkt, s):
        return s[5:], self.m2i(pkt, struct.unpack(self.fmt[0] + "Q", s[:5] + b'\x00\x00\x00')[0])

    def i2repr(self, pkt, x):
        return hex(x)
    
class X40Field(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, fmt="!Q")

    def addfield(self, pkt, s, val):
        return s + val.to_bytes(5, byteorder='big')

    def getfield(self, pkt, s):
        return s[5:], int.from_bytes(s[:5], byteorder='big')

class P4calc(Packet):
    name = "P4calc"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    
                    IntField("max_pool_index", 0x00),
                    Int40Field("data", 0xF0F0F0F0F0),
                    
                    IntField("replication", 0x00),
                    XLongField("res",0x0000000000000000),
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
        try:
            pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4calc(
                data=int(s, 16),
                max_pool_index=0x00,
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
