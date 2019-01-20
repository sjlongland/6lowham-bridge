#!/usr/bin/env python3
# vim: set tw=78 et sw=4 ts=4 sts=4 fileencoding=utf-8:
# SPDX-License-Identifier: GPL-2.0

import construct
import weakref

from .ip6 import IP6DatagramHeader, IP6Datagram, IP6Address
from .rfc1071 import checksum
from .util import tobytes, checktypes

class ICMP6Message(IP6DatagramHeader):
    """
    A representation of an ICMP message.
    """
    _HEADER_ID_ = 58
    _STRUCT_ = construct.Struct(
            "msgtype" / construct.Byte,
            "msgcode" / construct.Byte,
            "checksum" / construct.Int16ub,
            "message" / construct.Array(8, construct.Byte),
            "payload" / construct.GreedyBytes
    )

    _PSEUDOHEADER_ = construct.Struct(
            "source" / IP6Address._STRUCT_,
            "dest" / IP6Address._STRUCT_,
            "length" / construct.Int32ub,
            construct.Padding(3),
            "next_header" / construct.Byte
    )

    def __init__(self, msgtype, msgcode, message, payload):
        message = tobytes(message or b'')
        payload = tobytes(payload or b'')
        checktypes(
                ('msgtype',     msgtype,    int,    False),
                ('msgcode',     msgcode,    int,    False)
        )
        self._msgtype = msgtype
        self._msgcode = msgcode
        self._message = message
        self._datagram = None
        super(ICMP6Message, self).__init__(self._HEADER_ID_, payload)

    @property
    def datagram(self):
        return self._datagram()

    @datagram.setter
    def datagram(self, datagram):
        if not isinstance(datagram, IP6Datagram):
            raise TypeError('assigned object is not an IP6Datagram')
        self._datagram = weakref.ref(datagram)

    @property
    def msgtype(self):
        return self._msgtype

    @property
    def msgcode(self):
        return self._msgcode

    @property
    def message(self):
        return self._message

    @property
    def payload(self):
        return self._payload

    @classmethod
    def parse(cls, payload, this_header=None):
        """
        Parse the payload and return the data for this header, and the
        remaining payload data.
        """
        parsed = cls._STRUCT_.parse(payload)
        header = cls(
                msgtype=parsed.msgtype,
                msgcode=parsed.msgcode,
                message=parsed.message,
                payload=parsed.payload)
        return (header, None, None)

    def dump(self, next_header=None):
        # Construct the pseudoheader for checksumming purposes.
        message = self.message
        payload = self.payload

        # Computer the checksum
        checksum_val = checksum(self._PSEUDOHEADER_.build(dict(
            source=bytes(self.datagram.source),
            dest=bytes(self.datagram.dest),
            length=8 + len(payload)
        )) + self._STRUCT_.build(dict(
            msgtype=self.msgtype,
            msgcode=self.msgcode,
            checksum=0x0000,    # RFC-1071
            message=message,
            payload=payload
        )))

        # Emit the payload
        return self._STRUCT_.build(dict(
            msgtype=self.msgtype,
            msgcode=self.msgcode,
            checksum=checksum_val,
            message=message,
            payload=payload
        ))

    def __repr__(self):
        return '<ICMP6 %d.%d %r>' % (self.__class__.__name__,
                self.msgtype, self.msgcode, self.payload)
IP6Datagram.registerprotocol(ICMP6Message)
