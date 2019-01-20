#!/usr/bin/env python3
# vim: set tw=78 et sw=4 ts=4 sts=4 fileencoding=utf-8:
# SPDX-License-Identifier: GPL-2.0

import construct
import ipaddress

from .ethernet import EthernetFrame
from .util import tobytes, checktypes

class IP6Address(ipaddress.IPv6Address):
    """
    Representation of an IPv6 address.
    """
    _STRUCT_ = construct.Array(16, construct.Byte)

    @classmethod
    def parse(cls, address):
        return cls(tobytes(address))

    def __bytes__(self):
        return self.packed


class IP6DatagramHeader(object):
    """
    A representation of a single header.
    """

    _STRUCT_ = construct.Struct(
            "next_header" / construct.Byte,
            "ext_len" / construct.Byte,
            "payload" / construct.Array(
                6 + (construct.this.ext_len * 8)
            ),
            "remainder" / construct.GreedyBytes
    )

    def __init__(self, this_header, payload):
        self._this_header = this_header
        self._payload = tobytes(payload)

    @classmethod
    def parse(cls, payload, this_header=None):
        """
        Parse the payload and return the data for this header, and the
        remaining payload data.
        """
        if this_header is None:
            this_header = cls._HEADER_ID_

        parsed = cls._STRUCT_.parse(payload)
        header = cls(this_header=this_header, payload=parsed.payload)
        return (header, parsed.next_header, parsed.remainder)

    @property
    def this_header(self):
        return self._this_header

    @property
    def payload(self):
        return self._payload

    def dump(self, next_header):
        payload = self.payload

        # Length, in units of 8 bytes.
        length = int(((len(payload) - 6) + 7)/8)

        return self._STRUCT_.build(dict(
            next_header=next_header,
            ext_len=length,
            payload=payload,
            remainder=b''
        ))

    def __repr__(self):
        return '<%s %d %r>' % (self.__class__.__name__,
                self.next_header, self.payload)

class GenericIP6DatagramHeader(IP6DatagramHeader):
    """
    A datagram header that follows the standard pattern.
    """
    def __init__(self, payload):
        super(IP6DatagramHeader, self).__init__(
                self._HEADER_ID_, payload)


class IP6Datagram(object):
    """
    A representation of an IPv6 datagram.
    """
    _ETHERNET_PROTOCOL_ = 0x86dd
    _STRUCT_ = construct.Struct(
            "header" / construct.BitStruct(
                "version" / construct.BitsInteger(4),
                "trafficclass" / construct.BitsInteger(8),
                "flowlabel" / construct.BitsInteger(20)
            ),
            "payload_len" / construct.Int16ub,
            "next_header" / construct.Byte,
            "hop_limit" / construct.Byte,
            "source" / IP6Address._STRUCT_,
            "dest" / IP6Address._STRUCT_,
            # This will be more headers, then eventually the payload itself.
            "remainder" / construct.GreedyBytes,
    )

    _KNOWN_PROTOCOLS_ = {}

    def __init__(self, trafficclass, flowlabel, hop_limit, source, dest):
        # Check data types
        checktypes(
                ('trafficclass',    trafficclass,   int,        False),
                ('flowlabel',       flowlabel,      int,        False),
                ('hop_limit',       hop_limit,      int,        False),
                ('source',          source,         IP6Address, False),
                ('dest',            dest,           IP6Address, False)
        )
        self._headers = []
        self._trafficclass = trafficclass
        self._flowlabel = flowlabel
        self._hop_limit = hop_limit
        self._source = source
        self._dest = dest

    @classmethod
    def registerprotocol(cls, protocol):
        cls._KNOWN_PROTOCOLS_[protocol._ETHERNET_PROTOCOL_] = protocol

    @classmethod
    def parse(cls, datagram):
        """
        Parse from raw datagram bytes.
        """
        datagram_header = cls._STRUCT_.parse(datagram)
        if datagram_header.header.version != 6:
            raise ValueError('This is not an IPv6 datagram')

        ip6datagram = cls(
                trafficclass=datagram_header.header.trafficclass,
                flowlabel=datagram_header.header.flowlabel,
                source=IP6Address(datagram_header.source),
                dest=IP6Address(datagram_header.dest),
                hop_limit=datagram_header.hop_limit,
                next_header=datagram_header.next_header
        )

        payload = datagram_header.remainder
        next_header = datagram_header.next_header
        while (payload is not None) and (next_header is not None) \
                and len(payload):
            protocol = cls._KNOWN_PROTOCOLS_.get(next_header)
            if protocol is not None:
                (header, next_header, payload) = protocol.parse(payload)
            else:
                (header, next_header, payload) = IP6DatagramHeader.parse(
                        next_header, payload)
                ip6datagram.append_header(header)

        return ip6datagram

    def append_header(self, header):
        """
        Append the given header to the datagram.
        """
        try:
            # Pass an instance of ourselves to the header, in case it needs
            # it later for generating checksums (e.g. in ICMPv6).
            header.datagram = self
        except AttributeError:
            pass

        self._headers.append(header)

    @property
    def dest(self):
        return self._dest

    @property
    def source(self):
        return self._source

    @property
    def headers(self):
        return self._headers

    @property
    def next_header(self):
        try:
            return self._headers[0].this_header
        except IndexError:
            return NoNextHeader._HEADER_ID_ # No next header

    @property
    def payload(self):
        payload = b''
        for (this_header, next_header) in \
                zip(self._headers, [\
                    h.this_header for h in self._headers[1:]] + [None]):
            payload += this_header.dump(next_header=next_header)
        return payload

    def __bytes__(self):
        payload = self.payload

        return self._STRUCT_.build(dict(
            header=dict(
                version=6,
                trafficclass=self.trafficclass,
                flowlabel=self.flowlabel
            ),
            payload_len=len(payload),
            next_header=self.next_header,
            hop_limit=self.hop_limit,
            source=bytes(self.source),
            dest=bytes(self.dest),
            remainder=payload
        ))


class NoNextHeader(IP6DatagramHeader):
    """
    A header that says "no next header" (ironic I know)
    """
    _HEADER_ID_ = 59

    def __init__(self, payload):
        super(NoNextHeader, self).__init__(self._HEADER_ID, payload)

    @classmethod
    def parse(cls, payload, this_header=None):
        return (cls(payload=payload), None, None)

    def dump(self, next_header=None):
        return self.payload
IP6Datagram.registerprotocol(NoNextHeader)


# Register IP6Datagram with EthernetFrame.
EthernetFrame.registerprotocol(IP6Datagram)
