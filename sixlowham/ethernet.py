#!/usr/bin/env python3
# vim: set tw=78 et sw=4 ts=4 sts=4 fileencoding=utf-8:
# SPDX-License-Identifier: GPL-2.0

import re
import construct

from .util import tobytes, checktypes


class EthernetMACAddress(object):
    """
    A representation of a MAC (EUI-48) address.
    """
    _STRUCT_ = construct.Array(6, construct.Byte)
    _MAC_RE_ = re.compile(
            r'^([0-9A-Fa-f]{2})([:-])'
            r'([0-9A-Fa-f]{2})\2'
            r'([0-9A-Fa-f]{2})\2'
            r'([0-9A-Fa-f]{2})\2'
            r'([0-9A-Fa-f]{2})\2'
            r'([0-9A-Fa-f]{2})$'
    )

    def __init__(self, address):
        if isinstance(address, str):
            address = self.fromstr(address)

        address = tobytes(address)

        if len(address) != 6:
            raise ValueError('address must be 6 bytes long')

        self._address = address

    @classmethod
    def fromstr(cls, mac):
        match = cls._MAC_RE_.match(mac)
        if match is None:
            raise ValueError('%r does not match pattern' % mac)
        (mac1, _, mac2, mac3, mac4, mac5, mac6) = match.groups()
        return cls(bytes([
            int(mac1, base=16),
            int(mac2, base=16),
            int(mac3, base=16),
            int(mac4, base=16),
            int(mac5, base=16),
            int(mac6, base=16)
        ]))

    @property
    def islocal(self):
        return self._address[0] & (1 << 1)

    @property
    def ismulticast(self):
        return self._address[0] & (1 << 0)

    def __str__(self):
        return ':'.join(['%02x' % b for b in self._address])

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self._address)

    def __bytes__(self):
        return self._address


class EthernetFrame(object):
    """
    A representation of an Ethernet frame.
    """
    _STRUCT_ = construct.Struct(
            "dest" / EthernetMACAddress._STRUCT_,
            "source" / EthernetMACAddress._STRUCT_,
            "proto" / construct.Int16ub,
            "payload" / construct.GreedyBytes
    )
    _KNOWN_PROTOCOLS_ = {}

    def __init__(self, dest, source, proto, payload):
        # Coerce payload if possible
        payload = tobytes(payload)

        # Check data types
        checktypes(
                ('dest',    dest,       EthernetMACAddress, False),
                ('source',  source,     EthernetMACAddress, False),
                ('proto',   proto,      int,                False),
                ('payload', payload,    bytes,              False)
        )

    @classmethod
    def parse(cls, frame):
        """
        Parse from raw frame bytes.
        """
        framedata = cls._STRUCT_.parse(frame)
        return cls(
                dest=EthernetMACAddress(framedata.dest),
                source=EthernetMACAddress(framedata.source),
                proto=framedata.proto,
                payload=framedata.payload
        )

    @property
    def dest(self):
        return self._dest

    @property
    def source(self):
        return self._source

    @property
    def proto(self):
        return self._proto

    @property
    def rawpayload(self):
        return self._payload

    @property
    def payload(self):
        protocol = self._KNOWN_PROTOCOLS_.get(self.proto)
        if protocol is not None:
            return protocol.parse(self.rawpayload)
        else:
            return self.rawpayload

    def __bytes__(self):
        return self._STRUCT_.build(dict(
            dest=bytes(self.dest),
            source=bytes(self.source),
            proto=bytes(self.proto),
            payload=self.rawpayload))
