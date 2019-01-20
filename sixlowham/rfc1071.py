#!/usr/bin/env python3
# vim: set tw=78 et sw=4 ts=4 sts=4 fileencoding=utf-8:
# SPDX-License-Identifier: GPL-2.0
# Credit: https://github.com/mdelatorre/checksum/blob/master/ichecksum.py

def checksum(data, csum=0):
    """
    Compute the Internet Checksum of the supplied data.  The checksum is
    initialized to zero.  Place the return value in the checksum field of a
    packet.  When the packet is received, check the checksum, by passing
    in the checksum field of the packet and the data.  If the result is zero,
    then the checksum has not detected an error.
    """
    # make 16 bit words out of every two adjacent 8 bit words in the packet
    # and add them up
    for i in range(0,len(data),2):
        if i + 1 >= len(data):
            csum += data[i] & 0xff
        else:
            w = ((data[i] << 8) & 0xff00) + (data[i+1] & 0xff)
            csum += w

    # take only 16 bits out of the 32 bit csum and add up the carries
    while (csum >> 16) > 0:
        csum = (csum & 0xffff) + (csum >> 16)

    # one's complement the result
    csum = ~csum

    return csum & 0xffff
