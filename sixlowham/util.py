#!/usr/bin/env python3
# vim: set tw=78 et sw=4 ts=4 sts=4 fileencoding=utf-8:
# SPDX-License-Identifier: GPL-2.0

def tobytes(data):
    """
    Coerce the given input to bytes if we can.  Input can be:
    - a `bytes` object (this will be a no-op)
    - any object that implements `__bytes__`
    - any list containing integers in the range 0-255.
    """
    if isinstance(data, bytes):
        # No-op
        return data

    if hasattr(data, '__bytes__') or \
            (isinstance(data, list) and \
             (len(data) > 0) and \
             isinstance(data[0], int)):
        return bytes(data)

    raise ValueError('Unable to coerce %s object to bytes' \
            % (type(data).__name__))
