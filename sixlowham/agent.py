#!/usr/bin/env python3
# vim: set tw=78 et sw=4 ts=4 sts=4 fileencoding=utf-8:
# SPDX-License-Identifier: GPL-2.0

import signalslot
import weakref
import asyncio
import construct
import logging

from .ethernet import EthernetMACAddress, EthernetFrame
from .util import tobytes, checktypes

# Byte definitions
SOH     = b'\x01'
STX     = b'\x02'
E_STX   = b'b'
ETX     = b'\x03'
E_ETX   = b'c'
EOT     = b'\x04'
ACK     = b'\x06'
DLE     = b'\x10'
E_DLE   = b'p'
NAK     = b'\x15'
SYN     = b'\x16'
FS      = b'\x1c'

# Structure of SOH struct.
SOH_STRUCT = construct.Struct(
        "mac" / EthernetMACAddress._STRUCT_,
        "mtu" / construct.Int16ub,
        "idx" / construct.Int32ub,
        "name" / construct.PascalString(construct.Byte, "utf-8")
)

class SixLowHAMAgent(object):
    """
    Wrapper class for the 6LoWHAM agent.  This provides a Python interface
    for sending and receiving Ethernet frames via the 6LoWHAM Agent.
    """
    def __init__(self, agent_path=None, if_name=None, \
            if_mac=None, if_mtu=None, tx_attempts=3, log=None):

        # Check data types
        checktypes(
                ('agent_path',  agent_path,     str,                True),
                ('if_name',     if_name,        str,                True),
                ('if_mac',      if_mac,         EthernetMACAddress, True),
                ('if_mtu',      if_mtu,         int,                True),
                ('tx_attempts', tx_attempts,    int,                False),
                ('log',         log,            logging.Logger,     True)
        )

        # Interface settings.  Make a note of which ones were supplied
        # to us by the caller in case the agent gets stopped and re-started.
        self._agent_path = agent_path or '6lhagent'
        self._if_name_given = if_name is not None
        self._if_name = if_name
        self._if_mac_given = if_mac is not None
        self._if_mac = if_mac
        self._if_mtu_given = if_mtu is not None
        self._if_mtu = mtu
        self._tx_attempts = tx_attempts
        self._log = log

        # Internal state
        self._transport = None
        self._protocol = None
        self._if_idx = None
        self._frame_pending = False
        self._retries = tx_attempts
        self._tx_buffer = []

        # Public Signals
        self.connected = signalslot.Signal(name='connected')
        self.disconnected = signalslot.Signal(name='disconnected')
        self.receivedframe = signalslot.Signal(name='receivedframe')

    @property
    def if_name(self):
        """
        Return the name of the network interface (e.g. `tap0`)
        """
        return self._if_name

    @property
    def if_mac(self):
        """
        Return the MAC address of the network interface as a byte string.
        """
        return self._if_mac

    @property
    def if_idx(self):
        """
        Return the interface index of the network interface.
        """
        return self._if_idx

    @asyncio.coroutine
    def start(self):
        """
        Start the TAP device agent.
        """
        if self._transport is not None:
            raise RuntimeError('agent already started')

        args = [self._agent_path]

        if self._if_name_given:
            args += ['-n', self._if_name]
        if self._if_mac_given:
            args += ['-a', str(self._if_mac)]
        if self._if_mtu_given:
            args += ['-m', str(self._if_mtu)]

        if self._log:
            self._log.debug('Starting agent with arguments: %s', args)

        (self._transport, self._protocol) = yield from \
                asyncio.get_event_loop().subprocess_exec(
                        lambda : SixLowHamAgentProtocol(self),
                        *args,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE)

    def send_ethernet_frame(self, frame):
        """
        Enqueue an Ethernet frame to be transmitted.
        """
        frame = tobytes(frame)
        if self._log:
            self._log.debug('Enqueueing frame: %r', frame)

        self._tx_buffer.push(frame)
        if not self._frame_pending:
            self._send_next()

    def stop(self):
        """
        Stop the agent.
        """
        self._send_frame(EOT)

    def _report_frame_error(self, raw_frame):
        """
        Emit a frame error to the log.
        """
        if self._log is not None:
            self._log.debug('Dropping malformed frame: %r', raw_frame)

    def _on_receive_frame(self, frame):
        """
        Process a received frame from the protocol instance.
        """
        # Split off the frame type byte
        frametype = frame[0:1]
        framedata = frame[1:]

        if frametype == SOH:
            # Interface information
            ifdata = SOH_STRUCT.parse(framedata)
            self._if_mac = EthernetMACAddress(ifdata.mac)
            self._if_mtu = ifdata.mtu
            self._if_idx = ifdata.idx
            self._if_name = ifdata.name

            # Emit a signal from the event loop, catch all errors.
            def emit():
                try:
                    self.connected.emit(agent=self)
                except:
                    if self._log is not None:
                        self._log.exception(
                            'Exception raised from connected signal')
            asyncio.get_event_loop().call_soon(emit)

        elif frametype == FS:
            # Ethernet frame received
            try:
                etherframe = EthernetFrame.parse(framedata)
            except:
                if self._log is not None:
                    self._log.exception(
                            'Failed to parse frame %r', framedata)
                self._send_frame(NAK)
                return

            def emit():
                try:
                    self.receivedframe.emit(frame=etherframe)
                except:
                    if self._log is not None:
                        self._log.exception(
                            'Exception raised from receivedframe signal')
            asyncio.get_event_loop().call_soon(emit)

        elif frametype in (ACK, NAK):
            self._on_response(frametype == ACK)

        # Do we ACK or NAK this?
        if frametype in (SOH, FS, SYN):
            self._send_frame(ACK)
        else if frametype not in (ACK, NAK):
            # Don't recognise the frame
            self._send_frame(NAK)

    def _on_response(self, success):
        # Ignore if no frame was sent
        if not self._tx_buffer:
            return

        # Remove successful frames, reset retry counter
        if success:
            self._tx_buffer.pop(0)
            self._retries = self._tx_attempts

        # Reset the frame pending flag
        self._frame_pending = False

        if self._tx_buffer:
            self._send_next()

    def _send_next(self):
        assert not self._frame_pending
        while self._tx_buffer:
            if self._retries <= 0:
                # Too many attempts, dropping frame
                if self._log:
                    self._log.warning(
                            'Dropping frame %r after %d send attempts',
                            self._tx_buffer[0], self._tx_attempts)
                self._tx_buffer.pop(0)
                self._retries = self._tx_attempts
                continue

            # Try sending this frame
            self._send_frame(FS + self._tx_buffer[0])
            self._frame_pending = True
            self._retries -= 1
            return
        
        # No more to send
        assert len(self._tx_buffer) == 0
        self._frame_pending = False
        self._retries = self._tx_attempts

    def _send_frame(self, frame):
        # Apply byte stuffing
        frame = frame.replace(DLE, DLE + E_DLE)
        frame = frame.replace(STX, DLE + E_STX)
        frame = frame.replace(ETX, DLE + E_ETX)

        # Send to stdin of the process
        self._transport.get_pipe_transport(0).write(
                STX + frame + ETX)

    def _on_exit(self):
        # Clean up the transport and protocol
        self._transport = None
        self._protocol = None

        # Reset the internal state
        self._tx_buffer = []
        self._frame_pending = False
        self._retries = self._tx_attempts

        # Reset the values for parameters not passed into the constructor
        if not self._if_name_given:
            self._if_name = None
        if not self._if_mac_given:
            self._if_mac = None
        if not self._if_mtu_given:
            self._if_mtu = None


class SixLowHAMAgentProtocol(asyncio.SubprocessProtocol):
    """
    Implements the de-serialisation of agent frames and passes these
    back to the parent SixLowHAMAgent object.
    """
    def __init__(self, agent):
        self._agent = weakref.ref(agent)
        self._buffer = b''

    def pipe_connection_lost(self, fd, exc):
        pass

    def process_exited(self):
        self._agent._on_exit()

    def pipe_data_received(self, fd, data):
        # Pull in the data received
        self._buffer += data

        # Process all pending frames
        framestart = self._buffer.find(STX)
        pending = []
        while framestart >= 0:
            frameend = self._buffer.find(ETX, framestart)
            if frameend < 0:
                break

            frame = self._buffer[framestart+1:frameend]
            self._buffer = self._buffer[frameend+1:]
            pending.append(frame)

        # Decode all frames, discard any that cause issues.
        for raw_frame in pending:
            try:
                decoded_frame = self._process_raw_frame(raw_frame)
            except:
                self._agent()._report_frame_error(raw_frame)
                continue

            try:
                self._agent()._on_receive_frame(decoded_frame)
            except:
                pass

    def _process_raw_frame(self, rawframe):
        """
        Replace the byte-stuffing sequences and return it.
        """
        frame = rawframe.replace(self.DLE + self.E_STX, self.STX)
        frame = frame.replace(self.DLE + self.E_ETX, self.ETX)
        frame = frame.replace(self.DLE + self.E_DLE, self.DLE)
        return frame
