"""Low-level UDP packet framing (acking, zerocoding, reliability)."""

import struct

from .codec import zerocode_decode, zerocode_encode
from .messages import getMessageByID


class Packet:
    bytes = b""; body = None; MID = 0; sequence = 0; extra = b""
    flags = 0; zero_coded = 0; reliable = 0; resent = 0; ack = True
    
    def __init__(self, data=None, message=None, mid=0, sequence=0, zero_coded=0, reliable=0, resent=0, ack=0, acks=[]):
        self.acks = [] # FIX: Ensure ACKs don't accumulate in class attribute
        if data:
            self.flags, self.sequence, self.extra_bytes = struct.unpack_from(">BIB", data[:6])
            self.zero_coded = (self.flags&0x80 == 0x80)
            self.reliable = (self.flags&0x40 == 0x40)
            self.resent = (self.flags&0x20 == 0x20)
            self.ack = (self.flags&0x10 == 0x10)
            self.extra = data[6:6+self.extra_bytes]
            
            payload = data[6+self.extra_bytes:]
            
            # --- FIX: Extract MID BEFORE zero-coding decoding ---
            # This is critical because the MID is NOT zero-coded, but the rest of the body is.
            # If the MID contains \x00, zero-decoding it would corrupt the packet structure.
            
            mid_raw = 0
            mid_offset = 0
            if payload[0] == 0xFF:
                if payload[1] == 0xFF: # High/Fixed frequency (4 bytes)
                    mid_raw = struct.unpack(">I", payload[:4])[0]
                    mid_offset = 4
                else: # Medium frequency (2 bytes)
                    mid_raw = struct.unpack(">H", payload[:2])[0]
                    mid_offset = 2
            else: # Low frequency (1 byte)
                mid_raw = payload[0]
                mid_offset = 1

            # Save the raw MID bytes for later use in decoding the body
            self.MID = mid_raw
            body_payload = payload[mid_offset:]

            if self.zero_coded: self.bytes = zerocode_decode(body_payload)
            else: self.bytes = body_payload
            
            realID = mid_raw
            offset = 0 # body_payload already starts after the MID
            
            # Re-determine frequency-adjusted ID for message lookup
            if mid_raw & 0xFFFFFFFA == 0xFFFFFFFA: # Fixed-frequency packet (3)
                pass 
            elif mid_raw & 0xFFFF0000 == 0xFFFF0000: # High-frequency packet (2)
                realID = (mid_raw & 0x0000FFFF) + 0xFFFF0000
            elif mid_raw & 0xFFFFFF00 == 0xFFFF0000: # Wait, mid_raw for freq 1 is 2 bytes?
                # Actually frequency logic is easier if we use the bits:
                pass
            
            # Simplified Frequency/ID logic matching SL protocol:
            if mid_raw < 0xFF: # Low frequency
                realID = mid_raw
            elif mid_raw < 0xFFFF: # Medium
                realID = mid_raw # mid_raw already has the 0xFF prefix if 2 bytes
            else: # High or Fixed
                realID = mid_raw # mid_raw already has the 0xFFFF prefix if 4 bytes
            # Use the determined offset to get the body data
            # DEBUG: Print exact ID resolution
            # print(f"[PACKET DEBUG] MID Raw: {mid_raw} RealID: {realID}")
            
            try:
                self.body = getMessageByID(realID, self.bytes[offset:])
            except struct.error as e:
                print(f"[APPDEBUG] RAW PACKET CRASH: {e}")
                print(f"[APPDEBUG] MID {realID} HEX: {self.bytes[offset:].hex()}")
                raise e
            
            # DEBUG: Diagnose missing body
            if self.body is None:
#                  print(f"[PACKET ERROR] ID {realID} (Raw {mid_raw}) not found in lookup.")
                 # Create a dummy body to prevent crashes in handleInternalPackets
                 class DummyBody: name="UnknownID"
                 self.body = DummyBody()

            if not self.body: 
                self.body = type('UnknownMessage', (object,), {'name': 'Unknown'})()

            if self.ack:
                try:
                    ackcount = data[len(data)-1]
                    ack_offset = len(data) - (ackcount * 4) - 1
                    for _ in range(ackcount):
                        self.acks.append(struct.unpack_from(">I", data, ack_offset)[0])
                        ack_offset += 4
                except: 
                    pass # Handle malformed ACK data
        elif message:
            self.MID = message.id
            if len(acks) > 0 or ack: self.ack = True
            self.zero_coded = message.zero_coded
            self.sequence = sequence
            self.body = message
            self.acks = acks
            self.reliable = getattr(message, 'trusted', False) # Set reliable from message metadata
            if reliable: self.reliable = True # Override if explicitly set as reliable
            if resent: self.resent = True

    def __bytes__(self):
        try:
            self.flags = 0
            body = bytes(self.body)
            
            # 1. Zero-coding
            if self.zero_coded:
                tmp = zerocode_encode(body)
                if len(tmp) >= len(body):
                    self.zero_coded = False; self.flags &= ~0x80
                    body = bytes(self.body) 
                else:
                    self.flags |= 0x80
                    body = tmp
            
            # 2. Set Flags
            if self.reliable: self.flags |= 0x40
            if self.resent: self.flags |= 0x20
            if self.ack: self.flags |= 0x10
            
            # 3. ACK bytes
            acks_bytes = b""
            if self.ack:
                for i in self.acks: acks_bytes += struct.pack(">I", i)
                if len(self.acks) > 0:
                    acks_bytes += struct.pack(">B", len(self.acks))
                else:
                    self.flags &= ~0x10
                    acks_bytes = b""
            
            # 4. Message ID (MID)
            result = b""
            if self.body.freq == 3: result = struct.pack(">I", self.MID)
            elif self.body.freq == 2: result = struct.pack(">I", self.MID + 0xFFFF0000)
            elif self.body.freq == 1: result = struct.pack(">H", self.MID + 0xFF00)
            elif self.body.freq == 0: result = struct.pack(">B", self.MID)
            
            # 5. Full Packet Assembly
            return struct.pack(">BIB", self.flags, self.sequence, len(self.extra)) + self.extra + result + body + acks_bytes
        except Exception as e:
            print(f"[CRITICAL] Packet.__bytes__ ERROR: {e}")
            raise e

