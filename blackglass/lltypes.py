"""Core Second Life wire-format data types."""

import struct
import uuid as __uuid__


class null:
    def __bytes__(self):
        return b""
    def __str__(self):
        return "<NULL>"

class fixed:
    data = b""
    def __init__(self, data):
        if type(data) == bytes:
            self.data = data
        elif type(data) == str:
            # Improvement: Use utf-8 for protocol strings
            self.data = data.encode("utf-8")
        elif hasattr(data, "__bytes__"):
            self.data = bytes(data)
        else:
            self.data = type(data).encode("utf-8")
    def __bytes__(self):
        return self.data
    def __len__(self):
        return len(self.data)
    def __str__(self):
        try:
            return self.data.decode("utf-8") # Decoded with utf-8
        except:
            return "<FIXED: %i>"%len(self.data)

class variable:
    data = b""
    type = 0
    def __init__(self, ty = 1, data = b"", add_null = False):
        
        # --- FIX: Ensure Correct UTF-8 Encoding and Null Termination ---
        if type(data) == bytes:
            self.data = data
        elif type(data) == str:
            # FIX: Only encode and null-terminate if requested and if not already present.
            # Use utf-8 for protocol strings
            if add_null and not data.endswith('\x00'):
                self.data = (data + '\x00').encode("utf-8")
            else:
                self.data = data.encode("utf-8")
                
        elif hasattr(data, "__bytes__"):
            self.data = bytes(data)
        else:
            self.data = type(data).encode("utf-8")
        # --- END FIX ---
            
        self.type = ty
        if ty == 1:
            if len(self.data) >= 256: # Changed to 256 to allow a 255 length string + null
                # Should raise error or truncate
                pass 
        elif ty == 2:
            if len(self.data) >= 65536: # Changed to 65536 to allow a 65535 length string + null
                # Should raise error or truncate
                pass
    def __bytes__(self):
        # The length prefix includes the null terminator which is part of the data
        if self.type == 1:
            return struct.pack("<B", len(self.data)) + self.data
        elif self.type == 2:
            return struct.pack("<H", len(self.data)) + self.data
        # Fallback (same as type 1)
        return struct.pack("<B", len(self.data)) + self.data
    def __len__(self):
        # The length of the data *only* (excluding the prefix)
        return len(self.data)
    def __str__(self):
        try:
            # Decoded with utf-8, strip the null terminator
            return self.data.decode("utf-8").rstrip('\x00') 
        except:
            return "<VARIABLE %i: %i>"%(self.type,len(self.data))
    def __repr__(self):
        return "<VARIABLE %i: %i>"%(self.type,len(self.data))

class vector3:
    x = 0; y = 0; z = 0
    def __init__(self, x=0, y=0, z=0):
        self.x = x; self.y = y; self.z = z
    def __bytes__(self):
        return struct.pack("<fff", self.x, self.y, self.z)
    def __str__(self):
        return "<%f, %f, %f>"%(self.x, self.y, self.z)
    def __eq__(self, cmp):
        if type(cmp) != vector3: return False
        return self.x == cmp.x and self.y == cmp.y and self.z == cmp.z

class vector3d(vector3):
    def __bytes__(self):
        return struct.pack("<ddd", self.x, self.y, self.z)
    def __eq__(self, cmp):
        if type(cmp) != vector3d: return False
        return self.x == cmp.x and self.y == cmp.y and self.z == cmp.z

class vector4:
    x = 0; y = 0; z = 0; s = 0
    def __init__(self, x=0, y=0, z=0, s=0):
        self.x = x; self.y = y; self.z = z; self.s = s
    def __bytes__(self):
        return struct.pack("<ffff", self.x, self.y, self.z, self.s)
    def __str__(self):
        return "<%f, %f, %f, %f>"%(self.x, self.y, self.z, self.s)

class quaternion:
    x = 0; y = 0; z = 0; w = 1
    def __init__(self, x=0, y=0, z=0, w=1):
        self.x = x; self.y = y; self.z = z; self.w = w
    def __bytes__(self):
        return struct.pack("<ffff", self.x, self.y, self.z, self.w)
    def __str__(self):
        return "<%f, %f, %f, %f>"%(self.x, self.y, self.z, self.w)



class LLUUID:
    def __init__(self, key="00000000-0000-0000-0000-000000000000"):
        self.UUID = __uuid__.UUID("00000000-0000-0000-0000-000000000000")
        if isinstance(key, bytes):
            if len(key) == 16:
                self.UUID = __uuid__.UUID(bytes=key)
        elif isinstance(key, str):
            try:
                self.UUID = __uuid__.UUID(key)
            except:
                pass 
        elif isinstance(key, __uuid__.UUID):
            self.UUID = key
        elif isinstance(key, LLUUID):
            self.UUID = key.UUID

    def __bytes__(self):
        return self.UUID.bytes
    def __str__(self):
        return str(self.UUID)
    def __hash__(self):
        return hash(self.UUID)
    def __len__(self):
        return 16
    @property
    def bytes(self): 
        return self.UUID.bytes
    def __eq__(self, other):
        if not isinstance(other, LLUUID): return False
        return self.UUID == other.UUID

class IPAddr:
    addr = [0,0,0,0]
    def __init__(self, a=0,b=0,c=0,d=0):
        if type(a) == str:
            a = a.split(".")
            if len(a) == 4:
                b = int(a[1]); c = int(a[2]); d = int(a[3]); a = int(a[0])
        self.addr = [a,b,c,d]
    def __bytes__(self):
        return struct.pack("BBBB", self.addr[0], self.addr[1], self.addr[2], self.addr[3])
    def __str__(self):
        return "%i.%i.%i.%i"%(self.addr[0], self.addr[1], self.addr[2], self.addr[3])

class IPPort:
    port = 0
    def __init__(self, a=0):
        if type(a) == str: a = int(a)
        self.port = a
    def __bytes__(self):
        return struct.pack("<H", self.port)
    def __str__(self):
        return str(self.port)

class Constraints:
    def __init__(self):
        # Only essential ones for this script's functionality are defined here for brevity
        self.CHAT_NORMAL = 1
        # NEW CHAT CONSTANTS FOR FILTERING
        self.CHAT_START_TYPING = 4 
        self.CHAT_STOP_TYPING = 5
        
        # New/Expanded Movement Control Flags (U32)
        # These are used in the AgentUpdate packet's ControlFlags field
        self.AGENT_CONTROL_AT_POS = 0x01   # Forward (W, Arrow Up)
        self.AGENT_CONTROL_AT_NEG = 0x02   # Backward (S, Arrow Down)
        self.AGENT_CONTROL_LEFT_POS = 0x04 # Left (A, Arrow Left)
        self.AGENT_CONTROL_RIGHT_POS = 0x08# Right (D, Arrow Right)
        self.AGENT_CONTROL_UP_POS = 0x10   # Up (E, PageUp)
        self.AGENT_CONTROL_UP_NEG = 0x20   # Down (C, PageDown)
        self.AGENT_CONTROL_JUMP = 0x100    # Jump (Space)
        self.AGENT_CONTROL_FLY = 0x200     # Fly/Ground Toggle (F)
        # Full list from constraints.py would go here...

const = Constraints()

# ==========================================
# SECTION 3: AUTHENTICATION
# ==========================================

