import tkinter as tk
from tkinter import scrolledtext, Toplevel
import threading
import time
import sys
import struct
import socket
import uuid as __uuid__
import xmlrpc.client
import hashlib
import traceback
import random
from uuid import UUID, getnode as get_mac
from tkinter import ttk 
import json
import os
import base64
import math
import urllib.request
import urllib.parse 
import re
import html as html_parser
from io import BytesIO

# --- PIL/Pillow Import ---
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Warning: Pillow (PIL) not found. Map tiles will display a colored placeholder.")
# --- End PIL Import ---


# ==========================================
# SECTION 1: CORE TYPES (llTypes.py)
# ==========================================

# --- Performance Fix: Limited ScrolledText ---
class LimitedScrolledText(scrolledtext.ScrolledText):
    """
    A ScrolledText widget that limits the number of lines it displays
    to prevent memory bloat and UI lag over time.
    """
    def __init__(self, master=None, max_lines=1000, **kw):
        super().__init__(master, **kw)
        self.max_lines = max_lines

    def insert(self, index, chars, *args):
        super().insert(index, chars, *args)
        self._prune()

    def _prune(self):
        """Removes the oldest lines if we exceed max_lines."""
        # Get the number of lines (returns string like "100.0")
        try:
            # "end-1c" because "end" includes the auto-newline at the end
            num_lines = int(float(self.index("end-1c")))
            if num_lines > self.max_lines:
                # Delete from start to the number of excess lines
                diff = num_lines - self.max_lines
                # We can delete chunks to be more efficient, but line-by-line 
                # or block deletion logic:
                # Delete from 1.0 to (1.0 + diff lines)
                self.delete("1.0", f"{float(diff + 1)}.0")
        except Exception:
            pass
# ---------------------------------------------

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

def llDecodeType(t, ty = None):
    a = type(t)
    if a == null or a == fixed or a == variable or a == vector3 or \
        a == vector3d or a == vector4 or a == quaternion or a == LLUUID or \
        a == IPAddr or a == IPPort:
        return bytes(t)
    elif a == bytes:
        return t
    elif ty == "U8": return struct.pack("<B", t)
    elif ty == "U16": return struct.pack("<H", t)
    elif ty == "U32": return struct.pack("<I", t)
    elif ty == "U64": return struct.pack("<Q", t)
    elif ty == "S8": return struct.pack("<b", t)
    elif ty == "S16": return struct.pack("<h", t)
    elif ty == "S32": return struct.pack("<i", t)
    elif ty == "S64": return struct.pack("<q", t)
    elif ty == "F32": return struct.pack("<f", t)
    elif ty == "F64": return struct.pack("<d", t)
    elif ty == "BOOL" or t == bool: return struct.pack(">B", 1 if t == True else 0)
    return b""

def llEncodeType(t, ty = None, vlen = None):
    if ty == "Null": return null()
    # If t is already a Variable or Fixed object, this returns the object
    # If t is bytes, it creates the object from the bytes
    elif ty == "Fixed": return fixed(t)
    # When decoding Variable, t is the bytes *with* the length prefix already stripped by the load() function
    # So we pass the bytes and the correct type (vlen)
    elif ty == "Variable": return variable(vlen, t) 
    elif ty == "U8": return struct.unpack("<B", t)[0]
    elif ty == "U16": return struct.unpack("<H", t)[0]
    elif ty == "U32": return struct.unpack("<I", t)[0]
    elif ty == "U64": return struct.unpack("<Q", t)[0]
    elif ty == "S8": return struct.unpack("<b", t)[0]
    elif ty == "S16": return struct.unpack("<h", t)[0]
    elif ty == "S32": return struct.unpack("<i", t)[0]
    elif ty == "S64": return struct.unpack("<q", t)[0]
    elif ty == "F32": return struct.unpack("<f", t)[0]
    elif ty == "F64": return struct.unpack("<d", t)[0]
    elif ty == "LLVector3":
        tmp = struct.unpack("<fff", t)
        return vector3(tmp[0],tmp[1],tmp[2])
    elif ty == "LLVector3d":
        tmp = struct.unpack("<ddd", t)
        return vector3d(tmp[0],tmp[1],tmp[2])
    elif ty == "LLVector4":
        tmp = struct.unpack("<ffff", t)
        return vector4(tmp[0],tmp[1],tmp[2],tmp[3])
    elif ty == "LLQuaternion":
        tmp = struct.unpack("<ffff", t) # Corrected to 4 floats
        return quaternion(tmp[0],tmp[1],tmp[2],tmp[3])
    elif ty == "IPAddr":
        tmp = struct.unpack("BBBB", t)
        return IPAddr(tmp[0],tmp[1],tmp[2],tmp[3])
    elif ty == "IPPort":
        return IPPort(struct.unpack("<H", t)[0])
    elif ty == "BOOL":
        return struct.unpack("B", t)[0] != 0
    elif ty == "LLUUID":
        return LLUUID(t)
    return t

# ==========================================
# SECTION 2: UTILITIES (zerocode, errorHandler, constraints)
# ==========================================

def zerocode_decode(bytedata):
    """
    Decodes a byte string compressed with Second Life's zero-coding scheme.
    A null byte (\x00) followed by a non-zero byte C is replaced by C null bytes.
    """
    output = bytearray()
    i = 0
    l = len(bytedata)
    
    while i < l:
        if bytedata[i] != 0:
            output.append(bytedata[i])
            i += 1
            continue
        
        # Found null byte (marker)
        output.append(0x00) 
        i += 1
        
        # Check for count byte. If next byte is non-zero, it is the count (C extra nulls).
        if i < l:
            count = bytedata[i] 
            # Insert the C extra nulls
            output.extend(b"\x00" * count)
            i += 1 # Skip the count byte
            
    return bytes(output)

def zerocode_encode(bytedata):
    """
    Encodes a byte string using Second Life's zero-coding scheme.
    A run of nulls (\x00\x00...) is replaced by a null marker (\x00) followed by a count byte (C).
    C is the count of EXTRA nulls after the marker.
    """
    output = bytearray() 
    i = 0
    l = len(bytedata)
    
    while i < l:
        if bytedata[i] != 0:
            output.append(bytedata[i])
            i += 1
            continue
        
        # Found first null byte (the marker)
        output.append(0x00) 
        i += 1
        
        # Count consecutive nulls (c is the count of EXTRA nulls)
        c = 0 
        # Max run length is 255 (marker + 254 extra). We cap C at 254.
        while i < l and bytedata[i] == 0 and c < 254: 
            c += 1
            i += 1
        
        # If c >= 0 (meaning 1 or more consecutive nulls total), insert count byte for the extra nulls
        # Note: Even for a single null (c=0), we append the count byte (0) to maintain 
        # consistency with the decoder which ALWAYS expects a count byte after a null marker.
        output.append(c) 
        
    return bytes(output)

def printsafe(data):
    result = ""
    for i in data:
        if 0x20 <= i <= 0x7E:
            result = result + chr(i)
        else:
            result = result + "."
    return result

def hexdump(data):
    info = ""
    l = len(data)
    for i in range(0, l, 0x10):
        hexdump = ""
        for x in range(i, i+0x8 if i+0x8 <= l else l):
            hexdump = hexdump + "{0:02X} ".format(data[x])
        hexdump = hexdump + " "
        for x in range(i+0x8, i+0x10 if i+0x10 <= l else l):
            hexdump = hexdump + "{0:02X} ".format(data[x])
        info = info + "{0:04X}     {1: <49s}     {2:s}\n".format(i, hexdump, printsafe(data[i:i+0x10]))
    return info

def packetErrorTrace(data):
    a = traceback.format_exc()
    if not a: return "Error: No error"
    try:
        _, _, exlen = struct.unpack_from(">BIB", data, 0)
        mid = struct.unpack_from(">I", data, 6+exlen)[0]
        return "%s\nMID:%s\n%s"%(a, mid, ("-"*79)+"\n"+hexdump(data)+"\n"+("-"*79))
    except:
        return "%s\n%s"%(a, ("-"*79)+"\n"+hexdump(data)+"\n"+("-"*79))


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

def getMacAddress():
    mac = get_mac()
    return ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))

__PLATFORM_STRING__ = "Win"
if sys.platform == "linux": __PLATFORM_STRING__ = "Lnx"
elif sys.platform == "darwin": __PLATFORM_STRING__ = "Mac"

# This is the correct, default login URI from the pyverse authentication.py file
LOGIN_URI = "https://login.agni.lindenlab.com/cgi-bin/login.cgi" 
SL_USER_AGENT = "BlackGlass"

def login_to_simulator(firstname, lastname, password, mac=None, start="last", grid=None):
    if grid is None: grid = LOGIN_URI
    if mac == None: mac = getMacAddress()
    
    # Use default SSL context for verification
    proxy = xmlrpc.client.ServerProxy(grid, verbose=False, use_datetime=True)
    
    # NOTE: The original pyverse code used CZ_Python channel, adjusting to SLViewer_Py as per the original SLViewer.py
    result = proxy.login_to_simulator({
        "first": firstname,
        "last": lastname,
        "passwd": "$1$"+hashlib.md5(password.encode("latin")).hexdigest(),
        "start": start,
        "platform": __PLATFORM_STRING__,
        "mac": mac,
        "id0": hashlib.md5(("%s:%s:%s"%(__PLATFORM_STRING__,mac,sys.version)).encode("latin")).hexdigest(),
        "agree_to_tos": True,
        "last_exec_event": 0,
        "viewer_protocol_version": "1.0.0",
        "channel": "BlackGlass",
        "version": "1.4.0",
        "options": ["inventory-root", "buddy-list", "login-flags", "global-textures", "display-names"]
    })
    if result["login"] != "true":
        raise ConnectionError("Unable to log in:\n    %s"%(result["message"] if "message" in result else "Unknown error"))
    return result

# ==========================================
# SECTION 4: MESSAGE DEFINITIONS (message.py & messages.py)
# ==========================================

baseTypes = {
    "Null": null(), "Fixed": fixed(b""), "Variable": [None, variable(1, b""), variable(2, b"")],
    "U8": 0, "U16": 0, "U32": 0, "U64": 0, "S8": 0, "S16": 0, "S32": 0, "S64": 0, "F32": 0.0, "F64": 0.0,
    "LLVector3": vector3(), "LLVector3d": vector3d(), "LLVector4": vector4(),
    "LLQuaternion": quaternion(), "LLUUID": LLUUID(), "BOOL": False,
    "IPADDR": IPAddr(), "IPPORT": IPPort()
}
typeLengths = {
    "Null": 0, "Fixed": 0, "Variable": 0, "Color4U": 4, "U8": 1, "U16": 2, "U32": 4, "U64": 8,
    "S8": 1, "S16": 2, "S32": 4, "S64": 8, "F32": 4, "F64": 8,
    "LLVector3": 12, "LLVector3d": 24, "LLVector4": 16, "LLQuaternion": 16,
    "LLUUID": 16, "BOOL": 1, "IPADDR": 4, "IPPORT": 2
}

class BaseMessage:
    name = "TestMessage"; id = 1; freq = 2; trusted = False; zero_coded = True
    blocks = []; structure = {}
    def __init__(self, data=None):
        if not data:
            for key in self.blocks:
                if key[1] == 1: # Single block
                    tmp = {}
                    for value in self.structure[key[0]]:
                        # FIX: Handle variable-sized types which have an index in baseTypes
                        if value[1] == "Variable": tmp[value[0]] = baseTypes[value[1]][value[2]]
                        else: tmp[value[0]] = baseTypes[value[1]]
                    setattr(self, key[0], tmp)
                else: # Multi block (Variable or Fixed count)
                    setattr(self, key[0], [])
        else:
            self.load(data)
    
    def load(self, data):
        # Heuristic fix for padded ObjectUpdateCompressed packets
        offset_shift = 0
        if self.name == "ObjectUpdateCompressed":
             # Check if the count at the expected offset (10) is 0, but packet is large
             # Expected offset 10 comes from RegionData (10 bytes)
             if len(data) > 20 and data[10] == 0:
#                 print(f"[DEBUG] Repositioning scanner for {self.name}...")
                 for i in range(11, min(len(data), 64)):
                     if data[i] != 0:
                         # Found potential count
#                         print(f"[DEBUG] Found non-zero byte {data[i]} at offset {i}. shifting...")
                         # We need the scanner to arrive at 'i' when it wants to read the count.
                         # The scanner is at 'offset' (which tracks key processing).
                         # We can't easily change the loop behavior, but we can slide the data?
                         # Or simpler: The scanner logic below uses 'offset'.
                         # We can artificially increase 'offset' IF we are processing ObjectDate (key[1]==0).
                         
                         # Actually, we can just detect the padding and consume it explicitly?
                         # But the structure is rigid.
                         
                         # Strategy: If we are here, we modify 'data' to remove padding?
                         # No, 'RegionData' needs 10 bytes. The padding is AFTER RegionData?
                         # i = new offset for count.
                         # expected = 10.
                         # padding = i - 10.
                         
                         # found potential count
                         offset_shift = i - 10
#                          print(f"[DEBUG] Shift detected: {offset_shift}. New count byte: {data[i]}")
                         break
                         
        offset = 0
        for key in self.blocks:
            if key[1] == 1:
                tmp = {}
                for value in self.structure[key[0]]:
                    tlen = 0
                    if value[1] == "Variable":
                        if value[2] == 1:
                            tlen_prefix = struct.unpack_from("<B", data, offset)[0]
                            offset += 1
                        elif value[2] == 2:
                            tlen_prefix = struct.unpack_from("<H", data, offset)[0]
                            offset += 2
                        tlen = tlen_prefix
                    elif value[1] == "Fixed": tlen = value[2]
                    else: tlen = typeLengths[value[1]]
                    
                    val_data = data[offset:offset+tlen]
                    # FIX: Pass the Variable length type (1 or 2) to llEncodeType
                    tmp[value[0]] = llEncodeType(val_data, value[1], value[2] if value[1]=="Variable" else None)
                    offset += tlen
                setattr(self, key[0], tmp)
            else: # Variable count blocks (key[1] == 0) or Fixed count blocks (key[1] > 1)
                
                # Apply heuristic shift if this is the variable block and we detected padding
                if self.name == "ObjectUpdateCompressed" and key[1] == 0 and offset_shift > 0:
#                     print(f"[DEBUG] Applying offset shift {offset_shift} for ObjectData...")
                    offset += offset_shift
                
                count = key[1]
                if count == 0: # Variable count (always U8)
                    count = struct.unpack_from(">B", data, offset)[0]; offset += 1
                
                outblock = []
                for i in range(count):
                    tmp = {}
                    for value in self.structure[key[0]]:
                        tlen = 0
                        if value[1] == "Variable":
                            if value[2] == 1:
                                tlen_prefix = struct.unpack_from("<B", data, offset)[0]
                                offset += 1
                            elif value[2] == 2:
                                tlen_prefix = struct.unpack_from("<H", data, offset)[0]
                                offset += 2
                            tlen = tlen_prefix
                        elif value[1] == "Fixed": tlen = value[2]
                        else: tlen = typeLengths[value[1]]
                        
                        val_data = data[offset:offset+tlen]
                        # FIX: Pass the Variable length type (1 or 2) to llEncodeType
                        tmp[value[0]] = llEncodeType(val_data, value[1], value[2] if value[1]=="Variable" else None)
                        offset += tlen
                    outblock.append(tmp)
                setattr(self, key[0], outblock)

    def __bytes__(self):
        try:
            result = b""
            for key in self.blocks:
                if key[1] == 1:
                    tmp = getattr(self, key[0])
                    for value in self.structure[key[0]]:
                        result += llDecodeType(tmp[value[0]], value[1])
                else:
                    tmp = getattr(self, key[0])
                    if key[1] == 0: result += struct.pack("B", len(tmp))
                    for item in tmp:
                        for value in self.structure[key[0]]:
                            result += llDecodeType(item[value[0]], value[1])
            return result
        except Exception as e:
            print(f"[CRITICAL] BaseMessage.__bytes__ ERROR: {e}")
            raise e

message_lookup = {}
def registerMessage(msg):
    id = msg.id
    if msg.freq == 1: id = id + 0xFF00
    elif msg.freq == 2: id = id + 0xFFFF0000
    message_lookup[id] = msg
    message_lookup[msg.name.lower()] = msg

def getMessageByID(key, data = None):
    if key in message_lookup: return message_lookup[key](data=data)
    else: return None

def getMessageByName(key, data = None):
    key = key.lower()
    if key in message_lookup: return message_lookup[key](data=data)
    else: return None

# --- ESSENTIAL MESSAGES FOR CHAT/LOGIN/TELEPORT ---

class UseCircuitCode(BaseMessage):
    name = "UseCircuitCode"; id = 3; freq = 2; trusted = False; zero_coded = False
    blocks = [("CircuitCode", 1)]
    structure = {"CircuitCode": [("Code", "U32"), ("SessionID", "LLUUID"), ("ID", "LLUUID")]}
registerMessage(UseCircuitCode)

class CompleteAgentMovement(BaseMessage):
    name = "CompleteAgentMovement"; id = 249; freq = 2; trusted = False; zero_coded = False
    blocks = [("AgentData", 1)]
    structure = {"AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID"), ("CircuitCode", "U32")]}
registerMessage(CompleteAgentMovement)

class RegionHandshake(BaseMessage):
    name = "RegionHandshake"; id = 148; freq = 2; trusted = True; zero_coded = True
    blocks = [("RegionInfo", 1), ("RegionInfo2", 1), ("RegionInfo3", 1), ("RegionInfo4", 0)]
    structure = {
        "RegionInfo": [("RegionFlags", "U32"), ("SimAccess", "U8"), ("SimName", "Variable", 1), ("SimOwner", "LLUUID"), ("IsEstateManager", "BOOL"), ("WaterHeight", "F32"), ("BillableFactor", "F32"), ("CacheID", "LLUUID"), ("TerrainBase0", "LLUUID"), ("TerrainBase1", "LLUUID"), ("TerrainBase2", "LLUUID"), ("TerrainBase3", "LLUUID"), ("TerrainDetail0", "LLUUID"), ("TerrainDetail1", "LLUUID"), ("TerrainDetail2", "LLUUID"), ("TerrainDetail3", "LLUUID"), ("TerrainStartHeight00", "F32"), ("TerrainStartHeight01", "F32"), ("TerrainStartHeight10", "F32"), ("TerrainStartHeight11", "F32"), ("TerrainHeightRange00", "F32"), ("TerrainHeightRange01", "F32"), ("TerrainHeightRange10", "F32"), ("TerrainHeightRange11", "F32")],
        "RegionInfo2": [("RegionID", "LLUUID")],
        "RegionInfo3": [("CPUClassID", "S32"), ("CPURatio", "S32"), ("ColoName", "Variable", 1), ("ProductSKU", "Variable", 1), ("ProductName", "Variable", 1)],
        "RegionInfo4": [("RegionFlagsExtended", "U64"), ("RegionProtocols", "U64")]
    }
registerMessage(RegionHandshake)

class FindAgentReply(BaseMessage):
    name = "FindAgentReply"; id = 241; freq = 2; trusted = False; zero_coded = True
    blocks = [("AgentBlock", 1), ("LocationBlock", 0)]
    structure = {
        "AgentBlock": [("AgentID", "LLUUID")],
        "LocationBlock": [("X", "F64"), ("Y", "F64")]
    }
registerMessage(FindAgentReply)

class AvatarPropertiesRequest(BaseMessage):
    name = "AvatarPropertiesRequest"; id = 169; freq = 2; trusted = False; zero_coded = False
    blocks = [("AgentData", 1)]
    structure = {"AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID"), ("AvatarID", "LLUUID")]}
registerMessage(AvatarPropertiesRequest)

class AvatarPropertiesReply(BaseMessage):
    name = "AvatarPropertiesReply"; id = 171; freq = 2; trusted = True; zero_coded = True
    blocks = [("AgentData", 1), ("PropertiesData", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("AvatarID", "LLUUID")],
        "PropertiesData": [
            ("ImageID", "LLUUID"),
            ("FLImageID", "LLUUID"),
            ("PartnerID", "LLUUID"),
            ("AboutText", "Variable", 2),
            ("FLAboutText", "Variable", 1),
            ("BornOn", "Variable", 1),
            ("ProfileURL", "Variable", 1),
            ("CharterMember", "Variable", 1),
            ("Flags", "U32")
        ]
    }
registerMessage(AvatarPropertiesReply)

class RegionHandshakeReply(BaseMessage):
    name = "RegionHandshakeReply"; id = 149; freq = 2; trusted = False; zero_coded = True
    blocks = [("AgentData", 1), ("RegionInfo", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        "RegionInfo": [("Flags", "U32")]
    }
registerMessage(RegionHandshakeReply)

class ChatFromSimulator(BaseMessage):
    name = "ChatFromSimulator"; id = 139; freq = 2; trusted = True; zero_coded = False
    blocks = [("ChatData", 1)]
    # Message field uses Variable, type 2, which allows for longer messages (up to 65535 bytes)
    structure = {"ChatData": [("FromName", "Variable", 1), ("SourceID", "LLUUID"), ("OwnerID", "LLUUID"), ("SourceType", "U8"), ("ChatType", "U8"), ("Audible", "U8"), ("Position", "LLVector3"), ("Message", "Variable", 2)]}
registerMessage(ChatFromSimulator)

class ChatFromViewer(BaseMessage):
    name = "ChatFromViewer"; id = 80; freq = 2; trusted = False; zero_coded = False
    blocks = [("AgentData", 1), ("ChatData", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        "ChatData": [("Message", "Variable", 2), ("Type", "U8"), ("Channel", "S32")]
    }
registerMessage(ChatFromViewer)

class AgentThrottle(BaseMessage):
    name = "AgentThrottle"; id = 81; freq = 2; trusted = False; zero_coded = True
    blocks = [("AgentData", 1), ("Throttle", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID"), ("CircuitCode", "U32")],
        # Throttles field is a Variable, type 1, containing the 7 floats
        "Throttle": [("GenCounter", "U32"), ("Throttles", "Variable", 1)]
    }
registerMessage(AgentThrottle)

class AgentFOV(BaseMessage):
    name = "AgentFOV"; id = 82; freq = 2; trusted = False; zero_coded = False
    blocks = [("AgentData", 1), ("FOVBlock", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID"), ("CircuitCode", "U32")],
        "FOVBlock": [("GenCounter", "U32"), ("VerticalAngle", "F32")]
    }
registerMessage(AgentFOV)

class AgentHeightWidth(BaseMessage):
    name = "AgentHeightWidth"; id = 83; freq = 2; trusted = False; zero_coded = False
    blocks = [("AgentData", 1), ("HeightWidthBlock", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID"), ("CircuitCode", "U32")],
        "HeightWidthBlock": [("GenCounter", "U32"), ("Height", "U16"), ("Width", "U16")]
    }
registerMessage(AgentHeightWidth)

class AgentUpdate(BaseMessage):
    name = "AgentUpdate"; id = 4; freq = 0; trusted = False; zero_coded = True
    blocks = [("AgentData", 1)]
    structure = {"AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID"), ("BodyRotation", "LLQuaternion"), ("HeadRotation", "LLQuaternion"), ("State", "U8"), ("CameraCenter", "LLVector3"), ("CameraAtAxis", "LLVector3"), ("CameraLeftAxis", "LLVector3"), ("CameraUpAxis", "LLVector3"), ("Far", "F32"), ("ControlFlags", "U32"), ("Flags", "U8")]}
registerMessage(AgentUpdate)

class PacketAck(BaseMessage):
    name = "PacketAck"; id = 4294967291; freq = 3; trusted = False; zero_coded = False
    blocks = [("Packets", 0)]
    structure = {"Packets": [("ID", "U32")]}
registerMessage(PacketAck)

class StartPingCheck(BaseMessage):
    name = "StartPingCheck"; id = 1; freq = 0; trusted = False; zero_coded = False
    blocks = [("PingID", 1)]
    structure = {"PingID": [("PingID", "U8"), ("OldestUnacked", "U32")]}
registerMessage(StartPingCheck)

class CompletePingCheck(BaseMessage):
    name = "CompletePingCheck"; id = 2; freq = 0; trusted = False; zero_coded = False
    blocks = [("PingID", 1)]
    structure = {"PingID": [("PingID", "U8")]}
registerMessage(CompletePingCheck)

class LogoutRequest(BaseMessage):
    name = "LogoutRequest"; id = 252; freq = 2; trusted = False; zero_coded = False
    blocks = [("AgentData", 1)]
    structure = {"AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")]}
registerMessage(LogoutRequest)

class TeleportFinish(BaseMessage):
    name = "TeleportFinish"; id = 69; freq = 2; trusted = True; zero_coded = False
    blocks = [("Info", 1)]
    structure = {"Info": [("AgentID", "LLUUID"), ("LocationID", "U32"), ("SimIP", "IPADDR"), ("SimPort", "IPPORT"), ("RegionHandle", "U64"), ("SeedCapability", "Variable", 2), ("SimAccess", "U8"), ("TeleportFlags", "U32")]}
registerMessage(TeleportFinish)

class CloseCircuit(BaseMessage):
    name = "CloseCircuit"; id = 4294967293; freq = 3; trusted = False; zero_coded = False
    blocks = []
    structure = {}
registerMessage(CloseCircuit)

# --- Teleport Messages ---

class TeleportOffer(BaseMessage):
    name = "TeleportOffer"; id = 71; freq = 2; trusted = True; zero_coded = True
    blocks = [("Offer", 1)]
    structure = {"Offer": [("TeleportID", "LLUUID"), ("FromAgentID", "LLUUID"), ("TargetPosition", "LLVector3"), ("RegionHandle", "U64"), ("SIMIP", "IPADDR"), ("SIMPort", "IPPORT"), ("L$Cost", "S32"), ("RegionName", "Variable", 1)]}
registerMessage(TeleportOffer)

class TeleportAccept(BaseMessage):
    name = "TeleportAccept"; id = 73; freq = 2; trusted = False; zero_coded = True
    blocks = [("AgentData", 1), ("Teleport", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        "Teleport": [("TeleportID", "LLUUID"), ("LicenseAccepted", "BOOL"), ("L$Cost", "S32")]
    }
registerMessage(TeleportAccept)

class TeleportLocationRequest(BaseMessage):
    name = "TeleportLocationRequest"; id = 67; freq = 2; trusted = False; zero_coded = True
    blocks = [("AgentData", 1), ("Info", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        "Info": [("RegionHandle", "U64"), ("Position", "LLVector3"), ("LookAt", "LLVector3")]
    }
registerMessage(TeleportLocationRequest)

class TeleportStart(BaseMessage):
    name = "TeleportStart"; id = 59; freq = 2; trusted = True; zero_coded = True
    blocks = [("Info", 1)]
    structure = {"Info": [("TeleportFlags", "U32")]}
registerMessage(TeleportStart)

class TeleportProgress(BaseMessage):
    name = "TeleportProgress"; id = 60; freq = 2; trusted = True; zero_coded = True
    blocks = [("Info", 1), ("AgentData", 1)]
    structure = {
        "Info": [("TeleportFlags", "U32"), ("Message", "Variable", 1)],
        "AgentData": [("AgentID", "LLUUID")]
    }
registerMessage(TeleportProgress)

class TeleportFailed(BaseMessage):
    name = "TeleportFailed"; id = 61; freq = 2; trusted = True; zero_coded = True
    blocks = [("Info", 1), ("AlertInfo", 0)]
    structure = {
        "Info": [("Reason", "Variable", 1)],
        "AlertInfo": [("ExtraParams", "Variable", 1)]
    }
registerMessage(TeleportFailed)

class UUIDNameRequest(BaseMessage):
    name = "UUIDNameRequest"; id = 155; freq = 2; trusted = False; zero_coded = False
    blocks = [("UUIDNameBlock", 0)]
    structure = {"UUIDNameBlock": [("ID", "LLUUID")]}
registerMessage(UUIDNameRequest)

class UUIDNameReply(BaseMessage):
    name = "UUIDNameReply"; id = 156; freq = 2; trusted = True; zero_coded = False
    blocks = [("UUIDNameBlock", 0)]
    structure = {"UUIDNameBlock": [("ID", "LLUUID"), ("FirstName", "Variable", 1), ("LastName", "Variable", 1)]}
registerMessage(UUIDNameReply)

# --- Map Lookup Messages ---

class MapNameRequest(BaseMessage):
    name = "MapNameRequest"; id = 66; freq = 2; trusted = False; zero_coded = True
    blocks = [("AgentData", 1), ("RequestData", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        # Name field uses Variable, type 1
        "RequestData": [("Name", "Variable", 1), ("Flags", "U32")]
    }
registerMessage(MapNameRequest)

class MapItemReply(BaseMessage):
    name = "MapItemReply"; id = 100; freq = 2; trusted = True; zero_coded = True
    blocks = [("AgentData", 1), ("Data", 0)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        "Data": [
            ("X", "U16"), ("Y", "U16"), ("Handle", "U64"),
            ("Name", "Variable", 1), ("Agents", "U8")
        ]
    }
registerMessage(MapItemReply)

# --- Agent Data Messages ---

class AgentMovementComplete(BaseMessage):
    name = "AgentMovementComplete"; id = 250; freq = 2; trusted = True; zero_coded = True
    blocks = [("AgentData", 1), ("Data", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        "Data": [
            ("Position", "LLVector3"), ("LookAt", "LLVector3"), 
            ("RegionHandle", "U64"), ("Timestamp", "U32")
        ]
    }
registerMessage(AgentMovementComplete)

class AgentDataRequest(BaseMessage):
    name = "AgentDataRequest"; id = 225; freq = 2; trusted = False; zero_coded = True
    blocks = [("AgentData", 1)]
    structure = {"AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")]}
registerMessage(AgentDataRequest)

class AgentDataUpdate(BaseMessage):
    name = "AgentDataUpdate"; id = 156; freq = 2; trusted = True; zero_coded = True
    blocks = [("AgentData", 1)]
    structure = {
        "AgentData": [
            ("AgentID", "LLUUID"), ("SessionID", "LLUUID"), 
            ("FirstName", "Variable", 1), ("LastName", "Variable", 1),
            ("GroupMask", "U32"), ("AbilityMask", "U32"), ("GodLevel", "U8")
        ]
    }
registerMessage(AgentDataUpdate)

# --- Object/Self Position Update Messages (For Minimap) ---

class ImprovedTerseObjectUpdate(BaseMessage):
    name = "ImprovedTerseObjectUpdate"; id = 4294967292; freq = 3; trusted = False; zero_coded = True
    blocks = [("RegionData", 1), ("ObjectData", 0)]
    structure = {
        "RegionData": [("RegionHandle", "U64"), ("TimeDilation", "U16"), ("TimeSinceLastUpdate", "U16")],
        "ObjectData": [
            ("ID", "U32"), 
            ("CRC", "U32"),
            ("Data", "Variable", 1) # Variable length data block containing position/rotation/etc.
        ]
    }
registerMessage(ImprovedTerseObjectUpdate)

class ObjectUpdate(BaseMessage):
    # FIX: Frequency is 0 (High Priority / 1-byte ID) for ObjectUpdate (ID 16)
    name = "ObjectUpdate"; id = 16; freq = 0; trusted = True; zero_coded = True
    blocks = [("RegionData", 1), ("ObjectData", 0)]
    structure = {
        "RegionData": [("RegionHandle", "U64"), ("TimeDilation", "U16")],
        "ObjectData": [
            ("ID", "U32"), ("State", "U8"), ("FullID", "LLUUID"), ("CRC", "U32"), ("PCode", "U8"),
            ("Material", "U8"), ("ClickAction", "U8"), ("Scale", "LLVector3"), ("ObjectData", "Variable", 1),
            ("ParentID", "U32"), ("UpdateFlags", "U32"), ("PathCurve", "U8"), ("ProfileCurve", "U8"),
            ("PathBegin", "U16"), ("PathEnd", "U16"), ("PathScaleX", "U8"), ("PathScaleY", "U8"),
            ("PathShearX", "U8"), ("PathShearY", "U8"), ("PathTwist", "S8"), ("PathTwistBegin", "S8"),
            ("PathRadiusOffset", "S8"), ("PathTaperX", "S8"), ("PathTaperY", "S8"), ("PathRevolutions", "U8"),
            ("PathSkew", "S8"), ("ProfileBegin", "U16"), ("ProfileEnd", "U16"), ("ProfileHollow", "U16"),
            ("TextureEntry", "Variable", 2), ("TextureAnim", "Variable", 1), ("NameValue", "Variable", 1),
            ("Data", "Variable", 2), ("Text", "Variable", 1), ("TextColor", "Color4U"),
            ("MediaURL", "Variable", 1), ("ParticleSystem", "Variable", 1), ("ExtraParams", "Variable", 1),
            ("Sound", "LLUUID"), ("OwnerID", "LLUUID"), ("SoundGain", "F32"), ("SoundRadius", "U8"),
            ("SoundFlags", "U8"), ("JointType", "U8"), ("JointPivot", "LLVector3"), ("JointAxisOrAnchor", "LLVector3")
        ]
    }
registerMessage(ObjectUpdate)

class ObjectUpdateCompressed(BaseMessage):
    name = "ObjectUpdateCompressed"; id = 17; freq = 1; trusted = True; zero_coded = True
    blocks = [("RegionData", 1), ("ObjectData", 0)]
    structure = {
        "RegionData": [("RegionHandle", "U64"), ("TimeDilation", "U16")],
        "ObjectData": [
            ("UpdateFlags", "U32"), ("Data", "Variable", 1)
        ]
    }
registerMessage(ObjectUpdateCompressed)

class CoarseLocationUpdate(BaseMessage):
    # FIX: Medium Frequency (1) for CoarseLocationUpdate
    name = "CoarseLocationUpdate"; id = 6; freq = 1; trusted = False; zero_coded = False
    blocks = [("Location", 0), ("Index", 0), ("AgentData", 0)]
    structure = {
        "Location": [("X", "U8"), ("Y", "U8"), ("Z", "U8")],
        "Index": [("You", "S16"), ("Prey", "S16")],
        "AgentData": [("AgentID", "LLUUID")]
    }
registerMessage(CoarseLocationUpdate)

class ImagePacket(BaseMessage):
    name = "ImagePacket"; id = 11; freq = 0; trusted = False; zero_coded = True
    blocks = [("ImageID", 1), ("ImageData", 1)]
    structure = {
        "ImageID": [("ID", "LLUUID"), ("Codec", "U8"), ("Packet", "U16"), ("Packets", "U16")],
        "ImageData": [("Data", "Variable", 2)]
    }
registerMessage(ImagePacket)

# --- KICKUSER PACKET ---
class KickUser(BaseMessage):
    # This is a high-frequency (2), trusted message
    name = "KickUser"; id = 244; freq = 2; trusted = True; zero_coded = True
    blocks = [("UserInfo", 1), ("TargetBlock", 1)]
    structure = {
        "UserInfo": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        # Reason field uses Variable, type 2, which allows for longer messages
        "TargetBlock": [("Reason", "Variable", 2), ("TargetID", "LLUUID")]
    }
registerMessage(KickUser)
# --- END KICKUSER PACKET ---


# ==========================================
# SECTION 5: PACKET HANDLING (packet.py)
# ==========================================

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

# ==========================================
# SECTION 6: NETWORK LAYER (UDPStream.py as RegionClient)
# ==========================================

class RegionClient:
    host = ""; port = 0; sock = None
    agent_id = None; session_id = None; loginToken = {}
    nextAck = 0
    sequence = 1; acks = []
    circuit_code = None; debug = False
    
    # Existing control variables (now updated by the Agent via methods)
    controls = 0; controls_once = 0 
    
    sim = {}
    log_callback = None
    ui_callback = None
    
    # --- New variables for Handshake Retries ---
    handshake_complete = False
    last_circuit_send = 0 
    last_update_send = 0
    circuit_packet = None 
    circuit_sequence = 0 
    
    # NEW: Tracking for CompleteAgentMovement (CAM)
    cam_packet = None
    last_cam_send = 0
    cam_sequence = 0
    
    # NEW: General Reliable Packet Tracking
    reliable_packets = {} 

    # NEW: Thread-safe primitives for map lookup
    teleport_lookup_lock = threading.Lock()
    teleport_lookup_event = threading.Event()
    teleport_lookup_result = None
    teleport_lookup_target_name = None 

    # NEW: Agent position data (For Minimap)
    agent_x = 128.0
    agent_y = 128.0
    agent_z = 30.0
    
    # NEW: Global Grid Coordinates for Map Fetching
    grid_x = 1000
    grid_y = 1000
    local_id = 0 # NEW: Store the simulator-assigned LocalID for the agent

    # NEW: List to store positions of other avatars [(x, y, z), ...]
    other_avatars = []
    
    # NEW: Capability storage
    capabilities = {}
    seed_cap_url = ""

    # MODIFIED: Added log_callback to constructor
    def __init__(self, loginToken, host="0.0.0.0", port=0, debug=False, log_callback=None):
        self.debug = debug
        self.log_callback = log_callback if log_callback is not None else lambda msg: None
        self.other_avatars = [] # Initialize list
        self.tracked_avatars = {} # NEW: UUID string -> dict of info
        self.local_id = 0 # Reset local_id
        
        if loginToken.get("login") != "true":
            raise ConnectionError("Unable to log into simulator: %s" % loginToken.get("message", "Unknown"))
        
        self.loginToken = loginToken
        self.host = loginToken["sim_ip"]
        self.port = loginToken["sim_port"]
        self.session_id = LLUUID(loginToken["session_id"])
        self.agent_id = LLUUID(loginToken["agent_id"])
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.settimeout(1.0)
        # Using 0.0.0.0 allows listening on all interfaces
        self.sock.bind((host, port))
        
        # The circuit_code from login token is a string (e.g., "1234567"), need to pack the integer value
        self.circuit_code = int(loginToken["circuit_code"])
        
        # Capture Seed Capability URL
        self.seed_cap_url = loginToken.get("seed_capability", "")
        # FIX: Capture all initial capabilities provided at login time
        self.capabilities = loginToken.get("capabilities", {}).copy()
        self.log(f"Seed Capability obtained: {self.seed_cap_url}")
        self.log(f"Initial capabilities: {list(self.capabilities.keys())}")

        # Extract initial region grid coordinates (in meters) and convert to tile coordinates
        # Default is Da Boom (1000, 1000) if missing
        
        try:
            val_x = loginToken.get("region_x", 0)
            val_y = loginToken.get("region_y", 0)
            
            r_x = int(float(val_x))
            r_y = int(float(val_y))
        except Exception as e:
            self.log(f"Coord Parse Error: {e}")
            r_x = 0; r_y = 0
            
        if r_x > 0 and r_y > 0:
            self.grid_x = r_x // 256
            self.grid_y = r_y // 256
        else:
            # If coordinates are missing, we default to 0, 0 to trigger the fallback lookup mechanism
            self.log_callback("[CHAT] Warning: Region coordinates missing/invalid. Defaulting to (0, 0).")
            self.grid_x = 0
            self.grid_y = 0
        
        
        self.last_circuit_send = 0 # Forces an immediate send on first loop iteration

    @property
    def seq(self):
        self.sequence += 1
        return self.sequence - 1
    
    def log(self, message):
        """Helper function to route messages via the callback."""
        if self.log_callback:
            self.log_callback(message)
        # Always print to console for "activated debug console output" request
        print(f"[CLIENT_LOG] {message}")
    
    def send_use_circuit_code(self):
        # *** FIX: Store and reuse the packet and sequence number ***
        if self.circuit_packet is None:
            # First time: generate and store the packet
            msg = getMessageByName("UseCircuitCode")
            msg.CircuitCode["Code"] = self.circuit_code
            msg.CircuitCode["SessionID"] = self.session_id
            msg.CircuitCode["ID"] = self.agent_id
            
            self.circuit_sequence = self.seq 
            # The use of ack=False is important here to ensure no acks are piggybacked on the first packet.
            # FIX: Ensure reliable=True is explicitly set for handshake packets
            self.circuit_packet = Packet(sequence=self.circuit_sequence, message=msg, reliable=True, ack=False)
        
        # Resend the stored packet (with the original sequence number)
        self.send(self.circuit_packet)
        self.last_circuit_send = time.time()

    def send_complete_movement(self):
        # *** NEW: Store and reuse the CAM packet and sequence number ***
        if self.cam_packet is None:
            # First time: generate and store the packet
            msg = getMessageByName("CompleteAgentMovement")
            msg.AgentData["AgentID"] = self.agent_id
            msg.AgentData["SessionID"] = self.session_id
            msg.AgentData["CircuitCode"] = self.circuit_code
            
            self.cam_sequence = self.seq 
            # FIX: Ensure reliable=True is explicitly set for handshake packets
            self.cam_packet = Packet(sequence=self.cam_sequence, message=msg, reliable=True, ack=False)
        
        # Resend the stored packet (with the original sequence number)
        self.send(self.cam_packet)
        self.last_cam_send = time.time()
        
    def send_teleport_accept(self, teleport_id, cost=0, license=True):
        msg = getMessageByName("TeleportAccept")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        msg.Teleport["TeleportID"] = teleport_id
        msg.Teleport["LicenseAccepted"] = license
        msg.Teleport["L$Cost"] = cost
        # TeleportAccept must be reliable, sending directly via send will use the new logic
        self.send(msg, reliable=True) 
        return True



    def handleInternalPackets(self, pck):
        if pck.body.name == "UnknownID":
             if self.local_id == 0:
                 self.log_callback(f"[SPY] Unrecognized ID: {pck.MID}")
             return

        # Packet Spy: Log all named packets until we find ourselves
        if self.local_id == 0:
             self.log_callback(f"[SPY] Packet: {pck.body.name} (ID {pck.MID})")
        
        # NEW: Process ACKs in the received packet
        for seq_id in pck.acks:
            if seq_id in self.reliable_packets:
                del self.reliable_packets[seq_id]
                self.log(f"ACK received for reliable packet {seq_id}.")
                self.log(f"ACK_CONFIRMED: {seq_id}") # Trigger UI notification

        if pck.body.name == "PacketAck":
            # Process dedicated PacketAck messages
            for block in pck.body.Packets:
                seq_id = block["ID"]
                if seq_id in self.reliable_packets:
                    del self.reliable_packets[seq_id]
                    self.log(f"Dedicated ACK received for reliable packet {seq_id}.")
                    self.log(f"ACK_CONFIRMED: {seq_id}") # Trigger UI notification

        elif pck.body.name == "MapItemReply":
            # NEW: Handle MapItemReply for active lookup
            if self.teleport_lookup_target_name is not None:
                with self.teleport_lookup_lock:
                    target_name = self.teleport_lookup_target_name
                    
                    # Search through the blocks for a matching region name
                    for block in pck.body.Data:
                        # Ensure comparison is case-insensitive, robust to variable encoding
                        # FIX: Need to strip the null terminator from MapItemReply too!
                        if safe_decode_llvariable(block["Name"]).lower() == target_name: 
                            # *** FIX: Check if we already have a result. If so, don't overwrite
                            if self.teleport_lookup_result is None:
                                self.teleport_lookup_result = block
                                self.teleport_lookup_event.set() # Signal the waiting thread
                            return
            
        elif pck.body.name == "ObjectUpdate":
            # Capture LocalID from ObjectUpdate to enable Terse updates
            for block in pck.body.ObjectData:
                # Check if this object is ME
                # Note: FullID might be under 'FullID' or similar depending on the block type
                # FIX: Use dictionary access and compare UUID bytes or string
                full_id = block.get("FullID")
                pcode = block.get("PCode")
                
                # DIAGNOSTIC: Log all ObjectUpdate IDs to see if we are missed
#                 print(f"[OBJ] ObjectUpdate Candidate: {full_id} vs {self.agent_id}")
                
                if full_id and str(full_id).lower() == str(self.agent_id).lower():
                    self.local_id = block["ID"]
                    print(f"[VERBOSE] MINIMAP SYNC: LocalID Captured from ObjectUpdate: {self.local_id}")
                    self.log_callback("MINIMAP_UPDATE")
                    
                    # Also set self position if present
                    obj_data = block.get("ObjectData", b"")
                    if hasattr(obj_data, "data"):
                        obj_data = obj_data.data
                    if len(obj_data) >= 12:
                        try:
                            px, py, pz = struct.unpack("<fff", obj_data[0:12])
                            if px < 1000 and py < 1000:
                                self.agent_x, self.agent_y, self.agent_z = px, py, pz
                        except: pass
                    
                # Track other avatars
                if pcode == 47:
                    uuid_str = str(full_id) if full_id else None
                    if not uuid_str: continue
                    
                    # STRICT FILTERING: Never track ourselves
                    if uuid_str.lower() == str(self.agent_id).lower():
                        continue
                    
                    # USE LOWERCASE KEYS FOR CONSISTENCY
                    uuid_str = uuid_str.lower()
                    
                    # Try to extract initial position from ObjectData bytes (12 bytes float vector)
                    pos = (0, 0, 0)
                    obj_data = block.get("ObjectData", b"")
                    if hasattr(obj_data, "data"):
                        obj_data = obj_data.data
                    if len(obj_data) >= 12:
                        try:
                            px, py, pz = struct.unpack("<fff", obj_data[0:12])
                            if px < 1000 and py < 1000:
                                pos = (px, py, pz)
                        except: pass
                    
                    if uuid_str not in self.tracked_avatars:
                        self.tracked_avatars[uuid_str] = {"pos": pos, "name": "Resolving...", "distance": 0.0, "last_seen": time.time(), "local_id": block.get("ID", 0)}
                    else:
                        self.tracked_avatars[uuid_str]["pos"] = pos
                        self.tracked_avatars[uuid_str]["last_seen"] = time.time()
                        self.tracked_avatars[uuid_str]["local_id"] = block.get("ID", 0)

        elif pck.body.name == "ObjectUpdateCompressed":
            # Handle Compressed Updates - Try to find ourselves in the blob
            # self.log_callback(f"[DEBUG] Received ObjectUpdateCompressed!")
#             print(f"[DEBUG] ObjectUpdateCompressed: {len(pck.body.ObjectData)} objects")
            
            for block in pck.body.ObjectData:
                 data_blob = block["Data"].data
                 # DIAGNOSTIC: Hexdump start of blob
#                  print(f"[COMP] Blob Len: {len(data_blob)}")
#                  print(hexdump(data_blob[:64]))
                 
                 # SEARCH for our UUID in the blob
                 search_target = self.agent_id.bytes
                 self.agent_id.bytes[::-1]
#                  print(f"[DEBUG] Searching for AgentID: {self.agent_id} in blob ({len(data_blob)} bytes)")
                 
                 found_idx = -1
                 if search_target in data_blob:
                     found_idx = data_blob.find(search_target)

                 if found_idx >= 0 and found_idx + 20 <= len(data_blob):
                     # In ObjectUpdateCompressed, if FullID is included, LocalID (U32) is immediately after the 16-byte UUID.
                     guessed_local_id = struct.unpack("<I", data_blob[found_idx+16:found_idx+20])[0]
                     if self.local_id != guessed_local_id:
                         print(f"[INFO] Discovered own LocalID from Compressed Update: {guessed_local_id}")
                         self.local_id = guessed_local_id
            
        elif pck.body.name == "ImprovedTerseObjectUpdate":
            for block in pck.body.ObjectData:
                # Match against the captured LocalID or heuristic
                is_me = False
                if self.local_id != 0:
                    is_me = (block["ID"] == self.local_id)
                # Removed the bad fallback logic
                
                if is_me:
                    data = block["Data"].data 
                    # self.log_callback(f"[DEBUG] Terse Update for ME. Len={len(data)}")
                    
                    if len(data) >= 12:
                        try:
                            # Standard Avatar Interpretation (Offset 1, 12 bytes float)
                            # Or maybe Offset 0?
                            # Try to find reasonable coordinates
                            # Debug dump
                            # self.log_callback(f"[DEBUG] Terse Hex: {data.hex()}")
                            
                            if len(data) >= 13: # Heuristic check for uncompressed
                                px, py, pz = struct.unpack("<fff", data[0:12]) # TRY OFFSET 0
                                # If silly values, try offset 1
                                if px > 1000 or py > 1000:
                                     px, py, pz = struct.unpack("<fff", data[1:13])
                                
                                # Normalizing: if values are > 256, they are likely global.
                                # Region local is always 0.0-256.0.
                                if px > 256: px %= 256
                                if py > 256: py %= 256
                                
                                self.agent_x, self.agent_y = px, py
                                print(f"[DEBUG] Self Pos Terse (uncomp): {self.agent_x}, {self.agent_y}")
                                self.log_callback("MINIMAP_UPDATE")
                                break
                            
                            # Compressed Interpretation (Offset 0, 4 bytes U16)
                            px_raw, py_raw = struct.unpack("<HH", data[0:4])
                            px, py = px_raw / 256.0, py_raw / 256.0
                            self.agent_x, self.agent_y = px, py
                            print(f"[DEBUG] Self Pos Terse (comp): {self.agent_x}, {self.agent_y}")
                            self.log_callback("MINIMAP_UPDATE")
                        except:
                            pass
                    break
        
        elif pck.body.name == "CoarseLocationUpdate":
            # Handle other avatars for minimap
            new_avatars = []
            
            # The sim typically sends 'Location' block.
            location_blocks = getattr(pck.body, 'Location', [])
            if not location_blocks:
                location_blocks = getattr(pck.body, 'AgentData', [])
                
            getattr(pck.body, 'AgentData', [])
            
            # Check for the 'Index' block to identify our own avatar
            my_index = -1
            getattr(pck.body, 'Index', [])
            
            # --- ROBUST BYTE ALIGNMENT & STRIDE FIX FOR COARSE LOCATION ---
            # Modern SL simulators include extra fields (like Status) in the AgentData block.
            # PyOGP's template only knows about AgentID (16 bytes), causing a cumulative drift.
            # We calculate the real stride (K) by dividing total remaining bytes by avatar count.
            real_uuids = [None] * len(location_blocks)
            raw = pck.bytes
            
            try:
                # Structure: [LocCount:U8] [Locs:N*3] [Idx:4] [AgentCount:U8] [Agents:N*Stride]
                loc_count = raw[0]
                agent_data_count_pos = 1 + loc_count * 3 + 4
                if agent_data_count_pos < len(raw):
                    agent_count = raw[agent_data_count_pos]
                    blocks_start = agent_data_count_pos + 1
                    remaining = len(raw) - blocks_start
                    
                    if agent_count > 0:
                        stride = remaining // agent_count
                        # print(f"[DEBUG] Coarse Stride: {stride} bytes (Expected 16+)")
                        
                        import uuid
                        for idx in range(agent_count):
                            offset = blocks_start + (idx * stride)
                            if offset + 16 <= len(raw):
                                real_uuids[idx] = str(uuid.UUID(bytes=raw[offset:offset+16])).lower()
            except Exception as e:
                self.log(f"Error in Coarse stride calculation: {e}")
            # --- END ROBUST FIX ---
            
            for i, block in enumerate(location_blocks):
                if 'X' in block and 'Y' in block:
                    x = block['X']
                    y = block['Y']
                    z = block.get('Z', 0)
                    
                    # Fetch dynamically aligned UUID
                    uuid_str = real_uuids[i] if i < len(real_uuids) else None
                    
                    # Fix: Ensure my_index is an int and compare correctly
                    # NEW: Also treat NULL UUID as 'me' (common for self-position in Coarse packets)
                    NULL_UUID = "00000000-0000-0000-0000-000000000000"
                    is_me = (i == int(my_index))
                    if uuid_str:
                        if uuid_str.lower() == str(self.agent_id).lower() or uuid_str == NULL_UUID:
                            is_me = True
                        
                    if is_me:
                        # For self-position in CoarseLocationUpdate, we overwrite our coordinates.
                        # This ensures distances in ChatTab are calculated from the current real position.
                        self.agent_x = float(x)
                        self.agent_y = float(y)
                        self.agent_z = float(z) * 4.0 # Scale Z by 4
                        # print(f"[VERBOSE] MINIMAP SYNC: Coarse Self Position Set to -> {self.agent_x}, {self.agent_y}")
                    else:
                        scaled_z = float(z) * 4.0
                        new_avatars.append((x, y, scaled_z))
                        
                        # --- USE ACTUAL UUID FOR NEARBY LIST UI ---
                        # STRICT FILTERING: Ensure uuid_str exists and is NOT us (case-insensitive)
                        if uuid_str:
                            is_us = (uuid_str.lower() == str(self.agent_id).lower())
                            if not is_us:
                                # USE LOWERCASE KEYS FOR CONSISTENCY
                                uuid_str = uuid_str.lower()
                                if uuid_str not in self.tracked_avatars:
                                    self.tracked_avatars[uuid_str] = {"pos": (x,y,scaled_z), "name": "Resolving...", "distance": 0.0, "last_seen": time.time(), "local_id": 0}
                                else:
                                    self.tracked_avatars[uuid_str]["pos"] = (x,y,scaled_z)
                                    self.tracked_avatars[uuid_str]["last_seen"] = time.time()
                
            self.other_avatars = new_avatars
            self.log_callback("MINIMAP_UPDATE")

        elif pck.body.name == "AgentMovementComplete":
            pos = pck.body.Data["Position"]
            self.agent_x = pos.x
            self.agent_y = pos.y
            self.agent_z = pos.z
            # self.log(f"[DEBUG] Location updated via AgentMovementComplete: {pos.x:.1f}, {pos.y:.1f}")
            self.log_callback("MINIMAP_UPDATE")

        elif pck.body.name == "AgentDataUpdate":
            # AgentDataUpdate usually doesn't have Position in this freq/id combo, but we handle it safely
            pass

        elif pck.body.name == "StartPingCheck":
            msg = getMessageByName("CompletePingCheck")
            msg.PingID["PingID"] = pck.body.PingID["PingID"]
            self.send(msg)
            
        elif pck.body.name == "RegionHandshake":
            self.handshake_complete = True # Signal that Handshake is done!
            
            # FIX: Safely decode SimName, handling potential missing/null values
            try:
                raw_name = pck.body.RegionInfo["SimName"]
                if hasattr(raw_name, 'data'):
                    self.sim['name'] = raw_name.data.replace(b'\x00', b'').decode('utf-8', errors='ignore').strip()
                else:
                    self.sim['name'] = bytes(raw_name).replace(b'\x00', b'').decode('utf-8', errors='ignore').strip()
            except Exception as e:
                self.log(f"Error decoding SimName: {e}")
                self.sim['name'] = "Unknown Region"
                
            if not self.sim['name']:
                self.sim['name'] = "Unknown Region"
            
            # self.acks.append(self.circuit_sequence) # REMOVED: Correct ACK logic is via received ACKs or PacketAck
            self.circuit_packet = None # No longer need to resend the circuit code
            self.cam_packet = None # ADDED: Clear CAM state

            msg = getMessageByName("RegionHandshakeReply")
            msg.AgentData["AgentID"] = self.agent_id
            msg.AgentData["SessionID"] = self.session_id
            msg.RegionInfo["Flags"] = 0
            self.send(msg)
            
            # Send initial state information
            self.throttle()
            self.setFOV()
            self.setWindowSize()
            
            # --- RECOMMENDED FIX: Send a reliable AgentUpdate immediately post-handshake ---
            # This confirms the client's state and location, often resolving a silent sim info deadlock.
            self.agentUpdate(controls=0, reliable=True)
            # --- END RECOMMENDED FIX ---
            
            # --- NEW: Request Agent Data for initial location ---
            self.requestAgentData()
            
            # --- MAP FETCH TRIGGER ---
            # Trigger map fetch whenever a RegionHandshake is successfully processed.
            if PIL_AVAILABLE: 
                self.log_callback(f"MAP_FETCH_TRIGGER, {self.sim['name']}")
                self.log(f"Handshake complete. Requesting map for {self.sim['name']}...")
            else:
                 self.log(f"Handshake complete. Map unavailable (PIL missing).")
            # --- END MAP FETCH TRIGGER ---
            
            # --- FIX: Send the successful login status to the UI ---
            self.log_callback(f"HANDSHAKE_COMPLETE, {self.sim['name']}")

        elif pck.body.name == "TeleportStart":
            self.log("TeleportStart received. Teleport sequence started...")

        elif pck.body.name == "TeleportProgress":
            msg = getattr(pck.body.Info, 'Message', b'').decode('utf-8', errors='ignore').strip()
            self.log(f"TeleportProgress: {msg}")

        elif pck.body.name == "TeleportFailed":
            reason = getattr(pck.body.Info, 'Reason', b'').decode('utf-8', errors='ignore').strip()
            self.log(f"TeleportFailed: {reason}")
            # --- END FIX ---
            
        # --- KICKUSER HANDLING (NEW) ---
        elif pck.body.name == "KickUser":
            reason = safe_decode_llvariable(pck.body.TargetBlock.get('Reason', 'Unknown reason from sim.'))
            self.log_callback(f"KICKED, {reason}")
        # --- END KICKUSER HANDLING ---

        elif pck.body.name == "TeleportFinish":
            # Update seed capability if available in TeleportFinish
            if hasattr(pck.body, 'Info'):
                self.seed_cap_url = safe_decode_llvariable(pck.body.Info.get("SeedCapability", ""))
                self.capabilities = {} # Reset caps for the new region
                self.log(f"Updated Seed Capability to {self.seed_cap_url}")
                
        # --- NEW: Catch UUIDNameReply for fast Avatar Name resolution ---
        elif pck.body.name == "UUIDNameReply":
            if hasattr(pck.body, 'UUIDNameBlock'):
                for block in pck.body.UUIDNameBlock:
                    uid = block.get("ID")
                    first = safe_decode_llvariable(block.get("FirstName", ""))
                    last = safe_decode_llvariable(block.get("LastName", ""))
                    
                    if uid and first:
                        uid_str = str(uid)
                        full_name = f"{first} {last}".strip()
                        
                        # Cache the name for general use
                        # Add a hook to UI callback if necessary (using the same event)
                        self.ui_callback("update_display_name", (uid_str, full_name))
                        
                        # Clean up fetch tracking
                        if uid_str in self.fetching_names:
                            self.fetching_names.remove(uid_str)
        # --- END UUIDNameReply Catch ---

        elif pck.body.name == "AvatarPropertiesReply":
            # Extract profile info from LLUDP packet
            try:
                agent_data = getattr(pck.body, 'AgentData', {})
                prop = getattr(pck.body, 'PropertiesData', {})
                
                avatar_id = agent_data.get('AvatarID')
                if not avatar_id:
                    self.log("[ERROR] AvatarPropertiesReply missing AvatarID")
                    return

                uid = str(avatar_id).lower()
                self.log(f"[DEBUG] Profile reply received for {uid}")
                
                # Helper to safely extract string from 'Variable' or bytes object
                def get_str(field_name):
                    val = prop.get(field_name)
                    if val is None: return ""
                    if hasattr(val, 'data') and isinstance(val.data, bytes):
                        return val.data.rstrip(b'\x00').decode('utf-8', errors='ignore')
                    elif isinstance(val, (bytes, bytearray)):
                        return val.rstrip(b'\x00').decode('utf-8', errors='ignore')
                    return str(val).strip('\x00').strip()
                
                # Helper to safely extract UUID string from LLUUID object
                def get_uuid_str(field_name):
                    val = prop.get(field_name)
                    if val is None: return ""
                    # LLUUID has a __bytes__ method; just str() it
                    return str(val).strip()
                
                about_text = get_str('AboutText')
                born_on = get_str('BornOn')
                profile_url = get_str('ProfileURL')
                # ImageID is an LLUUID type, NOT a Variable string
                image_id = get_uuid_str('ImageID')
                fl_image_id = get_uuid_str('FLImageID')
                
                # Use a non-empty profile image (prefer ImageID, fallback to FLImageID)
                final_image_id = image_id if image_id and image_id != '00000000-0000-0000-0000-000000000000' else fl_image_id
                
                # Cleanup
                about = about_text.strip() if about_text else "No profile text."
                born = born_on.strip() if born_on else "Unknown"
                url = profile_url.strip() if profile_url else ""

                self.ui_callback("show_profile", {
                    "id": uid,
                    "about": about,
                    "born": born,
                    "url": url,
                    "image_id": final_image_id,
                    "source": "LLUDP"
                })
            except Exception as e:
                self.log(f"[ERROR] Failed to parse AvatarPropertiesReply: {e}")
                import traceback
                print(traceback.format_exc())

        if pck.reliable:
            self.acks.append(pck.sequence)
        
        # Only run network maintenance if handshake is still incomplete
        if not self.handshake_complete:
            if time.time() > self.nextAck: self.sendAcks()

    def recv(self):
        try:
            # Original socket timeout is 1.0s, which is fine for the main loop
            blob = self.sock.recv(65507) 
            try: pck = Packet(data=blob)
            except Exception as e: 
                # Log deserialization error using the debug flag
                if self.debug: self.log_callback(f"ERROR: Packet deserialization error: {e}")
                if self.debug: self.log_callback(packetErrorTrace(blob))
                return None
            
            
            self.handleInternalPackets(pck)
            return pck
        except socket.timeout:
            return None
        except Exception as e:
            if self.debug: self.log_callback(f"ERROR: Socket error: {e}")
            return None

    def send(self, blob, reliable=False): # ADD reliable argument
        if type(blob) is not Packet:
            # Determine reliability from argument or message property
            if reliable or getattr(blob, 'trusted', False): 
                 reliable = True
                 
            acks_to_send = self.acks[:255]
            if acks_to_send:
                self.acks = self.acks[255:]
                self.nextAck = time.time() + 1
            
            try:
                blob = Packet(sequence=self.seq, message=blob, acks=acks_to_send, ack=bool(acks_to_send), reliable=reliable)
            except Exception as e:
                self.log(f"[RAW-UDP-SEND] FATAL PACKET BUILD ERROR: {e}")
                import traceback
                self.log(traceback.format_exc())
                return False

        if blob.reliable and blob.sequence not in [self.circuit_sequence, self.cam_sequence]:
            self.reliable_packets[blob.sequence] = (blob, time.time())
            
        try:
            if getattr(blob, 'message', None) and blob.message.name == "AvatarPropertiesRequest":
                self.log(f"[RAW-UDP-SEND] Sending {blob.message.name} (SEQ: {blob.sequence})")
                
            self.sock.sendto(bytes(blob), (self.host, self.port))
            return blob.sequence
        except Exception as e: 
            self.log(f"ERROR: Send error: {e}")
            return False

    def logout(self):
        msg = getMessageByName("LogoutRequest")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        self.send(msg)

    def sendAcks(self):
        if len(self.acks) > 0:
            msg = getMessageByName("PacketAck")
            tmp = self.acks[:255]
            self.acks = self.acks[255:]
            msg.Packets = [{"ID": i} for i in tmp]
            self.send(msg)
            self.nextAck = time.time() + 1

    def throttle(self):
        msg = getMessageByName("AgentThrottle")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        msg.AgentData["CircuitCode"] = self.circuit_code
        msg.Throttle["GenCounter"] = 0
        # 7 floats: Resend, Land, Wind, Cloud, Task, Texture, Asset
        floats = struct.pack("<fffffff", 150000.0, 170000.0, 34000.0, 34000.0, 446000.0, 446000.0, 220000.0)
        # FIX: The Variable field must be an object of type 'variable' which wraps the bytes.
        msg.Throttle["Throttles"] = variable(1, floats)
        self.send(msg)

    def setFOV(self):
        msg = getMessageByName("AgentFOV")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        msg.AgentData["CircuitCode"] = self.circuit_code
        msg.FOVBlock["GenCounter"] = 0
        msg.FOVBlock["VerticalAngle"] = 6.28
        self.send(msg)

    def setWindowSize(self):
        msg = getMessageByName("AgentHeightWidth")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        msg.AgentData["CircuitCode"] = self.circuit_code
        msg.HeightWidthBlock["GenCounter"] = 0
        msg.HeightWidthBlock["Height"] = 768
        msg.HeightWidthBlock["Width"] = 1024
        self.send(msg)
    
    # MODIFIED: Added reliable=False to the signature
    def agentUpdate(self, controls=0, reliable=False): 
        msg = getMessageByName("AgentUpdate")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        
        # NOTE: Using corrected identity quaternion (0,0,0,1)
        body_rotation = quaternion(0.0, 0.0, 0.0, 1.0) 
        
        msg.AgentData["BodyRotation"] = body_rotation
        msg.AgentData["HeadRotation"] = body_rotation
        msg.AgentData["State"] = 0
        # Use the agent's actual position for the camera center
        msg.AgentData["CameraCenter"] = vector3(self.agent_x, self.agent_y, self.agent_z)
        msg.AgentData["CameraAtAxis"] = vector3(0,1,0)
        msg.AgentData["CameraLeftAxis"] = vector3(1,0,0)
        msg.AgentData["CameraUpAxis"] = vector3(0,0,1)
        msg.AgentData["Far"] = 1024.0
        msg.AgentData["ControlFlags"] = controls
        msg.AgentData["Flags"] = 0
        self.send(msg, reliable=reliable)
        self.last_update_send = time.time()
        
    def requestAgentData(self):
        msg = getMessageByName("AgentDataRequest")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        self.send(msg)
        
    def fetch_capabilities(self, cap_names):
        """Fetches capability URLs from the seed capability."""
        if not self.seed_cap_url: return
        
        try:
            msg = f"Requesting capabilities {cap_names} from {self.seed_cap_url}..."
            self.log(msg)

            
            headers = {
                'User-Agent': SL_USER_AGENT,
                'Accept': 'application/llsd+json, application/llsd+xml',
                'X-SecondLife-Agent-ID': str(self.agent_id),
                'X-SecondLife-Session-ID': str(self.session_id)
            }
            
            def _do_fetch(payload, content_type):
                h = headers.copy()
                if content_type: h['Content-Type'] = content_type
                req = urllib.request.Request(self.seed_cap_url, data=payload, headers=h)
                try:
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.getcode() == 200:
                            return response.read().decode('utf-8')
                except Exception:
#                     print(f"DEBUG: Fetch attempt failed: {ex}")
                    pass
                return None

            payload_xml = render_llsd_xml(cap_names).encode('utf-8')
            resp_data = _do_fetch(payload_xml, 'application/llsd+xml')
            
            if resp_data:
                self.log(f"Raw capability response: {resp_data}")
#                 print(f"DEBUG: Capability response: {resp_data}") # Fallback
                
                if resp_data.strip().startswith('<'):
                    new_caps = parse_llsd_xml(resp_data)
                else:
                    new_caps = json.loads(resp_data)

                # NEW: If any of our requested caps are missing, try a GET on the seed URL.
                # Many simulators respond to GET with the FULL list of available caps.
                missing_some = any(c not in new_caps and (not isinstance(new_caps.get('Metadata'), dict) or c not in new_caps['Metadata']) for c in cap_names)
                
                if missing_some:
                    missing_list = [c for c in cap_names if c not in new_caps and (not isinstance(new_caps.get('Metadata'), dict) or c not in new_caps['Metadata'])]
                    self.log(f"Some caps missing ({missing_list}). Retrying with GET on SeedCap...")

                    resp_data_get = _do_fetch(None, None) # GET request
                    if resp_data_get:
                        self.log(f"Raw GET capability response (first 200 chars): {resp_data_get[:200]}...")
#                         print(f"DEBUG: GET Capability response (first 200 chars): {resp_data_get[:200]}...")
                        if resp_data_get.strip().startswith('<'):
                            new_caps_get = parse_llsd_xml(resp_data_get)
                        else:
                            new_caps_get = json.loads(resp_data_get)
                        
                        if isinstance(new_caps_get, dict):
                            # Flatten Metadata in GET response as well
                            if 'Metadata' in new_caps_get and isinstance(new_caps_get['Metadata'], dict):
                                self.capabilities.update(new_caps_get['Metadata'])
                            self.capabilities.update(new_caps_get)
                            new_caps.update(new_caps_get)
                            self.log(f"Merged GET capabilities. Total now: {len(self.capabilities)}")
                    else:
#                         print("DEBUG: GET fallback returned no data.")
                        pass

                if isinstance(new_caps, dict):
                    # FIX: Flatten the Metadata map if returned
                    if 'Metadata' in new_caps and isinstance(new_caps['Metadata'], dict):
                        self.log("Flattening Metadata map from capability response.")
                        self.capabilities.update(new_caps['Metadata'])
                    
                    self.capabilities.update(new_caps)
                    self.log(f"Fetched capabilities: {list(new_caps.keys())}")
                    # DEBUG: Log all known caps to help identify missing ones
                    self.log(f"[DEBUG] Total capabilities known: {len(self.capabilities)}")
                else:
                    self.log(f"Unexpected capability response format: {type(new_caps)}")
            else:
                self.log("Capability fetch failed or returned no data.")
        except Exception as e:
            err = f"Error fetching capabilities: {e}"
            self.log(err)
#            print(f"ERROR: {err}")

def parse_llsd_xml(xml_str):
    """
    Very basic LLSD XML to Python dict/list parser.
    Supports <map>, <key>, <string>, <array>, <integer>, <boolean>.
    """
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_str)
        def _parse_node(node):
            tag = node.tag
            if tag == 'map':
                res = {}
                key = None
                for child in node:
                    if child.tag == 'key':
                        key = child.text
                    else:
                        res[key] = _parse_node(child)
                return res
            elif tag == 'array':
                return [_parse_node(child) for child in node]
            elif tag == 'string':
                return node.text or ""
            elif tag == 'integer':
                return int(node.text or 0)
            elif tag == 'boolean':
                return (node.text or "0") == "1" or (node.text or "").lower() == "true"
            elif tag == 'llsd':
                return _parse_node(node[0]) if len(node) > 0 else {}
            return node.text
            
        return _parse_node(root)
    except Exception:
#         print(f"LLSD XML Parse Error: {e}")
        return None

def render_llsd_xml(data):
    """
    Renders a Python structure to LLSD XML.
    Supports: LLUUID, bool, int, float, str, dict, list.
    """
    def _render_node(v):
        if isinstance(v, bool):
            return f"<boolean>{'true' if v else 'false'}</boolean>"
        elif isinstance(v, int):
            return f"<integer>{v}</integer>"
        elif isinstance(v, float):
            return f"<real>{v}</real>"
        elif isinstance(v, LLUUID):
            return f"<uuid>{str(v)}</uuid>"
        elif isinstance(v, dict):
            inner = "".join([f"<key>{k}</key>{_render_node(val)}" for k, val in v.items()])
            return f"<map>{inner}</map>"
        elif isinstance(v, list):
            inner = "".join([_render_node(val) for val in v])
            return f"<array>{inner}</array>"
        else:
            # Escape XML special characters in strings
            s = str(v).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            return f"<string>{s}</string>"
    
    return f"<llsd>{_render_node(data)}</llsd>"

    # RegionClient.teleport_to_region now implemented above

# ==========================================
# SECTION 7: MAIN APPLICATION (SLviewer.py)
# ==========================================

def safe_decode_llvariable(ll_var):
    """
    Safely decode a Variable LL packet field.
    
    The 'll_var' object passed here is an instance of the 'variable' class, 
    which already has the length prefix stripped during packet loading. 
    Its 'data' attribute holds the raw string bytes (including the trailing \x00).
    """
    if hasattr(ll_var, 'data') and isinstance(ll_var.data, bytes):
        try:
            # FIX: Use the 'data' attribute directly for the raw bytes, and strip the null terminator
            return ll_var.data.decode('utf-8').rstrip('\x00')
        except:
            return str(ll_var.data)
    # If the object is passed as a string/simple type, return it as a string
    return str(ll_var)

# --- Core Second Life Agent Class ---
class SecondLifeAgent:
    """Manages the connection and interaction with the Second Life grid."""
    def __init__(self, ui_callback, debug_callback=None):
        self.client = None 
        self.ui_callback = ui_callback 
        self.debug_callback = debug_callback
        self.running = False
        self.event_thread = None
        self.current_region_name = ""
        
        # NEW: Display Name and Username Caching
        self.display_name_cache = {} # UUID -> DisplayName
        self.username_cache = {}     # UUID -> Username (e.g. 'sarahlionheart')
        self.fetching_names = set() # Set of UUIDs currently being fetched
        self.pending_profile_fetches = set() # UUIDs waiting for usernames to fetch web profiles
        
        # Connection credentials
        self.agent_id = None
        self.session_id = None
        self.circuit_code = None
        self.raw_socket = None
        self.first_name = "" 

        # NEW: Movement Control State
        self.key_states = {
            'Up': const.AGENT_CONTROL_AT_POS,
            'Down': const.AGENT_CONTROL_AT_NEG,
            'Left': const.AGENT_CONTROL_LEFT_POS,
            'Right': const.AGENT_CONTROL_RIGHT_POS,
            'e': const.AGENT_CONTROL_UP_POS,
            'c': const.AGENT_CONTROL_UP_NEG,
            'space': const.AGENT_CONTROL_JUMP
        }
        self.is_key_down = {}
        self.is_flying = False


    def log(self, message):
        """Helper to send logs to the UI thread."""
        if self.debug_callback:
            # We strip "DEBUG: " since the log handler adds its own formatting.
            if message.startswith("DEBUG: "):
                 message = message[7:]
            
            # --- MAP FETCH LOG HANDLER ---
            if message.startswith("MAP_FETCH_TRIGGER"):
                # Handle map fetch request triggered by RegionClient
                _, region_name = message.split(", ", 1)
                self.ui_callback("map_fetch_request", region_name.strip())

            # --- DEBUG NOTIFICATION HANDLER ---
            elif message.startswith("[NOTIFICATION]"):
                 # Direct message to notification area
                 clean_msg = message.replace("[NOTIFICATION]", "").strip()
                 self.ui_callback("notification", clean_msg)

            # --- FIX: New Handshake Complete Handler ---
            if message.startswith("HANDSHAKE_COMPLETE"):
                # We still update status/progress here for immediate feedback
                _, region_name = message.split(", ", 1)
                self.ui_callback("status", f"🟢 Successfully logged in to {region_name.strip()}!")
                self.ui_callback("progress", ("RegionHandshake", 100))
                
                # Verify the region name via Gridsurvey to ensure we have the REAL name (handling redirections)
                threading.Thread(target=self.verify_region_name, daemon=True).start()
                
                # FIX: Forward to debug_callback so ChatTab can trigger map fetch
                if self.debug_callback:
                    self.debug_callback(message)
                    
            # --- KICKED LOG HANDLER (NEW) ---
            elif message.startswith("KICKED"):
                _, reason = message.split(", ", 1)
                self.ui_callback("status", f"🔴 Kicked: {reason.strip()}")
                self.running = False # Stop the event loop upon kick
                
                # FIX: Forward to debug_callback so ChatTab can handle disconnect UI
                if self.debug_callback:
                    self.debug_callback(message)
                
            # --- CHAT ACK HANDLER ---
            elif message.startswith("ACK_CONFIRMED:"):
                _, seq_id = message.split(": ", 1)
                self.ui_callback("chat_ack", int(seq_id.strip()))
                
            else:
                # Filter out [SPY] messages from reaching the UI/console
                if not message.startswith("[SPY]"):
                    self.debug_callback(message)

    # ... (rest of class) ...


    def _event_handler(self):
        """Runs in a separate thread to constantly check for new grid events."""
        self.log("Event handler thread started. Waiting for packets...")
        
        RESEND_INTERVAL = 1.0 # 1.0 second timeout for reliable packets
        
        while self.running and self.client:
            
            current_time = time.time()
            
            # --- Periodic Network Maintenance ---
            # Send periodic AgentUpdates both DURING and AFTER handshake to stay active.
            if current_time - self.client.last_update_send > 0.5:
                # Pass the client's internal controls state
                self.client.agentUpdate(controls=self.client.controls_once|self.client.controls, reliable=False) 
                self.client.controls_once = 0
                if not self.client.handshake_complete:
                    self.log("Sending Handshake AgentUpdate...")
                    self.ui_callback("progress", ("AgentUpdate", 75))

            if not self.client.handshake_complete:
                # Resend handshake packets if needed
                if current_time - self.client.last_circuit_send > 1.0: 
                    self.log("Resending UseCircuitCode...")
                    self.ui_callback("progress", ("CircuitCode", 25))
                    self.client.send_use_circuit_code()
                    
                if current_time - self.client.last_cam_send > 1.0: 
                    self.log("Resending CompleteAgentMovement...")
                    self.ui_callback("progress", ("CompleteAgentMovement", 50))
                    self.client.send_complete_movement()
            
            # --- Resend Reliable Packets ---
            if self.client.handshake_complete:
                resend_list = []
                # Use list(items()) to allow safe iteration while modifying the dictionary
                for seq_id, (pck, last_send_time) in list(self.client.reliable_packets.items()):
                    if current_time - last_send_time > RESEND_INTERVAL:
                        resend_list.append(seq_id)
                
                for seq_id in resend_list:
                    # Retrieve the original packet object
                    if seq_id in self.client.reliable_packets:
                        pck, _ = self.client.reliable_packets[seq_id]
                        self.log(f"Resending reliable packet {seq_id} ({pck.body.name})...")
                        
                        # Use raw socket send with the original packet bytes
                        # NOTE: We do NOT update the sequence number, only the resent flag needs setting
                        pck.resent = True
                        self.client.sock.sendto(bytes(pck), (self.client.host, self.client.port))
                        pck.resent = False # Clear flag after sending
                        
                        # Update last_send_time for tracking
                        self.client.reliable_packets[seq_id] = (pck, current_time) 
            # --- End Resend Reliable Packets ---

            # --- Performance Fix: Prune Reliable Packets ---
            # Remove packets older than 60 seconds to prevent memory leaks/unbounded growth
            # if the server stops ACking them.
            if len(self.client.reliable_packets) > 0:
                 # Check periodically (every 5 seconds roughly, based on iteration count or just random)
                 if random.random() < 0.05: 
                     cutoff = current_time - 60.0
                     # Find expired keys
                     expired = [sid for sid, (_, ts) in self.client.reliable_packets.items() if ts < cutoff]
                     for sid in expired:
                         del self.client.reliable_packets[sid]
                         self.log(f"Pruned stale reliable packet {sid} (Older than 60s)")
            # -----------------------------------------------


            # --- Packet Receiving ---
            packet = self.client.recv()

            if packet:
                packet_name = 'Unknown'
                if hasattr(packet, 'body') and hasattr(packet.body, 'name'):
                    packet_name = packet.body.name
                
                # Log incoming packet name (debug mode enabled)
                self.log(f"RX Packet: {packet_name}")

                # --- Handle Login/Handshake ---
                if packet_name == "RegionHandshake":
                    if hasattr(packet.body, 'RegionInfo'):
                        # FIX: Use safe_decode_llvariable on SimName (Variable 1)
                        self.current_region_name = safe_decode_llvariable(packet.body.RegionInfo.get('SimName', 'Connected Region'))
                    
                    # The success message is now handled inside self.log via the HANDSHAKE_COMPLETE trigger
                    self.log(f"HANDSHAKE_COMPLETE, {self.current_region_name}") # FIX: Trigger the UI update
                    
                    time.sleep(0.1) 
                    # FIX: Send reliable CAM, it's already set to reliable=True in RegionClient.send_complete_movement()
                    self.client.send_complete_movement() 
                    
                    time.sleep(0.1) 
                    # NOTE: This AgentUpdate is now redundant as a RELIABLE one is sent in handleInternalPackets, 
                    # but we keep it here to ensure quick non-reliable state assertion.
                    self.client.agentUpdate(controls=self.client.controls_once|self.client.controls, reliable=False) 

                # --- Handle Chat ---
                elif packet_name == "ChatFromSimulator":
                    chat_data = getattr(packet.body, 'ChatData', None)
                    if chat_data:
                        from_name = safe_decode_llvariable(chat_data.get('FromName', 'Unknown'))
                        msg_text = safe_decode_llvariable(chat_data.get('Message', ''))
                        # ChatType is U8
                        chat_type = chat_data.get('ChatType', 0) 
                        # SourceID is the UUID of the sender
                        source_id = chat_data.get('SourceID', None)

                        # 1. Filter typing indicators AND Prefetch Display Names
                        # NOTE: We do this BEFORE filtering empty messages, as typing indicators often have empty bodies.
                        if chat_type in (const.CHAT_START_TYPING, const.CHAT_STOP_TYPING):
#                             print(f"DEBUG: Processed Typing Indicator: {chat_type} from {source_id}")
                            pass
                            if chat_type == const.CHAT_START_TYPING and source_id:
                                # Prefetch the display name so it's ready when the message actually arrives
                                if str(source_id) not in self.display_name_cache:
#                                     print(f"DEBUG: Triggering Name Prefetch for {source_id}")
                                    pass
                                    self.log(f"Prefetching display name for typing user: {source_id}")
                                    self.get_display_name(source_id, from_name)
                                else:
#                                     print(f"DEBUG: Name already cached for {source_id}")
                                    pass
                                    
                            # Filter the message from the UI log
                            # self.log(f"Filtered typing indicator (Type: {chat_type}) from {from_name}.")
                            continue

                        # 2. Filter empty messages
                        if not msg_text:
                            self.log(f"Filtered empty chat message from {from_name}.")
                            continue
                        
                        # Filter Firestorm LSL Bridge messages
                        if "Firestorm LSL Bridge" in from_name:
                            self.log(f"Filtered bridge message from {from_name}.")
                            continue
                        
                        # 3. Filter own messages (already displayed when ACK'd)
                        if source_id and source_id == self.client.agent_id:
                            self.log(f"Filtered own message echo from simulator.")
                            continue
                            
                        # Fetch and use display name
                        display_name = self.get_display_name(source_id, from_name)
                        
                        # FIX: Avoid printing the same name twice AND filter "Resident"
                        clean_from_name = from_name.replace(" Resident", "")
                        
                        if display_name and display_name != from_name:
                            name_label = f"{display_name} ({clean_from_name})"
                        else:
                            name_label = clean_from_name
                            
                        self.ui_callback("chat", (name_label, msg_text))
                
                # --- Handle Teleport Offer ---
                elif packet_name == "TeleportOffer":
                    offer = getattr(packet.body, 'Offer', {})
                    if offer:
                        # Extract necessary data
                        teleport_id = offer.get("TeleportID")
                        # FIX: Use safe_decode_llvariable on RegionName (Variable 1)
                        region_name = safe_decode_llvariable(offer.get("RegionName", "Unknown Region"))
                        l_cost = offer.get("L$Cost", 0)
                        
                        # Extract RegionHandle (U64) to get coordinates early (optional usage)
                        offer.get("RegionHandle", 0)

                        # Send offer data to the UI thread

                        self.ui_callback("teleport_offer", {
                            "id": teleport_id,
                            "region": region_name,
                            "cost": l_cost
                        })
                
                # --- General Connection Messages ---
                elif packet_name == "TeleportFinish":
                    # Update coordinates from the handle
                    if hasattr(packet.body, 'Info'):
                        handle = packet.body.Info.get("RegionHandle", 0)
                        if handle:
                            # Handle is a 64-bit int: y grid (in meters) << 32 | x grid (in meters)
                            w_y = handle >> 32
                            w_x = handle & 0xFFFFFFFF
                            self.client.grid_x = w_x // 256
                            self.client.grid_y = w_y // 256
                            self.log(f"TeleportFinish: Updated grid coords to {self.client.grid_x}, {self.client.grid_y}")

                    self.ui_callback("status", "🚀 Teleport finished! Starting handshake in new region...")
                    # The network thread will now start the handshake process with the new region.
                    # Clear handshake state to trigger new handshake process
                    self.client.handshake_complete = False 
                    self.client.last_circuit_send = 0
                    self.client.circuit_packet = None
                    self.client.cam_packet = None
                    self.client.controls = 0
                    self.client.controls_once = 0

                elif packet_name == "CloseCircuit":
                    self.ui_callback("status", "👋 Disconnected from the grid.")
                    self.running = False
                    break
            
            # Send periodic ACKs and AgentUpdates
            if self.client and current_time - self.client.nextAck > 1.0:
                self.client.sendAcks()
                
            # Continuous AgentUpdate for movement
            if self.client and self.client.handshake_complete and current_time - self.client.last_update_send > 0.1: # 10Hz
                self.client.agentUpdate(controls=self.client.controls_once|self.client.controls, reliable=False) 
                self.client.controls_once = 0

            time.sleep(0.005)

    # --- Movement Control Methods (NEW) ---
    def process_control_change(self, key, is_press):
        """Updates the control flags based on key state."""
        
        # Handle Toggle (Fly)
        if key == 'f' and is_press:
            # Toggle the fly flag only on key down
            self.is_flying = not self.is_flying
            self.log(f"Fly mode toggled: {self.is_flying}")
            # Ensure the state reflects the new mode
            self.update_controls(toggle_fly=True) 
            return

        # Handle Continuous Controls (Arrow Keys, Jump, Up/Down)
        if key in self.key_states:
            control_flag = self.key_states[key]
            
            # Use self.is_key_down for debouncing and state tracking
            if is_press and key not in self.is_key_down:
                self.is_key_down[key] = True
                self.update_controls(add_flags=control_flag)
                
            elif not is_press and key in self.is_key_down:
                del self.is_key_down[key]
                self.update_controls(remove_flags=control_flag)
                
    def update_controls(self, add_flags=0, remove_flags=0, toggle_fly=False):
        """Calculates the new ControlFlags and updates the client."""
        if not self.client: return
        
        current_flags = self.client.controls
        
        # 1. Apply Add/Remove for continuous controls (Arrow Keys, E, C, Space)
        current_flags |= add_flags    # Set the flags for pressed keys
        current_flags &= ~remove_flags # Clear the flags for released keys
        
        # 2. Apply Fly toggle
        if toggle_fly:
            current_flags ^= const.AGENT_CONTROL_FLY # Flip the fly bit
            self.is_flying = bool(current_flags & const.AGENT_CONTROL_FLY)
        elif self.is_flying:
            current_flags |= const.AGENT_CONTROL_FLY # Ensure fly is set if state says so
        else:
            current_flags &= ~const.AGENT_CONTROL_FLY # Ensure fly is clear if state says so

        # 3. Only send the jump flag once (or for one AgentUpdate cycle)
        # We handle this by separating temporary flags (like Jump) into controls_once.
        if add_flags & const.AGENT_CONTROL_JUMP:
            self.client.controls_once |= const.AGENT_CONTROL_JUMP
            
        # 4. Update the main control flags (minus the jump flag, which is momentary)
        self.client.controls = current_flags & ~const.AGENT_CONTROL_JUMP # JUMP is momentary
        
        # Force an AgentUpdate immediately to avoid lag
        self.client.agentUpdate(controls=self.client.controls_once|self.client.controls, reliable=False)
        self.client.controls_once = 0


    # --- Packet Sending Wrappers ---
    def get_socket(self):
        if self.client: return self.client.sock
        return None


    



    def send_chat_raw(self, message, channel=0, chat_type=1): 
        self.log(f"Sending Chat: '{message[:15]}...' (Type: {chat_type}, Channel: {channel})")
        
        msg = getMessageByName("ChatFromViewer")
        # FIX: Use client's agent_id and session_id to ensure consistency with the active UDP connection
        msg.AgentData["AgentID"] = self.client.agent_id
        msg.AgentData["SessionID"] = self.client.session_id
        
        # --- CHAT FIX: Variable Type 2, UTF-8, WITH AUTOMATIC NULL TERMINATION ---
        # Passing the string with add_null=True to match standard SL chat packet expectations.
        msg.ChatData["Message"] = variable(2, message, add_null=True) 
        
        msg.ChatData["Type"] = chat_type
        msg.ChatData["Channel"] = channel
        
        # Use reliable=True for chat so we can track receipt via ACK
        return self.client.send(msg, reliable=True)
    
    def send_chat(self, message):
        """Public method for the UI to send chat messages."""
        if self.client and self.running:
            # chat_type 1 is CHAT_NORMAL (local chat)
            return self.send_chat_raw(message, chat_type=const.CHAT_NORMAL)
        return False
    
    def accept_teleport_offer(self, teleport_id, cost=0):
        """Sends the TeleportAccept packet."""
        self.log(f"Accepting teleport offer ID {teleport_id}...")
        self.ui_callback("status", "Sending TeleportAccept. Stand by for jump...")
        return self.client.send_teleport_accept(teleport_id, cost, license=True)

    def get_display_name(self, source_id, fallback_name):
        """Returns the display name if cached, otherwise starts a fetch and returns fallback."""
        if not source_id: return fallback_name
        
        uuid_str = str(source_id).lower()
        
        # If we have a fallback name (from chat), use it and cache it immediately
        # This allows the Nearby List to see the chat-resolved name instantly.
        if fallback_name and fallback_name != "Unknown":
            # Strip " Resident" suffix for a cleaner look
            clean_fallback = fallback_name.replace(" Resident", "")
            if uuid_str not in self.display_name_cache or self.display_name_cache[uuid_str] in ("Resolving...", ""):
                print(f"[DEBUG] CACHING CHAT NAME: {uuid_str} -> {clean_fallback}")
                self.display_name_cache[uuid_str] = clean_fallback
        
        if uuid_str in self.display_name_cache:
            return self.display_name_cache[uuid_str]
            

            
        # --- Performance Fix: Limit Cache Size ---
        if len(self.display_name_cache) > 2000:
            # Clear half the cache if it gets too big (simplest LRU approximation without using OrderedDict)
            # Python 3.7+ dicts preserve insertion order, so this removes the oldest 1000 items.
            self.log("Pruning display name cache...")
            keys_to_remove = list(self.display_name_cache.keys())[:1000]
            for k in keys_to_remove:
                del self.display_name_cache[k]
        # -----------------------------------------

        if uuid_str not in self.fetching_names:
            self.fetching_names.add(uuid_str)

            threading.Thread(target=self._fetch_display_names_task, args=([uuid_str],), daemon=True).start()
            
        return fallback_name

    def request_uuid_name(self, uuid_list):
        """Send a lightweight UUIDNameRequest packet to resolve avatar names."""
        if not self.client or not self.running or not uuid_list: return
        
        # Only request IDs we haven't already fetched or are currently fetching
        to_fetch = []
        for uid_str in uuid_list:
            u_key = uid_str.lower()
            if u_key not in self.display_name_cache and u_key not in self.fetching_names:
                to_fetch.append(uid_str)
                self.fetching_names.add(u_key)
        
        if to_fetch:
            # Construct and send UUIDNameRequest packet
            msg = getMessageByName("UUIDNameRequest")
            msg.UUIDNameBlock = []
            for uid in to_fetch:
                msg.UUIDNameBlock.append({"ID": LLUUID(uid)})
            self.client.send(msg, reliable=True)
            
            # Also try the HTTP fallback immediately since sometimes UDP packets drop
            threading.Thread(target=self._fetch_display_names_task, args=(to_fetch,), daemon=True).start()

    def request_avatar_properties(self, avatar_id):
        """Sends a request for detailed avatar profile properties."""
        if not self.client or not self.running: return
        
        try:
            msg = getMessageByName("AvatarPropertiesRequest")
            # Correcting block assignment: msg.AgentData is a dict for single blocks
            msg.AgentData["AgentID"] = self.client.agent_id
            msg.AgentData["SessionID"] = self.client.session_id
            msg.AgentData["AvatarID"] = LLUUID(avatar_id)
            
            self.log(f"[DEBUG] Sending Profile Request for {avatar_id}")
            result = self.client.send(msg, reliable=True)
            self.log(f"[DEBUG] Profile Request sent over UDP result: {result}")
        except Exception as e:
            self.log(f"[DEBUG] CRITICAL ERROR IN PROFILE REQUEST BUILDING: {e}")
            import traceback
            self.log(traceback.format_exc())
            
        # Priority 1: Grid Capabilities (Modern)
        if "AvatarProperties" in getattr(self.client, 'capabilities', {}) or "AgentProfile" in getattr(self.client, 'capabilities', {}):
            threading.Thread(target=self._fetch_avatar_properties_cap_task, args=(avatar_id,), daemon=True).start()
        
        # Priority 2: Web Fallback (Scraper)
        uid_key = str(avatar_id).lower()
        uname = self.username_cache.get(uid_key)
        if uname:
            threading.Thread(target=self._fetch_web_profile_task, args=(avatar_id, uname), daemon=True).start()
        else:
            self.pending_profile_fetches.add(uid_key)
            # If we don't have the username yet, request names again for just this one
            threading.Thread(target=self.request_uuid_name, args=([avatar_id],), daemon=True).start()

    def _fetch_avatar_properties_cap_task(self, avatar_id):
        """Background task to fetch profile data via modern HTTP capability."""
        if not self.client: return
        
        try:
            cap_url = self.client.capabilities.get("AvatarProperties") or self.client.capabilities.get("AgentProfile")
            if not cap_url:
                self.log(f"[DEBUG] Profile capabilities (AvatarProperties/AgentProfile) NOT FOUND in cache.")
                return
            
            self.log(f"[DEBUG] Fetching grid profile via cap: {cap_url}")
            
            headers = {
                'User-Agent': SL_USER_AGENT,
                'Accept': 'application/llsd+json, application/llsd+xml',
                'X-SecondLife-Agent-ID': str(self.agent_id),
                'X-SecondLife-Session-ID': str(self.session_id)
            }
            
            # 1. Build common query URL format
            if "?" in cap_url:
                query_url = f"{cap_url}&avatar_id={avatar_id}"
            else:
                query_url = f"{cap_url}?avatar_id={avatar_id}"
            
            profile_found = False
            
            # --- PHASE 1: Try standard GET (common in OpenSim/certain caps) ---
            try:
                req_get = urllib.request.Request(query_url, headers=headers)
                with urllib.request.urlopen(req_get, timeout=10) as response:
                    resp_code = response.getcode()
                    self.log(f"[DEBUG] Profile cap (GET) response code: {resp_code}")
                    if resp_code == 200:
                        resp_data = response.read().decode('utf-8')
                        profile_found = self._parse_and_show_profile_cap(avatar_id, resp_data, cap_url, "grid (GET)")
            except Exception as e:
                err_msg = str(e).encode('ascii', errors='replace').decode('ascii')
                self.log(f"[DEBUG] GET Profile cap failed: {err_msg}")

            # --- PHASE 2: Try LLSD POST (Standard Linden/modern SL caps) ---
            if not profile_found:
                self.log(f"[DEBUG] Trying POST for profile cap: {cap_url}")
                
                # Payload structures to test
                payloads_to_try = [
                    [LLUUID(avatar_id)],
                    {'avatar_ids': [LLUUID(avatar_id)]},
                    {'avatar_id': LLUUID(avatar_id)}
                ]
                
                # Use the original cap URL without the query string for POST
                clean_url = cap_url.split('?')[0]
                
                for attempt_idx, payload_obj in enumerate(payloads_to_try, 1):
                    self.log(f"[DEBUG] POST Profile attempt {attempt_idx} payload: {payload_obj}")
                    # FIX: Use LLUUID object so render_llsd_xml uses <uuid> tag
                    payload = render_llsd_xml(payload_obj).encode('utf-8')
                    post_headers = headers.copy()
                    post_headers['Content-Type'] = 'application/llsd+xml'
                    
                    req_post = urllib.request.Request(clean_url, data=payload, headers=post_headers)
                    
                    try:
                        with urllib.request.urlopen(req_post, timeout=10) as response:
                            if response.getcode() == 200:
                                resp_data = response.read().decode('utf-8')
                                profile_found = self._parse_and_show_profile_cap(avatar_id, resp_data, cap_url, "grid (POST)")
                                if profile_found:
                                    break # Stop trying payloads if we succeeded
                    except Exception as e:
                        err_msg = str(e).encode('ascii', errors='replace').decode('ascii')
                        self.log(f"[DEBUG] POST Profile cap attempt {attempt_idx} failed: {err_msg}")
                    
            # --- PHASE 3: Try PeopleAPI if available (Modern SL) ---
            if not profile_found and "PeopleAPI" in self.client.capabilities:
                people_url = self.client.capabilities["PeopleAPI"]
                self.log(f"[DEBUG] Trying PeopleAPI for profile: {people_url}")
                # PeopleAPI often uses /agent_id/details/target_id
                # But we'll try a simpler version first if it matches standard patterns
                target_details_url = f"{people_url}/{self.agent_id}/details/{avatar_id}"
                req_people = urllib.request.Request(target_details_url, headers=headers)
                try:
                    with urllib.request.urlopen(req_people, timeout=10) as response:
                        if response.getcode() == 200:
                            resp_data = response.read().decode('utf-8')
                            profile_found = self._parse_and_show_profile_cap(avatar_id, resp_data, people_url, "grid (PeopleAPI)")
                except Exception as e:
                    err_msg = str(e).encode('ascii', errors='replace').decode('ascii')
                    self.log(f"[DEBUG] PeopleAPI attempt failed: {err_msg}")

        except Exception as e:
            err_msg = str(e).encode('ascii', errors='replace').decode('ascii')
            self.log(f"Error fetching grid profile cap for {avatar_id}: {err_msg}")

    def _parse_and_show_profile_cap(self, avatar_id, resp_data, cap_url, source_label):
        """Helper to parse LLSD/JSON profile response and update UI."""
        if not resp_data or not resp_data.strip(): return False
        
        try:
            data = None
            stripped = resp_data.strip()
            if stripped.startswith('<'):
                # Avoid parsing HTML error pages as LLSD
                if stripped.lower().startswith('<!doctype html') or stripped.lower().startswith('<html'):
                    self.log(f"[DEBUG] Profile cap returned HTML (likely error page) instead of LLSD.")
                    return False
                data = parse_llsd_xml(resp_data)
            else:
                try:
                    import json
                    data = json.loads(resp_data)
                except:
                    pass
            
            if data is None:
                self.log(f"[DEBUG] Profile cap parsing failed for source {source_label}.")
                return False
                
            # Unwrap if it's a list (OpenSim sometimes wraps in an array)
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
                
            if isinstance(data, dict):
                # Check for 'agents' list (standard modern SL profile cap format)
                if 'agents' in data and isinstance(data['agents'], list) and len(data['agents']) > 0:
                    data = data['agents'][0]
                # Check for UUID-keyed dict
                elif str(avatar_id) in data and isinstance(data[str(avatar_id)], dict):
                    data = data[str(avatar_id)]
                elif str(avatar_id).lower() in data and isinstance(data[str(avatar_id).lower()], dict):
                    data = data[str(avatar_id).lower()]
                
                # Extract fields
                about = data.get('about') or data.get('AboutText') or data.get('about_text') or data.get('profile_about') or ''
                born = data.get('born') or data.get('BornOn') or data.get('born_on') or 'Unknown'
                image_id = data.get('image_id') or data.get('ImageID') or data.get('image') or data.get('profile_image') or ''

                if not about and born == "Unknown" and not image_id:
                     self.log(f"[DEBUG] Profile cap returned empty/minimal dict for {avatar_id}.")
                     return False

                uid_key = str(avatar_id).lower()
                uname = self.username_cache.get(uid_key, "")
                profile_url = f"https://my.secondlife.com/{uname}" if uname else ""
                
                if isinstance(about, list): about = "\n".join(about)
                
                self.log(f"[DEBUG] Profile for {avatar_id} fetched via {source_label}.")
                self.ui_callback("show_profile", {
                    "id": avatar_id,
                    "about": about,
                    "born": born,
                    "url": profile_url,
                    "image_id": image_id,
                    "source": source_label
                })
                return True
            else:
                self.log(f"[DEBUG] Profile cap parsed data is not a dict ({type(data)}).")
                return False
        except Exception as e:
            self.log(f"Error parsing profile cap response: {e}")
            return False

    def _fetch_display_names_task(self, uuids):
        """Background task to fetch display names (Legacy HTTP method)."""
        if not self.client: return
        
        try:
            # 1. Ensure we have the AvatarsDisplayName capability
            if "AvatarsDisplayName" not in self.client.capabilities and "GetDisplayNames" not in self.client.capabilities:
                # Add PeopleAPI and GetDisplayNames as fallbacks
                self.client.fetch_capabilities(["AvatarsDisplayName", "GetDisplayNames", "EventQueueGet", "PeopleAPI", "AvatarProperties", "AgentProfile"])
                
            cap_url = self.client.capabilities.get("AvatarsDisplayName") or self.client.capabilities.get("GetDisplayNames")
            if not cap_url:
                self.log("AvatarsDisplayName capability not available. Relying on UUIDNameReply only.")
                return
                
            # 2. Request display names
            query_url = f"{cap_url}?ids=" + "&ids=".join([str(u) for u in uuids])
            msg = f"Fetching display names from: {query_url}"
            self.log(msg)
            
            headers = {
                'User-Agent': SL_USER_AGENT,
                'Accept': '*/*', # Try to be maximally permissive
                'X-SecondLife-Agent-ID': str(self.agent_id),
                'X-SecondLife-Session-ID': str(self.session_id)
            }
            
            req = urllib.request.Request(query_url, headers=headers)
            
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.getcode() == 200:
                        resp_data = response.read().decode('utf-8')
                        # DO NOT LOG THE RAW RESPONSE: Windows console throws UnicodeEncodeError on exotic Display Names!
                        # self.log(f"Raw display name response: {resp_data}")                        
                        if resp_data.strip().startswith('<'):
                            data = parse_llsd_xml(resp_data)
                            self.log(f"[DEBUG] Parsed LLSD display names: {len(data.get('agents', []))} agents")
                        else:
                            data = json.loads(resp_data)
                            self.log(f"[DEBUG] Parsed JSON display names: {len(data.get('agents', []))} agents")
                            
                        # Parse standard Display Name response
                        if isinstance(data, dict):
                            if 'agents' in data:
                                for agent in data['agents']:
                                    uid = agent.get('id')
                                    dname = agent.get('display_name')
                                    uname = agent.get('username')
                                    if uid:
                                        uid_str = str(uid).lower()
                                        if dname:
                                            self.display_name_cache[uid_str] = dname
                                        if uname:
                                            self.username_cache[uid_str] = uname
                                        
                                        if dname:
                                            self.ui_callback("update_display_name", (uid_str, dname))
                                            
                                        # Check if we were waiting for this username to fetch a profile
                                        if uid in self.pending_profile_fetches and uname:
                                            self.pending_profile_fetches.remove(uid)
                                            threading.Thread(target=self._fetch_web_profile_task, args=(uid, uname), daemon=True).start()
                            elif 'bad_ids' in data and len(data) == 1:
                                self.log(f"Display name fetch returned bad_ids: {data['bad_ids']}")
                            else:
                                self.log(f"Unexpected display name response format: {list(data.keys())}")
                                # CHECK: If we got back a capability list ( Metadata / EventQueueGet ), Try POST!
                                if 'Metadata' in data or 'EventQueueGet' in data:
                                    self.log("GET returned capability list? Retrying with POST...")

                                    
                                    # Prepare POST payload
                                    payload = render_llsd_xml({'ids': [str(u) for u in uuids]}).encode('utf-8')
                                    req_post = urllib.request.Request(query_url.split('?')[0], data=payload, headers={
                                        'User-Agent': SL_USER_AGENT,
                                        'Content-Type': 'application/llsd+xml',
                                        'Accept': 'application/llsd+xml',
                                        'X-SecondLife-Agent-ID': str(self.agent_id),
                                        'X-SecondLife-Session-ID': str(self.session_id)
                                    })
                                    
                                    with urllib.request.urlopen(req_post, timeout=10) as response_post:
                                        if response_post.getcode() == 200:
                                            resp_data_post = response_post.read().decode('utf-8')

                                            if resp_data_post.strip().startswith('<'):
                                                data_post = parse_llsd_xml(resp_data_post)
                                                self.log(f"[DEBUG] POST Parsed LLSD display names: {len(data_post.get('agents', []))} agents")
                                            else:
                                                data_post = json.loads(resp_data_post)
                                                self.log(f"[DEBUG] POST Parsed JSON display names: {len(data_post.get('agents', []))} agents")
                                            
                                            if isinstance(data_post, dict) and 'agents' in data_post:
                                                for agent in data_post['agents']:
                                                    uid = agent.get('id')
                                                    dname = agent.get('display_name')
                                                    uname = agent.get('username')
                                                    if uid:
                                                        uid_str = str(uid).lower()
                                                        if dname:
                                                            self.display_name_cache[uid_str] = dname
                                                        if uname:
                                                            self.username_cache[uid_str] = uname
                                                        
                                                        if dname:
                                                            self.ui_callback("update_display_name", (uid_str, dname))

                                                        # Check if we were waiting for this username to fetch a profile
                                                        if uid in self.pending_profile_fetches and uname:
                                                            self.pending_profile_fetches.remove(uid)
                                                            threading.Thread(target=self._fetch_web_profile_task, args=(uid, uname), daemon=True).start()
            except urllib.error.HTTPError as e:
                self.log(f"HTTP Error fetching display names: {e.code} {e.reason}")

                # Try reading error body
                try:
                    e.read().decode('utf-8')
                except: pass
                        
        except Exception as e:
            # Safely log the exception without throwing UnicodeEncodeError on Windows
            err_msg = str(e).encode('ascii', errors='replace').decode('ascii')
            err = f"Error fetching display names: {err_msg}"
            self.log(err)
#            print(f"ERROR: {err}")
        finally:
            for uid in uuids:
                if uid in self.fetching_names:
                    self.fetching_names.remove(uid)

    def _fetch_web_profile_task(self, avatar_id, username):
        """Background task to fetch profile data from world.secondlife.com (no login required)."""
        # Use world.secondlife.com/resident/{UUID} - publicly accessible, no login needed.
        # my.secondlife.com requires login cookies and returns an empty login redirect page.
        public_url = f"https://world.secondlife.com/resident/{avatar_id}"
        web_url = f"https://my.secondlife.com/{username}"
        
        try:
            self.log(f"[DEBUG] Fetching web profile for {username} ({avatar_id})...")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
            
            req = urllib.request.Request(public_url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=15) as response:
                html_text = response.read().decode('utf-8', errors='replace')
            
            # --- Parse Born On date ---
            born = "Unknown"
            # The HTML has "Resident Since: 2006-06-16" possibly with HTML around it
            # We use re.S and allow any whitespace/tags between the label and date
            since_match = re.search(r'Resident\s+Since:?\s*(?:<[^>]*>\s*)*([0-9]{4}-[0-9]{2}-[0-9]{2})', html_text, re.I | re.S)
            if since_match:
                born = since_match.group(1)
            else:
                # Fallback: look for any YYYY-MM-DD date in a 'date' class element
                date_match = re.search(r'class="[^"]*date[^"]*"[^>]*>\s*(?:<[^>]+>\s*)*([0-9]{4}-[0-9]{2}-[0-9]{2})', html_text, re.I | re.S)
                if date_match:
                    born = date_match.group(1)
            
            # --- Parse About / Bio ---
            about = ""
            # world.secondlife.com uses <div class="bio"> or puts bio inline
            bio_match = re.search(r'<div[^>]+class=["\'][^"\']*bio[^"\']*["\'][^>]*>(.*?)</div>', html_text, re.S | re.I)
            if bio_match:
                raw_bio = bio_match.group(1)
                about = re.sub(r'<br\s*/?>', '\n', raw_bio, flags=re.I)
                about = re.sub(r'<[^>]+>', '', about)
                about = html_parser.unescape(about).strip()
            
            if not about:
                # Fallback: meta description
                meta_desc = re.search(r'<meta\s+(?:name|property)=["\']description["\'][^>]+content=["\']([^"\']+)["\']', html_text, re.I)
                if meta_desc:
                    about = html_parser.unescape(meta_desc.group(1)).strip()
            
            # Filter LL marketing boilerplate
            if "Second Life. Join Second Life to connect with" in about:
                about = ""
            
            # --- Parse Image ID ---
            # world.secondlife.com uses a <meta name="imageid"> tag with the texture UUID
            # and the picture-service URL is: https://picture-service.secondlife.com/{UUID}/256x192.jpg
            image_id = ""
            # Primary: meta imageid tag
            meta_img = re.search(r'<meta\s+name=["\']imageid["\']\s+content=["\']([a-fA-F0-9\-]{36})["\']', html_text, re.I)
            if meta_img:
                image_id = meta_img.group(1)
            else:
                # Fallback: picture-service URL
                ps_match = re.search(r'picture-service\.secondlife\.com/([a-fA-F0-9\-]{36})/', html_text, re.I)
                if ps_match:
                    image_id = ps_match.group(1)
                else:
                    # Last fallback: /app/image/ format
                    app_img = re.search(r'/app/image/([a-fA-F0-9\-]{36})/', html_text)
                    if app_img:
                        image_id = app_img.group(1)
            
            self.log(f"[DEBUG] Web profile for {username} fetched successfully.")
            
            self.ui_callback("show_profile", {
                "id": avatar_id,
                "about": about or "(No biography shared)",
                "born": born,
                "url": web_url,  # Link to the user-facing profile page
                "image_id": image_id,
                "username": username,
                "source": "web"
            })
            
        except Exception as e:
            self.log(f"Error fetching web profile for {username}: {e}")
            # Still show the dialog, but with fallback text
            self.ui_callback("show_profile", {
                "id": avatar_id,
                "about": f"Could not load profile. ({type(e).__name__})",
                "born": "Unknown",
                "url": web_url,
                "image_id": "",
                "username": username,
                "source": "error"
            })


            
    # MODIFIED: Worker thread target for map image fetching with new robust fallbacks
    def _fetch_map_image_task(self, region_name):
        # 1. Prepare region name for URL (underscores for spaces)
        # Use simple unquoted version for the tile name part
        region_name_url = urllib.parse.quote(region_name.strip().replace(' ', '_')) 
        
        # *** NEW: Removed small delay for map server processing to speed up load ***
        # time.sleep(2.0)
        
        # 2. Define multiple URLs with fallback logic
        # *** FIX: Using robust coordinate-based URLs as primary ***
        
        # Current grid coordinates
        gx = self.client.grid_x
        gy = self.client.grid_y
        
        # FIX: If coords are missing (fresh login), try to resolve them via gridsurvey
        if gx == 0 and gy == 0:
             self.ui_callback("status", f"📍 Resolving coordinates for {region_name}...")
             self.log(f"Map fetch: Coords are 0,0. Attempting gridsurvey lookup for '{region_name}'...")
             
             info = self._gridsurvey_region_lookup(region_name)
             if info:
                 gx = int(info['X'])
                 gy = int(info['Y'])
                 # Update client state for future use
                 self.client.grid_x = gx
                 self.client.grid_y = gy
                 self.log(f"Map fetch: Resolved coords to {gx}, {gy}")
             else:
                 self.log(f"Map fetch: Gridsurvey lookup failed. Will attempt fallback URLs.")
        
        urls_to_try = [
            # Primary: Standard coordinate-based format (Zoom level 1) - FORCE HTTPS
            # https://map.secondlife.com/map-1-{x}-{y}-objects.jpg
            f"https://map.secondlife.com/map-1-{gx}-{gy}-objects.jpg",
            
            # Fallback 0: HTTP version (in case of SSL issues)
            f"http://map.secondlife.com/map-1-{gx}-{gy}-objects.jpg",
            
            # Fallback 1: Robust coordinate-based format 
            f"https://map.secondlife.com/map/secondlife/{region_name_url}/128/128/1000/256x256.jpg", 
            # Fallback 2: Simplified URL on map domain (often redirects to the primary)
            f"https://map.secondlife.com/map/secondlife/{region_name_url}.jpg",
            # Fallback 3: Older world domain simplified format (as a last resort)
            f"https://world.secondlife.com/map/secondlife/{region_name_url}.jpg" 
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        last_error = ""

        for map_url in urls_to_try:
            try:
                request = urllib.request.Request(map_url, headers=headers)
                
                with urllib.request.urlopen(request, timeout=7) as response:
                    # Check if the response code indicates success
                    if response.getcode() == 200:
                        map_data = response.read()
                        # A valid map image should be significantly larger than a few bytes
                        # Error images or small placeholders are often < 2KB
                        if len(map_data) > 2000: 
                            # Use the verified name if available to avoid confusion
                            display_name = self.current_region_name if self.current_region_name else region_name
                            self.ui_callback("status", f"Map loaded for {display_name}.")
                            
                            self.ui_callback("map_image_fetched", map_data)
                            return # Success!
                        else:
                            msg = f"Map fetch size too small ({len(map_data)} bytes) from {map_url}"
                            last_error = msg
                            # Continue to next URL
                    else:
                        msg = f"HTTP {response.getcode()} from {map_url}"
                        last_error = msg
                        # Continue to next URL

            except urllib.error.HTTPError as e:
                # *** MODIFIED LOGGING: Log specific HTTP error ***
                last_error = f"HTTP {e.code}"
                # Continue to next URL
            except Exception as e:
                # *** MODIFIED LOGGING: Log general network errors ***
                f"General Error fetching map image from {map_url}: {type(e).__name__}: {e}"
                last_error = str(e)
                # Continue to next URL
        
        # 3. If all attempts fail
        self.ui_callback("status", f"⚠️ Map unavailable. ({last_error})")
        self.ui_callback("map_image_fetched", None)

    # NEW: Verify region name using Gridsurvey (post-handshake)
    def verify_region_name(self):
        """
        Uses Gridsurvey to verify the real region name based on the current grid coordinates.
        This handles cases where the RegionHandshake SimName is missing or we were redirected.
        """
        if not self.client: return
        
        gx = self.client.grid_x
        gy = self.client.grid_y
        
        if gx == 0 and gy == 0:
            self.log("[Verify] Cannot verify region name: Grid coordinates are 0,0.")
            return

        self.log(f"[Verify] Verifying region name for coordinates {gx}, {gy}...")
        
        # Use our existing lookup method
        try:
            info = self._gridsurvey_region_lookup(grid_x=gx, grid_y=gy)
            
            if info and 'Name' in info:
                real_name = info['Name']
                current = self.client.sim.get('name', 'Unknown')
                
                # If the names differ significantly (ignoring case), update and notify
                if real_name.lower().strip() != current.lower().strip() or current == "Unknown Region":
                    self.log(f"[Verify] Correction! Handshake said '{current}', but Gridsurvey says '{real_name}'. Updating...")
                    
                    # Update Client state
                    self.client.sim['name'] = real_name
                    self.current_region_name = real_name
                    
                    # Update UI
                    self.ui_callback("status", f"📍 Verified Location: {real_name}")
                    
                    # Also re-trigger map fetch if the name changed
                    self.fetch_map(real_name)
                else:
                    self.log(f"[Verify] Region name confirmed: {real_name}")
            else:
                self.log("[Verify] Gridsurvey lookup failed or returned no name.")
                
        except Exception as e:
            self.log(f"[Verify] Error during verification: {e}")


            
    def fetch_map(self, region_name):
        """Public entry point for fetching the map image."""
        if not self.running or not PIL_AVAILABLE: # *** FIX: Check if PIL is available before trying to fetch/process ***
            self.log("PIL/Pillow not available, skipping map fetch.")
            self.ui_callback("map_image_fetched", None) # Send None to trigger placeholder
            return
            
        threading.Thread(target=self._fetch_map_image_task, args=(region_name,), daemon=True).start()
    
    # NEW: GridSurvey API-based region lookup (doesn't require handshake)
    def _gridsurvey_region_lookup(self, region_name=None, grid_x=None, grid_y=None):
        """Look up region handle using the gridsurvey.com API.
        
        Can look up by name OR by grid coordinates (x, y).
        
        Args:
            region_name: Name of the region to look up (optional)
            grid_x: Grid X coordinate (optional)
            grid_y: Grid Y coordinate (optional)
            
        Returns:
            dict with 'Handle', 'X', 'Y', 'Name' keys, or None if lookup failed
        """
        if region_name:
            encoded_name = urllib.parse.quote(region_name.strip())
            url = f"http://api.gridsurvey.com/simquery.php?region={encoded_name}"
        elif grid_x is not None and grid_y is not None:
            # FIX: Correct parameter is 'xy' and we request just the name
            url = f"http://api.gridsurvey.com/simquery.php?xy={grid_x},{grid_y}&item=name"
        else:
            self.log("[GridSurvey] Error: Must provide either region_name or grid coordinates.")
            return None
        
        try:
            self.log(f"[GridSurvey] Looking up '{region_name}' at {url}")
            headers = {
                'User-Agent': 'BlackGlass SL Client/1.0 (gridsurvey lookup)'
            }
            request = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(request, timeout=7) as response:
                if response.getcode() == 200:
                    data = response.read().decode('utf-8')
                    self.log(f"[GridSurvey] Response received: {len(data)} bytes")
                    
                    # --- Special handling for coordinate lookup (item=name) ---
                    if grid_x is not None and 'item=name' in url:
                        name_result = data.strip()
                        if "Error" not in name_result:
                            self.log(f"[GridSurvey] Found region name by coords: {name_result}")
                            # We construct a synthetic result since we already know X/Y
                            # Calculate handle
                            x_meters = int(grid_x) * 256
                            y_meters = int(grid_y) * 256
                            handle = (y_meters << 32) | x_meters
                            return {
                                'Handle': handle,
                                'X': int(grid_x),
                                'Y': int(grid_y),
                                'Name': name_result
                            }
                        else:
                            self.log(f"[GridSurvey] API Error: {name_result}")
                            return None
                    # -----------------------------------------------------------

                    # Parse key-value pairs (format: "key value\n" - space-separated) for standard region lookup
                    result = {}
                    for line in data.strip().split('\n'):
                        # Support both space-separated and equals-separated formats
                        if '=' in line:
                            key, value = line.split('=', 1)
                            result[key.strip()] = value.strip()
                        elif ' ' in line and not line.startswith('Error'):
                            parts = line.split(' ', 1)
                            if len(parts) == 2:
                                result[parts[0].strip()] = parts[1].strip()
                    
                    # Check if region was found - gridsurvey returns x/y coordinates, not simhandle
                    if 'x' in result and 'y' in result:
                        try:
                            grid_x = int(result['x'])
                            grid_y = int(result['y'])
                            
                            # Check if region has valid coordinates (not 0,0 which means not found)
                            if grid_x == 0 and grid_y == 0:
                                self.log(f"[GridSurvey] Region '{region_name}' not found (coords=0,0)")
                                return None
                            
                            # Calculate region handle from grid coordinates
                            # Handle format: (y_meters << 32) | x_meters
                            # Grid coordinates are in 256m tiles, so multiply by 256 to get meters
                            x_meters = grid_x * 256
                            y_meters = grid_y * 256
                            handle = (y_meters << 32) | x_meters
                            
                            self.log(f"[GridSurvey] Found region: grid=({grid_x}, {grid_y}), handle={handle}")
                            
                            return {
                                'Handle': handle,
                                'X': grid_x,
                                'Y': grid_y,
                                'Name': result.get('name', region_name)
                            }
                        except (ValueError, KeyError) as e:
                            self.log(f"[GridSurvey] Invalid coordinate format: x={result.get('x')}, y={result.get('y')} - {e}")
                            return None
                    else:
                        self.log(f"[GridSurvey] No 'x' or 'y' fields in response. Keys: {list(result.keys())}")
                        return None
                else:
                    self.log(f"[GridSurvey] HTTP {response.getcode()} from API")
                    return None
                    
        except urllib.error.HTTPError as e:
            self.log(f"[GridSurvey] HTTP Error {e.code}: {e.reason}")
            return None
        except Exception as e:
            self.log(f"[GridSurvey] Lookup error: {type(e).__name__}: {e}")
            return None
            


    def hard_teleport(self, region_name, x=128, y=128, z=30):
        """
        Performs a 'hard teleport' by logging out and immediately logging back in 
        at the target region and coordinates.
        """
        # --- Height adjustment (+3m) to prevent falling through floors ---
        z += 3.0
        
        self.log(f"Initiating Hard Teleport to '{region_name}' at <{x}, {y}, {z}>...")
        self.ui_callback("status", f"🔄 Relogging to {region_name} ({x}, {y})...")
        
        # 1. Format the start URI
        # Format: uri:Region%20Name&x&y&z
        encoded_region_name = urllib.parse.quote(region_name.strip())
        start_uri = f"uri:{encoded_region_name}&{int(x)}&{int(y)}&{int(z)}"
        
        # --- FIX: Clear the minimap only if changing regions ---
        # If we are just relogging in the same region, keep the map for context.
        if self.current_region_name and region_name.lower().strip() != self.current_region_name.lower().strip():
             self.ui_callback("clear_map", None)
        # ------------------------------------------
        
        # 2. Stop the current connection
        self.stop()
        
        # 3. Wait a moment for socket cleanup
        time.sleep(2.0)
        
        # 4. Start a new login sequence in a new thread to avoid blocking the UI
        # We need to call login() again. Since we stored credentials, we can reuse them.
        
        def relog_task():
            try:
                self.login(self.first_name, self.last_name, self.password, start_uri)
            except Exception as e:
                self.ui_callback("status", f"❌ Hard Teleport Failed: {e}")
                
        threading.Thread(target=relog_task, daemon=True).start()


            
    def stop(self):
        self.log("Stopping client...")
        self.running = False
        if self.client:
            try:
                self.client.logout() 
            except:
                pass 
        if self.event_thread and self.event_thread.is_alive():
            try:
                self.event_thread.join(1)
            except: pass

    def login(self, first, last, password, region_name):
        self.ui_callback("status", "🌐 Connecting to the Second Life Grid (HTTP)...")
        self.ui_callback("progress", ("Initial Connection", 5))
        self.log(f"Starting login process for {first} {last} @ {region_name}")
        
        try:
            self.log("Requesting XML-RPC login token...")
            # The 'start' parameter is what determines the landing spot
            login_token = login_to_simulator(first, last, password, start=region_name)

            if login_token.get("login") != "true":
                 message = login_token.get("message", "Unknown login error")
                 self.log(f"Login failed. Server response: {message}")
                 raise ConnectionError(message)
            
            self.log("HTTP Login successful! Token received.")
            self.ui_callback("progress", ("HTTP Login Success", 10))
            
            # Diagnostic: Log all keys and if 'capabilities' is present
#             print(f"DEBUG: Login Token Keys: {list(login_token.keys())}")
            if 'capabilities' in login_token:
#                 print(f"DEBUG: Capabilities in Login Token: {list(login_token['capabilities'].keys())}")
                pass
            
            self.circuit_code = int(login_token['circuit_code'])
            self.agent_id = UUID(login_token['agent_id'])
            self.session_id = UUID(login_token['session_id'])

            self.first_name = first 
            self.last_name = last
            self.password = password 

            self.log("Initializing UDP Stream...")
            # Always set debug=True in RegionClient so that it sends logs to SecondLifeAgent.log
            # The agent itself will decide whether to pass them to the UI based on debug_callback.
            self.client = RegionClient(login_token, debug=True, log_callback=self.log) 
            self.client.ui_callback = self.ui_callback
            self.raw_socket = self.get_socket()
            self.log(f"Socket acquisition status: {'Success' if self.raw_socket else 'Failed'}")


            self.running = True
            self.event_thread = threading.Thread(target=self._event_handler, daemon=True)
            self.event_thread.start()
            
            # --- FIX: Set the initial status to reflect the UDP handshake phase ---
            self.ui_callback("status", "Teleport complete.")
            
            # --- MANDATORY: Resolve final region name from coordinates ---
            # Login server may redirect us (e.g. if target is down). 
            # We MUST trust the coordinates in the login token, not the initial URI.
            
            # We should have coordinates from the login token (via RegionClient)
            gx = self.client.grid_x
            gy = self.client.grid_y
            
            self.current_region_name = None # Clear any previous assumption
            
            if gx and gy:
                 self.ui_callback("status", f"📍 Verifying region name for coordinates {gx}, {gy}...")
                 self.log(f"Login: Verifying region name via Gridsurvey for {gx}, {gy}...")
                 
                 # Perform blocking lookup (since we are in a thread)
                 info = self._gridsurvey_region_lookup(grid_x=gx, grid_y=gy)
                 
                 if info and 'Name' in info:
                     self.current_region_name = info['Name']
                     self.client.sim['name'] = info['Name'] # Pre-populate sim name
                     self.log(f"Resolved actual region name: '{self.current_region_name}'")
                     self.ui_callback("status", f"✅ Location verified: {self.current_region_name}")
                     
                     # Fetch map immediately with the CORRECT name
                     self.fetch_map(self.current_region_name)
                 else:
                     self.log("Region name lookup failed.")
                     self.ui_callback("status", "⚠️ Could not resolve region name from coordinates.")
            else:
                 self.log(f"Login token missing coordinates? gx={gx}, gy={gy}")
            # -------------------------------------------------------------------------
            # --- END FIX ---
            
            return True
                
        except Exception as e:
            # We don't call ui_callback("error", ...) here, we raise the error 
            # and let the calling thread (login_task) handle the UI failure via its own callback.
            raise ConnectionError(str(e))


# ==========================================
# SECTION 8: PERSISTENCE AND ENCRYPTION
# ==========================================
# Simple XOR Cipher for "encryption" as requested, using a constant key.
# NOTE: This is NOT cryptographically secure and should not be used for real security.
_SECRET_KEY = b"sl_chat_key_v1"
CREDENTIALS_FILE = "sl_credentials.json"

def _cipher_xor(data_bytes, key=_SECRET_KEY):
    """Simple repeating-key XOR cipher."""
    key_len = len(key)
    return bytes(data_bytes[i] ^ key[i % key_len] for i in range(len(data_bytes)))

def save_credentials(credentials):
    """Saves a single credential entry to the JSON file, encrypting the password."""
    try:
        if os.path.exists(CREDENTIALS_FILE):
            with open(CREDENTIALS_FILE, 'r') as f:
                data = json.load(f)
        else:
            data = []
            
        full_name = f"{credentials['first']} {credentials['last']}"
        existing_names = [f"{c['first']} {c['last']}" for c in data]

        if full_name in existing_names:
            index = existing_names.index(full_name)
            data.pop(index) 
        
        password_bytes = credentials['password'].encode('utf-8')
        encrypted_password = _cipher_xor(password_bytes)
        
        encoded_password = base64.b64encode(encrypted_password).decode('utf-8')
        
        new_entry = {
            'first': credentials['first'],
            'last': credentials['last'],
            'password_enc': encoded_password,
            'region': credentials['region']
        }
        data.append(new_entry)

        with open(CREDENTIALS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
            
        return True
    except Exception:
#         print(f"Error saving credentials: {e}")
        return False

def load_credentials():
    """Loads all credentials from the JSON file, decrypting passwords."""
    if not os.path.exists(CREDENTIALS_FILE):
        return []
    
    try:
        with open(CREDENTIALS_FILE, 'r') as f:
            data = json.load(f)
            
        decrypted_data = []
        for entry in data:
            try:
                encoded_password = entry.get('password_enc', '')
                if not encoded_password: continue
                
                encrypted_password = base64.b64decode(encoded_password)
                password_bytes = _cipher_xor(encrypted_password)
                password = password_bytes.decode('utf-8')
                
                decrypted_data.append({
                    'first': entry['first'],
                    'last': entry['last'],
                    'password': password,
                    'region': entry.get('region', 'last') 
                })
            except Exception as e:
                print(f"Warning: Failed to decrypt credential entry. Skipping. Error: {e}")
                continue
                
        return decrypted_data
    except Exception:
#         print(f"Error loading credentials (file corrupted?): {e}")
        return []

# ==========================================
# SECTION 9: GUI IMPLEMENTATION (Multi-Client)
# ==========================================

# --- Custom Themed Dialogs (NEW) ---

class ThemedDialog(Toplevel):
    def __init__(self, parent, title=None, topmost=False):
        super().__init__(parent)
        self.transient(parent)
        if title:
            self.title(title)
        
        self.parent = parent
        self.result = None
        
        # Set window properties to adhere to theme
        self.configure(bg='#0A0A0A')
        self.resizable(False, False)
        if topmost:
            self.attributes("-topmost", True)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.body()
        self.buttonbox()
        
        self.grab_set()
        
        # Center the dialog
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width()
        parent_h = parent.winfo_height()
        
        # Must update_idletasks before getting window size
        self.update_idletasks()
        
        win_w = self.winfo_width()
        win_h = self.winfo_height()
        
        x = parent_x + (parent_w - win_w) // 2
        y = parent_y + (parent_h - win_h) // 2
        
        self.geometry(f'+{x}+{y}')
        
        self.initial_focus = self
        if self.initial_focus:
            self.initial_focus.focus_set()
            
        self.wait_window(self)

    def body(self):
        # Create dialog body. Override in subclasses.
        pass

    def buttonbox(self):
        # Create buttons. Override in subclasses.
        box = ttk.Frame(self, style='BlackGlass.TFrame')
        box.pack(padx=10, pady=10)

    def ok(self):
        self.result = True
        self.destroy()

    def cancel(self):
        self.result = False
        self.destroy()

class ThemedMessageBox(ThemedDialog):
    """
    Custom equivalent of messagebox.askyesno, showinfo, etc.
    type_ is 'yesno', 'ok', 'error', 'warning'
    """
    def __init__(self, parent, title, message, type_='yesno', topmost=False):
        self.message = message
        self.type = type_
        super().__init__(parent, title, topmost=topmost)

    def body(self):
        # Icon can be styled with text or an image if PIL was used, but sticking to text/color for now
        icon_text = ""
        icon_color = "#FFFFFF"
        
        if self.type == 'error':
            icon_text = "❌"
            icon_color = "#FF0000"
        elif self.type == 'warning' or self.type == 'yesno':
            icon_text = "⚠️"
            icon_color = "#FFFF00"
        elif self.type == 'info':
            icon_text = "ℹ️"
            icon_color = "#00FFFF"
        
        main_frame = ttk.Frame(self, style='BlackGlass.TFrame', padding=(15, 15, 15, 0))
        main_frame.pack(fill='both', expand=True)

        # Icon/Message frame
        content_frame = ttk.Frame(main_frame, style='BlackGlass.TFrame')
        content_frame.pack(fill='x', expand=True)
        
        ttk.Label(content_frame, text=icon_text, style='BlackGlass.TLabel', foreground=icon_color, font=('Helvetica', 20, 'bold')).pack(side=tk.LEFT, padx=(0, 10))
        
        # Use a Message widget for multi-line support
        msg = tk.Message(content_frame, text=self.message, 
                         bg='#0A0A0A', fg='#F0F0F0', 
                         font=('Helvetica', 11), 
                         justify=tk.LEFT)
        msg.pack(side=tk.LEFT, fill='both', expand=True)

    def buttonbox(self):
        box = ttk.Frame(self, style='BlackGlass.TFrame', padding=(15, 0, 15, 15))
        box.pack(fill='x')
        
        if self.type == 'yesno':
            yes_button = ttk.Button(box, text="Yes", command=self.ok, style='BlackGlass.TButton', width=10)
            yes_button.pack(side=tk.RIGHT, padx=5)
            self.bind("<Return>", lambda e: self.ok())
            
            no_button = ttk.Button(box, text="No", command=self.cancel, style='BlackGlass.TButton', width=10)
            no_button.pack(side=tk.RIGHT, padx=5)
            self.bind("<Escape>", lambda e: self.cancel())
        
        elif self.type in ('ok', 'error', 'warning', 'info'):
            ok_button = ttk.Button(box, text="OK", command=self.ok, style='BlackGlass.TButton', width=10)
            ok_button.pack(side=tk.RIGHT)
            self.bind("<Return>", lambda e: self.ok())
            self.bind("<Escape>", lambda e: self.ok())
            
        self.initial_focus = yes_button if self.type == 'yesno' else ok_button

class ThemedAskString(ThemedDialog):
    """
    Custom equivalent of simpledialog.askstring.
    """
    def __init__(self, parent, title, prompt, initialvalue="", topmost=False):
        self.prompt = prompt
        self.initialvalue = initialvalue
        self.value = None
        super().__init__(parent, title, topmost=topmost)
        
    def body(self):
        f = ttk.Frame(self, style='BlackGlass.TFrame')
        f.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        ttk.Label(f, text=self.prompt, style='BlackGlass.TLabel').pack(pady=(0, 10))
        
        self.entry = tk.Entry(f, font=('Helvetica', 12), 
                              bg='#2C2C2C', fg='#FFFFFF', 
                              insertbackground='white', relief=tk.FLAT, highlightthickness=1, highlightbackground='#555555')
        self.entry.insert(0, self.initialvalue)
        self.entry.pack(fill=tk.X)
        self.entry.bind("<Return>", lambda e: self.ok())
        self.initial_focus = self.entry

    def buttonbox(self):
        box = ttk.Frame(self, style='BlackGlass.TFrame')
        box.pack(padx=10, pady=10)
        
        ttk.Button(box, text="OK", width=10, command=self.ok, style='BlackGlass.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(box, text="Cancel", width=10, command=self.cancel, style='BlackGlass.TButton').pack(side=tk.LEFT, padx=5)

    def ok(self):
        self.value = self.entry.get().strip()
        self.result = True
        self.destroy()

    @staticmethod
    def askstring(parent, title, prompt, initialvalue="", topmost=False):
        d = ThemedAskString(parent, title, prompt, initialvalue, topmost)
        return d.value if d.result else None

class ThemedChoiceDialog(ThemedDialog):
    """
    Shows a list of buttons for choices.
    choices: List of strings.
    Returns the string chosen or None if cancelled.
    """
    def __init__(self, parent, title, prompt, choices, topmost=False):
        self.prompt = prompt
        self.choices = choices
        super().__init__(parent, title, topmost=topmost)

    def body(self):
        f = ttk.Frame(self, style='BlackGlass.TFrame')
        f.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        ttk.Label(f, text=self.prompt, style='BlackGlass.TLabel', font=('Helvetica', 10, 'bold')).pack(pady=(0, 15))
        
        for choice in self.choices:
            btn = ttk.Button(f, text=choice, command=lambda c=choice: self.choose(c), style='BlackGlass.TButton')
            btn.pack(fill=tk.X, pady=2)

    def buttonbox(self):
        box = ttk.Frame(self, style='BlackGlass.TFrame')
        box.pack(padx=10, pady=(0, 10))
        ttk.Button(box, text="Cancel", width=10, command=self.cancel, style='BlackGlass.TButton').pack()

    def choose(self, choice):
        self.result = choice
        self.destroy()

    @staticmethod
    def askchoice(parent, title, prompt, choices, topmost=False):
        d = ThemedChoiceDialog(parent, title, prompt, choices, topmost)
        return d.result

class ThemedProfileDialog(Toplevel):
    """
    Displays avatar profile information. 
    Modified to be non-blocking and support dynamic updates from web scraping.
    """
    def __init__(self, parent, profile_data, chat_tab, uid_key):
        super().__init__(parent)
        self.data = profile_data
        self.chat_tab = chat_tab
        self.uid_key = uid_key
        
        self.transient(parent)
        self.title(f"Profile: {profile_data.get('name', 'Unknown')}")
        self.configure(bg='#0A0A0A')
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.setup_ui()
        
        # Center the dialog
        self.update_idletasks()
        win_w = self.winfo_width()
        win_h = self.winfo_height()
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width()
        parent_h = parent.winfo_height()
        x = parent_x + (parent_w - win_w) // 2
        y = parent_y + (parent_h - win_h) // 2
        self.geometry(f'+{x}+{y}')
        
        self.focus_set()

    def setup_ui(self):
        # Clear existing widgets if this is a refresh
        for child in self.winfo_children():
            child.destroy()
            
        f = ttk.Frame(self, style='BlackGlass.TFrame')
        f.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        # Profile Header
        dname = self.data.get('name', 'Unknown')
        uname = self.data.get('username', '')
        header_text = f"{dname} (@{uname})" if uname else dname
            
        header = ttk.Label(f, text=header_text, style='BlackGlass.TLabel', font=('Helvetica', 14, 'bold'))
        header.pack(pady=(0, 5), anchor='w')
        
        uid_label = ttk.Label(f, text=f"ID: {self.data.get('id', 'Unknown')}", style='BlackGlass.TLabel', font=('Courier', 8), foreground='#888888')
        uid_label.pack(pady=(0, 15), anchor='w')
        
        content_frame = ttk.Frame(f, style='BlackGlass.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(content_frame, style='BlackGlass.TFrame')
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))

        self.image_label = ttk.Label(left_frame, background='#1C1C1C', anchor='center')
        self.image_label.pack(side=tk.TOP, pady=(0, 10))

        image_id = self.data.get('image_id', '')
        if image_id and image_id != "00000000-0000-0000-0000-000000000000":
             self.image_label.configure(text="Loading Picture...")
             threading.Thread(target=self._fetch_profile_image, args=(image_id,), daemon=True).start()
        else:
             self.image_label.configure(text="\nNo Picture\n")

        right_frame = ttk.Frame(content_frame, style='BlackGlass.TFrame')
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Born On
        ttk.Label(right_frame, text="Born On:", style='BlackGlass.TLabel', font=('Helvetica', 10, 'bold')).pack(anchor='w')
        ttk.Label(right_frame, text=self.data.get('born', 'Unknown'), style='BlackGlass.TLabel').pack(pady=(0, 10), anchor='w', padx=5)
        
        # About
        ttk.Label(right_frame, text="About/Bio:", style='BlackGlass.TLabel', font=('Helvetica', 10, 'bold')).pack(anchor='w')
        about_text = self.data.get('about', '')
        if not about_text.strip():
            about_text = "(No bio provided)"
            
        # Use a text box for About (read only), with clickable hyperlinks
        txt = tk.Text(right_frame, height=8, width=40, bg='#1E1E1E', fg='#CCCCCC', font=('Helvetica', 10),
                      relief=tk.FLAT, highlightthickness=1, highlightbackground='#333333', wrap=tk.WORD,
                      cursor='arrow')
        txt.tag_config('hyperlink', foreground='#00FFFF', underline=True)
        txt.insert(tk.END, about_text)
        
        # Detect and tag all http(s) URLs so they become clickable
        url_pattern = re.compile(r'https?://[^\s\]\[<>\"\']+', re.I)
        for match in url_pattern.finditer(about_text):
            start_char = match.start()
            end_char = match.end()
            # Convert character offsets to Tk "line.char" index notation
            start_idx = f"1.0 + {start_char} chars"
            end_idx   = f"1.0 + {end_char} chars"
            tag_name = f"link_{start_char}"
            link_url = match.group(0)
            txt.tag_add(tag_name, start_idx, end_idx)
            txt.tag_config(tag_name, foreground='#00FFFF', underline=True)
            txt.tag_bind(tag_name, '<Button-1>', lambda e, u=link_url: os.startfile(u))
            txt.tag_bind(tag_name, '<Enter>',   lambda e: txt.config(cursor='hand2'))
            txt.tag_bind(tag_name, '<Leave>',   lambda e: txt.config(cursor='arrow'))
        
        txt.config(state='disabled')
        txt.pack(pady=(0, 10), fill=tk.BOTH, expand=True)

        
        # URL
        url = self.data.get('url', '')
        if url:
             ttk.Label(right_frame, text="Web Profile:", style='BlackGlass.TLabel', font=('Helvetica', 10, 'bold')).pack(anchor='w')
             link = ttk.Label(right_frame, text=url, style='BlackGlass.TLabel', foreground='#00FFFF', cursor="hand2")
             link.pack(anchor='w', padx=5)
             link.bind("<Button-1>", lambda e: os.startfile(url))
        
        # Status / Fetch progress
        source = self.data.get('source', 'UDP')
        status_text = f"Source: {source.upper()}"
        if source == "UDP":
            status_text += " (Fetching full web profile...)"
        
        status = ttk.Label(f, text=status_text, style='BlackGlass.TLabel', font=('Helvetica', 8, 'italic'), foreground='#666666')
        status.pack(pady=(10, 0), anchor='w')

        # Close button
        box = ttk.Frame(self, style='BlackGlass.TFrame')
        box.pack(padx=10, pady=(0, 10))
        ttk.Button(box, text="Close", width=12, command=self.on_close, style='BlackGlass.TButton').pack()

    def _fetch_profile_image(self, image_id):
        if not PIL_AVAILABLE:
            self.image_label.after(0, lambda: self.image_label.configure(text="\nPIL missing\n"))
            return
        
        # world.secondlife.com uses picture-service.secondlife.com for profile images
        # Fall back to the old /app/image/ URL if needed
        urls_to_try = [
            f"https://picture-service.secondlife.com/{image_id}/256x192.jpg",
            f"https://secondlife.com/app/image/{image_id}/1",
        ]
        
        for url in urls_to_try:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': SL_USER_AGENT})
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.getcode() == 200:
                        image_data = response.read()
                        image = Image.open(BytesIO(image_data))
                        resample = Image.Resampling.LANCZOS if hasattr(Image, 'Resampling') else Image.LANCZOS
                        image.thumbnail((180, 240), resample)
                        photo = ImageTk.PhotoImage(image)
                        self.image_label.after(0, lambda p=photo: self._apply_profile_image(p))
                        self._profile_photo = photo
                        return  # Success - stop trying
            except Exception:
                continue
        
        # All URLs failed
        self.image_label.after(0, lambda: self.image_label.configure(text="\nNo Picture\n"))


    def _apply_profile_image(self, photo):
        # We check if the widget still exists before applying
        if self.image_label.winfo_exists():
            self.image_label.configure(image=photo, text="")

    def update_data(self, new_data):
        self.data.update(new_data)
        self.setup_ui()
        self.lift() # Bring to front

    def on_close(self):
        if self.uid_key in self.chat_tab.active_profiles:
            del self.chat_tab.active_profiles[self.uid_key]
        self.destroy()

# --- Minimap Widget ---
class MinimapCanvas(tk.Canvas):
    def __init__(self, master, agent, **kwargs):
        # We remove explicit width/height here, as the wrapper manages the size.
        # FIX: We restore explicit width=256, height=256 to prevent default Canvas sizing from expanding the column.
        kwargs.setdefault('width', 256)
        kwargs.setdefault('height', 256)
        super().__init__(master, **kwargs)
        self.agent = agent
        self.configure(bg='#1C1C1C', highlightthickness=1, highlightbackground='#444444')
        self.size = 256 # SL regions are 256x256 meters
        self.source_image = None # NEW: Store original PIL image
        self.map_image = None # Tkinter PhotoImage object for the map tile
        self.last_size = (0, 0) # NEW: Track size to avoid redundant resizing
        self.bind("<Configure>", self.on_resize)
        self.bind("<Double-Button-1>", self.on_double_click)
        self.after(1000, self.draw_map) # Start the drawing loop (1 FPS)

    def on_double_click(self, event):
        """Handles double-click to teleport within the region."""
        if not self.agent or not self.agent.client or not self.agent.running:
            return

        # Get canvas dimensions
        width = self.winfo_width()
        height = self.winfo_height()
        dest_size = min(width, height)
        
        # Calculate offsets
        offset_x = (width - dest_size) / 2
        offset_y = (height - dest_size) / 2
        
        # Get click position relative to the map area
        click_x_rel = event.x - offset_x
        click_y_rel = event.y - offset_y
        
        # Check if click is within the map area
        if click_x_rel < 0 or click_x_rel > dest_size or click_y_rel < 0 or click_y_rel > dest_size:
            return
            
        # Convert to SIM coordinates (0-256)
        # scale = dest_size / 256.0
        # sim_x = click_x_rel / scale
        # sim_y = (dest_size - click_y_rel) / scale (Y is inverted)
        
        scale = dest_size / 256.0
        sim_x = click_x_rel / scale
        sim_y = (dest_size - click_y_rel) / scale # Inverted Y for SL
        
        # Clamp coordinates to 0-255.9
        sim_x = max(0.0, min(255.9, sim_x))
        sim_y = max(0.0, min(255.9, sim_y))
        
        # Keep current altitude (Z)
        current_z = getattr(self.agent.client, 'agent_z', 30.0)
        
        # Calculate RegionHandle
        # Handle = (grid_y * 256) << 32 | (grid_x * 256)
        gx = getattr(self.agent.client, 'grid_x', 0)
        gy = getattr(self.agent.client, 'grid_y', 0)
        
        if gx == 0 and gy == 0:
             self.agent.ui_callback("status", "❌ Cannot teleport: Unknown region coordinates.")
             return

        region_handle = (gy * 256) << 32 | (gx * 256)
        
        self.agent.log(f"DEBUG: LocalTeleport - Grid: {gx},{gy} Sim: {sim_x:.1f},{sim_y:.1f} Handle: {region_handle} (0x{region_handle:X})")
        
        # Create target position vector
        vector3(sim_x, sim_y, current_z)
        
        
        region_name = self.agent.current_region_name
        if not region_name and self.agent.client:
             # Fallback to RegionClient's captured sim name (raw)
             # We might need to clean it if it wasn't decoded safely
             raw_name = self.agent.client.sim.get('name', '')
             if raw_name:
                 # It might be a variable object str() representation or a raw string
                 # Attempt to clean it if it looks like variable(...)
                 region_name = raw_name
                 if "variable(" in str(region_name):
                     # If we can't easily parse it, we might be stuck, but usually RegionClient uses str()
                     # If RegionClient used str(variable), it might be messy. 
                     # Let's hope RegionHandshake handler in SecondLifeAgent fired.
                     pass
                 else:
                     # Strip nulls
                     region_name = region_name.replace('\x00', '')

        if region_name and region_name.lower() != "home":
             self.agent.ui_callback("status", f"🏃 Hard Teleport (Relog) to {sim_x:.0f}, {sim_y:.0f}...")
             self.agent.hard_teleport(region_name, sim_x, sim_y, current_z)
        else:
             self.agent.ui_callback("status", "❌ Cannot teleport: Unknown region name.")

    def set_map_image(self, pil_image):
        """Sets the source PIL image for the map."""
        self.source_image = pil_image
        self.last_size = (0, 0) # Force re-render
        self.draw_map()




    def on_resize(self, event):
        # The canvas relies on its parent wrapper enforcing the square size.
        self.draw_map()

    def update_map_image(self, img_tk):
        """Sets the Tkinter PhotoImage to be displayed. Deprecated for set_map_image."""
        if img_tk is None:
            self.source_image = None
            self.map_image = None
            self.last_size = (0, 0)
        self.draw_map()

    def draw_map(self):
        # Clear canvas
        self.delete("all")
        
        # Get the actual dimensions of the canvas
        width = self.winfo_width()
        height = self.winfo_height()
        
        if width <= 1 or height <= 1:
             # Widget not fully initialized
             if self.agent.running:
                 self.after(100, self.draw_map)
             return

        dest_size = min(width, height)
        # Calculate offsets to center the map content
        offset_x = (width - dest_size) / 2
        offset_y = (height - dest_size) / 2

        # --- Handle Image Resizing ---
        if PIL_AVAILABLE and self.source_image:
             if (width, height) != self.last_size:
                 # Resize needed
                 try:
                     # High quality resize
                     resample = Image.Resampling.LANCZOS if hasattr(Image, 'Resampling') else Image.LANCZOS
                     resized = self.source_image.resize((int(dest_size), int(dest_size)), resample)
                     self.map_image = ImageTk.PhotoImage(resized)
                     self.last_size = (width, height)
                 except Exception:
                     pass

        # --- Map Image/Placeholder Drawing ---
        if self.map_image and PIL_AVAILABLE: # Only use image if PIL is available
            # Display the actual image centered
            self.create_image(width/2, height/2, image=self.map_image, anchor=tk.CENTER)
            # Draw the region boundary over the image
            self.create_rectangle(offset_x, offset_y, offset_x+dest_size, offset_y+dest_size, outline='#444444')
        else:
            # General placeholder when map is not loaded or failed
            self.create_rectangle(offset_x, offset_y, offset_x+dest_size, offset_y+dest_size, fill='#303030', outline='#444444')
            
            # --- FIX: Show debug info on the canvas ---
            gx = getattr(self.agent.client, 'grid_x', '?')
            gy = getattr(self.agent.client, 'grid_y', '?')
            debug_text = f"Map Unavailable\nGrid: {gx}, {gy}"
            
            center_x = width / 2
            center_y = height / 2
            if not PIL_AVAILABLE:
                self.create_text(center_x, center_y, text="Pillow Missing!", fill='#FF0000')
            else:
                self.create_text(center_x, center_y, text=debug_text, fill='#888888', justify=tk.CENTER)
        # --- End Map Image/Placeholder Drawing ---
        
        # --- Scale Factor ---
        # 1.0 means 256 meters = dest_size pixels
        scale = dest_size / self.size

        # --- Other Avatars Drawing (Black Dots) ---
        if self.agent.client and self.agent.running:
            for coords in self.agent.client.other_avatars:
                # Coarse coords are (x, y, z)
                ox, oy, _ = coords
                
                # Apply scaling and offsets
                x_other = ox * scale + offset_x
                y_other = (self.size - oy) * scale + offset_y
                
                # Draw small BLACK dot (radius 3)
                r = 3
                self.create_oval(x_other - r, y_other - r, x_other + r, y_other + r,
                                 fill="#000000", outline="#FFFFFF")
                                 
        # --- Agent Drawing (Own Location Indicator) ---
        if self.agent.client and self.agent.running: # Only draw agent if running
            # Agent Position (AgentUpdate/ImprovedTerseObjectUpdate is 0-256)
            agent_x_sl = self.agent.client.agent_x 
            agent_y_sl = self.agent.client.agent_y 
    
            # Map to Canvas: X is proportional, Y is inverted (256-Y)
            # Apply scaling and offsets
            x_on_canvas = agent_x_sl * scale + offset_x
            y_on_canvas = (self.size - agent_y_sl) * scale + offset_y
            
            # Draw Bullseye Indicator (Bright Cyan outer, White inner)
            # Sized to be distinct but not overly large
            r_outer = 3
            r_inner = 1
            
            # Outer Bright Cyan Circle
            self.create_oval(x_on_canvas - r_outer, y_on_canvas - r_outer, 
                             x_on_canvas + r_outer, y_on_canvas + r_outer,
                             fill="#00FFFF", outline="#000000", width=2)
            
            # Inner White Dot
            self.create_oval(x_on_canvas - r_inner, y_on_canvas - r_inner,
                             x_on_canvas + r_inner, y_on_canvas + r_inner,
                             fill="#FFFFFF", outline="#000000")

        # Schedule the next redraw
        if self.agent.running:
            self.after(1000, self.draw_map)
        
# --- Chat Tab ---
class ChatTab(ttk.Frame):
    """
    Refactored ChatWindow as a ttk.Frame to be placed inside a Notebook.
    Manages the UI and communication for a single logged-in agent.
    """
    def __init__(self, master, sl_agent, first, last, tab_manager):
        super().__init__(master, style='BlackGlass.TFrame') 
        self.sl_agent = sl_agent
        self.my_first_name = first
        self.my_last_name = last
        self.tab_manager = tab_manager 
        
        self.active_profiles = {} # UUID -> ThemedProfileDialog instance
        self.pending_chat = {} # FIX: Store messages awaiting ACK echo
        
        # Update the agent's callback to target this specific tab
        self.sl_agent.ui_callback = self.update_ui 
        # FIX: The log handler needs to check for minimap updates
        self.sl_agent.debug_callback = self.handle_debug_log_callback 
        self.map_image = None # Added for the Tkinter PhotoImage object

        self._set_style(master)
        self._create_widgets()
        self._bind_keys() # Movement key bindings
        
        # Start periodic nearby avatars refresh
        self.nearby_avatars_uuids = [] # NEW: Stores UUIDs corresponding to list items
        self._refresh_nearby_avatars()
        
        # --- ROBUST MAP TRIGGER ---
        # Trigger the map fetch shortly after the tab is created.
        # This avoids the race condition where the handshake packet arrives before the UI exists.
        def initial_map_load():
            time.sleep(3.0) # Wait for connection stabilization
            # Use current region or fallback to "map" (which logic handles)
            r_name = self.sl_agent.current_region_name or "Home" 
            self.sl_agent.fetch_map(r_name)
            
        threading.Thread(target=initial_map_load, daemon=True).start()
        # --------------------------

    def _set_style(self, master):
        ttk.Style(master)
        # Note: ChatTab relies on the styles defined in MultiClientApp
        
    # --- Helper to enforce square minimap ---
    def _enforce_square(self, event):
        """Forces the minimap wrapper to be a square based on its width."""
        # Use the event width, and check if height is already configured to that value
        # We check event.width > 1 to avoid issues during initialization/cleanup
        if event.width != self.minimap_wrapper.winfo_height() and event.width > 1:
            # Tell the widget to resize itself based on the width
            self.minimap_wrapper.configure(height=event.width)
    # --- End helper ---

    def _bind_keys(self):
        """Bind keyboard events for movement controls (Arrow Keys)."""
        # Need to ensure the frame captures events, which means it needs to be focusable
        self.focus_set() 
        self.bind('<FocusIn>', self._on_focus_in)

        # Bind Arrow Keys, E, C, and Space
        for key in ['Up', 'Down', 'Left', 'Right', 'e', 'c', 'space', 'f']:
            self.bind(f'<KeyPress-{key}>', self.on_key_press)
            # The release event should only be bound for continuous controls
            if key not in ['space', 'f']:
                self.bind(f'<KeyRelease-{key}>', self.on_key_release)
            # Bind KeyRelease-space explicitly for the jump flag
            if key == 'space':
                 self.bind(f'<KeyRelease-{key}>', self.on_key_release)
        
    def _on_focus_in(self, event):
        """Called when the tab receives focus."""
        # Ensure the frame stays focused when active
        self.focus_set()
        
    def on_key_press(self, event):
        """Handles key down event for movement."""
        key = event.keysym
        
        # The key handlers only work if the input entry box is NOT focused
        if self.message_entry != self.focus_get():
            self.sl_agent.process_control_change(key, is_press=True)

    def on_key_release(self, event):
        """Handles key up event for movement."""
        key = event.keysym
        
        # Release events only for continuous keys
        if key in self.sl_agent.is_key_down:
            self.sl_agent.process_control_change(key, is_press=False)


    def _create_widgets(self):
        
        # Control Frame (top bar)
        control_frame = ttk.Frame(self, style='BlackGlass.TFrame')
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(10, 5))
        
        self.agent_name_label = ttk.Label(control_frame, text=f"Agent: {self.my_first_name} {self.my_last_name}", style='BlackGlass.TLabel', font=('Helvetica', 12, 'bold'))
        self.agent_name_label.pack(side=tk.LEFT, padx=5)
        
        teleport_button = ttk.Button(control_frame, text="Teleport...", command=self.do_teleport, style='BlackGlass.TButton')
        teleport_button.pack(side=tk.RIGHT, padx=5)
        
        self.logout_button = ttk.Button(control_frame, text="Logout", command=self.on_closing, style='BlackGlass.TButton')
        self.logout_button.pack(side=tk.RIGHT, padx=5)
        
        # --- Main Content Frame (Chat + Right Panel) ---
        main_content_frame = ttk.Frame(self, style='BlackGlass.TFrame')
        main_content_frame.pack(padx=(10, 0), pady=(0, 10), fill=tk.BOTH, expand=True)

        # Configure 2 columns: Column 0 (Chat Log) expands, Column 1 (Minimap/Notification) fixed width.
        main_content_frame.grid_columnconfigure(0, weight=1) 
        main_content_frame.grid_columnconfigure(1, weight=0, minsize=256) 
        main_content_frame.grid_rowconfigure(0, weight=1)

        # 1. Chat Display (Column 0, Row 0 - Expanding)
        self.chat_display = LimitedScrolledText(main_content_frame, max_lines=500, state='disabled', wrap=tk.WORD, height=15, 
                                                     bg='#1C1C1C', fg='#E0E0E0', font=('Courier', 12), 
                                                     insertbackground='white', 
                                                     relief=tk.FLAT, highlightthickness=1, highlightbackground='#444444')
        self.chat_display.grid(row=0, column=0, sticky='nsew', padx=(0, 0))
        
        # --- FIX: Configure tag for gray speaker name ---
        self.chat_display.tag_config('speaker_name', foreground='#AAAAAA') 
        # ------------------------------------------------

        # 2. Right Panel Frame (Column 1, Row 0 - Contains Notifications and Minimap)
        right_panel_frame = ttk.Frame(main_content_frame, style='BlackGlass.TFrame')
        right_panel_frame.grid(row=0, column=1, sticky='nsew', padx=(0, 0))

        # Configure rows in the Right Panel: Notifications (expanding) and Minimap (fixed height/square)
        right_panel_frame.grid_columnconfigure(0, weight=1)
        right_panel_frame.grid_rowconfigure(0, weight=1) # Notifications/Events (EXPAND)
        right_panel_frame.grid_rowconfigure(1, weight=0) # Minimap (FIXED HEIGHT, ALIGNED BOTTOM)

        # 2a. Nearby Avatars Area (Row 0 - Takes up remaining vertical space)
        self.nearby_avatars_list = tk.Listbox(right_panel_frame, height=5, width=30,
                                              bg='#1C1C1C', fg='#00FFFF', font=('Courier', 10),
                                              relief=tk.FLAT, highlightthickness=1, highlightbackground='#444444')
        self.nearby_avatars_list.insert(tk.END, "Loading nearby avatars...")
        self.nearby_avatars_list.grid(row=0, column=0, sticky='nsew', pady=(0, 0), padx=0)
        self.nearby_avatars_list.bind("<Button-1>", self._on_avatar_click)

        # 2b. Minimap Wrapper (Row 1 - Fixed at the bottom and forces square aspect)
        # Give it an initial size but let the grid manage its width
        self.minimap_wrapper = ttk.Frame(right_panel_frame, style='BlackGlass.TFrame', width=256, height=256) # <--- FIX: Added explicit width/height=256
        self.minimap_wrapper.grid(row=1, column=0, sticky='sew', padx=0, pady=0) # Aligned bottom (s), expands horizontally (ew)
        
        # Enforce square aspect ratio on the wrapper by binding Configure event
        self.minimap_wrapper.bind("<Configure>", self._enforce_square)

        # 2c. Minimap Canvas inside the wrapper
        self.minimap = MinimapCanvas(self.minimap_wrapper, self.sl_agent)
        self.minimap.pack(fill=tk.BOTH, expand=True) # Canvas fills the square wrapper


        # Status Bar (bottom)
        self.status_bar = ttk.Label(self, text="Status/Connection Info", style='BlackGlass.TStatus.Label')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Input Frame (above status bar)
        input_frame = ttk.Frame(self, style='BlackGlass.TFrame')
        input_frame.pack(padx=10, pady=(0, 10), fill=tk.X)
        
        self.message_entry = tk.Entry(input_frame, font=('Courier', 16), 
                                      bg='#2C2C2C', fg='#FFFFFF', 
                                      insertbackground='white', relief=tk.FLAT, highlightthickness=1, highlightbackground='#555555')
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message_event)
        
        self.send_button = ttk.Button(input_frame, text="Send", command=self.send_message, style='BlackGlass.TButton')
        self.send_button.pack(side=tk.RIGHT)
        
        # --- FIX: Set initial status to a generic placeholder. The login process will update it. ---
        self._update_status(f"Initialized.")
        # --- END FIX ---

    def _refresh_nearby_avatars(self):
        """Periodic loop to update the Nearby Avatars list."""
        if not getattr(self, "sl_agent", None) or not getattr(self.sl_agent, "client", None):
            self.after(1000, self._refresh_nearby_avatars)
            return

        tracked = self.sl_agent.client.tracked_avatars
        my_x, my_y, my_z = self.sl_agent.client.agent_x, self.sl_agent.client.agent_y, self.sl_agent.client.agent_z
        
        # Super-paranoid cleanup of own UUID and NULL UUID just in case it sneaked in
        own_uuid = str(self.sl_agent.client.agent_id).lower()
        null_uuid = "00000000-0000-0000-0000-000000000000"
        
        for k in list(tracked.keys()):
            if k.lower() == own_uuid or k == null_uuid:
                try: del tracked[k]
                except: pass
        
        # Prune old avatars
        now = time.time()
        to_remove = [k for k, v in tracked.items() if now - v["last_seen"] > 15.0]
        for k in to_remove:
            del tracked[k]
            
        display_list = []
        needs_name_fetch = []
        
        for uuid_str, data in tracked.items():
            # Update name if cached (normalized to lowercase)
            u_key = uuid_str.lower()
            current_cache_name = self.sl_agent.display_name_cache.get(u_key)
            if current_cache_name and current_cache_name != "Resolving...":
                data["name"] = current_cache_name
                
            if data["name"] == "Resolving...":
                needs_name_fetch.append(uuid_str)
                    
            # Calculate distance
            px, py, pz = data["pos"]
            dist = math.sqrt((my_x - px)**2 + (my_y - py)**2 + (my_z - pz)**2)
            data["distance"] = dist
            
            display_list.append((dist, f" {data['name']} ({dist:.1f}m)", uuid_str))
            # print(f"[DEBUG] Listing Avatar: {data['name']} (Dist: {dist:.1f}m) UUID: {uuid_str}")
        
        # Trigger UUID name fetch for unresolved avatars
        if needs_name_fetch:
            # Start a background task so we don't hold up UI thread
            # Filter ones we've been fetching for too long
            
            # Simple retry mechanism: Clear fetching cache every 15s to allow retries
            if not hasattr(self, '_last_fetch_clear'):
                self._last_fetch_clear = time.time()
            if time.time() - self._last_fetch_clear > 15.0:
                self.sl_agent.fetching_names.clear()
                self._last_fetch_clear = time.time()
                
            threading.Thread(target=self.sl_agent.request_uuid_name, args=(needs_name_fetch,), daemon=True).start()
            
        # Sort by distance (dist is index 0)
        display_list.sort(key=lambda x: x[0])
        
        # Update the listbox
        if hasattr(self, "nearby_avatars_list"):
            self.nearby_avatars_list.config(state='normal')
            self.nearby_avatars_list.delete(0, tk.END)
            self.nearby_avatars_uuids = [] # Reset UUID tracker
            
            for dist, item_str, uuid_str in display_list:
                self.nearby_avatars_list.insert(tk.END, item_str)
                self.nearby_avatars_uuids.append(uuid_str)
                
            if not display_list:
                self.nearby_avatars_list.insert(tk.END, "No avatars nearby.")
                
        # Loop
        self.after(1000, self._refresh_nearby_avatars)

    def _on_avatar_click(self, event):
        """Handles single-click on the avatar list to show a context menu."""
        # Note: We use after(10) to let the selection update first
        self.after(10, self._process_avatar_click, event)

    def _process_avatar_click(self, event):
        selection = self.nearby_avatars_list.curselection()
        if not selection:
            return
            
        idx = selection[0]
        if idx >= len(self.nearby_avatars_uuids):
            return
            
        target_uuid = self.nearby_avatars_uuids[idx]
        display_text = self.nearby_avatars_list.get(idx)
        # Extract name from the string " Name (Dist m)" and strip leading space
        target_name = display_text.split(" (")[0].strip()
        
        # Show Choice Dialog
        choice = ThemedChoiceDialog.askchoice(
            self.master, 
            "Avatar Actions", 
            f"Actions for {target_name}:", 
            ["Teleport to", "Profile"]
        )
        
        if choice == "Teleport to":
            # Lookup coordinates from tracked_avatars
            tracked = self.sl_agent.client.tracked_avatars
            if target_uuid in tracked:
                pos = tracked[target_uuid]["pos"]
                px, py, pz = pos
                # Use current region name for hard teleport
                region = self.sl_agent.current_region_name
                self.sl_agent.hard_teleport(region, px, py, pz)
            else:
                self._append_notification(f"[ERROR] Could not find coordinates for {target_name}.")
        
        elif choice == "Profile":
            self._append_notification(f"[INFO] Fetching profile for {target_name}...")
            
            # Open a 'Loading...' dialog immediately so the user sees something right away
            loading_data = {
                "id": target_uuid,
                "name": target_name,
                "about": "Loading profile...",
                "born": "...",
                "url": "",
                "image_id": "",
                "source": "loading"
            }
            self.update_ui("show_profile", loading_data)
            
            # Kick off the async profile fetch (will call update_ui('show_profile', ...) when done)
            self.sl_agent.request_avatar_properties(target_uuid)

    def _start_map_fetch_task(self, region_name):
        """Starts the map image download thread."""
        self._append_notification(f"[INFO] Requesting map tile for {region_name}...")
        # Clear old map immediately
        self.minimap.update_map_image(None) 
        self.sl_agent.fetch_map(region_name)

    def _handle_map_image_data(self, map_data):
        """Handles the image data received from the fetch thread, now using PIL."""
        if not PIL_AVAILABLE:
            self._append_notification("[FATAL] PIL/Pillow missing. Cannot display map image.")
            self.minimap.update_map_image(None) 
            return
            
        if map_data is None or len(map_data) < 1000: # Check is now > 1000 bytes
            self._append_notification("[WARN] Map tile unavailable or failed to load. (Network/Source error)")
            self.minimap.update_map_image(None) # Clear any previous map
            return

        try:
            # Open the image from bytes stream using PIL
            image = Image.open(BytesIO(map_data))
            
            # We no longer resize here; we pass the source image to the minimap canvas
            # which handles resizing effectively.
            
            self.minimap.set_map_image(image)
            # self._append_notification("[SUCCESS] Map tile loaded and displayed.")

            
        except ImportError:
            # Should not happen if Pillow is installed
            self._update_status("[FATAL] PIL/Pillow missing. Cannot display map image.")
            self.minimap.update_map_image(None) 
        except Exception as e:
            self._update_status(f"[ERROR] Failed to process map image data: {e}")
            self.minimap.update_map_image(None)

        
    def handle_debug_log_callback(self, message):
        """Processes the debug log message, checking for special minimap update triggers."""
        
        # --- FIX: Add HANDSHAKE_COMPLETE to the log handler ---
        if message.startswith("HANDSHAKE_COMPLETE"):
            _, region_name = message.split(", ", 1)
            region_name = region_name.strip()
            self.after(0, self._update_status, f"🟢 Successfully logged in to {region_name}!")
            self.after(0, self._append_notification, f"[INFO] Logged in to {region_name}. Requesting map...")
            
            # --- FIX: Trigger Map Fetch via UI method (clears old map first) ---
            # Wait 2 seconds to ensure coordinates are stable
            # Use _start_map_fetch_task to ensure we clear the old map visually first
            # REMOVED: Redundant map fetch. Now handled directly in RegionHandshake handler.
            # self.after(2000, lambda: self._start_map_fetch_task(region_name))
            
        # --- KICKED LOG HANDLER (NEW) ---
        elif message.startswith("KICKED"):
            _, reason = message.split(", ", 1)
            # Pass the kick reason to the status update
            self.after(0, self._update_status, f"🔴 Kicked: {reason.strip()}")
            self.after(0, self._set_disconnected_ui)
        # --- END KICKED LOG HANDLER ---
            
        elif message == "MINIMAP_UPDATE":
             # Use self.after to redraw safely from the main thread
             # REDUNDANT: MinimapCanvas already has a loop. Removing this prevents event queue flooding.
             pass 
             
        elif message.startswith("[CHAT]"):
            # Some old scripts might still be sending messages prefix with [CHAT]
            clean = message.replace("[CHAT]", "").strip()
            self.after(0, self._append_chat, clean)
            
        elif message.startswith("[SPY]"):
             # Ignore SPY packets in the UI entirely
             pass
             
        else:
             # SILENCED: No longer route generic debug messages to the notification area
             # Still pass on to the application's central debug handler for logging if needed
             self.tab_manager.handle_debug_log(message)


    def update_ui(self, update_type, message):
        """Thread-safe update of the GUI."""
        if update_type == "chat":
            if isinstance(message, (list, tuple)) and len(message) == 2:
                name, text = message
                self.after(0, self._append_chat, text, name)
            else:
                self.after(0, self._append_chat, message)
        elif update_type == "chat_ack":
            # message is the sequence number
            seq_id = message
            if seq_id in self.pending_chat:
                confirmed_msg = self.pending_chat.pop(seq_id)
                # Fetch self display name
                agent_id = self.sl_agent.client.agent_id if self.sl_agent.client else None
                from_name = f"{self.my_first_name} {self.my_last_name}"
                display_name = self.sl_agent.get_display_name(agent_id, from_name)
                
                # FIX: Avoid printing the same name twice
                if display_name and display_name != from_name:
                    name_label = f"{display_name} ({from_name})"
                    self.after(0, self.agent_name_label.config, {'text': f"Agent: {name_label}"})
                else:
                    name_label = from_name
                    
                self.after(0, self._append_chat, confirmed_msg, name_label)
        elif update_type == "status":
            # This is primarily used for connection/teleport status updates
            self.after(0, self._update_status, message)
        elif update_type == "notification": # NEW: Generic notification handler
            self.after(0, self._append_notification, message)
            
        elif update_type == "show_profile":
            # message is a dict with id, about, born, url, username, source
            uid = message.get("id")
            uid_key = str(uid).lower()
            name = self.sl_agent.display_name_cache.get(uid_key, "Unknown")
            message["name"] = name
            
            def _create_or_update():
                if uid_key in self.active_profiles:
                    # Update existing dialog
                    dialog = self.active_profiles[uid_key]
                    if dialog.winfo_exists():
                        dialog.update_data(message)
                    else:
                        # Re-create if it was closed
                        self.active_profiles[uid_key] = ThemedProfileDialog(self.master, message, self, uid_key)
                else:
                    # Create new dialog
                    self.active_profiles[uid_key] = ThemedProfileDialog(self.master, message, self, uid_key)
            
            self.after(0, _create_or_update)

        elif update_type == "error":
            # Use custom ThemedMessageBox for critical errors
            self.after(0, lambda: ThemedMessageBox(self.master, f"{self.my_first_name} Error", message, 'error'))
            self.after(0, self._update_status, f"Error: {message}")
            self.after(0, self._set_disconnected_ui) # Disable chat/send on error
        elif update_type == "teleport_offer":
            # Show teleport offer in main chat window instead of notification area
            alert_msg = f"--- TELEPORT OFFER RECEIVED TO {message['region']} ---"
            self.after(0, self._append_chat, alert_msg)
            self.after(0, self._show_teleport_offer, message)
        elif update_type == "map_fetch_request":
            # Handle map fetch request triggered by RegionClient
            self.after(0, lambda: self._start_map_fetch_task(message))
        elif update_type == "delayed_map_fetch":
            # NEWROBUSTMETHOD: Wait 2.5s then fetch map
            self.after(2500, lambda: self.sl_agent.fetch_map(message))
        elif update_type == "map_image_fetched":
            # Handle image data received from the fetch thread
            self.after(0, lambda: self._handle_map_image_data(message))
            
        elif update_type == "update_display_name":
            # Handle asynchronous display name update
            uid, dname = message
            self.after(0, lambda: self.update_display_name(uid, dname))
            
        elif update_type == "clear_map":
            # Clear the minimap image (e.g. on logout/teleport start)
            self.after(0, lambda: self.minimap.update_map_image(None))

    def update_display_name(self, uid, display_name):
        """Updates the UI when a display name is resolved."""
        # 0. Sync back to the agent's central cache so the Nearby List sees it
        uid_lower = str(uid).lower()
        self.sl_agent.display_name_cache[uid_lower] = display_name
        # Use Python's sys.stdout write with safe encoding to avoid the `self.log` missing attribute and Windows console print crash
        try:
            print(f"[DEBUG] update_display_name SET CACHE: {uid_lower} -> {display_name}")
        except UnicodeEncodeError:
            print(f"[DEBUG] update_display_name SET CACHE: {uid_lower} -> {display_name.encode('ascii', 'replace').decode('ascii')}")

        # 1. Update the top bar label if it's the current agent
        if self.sl_agent.client and str(self.sl_agent.client.agent_id) == str(uid):
            full_name = f"{self.my_first_name} {self.my_last_name}"
            clean_full_name = full_name.replace(" Resident", "")
            
            if display_name != full_name:
                self.agent_name_label.config(text=f"Agent: {display_name} ({clean_full_name})")
            else:
                self.agent_name_label.config(text=f"Agent: {clean_full_name}")
                
        # 2. (Future) Retroactive chat log updates could be implemented here if messages were tagged.


    def _append_chat(self, message, name=None):
        self.chat_display.config(state='normal')
        
        if name:
            self.chat_display.insert(tk.END, "[")
            self.chat_display.insert(tk.END, name, 'speaker_name')
            self.chat_display.insert(tk.END, "]: " + message + "\n")
        else:
            self.chat_display.insert(tk.END, message + "\n")
            
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END) 
                
    def _append_notification(self, message):
        # Redirect all generic notification appends to the chat window or status bar
        self._update_status(message) 
        
    def _update_status(self, message):
        self.status_bar.config(text=message, foreground='#FFFFFF') 
        
        if message.startswith("🟢 Successfully logged in"): 
            self.status_bar.config(foreground='#00FF00') 
        elif "Teleport finished" in message or "Waiting for confirmation" in message:
             self.status_bar.config(foreground='#00FFFF') 
        elif "Error" in message or "Teleport failed" in message:
             self.status_bar.config(foreground='#FF0000') 
        # MODIFIED: Removed auto-close logic, now using a dedicated function for visual feedback
        elif "Disconnected" in message or message.startswith("🔴 Kicked"):
             self._set_disconnected_ui()

    # --- NEW METHOD (Start) ---
    def _set_disconnected_ui(self):
        """Sets the UI to a disconnected state."""
        self.status_bar.config(foreground='#FF0000') 
        self.message_entry.config(state='disabled')
        self.send_button.config(state='disabled')
        # Change the Logout button to a Close Tab button
        self.logout_button.config(text="Close Tab", command=lambda: self.tab_manager.remove_tab(self.my_first_name, self)) 
    # --- NEW METHOD (End) ---

    # --- NEW METHOD: Missing log callback ---
            
    def _show_teleport_offer(self, offer_data):
        region_name = offer_data['region']
        cost = offer_data['cost']
        teleport_id = offer_data['id']
        
        dialog_text = f"You have received a teleport offer to: {region_name}"
        if cost > 0:
            dialog_text += f"\nThis teleport will cost L${cost}."
        
        self.sl_agent.log(f"Teleport offer received for {region_name} (Cost: L${cost}).")
        
        # MODIFIED: Use ThemedMessageBox instead of messagebox.askyesno
        dialog_result = ThemedMessageBox(self.master, "Teleport Offer Received", dialog_text, 'yesno').result
        
        if dialog_result:
            self.sl_agent.accept_teleport_offer(teleport_id, cost)
            self._update_status(f"✅ Accepting teleport to {region_name}...")
        else:
            self._update_status("Teleport offer declined.")
            self._append_notification(f"[INFO] Teleport offer to {region_name} declined.")

    def send_message_event(self, event):
        self.send_message()
        return "break"

    def send_message(self):
        message = self.message_entry.get().strip()
        if not message:
            return
            
        # --- COMMAND INTERCEPTION ---
        if message.lower().startswith("/hardtp ") or message.lower().startswith("/relog "):
            parts = message.split(' ', 1)
            if len(parts) > 1:
                region_name = parts[1].strip()
                self.sl_agent.hard_teleport(region_name)
                self.message_entry.delete(0, tk.END)
                return
            else:
                self._append_notification("[USAGE] /hardtp <region_name> or /relog <region_name>")
                self.message_entry.delete(0, tk.END)
                return
        # ----------------------------
        
        # sequence is returned from send_chat
        seq_id = self.sl_agent.send_chat(message)
        
        if seq_id:
            # Store it so we can echo it only when ACKed
            self.pending_chat[seq_id] = message
            
        self.message_entry.delete(0, tk.END)

    def do_teleport(self):
        # MODIFIED: Use ThemedAskString instead of simpledialog.askstring
        region_name = ThemedAskString.askstring(self.master, "Teleport", "Enter the name of the region to teleport to:")
        
        if region_name:
            # FIX: User requested Hard Teleport as the default for the button
            self.sl_agent.hard_teleport(region_name.strip())

    def on_closing(self):
        """Handles the user-initiated logout."""
        # Only prompt if the agent is still running
        if self.sl_agent.running:
            # MODIFIED: Use ThemedMessageBox instead of messagebox.askyesno
            dialog_result = ThemedMessageBox(self.master, "Logout", f"Are you sure you want to log out {self.my_first_name} and close this tab?", 'yesno').result
        else:
            # If the agent is not running (e.g., disconnected/kicked), just ask to close the tab.
            dialog_result = True 
        
        if dialog_result:
            # Tell the minimap loop to stop
            try:
                 self.minimap.after_cancel(self.minimap.draw_map)
            except:
                 pass # May already be stopped
            self.sl_agent.stop()
            self.tab_manager.remove_tab(self.my_first_name, self)
            
# ----------------------------------------------------------------------

class LoginPanel(ttk.Frame):
    """
    A single frame containing the login form and credential management logic.
    """
    def __init__(self, master, app_instance):
        super().__init__(master, style='BlackGlass.TFrame')
        self.app_instance = app_instance
        self.credentials = load_credentials()
        self._set_style(master)
        self._create_widgets()
        
    def _set_style(self, master):
        s = ttk.Style(self)
        
        # Dropdown style (TCombobox) 
        s.configure('BlackGlass.TCombobox', 
                    fieldbackground='#2C2C2C', 
                    foreground='#FFFFFF', 
                    selectbackground='#00FFFF',
                    selectforeground='#1C1C1C',
                    background='#1E1E1E',
                    bordercolor='#444444',
                    relief='flat')
        s.map('BlackGlass.TCombobox', 
              background=[('readonly', '#1E1E1E')],
              fieldbackground=[('readonly', '#2C2C2C')],
              foreground=[('readonly', '#FFFFFF')])

        # Style for the dropdown list items
        master.option_add('*TCombobox*Listbox.background', '#1C1C1C')
        master.option_add('*TCombobox*Listbox.foreground', '#FFFFFF')
        master.option_add('*TCombobox*Listbox.selectBackground', '#00FFFF')
        master.option_add('*TCombobox*Listbox.selectForeground', '#1C1C1C')
        
    def _create_widgets(self):
        content_frame = ttk.Frame(self, style='BlackGlass.TFrame', padding=20)
        content_frame.pack(padx=10, pady=10)

        content_frame.grid_columnconfigure(0, weight=0) 
        content_frame.grid_columnconfigure(1, weight=1)

        row = 0
        
        # 1. Saved Credentials Dropdown
        ttk.Label(content_frame, text="Saved Profile:", style='BlackGlass.TLabel', anchor='e').grid(row=row, column=0, sticky='e', pady=5, padx=5)
        
        self.profile_names = ["-- New Login --"] + [f"{c['first']} {c['last']} ({c['region']})" for c in self.credentials]
        self.selected_profile = tk.StringVar(value=self.profile_names[0])
        
        self.profile_dropdown = ttk.Combobox(content_frame, 
                                             textvariable=self.selected_profile, 
                                             values=self.profile_names, 
                                             state="readonly", 
                                             width=30,
                                             style='BlackGlass.TCombobox')
        self.profile_dropdown.grid(row=row, column=1, sticky='ew', pady=5)
        self.profile_dropdown.bind("<<ComboboxSelected>>", self._fill_credentials)
        row += 1
        
        ttk.Separator(content_frame, orient='horizontal').grid(row=row, column=0, columnspan=2, sticky='ew', pady=(10, 10))
        row += 1
        
        # 2. Input Fields
        ttk.Label(content_frame, text="First Name:", style='BlackGlass.TLabel', anchor='e').grid(row=row, column=0, sticky='e', pady=5, padx=5)
        self.first_name_entry = tk.Entry(content_frame, width=25, bg='#2C2C2C', fg='#FFFFFF', insertbackground='white', relief=tk.FLAT)
        self.first_name_entry.grid(row=row, column=1, sticky='ew', pady=5)
        row += 1
        
        ttk.Label(content_frame, text="Last Name:", style='BlackGlass.TLabel', anchor='e').grid(row=row, column=0, sticky='e', pady=5, padx=5)
        self.last_name_entry = tk.Entry(content_frame, width=25, bg='#2C2C2C', fg='#FFFFFF', insertbackground='white', relief=tk.FLAT)
        self.last_name_entry.grid(row=row, column=1, sticky='ew', pady=5)
        row += 1
        
        ttk.Label(content_frame, text="Password:", style='BlackGlass.TLabel', anchor='e').grid(row=row, column=0, sticky='e', pady=5, padx=5)
        self.password_entry = tk.Entry(content_frame, show='*', width=25, bg='#2C2C2C', fg='#FFFFFF', insertbackground='white', relief=tk.FLAT)
        self.password_entry.grid(row=row, column=1, sticky='ew', pady=5)
        row += 1

        ttk.Label(content_frame, text="Start Region:", style='BlackGlass.TLabel', anchor='e').grid(row=row, column=0, sticky='e', pady=5, padx=5)
        self.region_entry = tk.Entry(content_frame, width=25, bg='#2C2C2C', fg='#FFFFFF', insertbackground='white', relief=tk.FLAT)
        self.region_entry.insert(0, "last") # Default is now "last"
        self.region_entry.grid(row=row, column=1, sticky='ew', pady=5)
        row += 1
        
        # 4. Login Button (Now at row 5)
        self.login_button = ttk.Button(content_frame, text="Login", command=self.start_login, width=15, style='BlackGlass.TButton')
        self.login_button.grid(row=row, column=0, columnspan=2, pady=(15, 10)) 
        row += 1
        
        # 5. Status and Progress 
        self.progress_bar = ttk.Progressbar(content_frame, orient='horizontal', length=180, mode='determinate', style='BlackGlass.TProgressbar')
        self.progress_bar.grid(row=row, column=0, columnspan=2, pady=5) 
        self.progress_bar['value'] = 0 
        row += 1

        self.status_label = ttk.Label(content_frame, text="Enter credentials or select a profile.", style='BlackGlass.TStatus.Label')
        self.status_label.grid(row=row, column=0, columnspan=2, pady=(5, 0))
        
        # Note: Removed default filling of the first saved profile to ensure a blank slate.

    def reset_fields(self):
        """Resets all input fields, profile selection, and UI state after a login."""
        self.first_name_entry.delete(0, tk.END)
        self.last_name_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.region_entry.delete(0, tk.END)
        
        # Set defaults
        self.region_entry.insert(0, "last") # Reset to "last"
        
        # Reload and reset dropdown to the first option ("-- New Login --")
        self.update_dropdown_data()
        self.selected_profile.set(self.profile_names[0])
        
        # Reset UI controls
        self.login_button.config(state=tk.NORMAL, text="Login")
        self.progress_bar.config(value=0)
        # Reset status text and color to initial state
        self.status_label.config(text="Enter credentials or select a profile.", foreground='grey')

    # --- NEW METHOD (Start) ---
    def update_dropdown_data(self):
        """Loads credentials and refreshes the dropdown without destroying the panel."""
        self.credentials = load_credentials()
        self.profile_names = ["-- New Login --"] + [f"{c['first']} {c['last']} ({c['region']})" for c in self.credentials]
        
        # Reconfigure the combobox with new values
        self.profile_dropdown.config(values=self.profile_names)
        
        # If the currently selected text is no longer valid, default back to 'New Login'.
        if self.selected_profile.get() not in self.profile_names:
            self.selected_profile.set(self.profile_names[0])
    # --- NEW METHOD (End) ---


    def _fill_credentials(self, event=None):
        """Fills entry fields based on the selected profile."""
        selection_index = self.profile_dropdown.current()
        
        # Clear fields first
        self.first_name_entry.delete(0, tk.END)
        self.last_name_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.region_entry.delete(0, tk.END)
        
        # Re-insert default region or load profile data
        self.region_entry.insert(0, "last") # Default insert is "last"
        self.status_label.config(text="Enter credentials or select a profile.", foreground='grey')

        if selection_index > 0:
            creds = self.credentials[selection_index - 1]
            
            self.first_name_entry.insert(0, creds['first'])
            self.last_name_entry.insert(0, creds['last'])
            self.password_entry.insert(0, creds['password'])
            self.region_entry.delete(0, tk.END)
            self.region_entry.insert(0, creds['region'])

    # --- MODIFIED METHOD (Start) ---
    def start_login(self, event=None):
        # Guard against double submission if the button is already disabled (login in progress)
        if self.login_button['state'] == tk.DISABLED:
            return

        first = self.first_name_entry.get().strip()
        last = self.last_name_entry.get().strip()
        password = self.password_entry.get()
        raw_region_name = self.region_entry.get().strip()
        
        if not first or not last or not password:
            self.app_instance.after(0, self.status_label.config, {'text': "All fields are required.", 'foreground': '#FF0000'})
            return

        # UI state change
        self.login_button.config(state=tk.DISABLED, text="Connecting...")
        self.status_label.config(text="Attempting login...", foreground="#00FFFF")
        self.progress_bar['value'] = 0 
        
        # Auto-save credentials (as requested)
        save_credentials({'first': first, 'last': last, 'password': password, 'region': raw_region_name})
        
        # Update the dropdown list data without destroying the panel/entries
        self.update_dropdown_data()
             
        # Format region string: 'home'/'last' are passed raw. Others are formatted as a URI for the login server.
        if raw_region_name.lower() in ("home", "last"):
             formatted_region_name = raw_region_name.lower()
        else:
             # Use URI format for actual region names
             encoded_region_name = urllib.parse.quote(raw_region_name)
             
             # FIX: Use ampersands '&' instead of slashes '/' as separators for the region URI.
             formatted_region_name = f"uri:{encoded_region_name}&128&128&30" 
             
        self.login_thread = threading.Thread(target=self.app_instance.login_task, 
                                             args=(first, last, password, formatted_region_name), 
                                             daemon=True)
        self.login_thread.start()
    # --- MODIFIED METHOD (End) ---

# ----------------------------------------------------------------------

class MultiClientApp(tk.Tk):
    """
    The main application window, now hosting a tabbed interface.
    """
    def __init__(self):
        super().__init__()
        self.title("Black Glass")
        self.geometry("800x650") 
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.resizable(True, True)
        self.eval('tk::PlaceWindow . center')
        
        # Global Enter Key Binding
        self.bind("<Return>", self.handle_global_return)

        self.active_agents = {} 
        self.login_panel = None # Will hold the instance of LoginPanel
        
        # --- Application Icon ---
        try:
             icon_path = "BlackGlass.ico"
             if os.path.exists(icon_path):
                 self.iconbitmap(default=icon_path)
             else:
                 print("Warning: BlackGlass.ico not found. Using default icon.")
        except Exception as e:
             print(f"Warning: Failed to set application icon: {e}")

        self._set_style()
        self._create_widgets()

    def _set_style(self):
        self.configure(bg='#0A0A0A') 
        s = ttk.Style(self)
        s.theme_use('clam')
        
        # Black Glass Frame/Background
        s.configure('BlackGlass.TFrame', background='#0A0A0A')
        
        # Black Glass Labels
        s.configure('BlackGlass.TLabel', background='#0A0A0A', foreground='#F0F0F0', font=('Helvetica', 10))
        
        # Sleek Button
        s.configure('BlackGlass.TButton', background='#1E1E1E', foreground='#00FFFF', relief='flat', borderwidth=0, font=('Helvetica', 12, 'bold'))
        s.map('BlackGlass.TButton', background=[('active', '#333333'), ('pressed', '#000000')], foreground=[('active', '#FFFFFF')])
        
        # Progressbar (Fix)
        s.configure('BlackGlass.TProgressbar', 
                    background='#00FFFF',          
                    troughcolor='#1C1C1C',         
                    bordercolor='#444444',         
                    thickness=10                   
                   )
        s.layout('BlackGlass.TProgressbar', 
                 [('Horizontal.Progressbar.trough', 
                   {'children': 
                    [('Horizontal.Progressbar.pbar', 
                      {'side': 'left', 'sticky': 'ns'})], 
                    'sticky': 'ew'})])

        # Notebook (Tab) style - Black Glass
        s.configure('BlackGlass.TNotebook', background='#0A0A0A', borderwidth=0)
        s.configure('BlackGlass.TNotebook.Tab', 
                    background='#1E1E1E',        # Background of unselected tabs
                    foreground='#FFFFFF',        # Text of unselected tabs
                    padding=[10, 5],
                    font=('Helvetica', 10, 'bold'))
        s.map('BlackGlass.TNotebook.Tab', 
              background=[('selected', '#0A0A0A')], 
              foreground=[('selected', '#00FFFF')]  
             )
        
        # Status Label
        s.configure('BlackGlass.TStatus.Label', background='#0A0A0A', foreground='grey', anchor='center')

    def _create_widgets(self):
        # Create the notebook and set it up
        self.notebook = ttk.Notebook(self, style='BlackGlass.TNotebook')
        self.notebook.pack(pady=10, padx=10, expand=True, fill='both')

        # Add the initial login panel tab
        self.login_panel = LoginPanel(self.notebook, self)
        self.notebook.add(self.login_panel, text="➕ New Login")




    def login_task(self, first, last, password, region_name):
        """
        Runs in a thread, attempts login, and calls back to the UI thread.
        login_panel_instance is the stale object, all resets must use self.login_panel.
        """
        agent = SecondLifeAgent(self.handle_agent_update, debug_callback=self.handle_debug_log)
        
        try:
            agent.login(first, last, password, region_name)
            
            # Login successful: Callback to the UI thread to add the chat tab
            # FIX: Only pass agent info. Use self.login_panel for UI updates.
            self.after(0, self._add_chat_tab, agent, first, last)
                
        except Exception as e:
            # Login failed: Use after to safely update the UI components from the main thread
            error_message = str(e)
            
            # FIX: Use self.login_panel and schedule reset after a small delay.
            if self.login_panel:
                self.after(0, self.login_panel.status_label.config, {'text': f"Error: {error_message}", 'foreground': '#FF0000'})
                # Schedule the final reset command to run after any pending updates
                self.after(50, self.login_panel.reset_fields) 
            
            agent.stop() # Ensure the failed agent is stopped

    def _add_chat_tab(self, agent, first, last):
        """Adds a new ChatTab to the notebook upon successful initial login."""
        full_name = f"{first} {last}"
        
        current_login_panel = self.login_panel # Get the current instance
        
        if full_name in self.active_agents:
            # MODIFIED: Use ThemedMessageBox instead of messagebox.showwarning
            ThemedMessageBox(self, "Already Logged In", f"Agent {full_name} is already logged in on another tab.", 'warning')
            agent.stop() 
            if current_login_panel:
                # FIX: Schedule reset_fields for clean state
                self.after(50, current_login_panel.reset_fields) 
            return
            
        # 1. Create the new tab and give it the agent's name
        chat_tab = ChatTab(self.notebook, agent, first, last, self)
        tab_name = f"{first} {last}"
        
        # 2. Add to notebook and select it
        self.notebook.add(chat_tab, text=tab_name)
        self.notebook.select(chat_tab)
        
        # 3. Store the active agent
        self.active_agents[full_name] = chat_tab
        
        # 4. Reset the Login Panel fields and UI state (progress bar and status)
        if current_login_panel:
            # FIX: Schedule reset_fields for clean state
            self.after(50, current_login_panel.reset_fields)


    def remove_tab(self, first_name, chat_tab_instance):
        """Stops the agent and removes the corresponding tab."""
        full_name = f"{first_name} {chat_tab_instance.my_last_name}"
        
        if full_name in self.active_agents:
            # The agent is already stopped by the ChatTab.on_closing logic, 
            # but ensure it's removed from the dictionary.
            del self.active_agents[full_name]
            self.notebook.forget(chat_tab_instance)
            
            # Select the "New Login" tab if it exists
            if self.notebook.index('end') > 0:
                self.notebook.select(0)

    # --- Communication Handlers ---
    def handle_debug_log(self, message):
        """Central debug log handler."""
        pass 

    def handle_agent_update(self, update_type, message):
        """
        Central update handler. Directs progress updates to the LoginPanel.
        All other updates are handled by the agent's assigned ChatTab.
        """
        if update_type == "progress":
            # Only update the login panel's progress bar (index 0)
            self.after(0, self._update_login_progress, message)
        # All other updates (chat, status, teleport_offer, map_fetch_request, map_image_fetched) 
        # are handled by the specific ChatTab via its own callbacks.

    def _update_login_progress(self, message):
        """Updates the progress bar in the LoginPanel safely."""
        if self.login_panel:
            step, value = message
            self.login_panel.progress_bar.config(value=value)
            
            # Only update the status text if it's NOT the final successful message
            if value < 100:
                 self.login_panel.status_label.config(text=f"Login Step: {step}", foreground='#00FFFF')
            
    def on_closing(self):
        """Handles closing the main window by logging out all agents."""
        # FIX: If the window is minimized, restore it so the dialog can be seen.
        if self.state() == 'iconic':
            self.deiconify()
            self.update()

        # If no agents are logged in, close immediately without prompting
        if not self.active_agents:
            self.destroy()
            return

        # MODIFIED: Use ThemedMessageBox instead of messagebox.askyesno
        dialog_result = ThemedMessageBox(self, "Quit", "Are you sure you want to log out all agents and exit?", 'yesno', topmost=True).result
        
        if dialog_result:
            for agent in list(self.active_agents.values()):
                agent.sl_agent.stop()
            self.destroy()

    def handle_global_return(self, event):
        """
        Handles the Enter key globally. 
        If the current tab is the LoginPanel, trigger the login.
        """
        try:
            # Check if active tab is the LoginPanel
            # self.notebook.select() returns the widget name (path) of the selected tab
            current_tab_id = self.notebook.select()
            
            # self.login_panel is the actual widget object. str(self.login_panel) gives its path.
            if self.login_panel and current_tab_id == str(self.login_panel):
                 # Call start_login on the LoginPanel
                 self.login_panel.start_login()
        except Exception:
            # In case of any weird focusing or widget state issues, just ignore
            pass


if __name__ == "__main__":
    # Ensure the credentials file exists
    if not os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'w') as f:
                f.write('[]')
        except:
            print(f"Warning: Could not create {CREDENTIALS_FILE}. Credentials will not be saved.")
            
    app = MultiClientApp()
    app.mainloop()
