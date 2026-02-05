import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, Toplevel
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
import ssl
from uuid import UUID, getnode as get_mac
from tkinter import ttk 
import json
import os
import base64
import math
import urllib.request
import urllib.parse 
from io import BytesIO

# --- PIL/Pillow Import ---
try:
    from PIL import Image, ImageTk, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Warning: Pillow (PIL) not found. Map tiles will display a colored placeholder.")
# --- End PIL Import ---


# ==========================================
# SECTION 1: CORE TYPES (llTypes.py)
# ==========================================
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

rotation = quaternion

class color4U:
    r = 0; g = 0; b = 0; a = 0
    def __init__(self, r=0, g=0, b=0, a=0):
        self.r = r; self.g = g; self.b = b; self.a = a
    def __bytes__(self):
        return struct.pack("<BBBB", self.r, self.g, self.b, self.a)

class LLUUID:
    UUID = __uuid__.UUID("00000000-0000-0000-0000-000000000000")
    def __init__(self, key = "00000000-0000-0000-0000-000000000000"):
        if type(key) == bytes:
            if len(key) == 16:
                self.UUID = __uuid__.UUID(bytes=key)
        elif type(key) == str:
            self.UUID = __uuid__.UUID(key)
        elif isinstance(key, __uuid__.UUID):
            self.UUID = key
    def __bytes__(self):
        return self.UUID.bytes
    def __str__(self):
        return str(self.UUID)
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
        flags, seq, exlen = struct.unpack_from(">BIB", data, 0)
        mid = struct.unpack_from(">I", data, 6+exlen)[0]
        return "%s\nMID:%s\n%s"%(a, mid, ("-"*79)+"\n"+hexdump(data)+"\n"+("-"*79))
    except:
        return "%s\n%s"%(a, ("-"*79)+"\n"+hexdump(data)+"\n"+("-"*79))


class Constraints:
    def __init__(self):
        # Only essential ones for this script's functionality are defined here for brevity
        self.CHAT_NORMAL = 1
        # NEW CHAT CONSTANTS FOR FILTERING
        self.CHAT_START_TYPING = 39 
        self.CHAT_STOP_TYPING = 40
        
        # New/Expanded Movement Control Flags (U32)
        # These are used in the AgentUpdate packet's ControlFlags field
        self.AGENT_CONTROL_AT_POS = 0x01   # Forward (W, Arrow Up)
        self.AGENT_CONTROL_AT_NEG = 0x02   # Backward (S, Arrow Down)
        self.AGENT_CONTROL_LEFT_POS = 0x04 # Left (A, Arrow Left)
        self.AGENT_CONTROL_RIGHT_POS = 0x08# Right (D, Arrow Right)
        self.AGENT_CONTROL_UP_POS = 0x10   # Up (E, PageUp)
        self.AGENT_CONTROL_UP_NEG = 0x20   # Down (C, PageDown)
        self.AGENT_CONTROL_LBUTTON = 0x40
        self.AGENT_CONTROL_MLBUTTON = 0x80
        self.AGENT_CONTROL_JUMP = 0x100    # Jump (Space)
        self.AGENT_CONTROL_FLY = 0x200     # Fly/Ground Toggle (F)
        self.AGENT_CONTROL_MOUSELOOK = 0x400 # Mouselook Toggle
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
        "start": start, # This is the critical parameter
        "channel": "SLViewer_Py", 
        "version": "Python "+sys.version,
        "platform": __PLATFORM_STRING__,
        "mac": mac,
        "id0": hashlib.md5(("%s:%s:%s"%(__PLATFORM_STRING__,mac,sys.version)).encode("latin")).hexdigest(),
        "agree_to_tos": True,
        "last_exec_event": 0,
        "options": ["inventory-root", "buddy-list", "login-flags", "global-textures"]
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
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID"), ("TeleportFlags", "U32")],
        "Info": [("RegionHandle", "U64"), ("Position", "LLVector3"), ("LookAt", "LLVector3")]
    }
registerMessage(TeleportLocationRequest)

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

# --- Object/Self Position Update Messages (For Minimap) ---

class CoarseLocationUpdate(BaseMessage):
    name = "CoarseLocationUpdate"; id = 234; freq = 2; trusted = True; zero_coded = True
    blocks = [("Location", 0), ("Index", 1), ("AgentData", 0)]
    structure = {
        "Location": [("X", "U8"), ("Y", "U8"), ("Z", "U8")],
        "Index": [("You", "S16"), ("PreYou", "S16")],
        "AgentData": [("AgentID", "LLUUID")]
    }
registerMessage(CoarseLocationUpdate)

class ObjectUpdate(BaseMessage):
    name = "ObjectUpdate"; id = 4294967295; freq = 3; trusted = True; zero_coded = True
    blocks = [("RegionData", 1), ("ObjectData", 0)]
    structure = {
        "RegionData": [("RegionHandle", "U64"), ("TimeDilation", "U16")],
        "ObjectData": [
            ("ID", "U32"), ("State", "U8"), ("FullID", "LLUUID"), ("CRC", "U32"),
            ("PCode", "U8"), ("Material", "U8"), ("ClickAction", "U8"), ("Scale", "LLVector3"),
            ("ObjectData", "Variable", 1), ("ParentID", "U32"), ("UpdateFlags", "U32"),
            ("Data", "Variable", 1)
        ]
    }
registerMessage(ObjectUpdate)

class ImprovedTerseObjectUpdate(BaseMessage):
    name = "ImprovedTerseObjectUpdate"; id = 4294967292; freq = 3; trusted = False; zero_coded = True
    blocks = [("RegionData", 1), ("ObjectData", 0)]
    structure = {
        "RegionData": [("RegionHandle", "U64"), ("TimeDilation", "U16"), ("TimeSinceLastUpdate", "U16")],
        "ObjectData": [
            ("ID", "U32"), 
            ("CRC", "U32"),
            ("Data", "Fixed", 46) # Variable length data block containing position/rotation/etc.
        ]
    }
registerMessage(ImprovedTerseObjectUpdate)

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
            self.body = getMessageByID(realID, self.bytes[offset:])
            if not self.body: 
                self.body = type('UnknownMessage', (object,), {'name': 'Unknown'})()

            if self.ack:
                try:
                    ackcount = data[len(data)-1]
                    ack_offset = len(data) - (ackcount * 4) - 1
                    for i in range(ackcount):
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
        self.flags = 0
        body = bytes(self.body)
        
        # 1. Zero-coding
        if self.zero_coded:
            tmp = zerocode_encode(body)
            # FIX: The check here should compare encoded length to original body length
            if len(tmp) >= len(body):
                self.zero_coded = False; self.flags &= ~0x80 # Don't zero-code if it makes it larger
                # Re-encode body without zero-coding
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
            # Only pack the count if there are actual ACKs
            if len(self.acks) > 0:
                acks_bytes += struct.pack(">B", len(self.acks)) # Corrected to B (U8) for the count
            else:
                self.flags &= ~0x10 # Clear the ACK flag if no ACKs were packed
                acks_bytes = b""
        
        # 4. Message ID (MID)
        result = b""
        if self.body.freq == 3: result = struct.pack(">I", self.MID)
        elif self.body.freq == 2: result = struct.pack(">I", self.MID + 0xFFFF0000)
        elif self.body.freq == 1: result = struct.pack(">H", self.MID + 0xFF00)
        elif self.body.freq == 0: result = struct.pack(">B", self.MID)
        
        # 5. Full Packet Assembly
        return struct.pack(">BIB", self.flags, self.sequence, len(self.extra)) + self.extra + result + body + acks_bytes

# ==========================================
# SECTION 6: NETWORK LAYER (UDPStream.py as RegionClient)
# ==========================================

class RegionClient:
    host = ""; port = 0; clientPort = 0; sock = None
    agent_id = None; session_id = None; loginToken = {}
    nextPing = 0; nextAck = 0; nextAgentUpdate = 0
    sequence = 1; acks = []
    circuit_code = None; debug = False
    
    # Existing control variables (now updated by the Agent via methods)
    controls = 0; controls_once = 0 
    
    sim = {}
    log_callback = None
    
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
    agent_rot_z = 0.0 # yaw only for minimap (radians)
    
    # NEW: Global Grid Coordinates for Map Fetching
    grid_x = 1000
    grid_y = 1000
    local_id = 0 # NEW: Store the simulator-assigned LocalID for the agent

    # NEW: List to store positions of other avatars [(x, y, z), ...]
    other_avatars = []

    # MODIFIED: Added log_callback to constructor
    def __init__(self, loginToken, host="0.0.0.0", port=0, debug=False, log_callback=None):
        self.debug = debug
        self.log_callback = log_callback if log_callback is not None else lambda msg: None
        self.other_avatars = [] # Initialize list
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

        # Extract initial region grid coordinates (in meters) and convert to tile coordinates
        # Default is Da Boom (1000, 1000) if missing
        
        # DEBUG: Dump token keys to check for region_x/y existence
        self.log_callback(f"[CHAT] Login Token Keys: {list(loginToken.keys())}")
        
        try:
            val_x = loginToken.get("region_x", 0)
            val_y = loginToken.get("region_y", 0)
            self.log_callback(f"[CHAT] Token Raw X: {val_x} ({type(val_x)}), Y: {val_y} ({type(val_y)})")
            
            r_x = int(float(val_x))
            r_y = int(float(val_y))
        except Exception as e:
            self.log_callback(f"[CHAT] Coord Parse Error: {e}")
            r_x = 0; r_y = 0
            
        if r_x > 0 and r_y > 0:
            self.grid_x = r_x // 256
            self.grid_y = r_y // 256
        else:
            # If coordinates are missing, we default to 1000, 1000 but log a warning
            self.log_callback("[CHAT] Warning: Region coordinates missing/invalid. Defaulting to (1000, 1000).")
            self.grid_x = 1000
            self.grid_y = 1000
            
        self.log_callback(f"[CHAT] Using Grid Coords: {self.grid_x}, {self.grid_y}")
        
        
        self.last_circuit_send = 0 # Forces an immediate send on first loop iteration

    @property
    def seq(self):
        self.sequence += 1
        return self.sequence - 1
    
    def log(self, message):
        """Helper function to route messages via the callback."""
        if self.debug:
            self.log_callback(f"DEBUG: {message}")
    
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

    # MODIFIED: Logic moved to _teleport_lookup_task, this is just a stub for Agent usage
    def teleport_to_region(self, region_name, region_handle, position):
        """Sends the final TeleportLocationRequest packet."""
        
        msg = getMessageByName("TeleportLocationRequest")
        
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        msg.AgentData["TeleportFlags"] = 0 

        msg.Info["RegionHandle"] = region_handle
        msg.Info["Position"] = position
        msg.Info["LookAt"] = vector3(0.0, 1.0, 0.0)

        # IMPORTANT: TeleportLocationRequest should be reliable and acknowledged
        self.send(msg, reliable=True)
        self.log(f"Sent TeleportLocationRequest to handle {region_handle}")
        return True

    # MODIFIED: Logic added to trigger MAP_FETCH_TRIGGER on RegionHandshake
    def handleInternalPackets(self, pck):
        if not hasattr(pck.body, 'name'): return
        
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
                # FIX: Blocks are dictionaries, use .get()
                full_id = block.get('FullID')
                if full_id == self.agent_id:
                    self.local_id = block["ID"]
                    self.log_callback(f"[CHAT] Agent LocalID Captured: {self.local_id}")
                    break

        elif pck.body.name == "ImprovedTerseObjectUpdate":
            for block in pck.body.ObjectData:
                # Match against the captured LocalID or heuristic
                is_me = False
                if self.local_id != 0:
                    is_me = (block["ID"] == self.local_id)
                else:
                    is_me = (block["ID"] == struct.unpack("<I", self.agent_id.bytes[:4])[0])
                
                if is_me:
                    data = block["Data"].data 
                    
                    if len(data) >= 12:
                        try:
                            # Standard Avatar Interpretation (Offset 1, 12 bytes float)
                            if len(data) >= 13:
                                px, py, pz = struct.unpack("<fff", data[1:13])
                                
                                # Process rotation if 12 bytes available after position (offset 13 + 12 = 25)
                                if len(data) >= 25:
                                    # Rotation is typically packed; for now, let's just log it if we can
                                    # Radian yaw is often at a specific offset in terse updates
                                    pass

                                # Normalizing: if values are > 256, they are likely global.
                                # Region local is always 0.0-256.0.
                                if px > 256: px %= 256
                                if py > 256: py %= 256
                                
                                self.agent_x, self.agent_y, self.agent_z = px, py, pz
                                self.log_callback(f"[CHAT] Own Pos: {px:.1f}, {py:.1f}, {pz:.1f}")
                                self.log_callback("MINIMAP_UPDATE")
                            else:
                                # Compressed Interpretation (Offset 0, 4 bytes U16)
                                px_raw, py_raw = struct.unpack("<HH", data[0:4])
                                px, py = px_raw / 256.0, py_raw / 256.0
                                self.agent_x, self.agent_y = px, py
                                self.log_callback(f"[CHAT] Own Pos (comp): {px:.1f}, {py:.1f}")
                                self.log_callback("MINIMAP_UPDATE")
                        except Exception as e:
                            self.log_callback(f"[CHAT] Failed to parse position: {e}")
                    break
        
        elif pck.body.name == "CoarseLocationUpdate":
            # Handle other avatars for minimap
            new_avatars = []
            
            # The simulator sends a 'Location' block and an optional 'Index' block
            # Index["You"] tells us where we are in the list.
            locations = getattr(pck.body, 'Location', [])
            you_index = -1
            if hasattr(pck.body, 'Index') and len(pck.body.Index) > 0:
                you_index = pck.body.Index[0].get('You', -1)
            
            for i, loc in enumerate(locations):
                if i == you_index:
                    continue # Skip self, we use terse updates for high precision
                
                # Coarse coords are U8 (0-255)
                new_avatars.append((loc['X'], loc['Y'], loc['Z']))
                
            self.other_avatars = new_avatars
            # Only log if there are actually avatars to avoid spam
            if len(self.other_avatars) > 0:
                self.log_callback(f"[CHAT] Received {len(self.other_avatars)} avatar dots.")
            self.log_callback("MINIMAP_UPDATE")

        elif pck.body.name == "StartPingCheck":
            msg = getMessageByName("CompletePingCheck")
            msg.PingID["PingID"] = pck.body.PingID["PingID"]
            self.send(msg)
            
        elif pck.body.name == "RegionHandshake":
            self.handshake_complete = True # Signal that Handshake is done!
            self.sim['name'] = str(pck.body.RegionInfo["SimName"])
            
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
            
            # --- MAP FETCH TRIGGER ---
            # Trigger map fetch whenever a RegionHandshake is successfully processed.
            if PIL_AVAILABLE: 
                self.log_callback("MAP_FETCH_TRIGGER", self.sim['name'])
            # --- END MAP FETCH TRIGGER ---
            
            # --- FIX: Send the successful login status to the UI ---
            self.log_callback("HANDSHAKE_COMPLETE", self.sim['name'])
            # --- END FIX ---
            
        # --- KICKUSER HANDLING (NEW) ---
        elif pck.body.name == "KickUser":
            reason = safe_decode_llvariable(pck.body.TargetBlock.get('Reason', 'Unknown reason from sim.'))
            self.log_callback("KICKED", reason)
        # --- END KICKUSER HANDLING ---

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
            # If a Message object is passed, wrap it in a Packet
            
            # Determine reliability from argument or message property
            if reliable or getattr(blob, 'trusted', False): 
                 reliable = True
                 
            # Piggyback any accumulated ACKs on this packet
            acks_to_send = self.acks[:255]
            if acks_to_send:
                self.acks = self.acks[255:]
                self.nextAck = time.time() + 1
            
            # Create the packet
            blob = Packet(sequence=self.seq, message=blob, acks=acks_to_send, ack=bool(acks_to_send), reliable=reliable)

        # NEW: Track outgoing reliable packets
        # Do not track handshake packets here, they are tracked separately for initial connection
        if blob.reliable and blob.sequence not in [self.circuit_sequence, self.cam_sequence]:
            # Store the full packet object and the time it was last sent
            self.reliable_packets[blob.sequence] = (blob, time.time())
            
        try:
            # If blob is a Packet (like self.circuit_packet or self.cam_packet), it is sent as-is.
            self.sock.sendto(bytes(blob), (self.host, self.port))
            return blob.sequence
        except Exception as e: 
            if self.debug: self.log_callback(f"ERROR: Send error: {e}")
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
        
        # We send the message object, letting self.send handle sequence and ACKs
        self.send(msg, reliable=reliable)
        self.last_update_send = time.time()
        
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
        self.current_position = ""
        
        # Connection credentials
        self.agent_id = None
        self.session_id = None
        self.circuit_code = None
        self.sim_ip = None
        self.sim_port = None
        self.raw_socket = None
        self.first_name = "" 
        self.connection_start_time = 0 
        self.login_step = 0

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
                self.ui_callback("progress", ("RegionHandshake Received", 100))
                
                # REMOVED: Triggering map fetch here is race-prone. 
                # It is now handled in ChatTab.__init__ to ensure UI readiness.
                    
            # --- KICKED LOG HANDLER (NEW) ---
            elif message.startswith("KICKED"):
                _, reason = message.split(", ", 1)
                self.ui_callback("status", f"🔴 Kicked: {reason.strip()}")
                self.running = False # Stop the event loop upon kick
                
            # --- CHAT ACK HANDLER ---
            elif message.startswith("ACK_CONFIRMED:"):
                _, seq_id = message.split(": ", 1)
                self.ui_callback("chat_ack", int(seq_id.strip()))
                
            else:
                self.debug_callback(message)

    # ... (rest of class) ...

    # MODIFIED: Worker thread target for map image fetching - CLEANED
    def _fetch_map_image_task(self, region_name):
        try:
            # Current grid coordinates
            gx = self.client.grid_x
            gy = self.client.grid_y
            
            # Use the proven URL format directly
            url = f"https://map.secondlife.com/map-1-{gx}-{gy}-objects.jpg"
            
            # Proven headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Proven SSL Context
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            request = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(request, timeout=15, context=ctx) as response:
                if response.getcode() == 200:
                    map_data = response.read()
                    
                    if len(map_data) > 2000:
                        self.ui_callback("map_image_fetched", map_data)
                    else:
                        print(f"Map data too small: {len(map_data)}")
                else:
                    print(f"Map HTTP Error: {response.getcode()}")

        except Exception as e:
            # Catch ANY crash in the thread
            error_msg = f"{type(e).__name__}: {e}"
            print(f"MAP THREAD CRASH: {error_msg}")
            self.ui_callback("status", f"⚠️ Map Error: {error_msg}")
            self.ui_callback("map_image_fetched", None)
            
    def fetch_map(self, region_name):
        """Public entry point for fetching the map image."""
        if not PIL_AVAILABLE:
            self.ui_callback("chat", "--- Map Debug: PIL NOT INSTALLED/DETECTED ---")
            self.ui_callback("map_image_fetched", None) 
            return
        
        if not self.running:
            return
            
        threading.Thread(target=self._fetch_map_image_task, args=(region_name,), daemon=True).start()

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
                    self.current_position = "Landed"
                    
                    # The success message is now handled inside self.log via the HANDSHAKE_COMPLETE trigger
                    
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

                        # 1. Filter empty messages
                        if not msg_text:
                            self.log(f"Filtered empty chat message from {from_name}.")
                            continue

                        # 2. Filter typing indicators (39: Start Typing, 40: Stop Typing)
                        if chat_type in (const.CHAT_START_TYPING, const.CHAT_STOP_TYPING):
                            self.log(f"Filtered typing indicator (Type: {chat_type}) from {from_name}.")
                            continue
                        
                        # 3. Filter own messages (already displayed when ACK'd)
                        if source_id and source_id == self.client.agent_id:
                            self.log(f"Filtered own message echo from simulator.")
                            continue
                            
                        # Only display valid messages from other avatars
                        self.ui_callback("chat", f"[{from_name}]: {msg_text}")
                
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
                        region_handle = offer.get("RegionHandle", 0)

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

    def send_raw_packet(self, packet_obj):
        # This is now only used for resending tracked reliable packets
        if self.client:
            return self.client.send(packet_obj)
        return False
    
    def send_complete_movement_raw(self):
        self.log("Building CompleteAgentMovement packet...")
        msg = getMessageByName("CompleteAgentMovement")
        msg.AgentData["AgentID"] = self.agent_id
        msg.AgentData["SessionID"] = self.session_id
        msg.AgentData["CircuitCode"] = self.circuit_code
        # FIX: Ensure it is sent as reliable
        pck = Packet(sequence=self.client.seq, message=msg, reliable=True, ack=False)
        self.send_raw_packet(pck)


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

    # MODIFIED: Fix implemented here to ensure MapNameRequest is reliable
    def teleport(self, region_name):
        self.ui_callback("status", f"Requesting teleport to {region_name}...")
        if self.client and self.running:
            # FIX: Execute the blocking lookup logic in a worker thread
            teleport_thread = threading.Thread(target=self._teleport_lookup_task, args=(region_name,), daemon=True)
            teleport_thread.start()
            
    # MODIFIED: Worker thread target for map image fetching with new robust fallbacks
    def _fetch_map_image_task(self, region_name):
        # 1. Prepare region name for URL (underscores for spaces)
        # Use simple unquoted version for the tile name part
        region_name_url = urllib.parse.quote(region_name.strip().replace(' ', '_')) 
        
        # *** NEW: Add a small delay for map server processing ***
        time.sleep(2.0)
        
        # 2. Define multiple URLs with fallback logic
        # *** FIX: Using robust coordinate-based URLs as primary ***
        
        # Current grid coordinates
        gx = self.client.grid_x
        gy = self.client.grid_y
        
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

        for i, map_url in enumerate(urls_to_try):
            try:
                request = urllib.request.Request(map_url, headers=headers)
                
                with urllib.request.urlopen(request, timeout=7) as response:
                    # Check if the response code indicates success
                    if response.getcode() == 200:
                        map_data = response.read()
                        # A valid map image should be significantly larger than a few bytes
                        # Error images or small placeholders are often < 2KB
                        if len(map_data) > 2000: 
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
                error_msg = f"HTTP Error {e.code} fetching map image from {map_url}: {e.reason}"
                last_error = f"HTTP {e.code}"
                # Continue to next URL
            except Exception as e:
                # *** MODIFIED LOGGING: Log general network errors ***
                error_msg = f"General Error fetching map image from {map_url}: {type(e).__name__}: {e}"
                last_error = str(e)
                # Continue to next URL
        
        # 3. If all attempts fail
        self.ui_callback("status", f"⚠️ Map unavailable. ({last_error})")
        self.ui_callback("map_image_fetched", None)
            
    def fetch_map(self, region_name):
        """Public entry point for fetching the map image."""
        if not self.running or not PIL_AVAILABLE: # *** FIX: Check if PIL is available before trying to fetch/process ***
            self.log("PIL/Pillow not available, skipping map fetch.")
            self.ui_callback("map_image_fetched", None) # Send None to trigger placeholder
            return
            
        threading.Thread(target=self._fetch_map_image_task, args=(region_name,), daemon=True).start()
            
    # NEW: Worker thread target for teleport lookup/request
    def _teleport_lookup_task(self, region_name):
        """Handles the blocking map lookup and subsequent teleport request with retries."""
        
        # NOTE: Teleporting to 'home' or 'last' is handled by the initial login server call
        # which is outside of this in-world mechanism.
        if region_name.lower() in ("home", "last"):
            self.log(f"Cannot use in-world teleport for special regions: '{region_name}'.")
            self.ui_callback("status", f"❌ Teleport failed: '{region_name}' requires relogging/login-server call.")
            return

        # --- Region Lookup with Retry Logic ---
        
        target_name_lower = region_name.lower()
        
        # 1. Initialize state
        with self.client.teleport_lookup_lock:
            self.client.teleport_lookup_target_name = target_name_lower
            self.client.teleport_lookup_result = None
            self.client.teleport_lookup_event.clear() # Ensure the event is clear
            
        max_attempts = 3
        wait_per_attempt = 3.0 # Increase wait time for network latency

        for attempt in range(max_attempts):
            
            # Send MapNameRequest
            self.log(f"Sending MapNameRequest (Attempt {attempt+1}/{max_attempts}) for '{region_name}'...")
            
            msg_request = getMessageByName("MapNameRequest")
            msg_request.AgentData["AgentID"] = self.agent_id
            msg_request.AgentData["SessionID"] = self.session_id
            
            # FIX: The 'variable' class handles null-termination automatically from the string
            
            if len(region_name) + 1 > 255: 
                 self.log(f"Region name '{region_name}' is too long.")
                 self.ui_callback("status", f"❌ Teleport failed: Region name too long.")
                 return
                 
            # FIX: Ensure the Variable field is set with the correctly encoded bytes and type 1
            # Pass the raw string, the variable class handles encoding.
            # Standard region names in map lookup are null-terminated.
            msg_request.RequestData["Name"] = variable(1, region_name, add_null=True) 
            msg_request.RequestData["Flags"] = 0 
            
            # Send the request
            # *** FIX: MapNameRequest MUST be sent as a reliable packet ***
            self.client.send(msg_request, reliable=True)
            
            # 2. Wait for MapItemReply (blocking the worker thread)
            if self.client.teleport_lookup_event.wait(wait_per_attempt):
                # Event was set, reply was received by the network thread
                self.log(f"Region lookup received reply on attempt {attempt+1}.")
                break
            else:
                self.log(f"Region lookup timed out on attempt {attempt+1}. Retrying...")
                # Loop continues for next attempt

        # --- Process Final Result ---
        
        # Extract result block safely
        with self.client.teleport_lookup_lock:
            result_block = self.client.teleport_lookup_result
            self.client.teleport_lookup_target_name = None # Clear state
            self.client.teleport_lookup_result = None 
            self.client.teleport_lookup_event.clear() # Clear event one final time

        if result_block is None:
            self.log(f"Region lookup for '{region_name}' failed after {max_attempts} attempts.")
            self.ui_callback("status", f"❌ Teleport failed: Region '{region_name}' not found or timed out.")
            return

        # 3. Process result and send TeleportLocationRequest
        region_handle = result_block["Handle"]
        
        # Update our client's expected destination coordinates immediately
        # (Handle is y << 32 | x)
        w_y = region_handle >> 32
        w_x = region_handle & 0xFFFFFFFF
        self.client.grid_x = w_x // 256
        self.client.grid_y = w_y // 256
        
        self.log(f"Region lookup success: Handle={region_handle}, Sim Tile X={result_block['X']}, Y={result_block['Y']}")
        
        # Default position in the region: Center (128, 128) at height 30.0
        position = vector3(128.0, 128.0, 30.0) 

        self.client.teleport_to_region(region_name, region_handle, position)
        self.ui_callback("status", f"Request sent for {region_name}. Waiting for confirmation...")


            
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
            
            self.circuit_code = int(login_token['circuit_code'])
            self.agent_id = UUID(login_token['agent_id'])
            self.session_id = UUID(login_token['session_id'])
            self.sim_ip = login_token.get('sim_ip')
            self.sim_port = int(login_token.get('sim_port'))
            self.first_name = first 

            self.log("Initializing UDP Stream...")
            # MODIFIED: Pass self.log directly as the log_callback
            self.client = RegionClient(login_token, debug=self.debug_callback is not None, log_callback=self.log) 
            self.raw_socket = self.get_socket()
            self.log(f"Socket acquisition status: {'Success' if self.raw_socket else 'Failed'}")

            self.connection_start_time = time.time()
            self.running = True
            self.event_thread = threading.Thread(target=self._event_handler, daemon=True)
            self.event_thread.start()
            
            # --- FIX: Set the initial status to reflect the UDP handshake phase ---
            self.ui_callback("status", "Handshake started. Waiting for region info...")
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
    except Exception as e:
        print(f"Error saving credentials: {e}")
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
    except Exception as e:
        print(f"Error loading credentials (file corrupted?): {e}")
        return []

# ==========================================
# SECTION 9: GUI IMPLEMENTATION (Multi-Client)
# ==========================================

# --- Custom Themed Dialogs (NEW) ---

class ThemedDialog(Toplevel):
    def __init__(self, parent, title=None):
        super().__init__(parent)
        self.transient(parent)
        if title:
            self.title(title)
        
        self.parent = parent
        self.result = None
        
        # Set window properties to adhere to theme
        self.configure(bg='#0A0A0A')
        self.resizable(False, False)
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
    def __init__(self, parent, title, message, type_='yesno'):
        self.message = message
        self.type = type_
        super().__init__(parent, title)

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
    def __init__(self, parent, title, prompt):
        self.prompt = prompt
        self.value = None
        super().__init__(parent, title)
        
    def body(self):
        main_frame = ttk.Frame(self, style='BlackGlass.TFrame', padding=15)
        main_frame.pack(fill='both', expand=True)
        
        ttk.Label(main_frame, text=self.prompt, style='BlackGlass.TLabel').pack(pady=(0, 5), anchor='w')
        
        self.entry = tk.Entry(main_frame, width=40, bg='#2C2C2C', fg='#FFFFFF', insertbackground='white', relief=tk.FLAT, highlightthickness=1, highlightbackground='#555555')
        self.entry.pack(fill='x')
        
        self.initial_focus = self.entry

    def buttonbox(self):
        box = ttk.Frame(self, style='BlackGlass.TFrame', padding=(15, 0, 15, 15))
        box.pack(fill='x')
        
        ok_button = ttk.Button(box, text="OK", command=self.ok, style='BlackGlass.TButton', width=10)
        ok_button.pack(side=tk.RIGHT, padx=5)
        self.bind("<Return>", lambda e: self.ok())
        
        cancel_button = ttk.Button(box, text="Cancel", command=self.cancel, style='BlackGlass.TButton', width=10)
        cancel_button.pack(side=tk.RIGHT, padx=5)
        self.bind("<Escape>", lambda e: self.cancel())

    def ok(self):
        self.value = self.entry.get().strip()
        self.destroy()

    # Public static methods for convenience
    @staticmethod
    def askstring(parent, title, prompt):
        d = ThemedAskString(parent, title, prompt)
        return d.value if d.value else None

# --- Minimap Widget ---
class MinimapCanvas(tk.Canvas):
    def __init__(self, master, agent, **kwargs):
        # We remove explicit width/height here, as the wrapper manages the size.
        super().__init__(master, **kwargs)
        self.agent = agent
        self.configure(bg='#1C1C1C', highlightthickness=1, highlightbackground='#444444')
        self.size = 256 # SL regions are 256x256 meters
        self.source_image = None # NEW: Store original PIL image
        self.map_image = None # Tkinter PhotoImage object for the map tile
        self.last_size = (0, 0) # NEW: Track size to avoid redundant resizing
        # NEW: Placeholder image if PIL is not available
        self.placeholder_image = self._create_placeholder_image() if PIL_AVAILABLE else None
        self.bind("<Configure>", self.on_resize)
        self.last_update_time = 0
        self.after(100, self.draw_map) # Start the drawing loop

    def set_map_image(self, pil_image):
        """Sets the source PIL image for the map."""
        self.source_image = pil_image
        self.last_size = (0, 0) # Force re-render
        self.draw_map()

    def _create_placeholder_image(self):
        """Creates a default green circle image for the agent, using PIL."""
        if not PIL_AVAILABLE: return None
        
        size = 10 
        img = Image.new('RGBA', (size * 2, size * 2), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Draw a bright green circle in the center
        draw.ellipse((0, 0, size * 2 - 1, size * 2 - 1), fill="#00FF00", outline="#00FF00")
        
        # Draw an arrow pointing up (representing direction)
        # Arrow: Top center, slightly below center, bottom center
        #draw.polygon([(size, 0), (size * 2, size), (0, size)], fill="#FFFFFF")
        
        # Save as a Tkinter object
        return ImageTk.PhotoImage(img)


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
                ox, oy, oz = coords
                
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
            agent_rot_z = self.agent.client.agent_rot_z # Yaw in radians
    
            # Map to Canvas: X is proportional, Y is inverted (256-Y)
            # Apply scaling and offsets
            x_on_canvas = agent_x_sl * scale + offset_x
            y_on_canvas = (self.size - agent_y_sl) * scale + offset_y
            
            # Draw Bullseye Indicator (Red outer, Yellow inner)
            # Replaces the complex Green Arrow
            r_outer = 5
            r_inner = 2
            
            # Outer Red Circle
            self.create_oval(x_on_canvas - r_outer, y_on_canvas - r_outer, 
                             x_on_canvas + r_outer, y_on_canvas + r_outer,
                             fill="#FF0000", outline="#000000")
            
            # Inner Yellow Dot
            self.create_oval(x_on_canvas - r_inner, y_on_canvas - r_inner,
                             x_on_canvas + r_inner, y_on_canvas + r_inner,
                             fill="#FFFF00", outline="#000000")

        # Schedule the next redraw
        if self.agent.running:
            self.after(100, self.draw_map)
        
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
        
        self.pending_chat = {} # FIX: Store messages awaiting ACK echo
        
        # Update the agent's callback to target this specific tab
        self.sl_agent.ui_callback = self.update_ui 
        # FIX: The log handler needs to check for minimap updates
        self.sl_agent.debug_callback = self.handle_debug_log_callback 
        self.map_image = None # Added for the Tkinter PhotoImage object

        self._set_style(master)
        self._create_widgets()
        self._bind_keys() # Movement key bindings
        
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
        s = ttk.Style(master)
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
        
        ttk.Label(control_frame, text=f"Agent: {self.my_first_name} {self.my_last_name}", style='BlackGlass.TLabel', font=('Helvetica', 12, 'bold')).pack(side=tk.LEFT, padx=5)
        
        teleport_button = ttk.Button(control_frame, text="Teleport...", command=self.do_teleport, style='BlackGlass.TButton')
        teleport_button.pack(side=tk.RIGHT, padx=5)
        
        self.logout_button = ttk.Button(control_frame, text="Logout", command=self.on_closing, style='BlackGlass.TButton')
        self.logout_button.pack(side=tk.RIGHT, padx=5)
        
        # --- Main Content Frame (Chat + Right Panel) ---
        main_content_frame = ttk.Frame(self, style='BlackGlass.TFrame')
        main_content_frame.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)

        # Configure 2 columns: Column 0 (Chat Log) weight 7, Column 1 (Minimap/Notification) weight 1.
        # This enforces a 7:1 ratio, ensuring the chat log is dominant.
        main_content_frame.grid_columnconfigure(0, weight=7) 
        main_content_frame.grid_columnconfigure(1, weight=1) 
        main_content_frame.grid_rowconfigure(0, weight=1)

        # 1. Chat Display (Column 0, Row 0 - Expanding)
        self.chat_display = scrolledtext.ScrolledText(main_content_frame, state='disabled', wrap=tk.WORD, height=15, 
                                                     bg='#1C1C1C', fg='#E0E0E0', font=('Courier', 10), 
                                                     insertbackground='white', 
                                                     relief=tk.FLAT, highlightthickness=1, highlightbackground='#444444')
        self.chat_display.grid(row=0, column=0, sticky='nsew', padx=(0, 5))

        # 2. Right Panel Frame (Column 1, Row 0 - Contains Notifications and Minimap)
        right_panel_frame = ttk.Frame(main_content_frame, style='BlackGlass.TFrame')
        right_panel_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 0))

        # Configure rows in the Right Panel: Notifications (expanding) and Minimap (fixed height/square)
        right_panel_frame.grid_columnconfigure(0, weight=1)
        right_panel_frame.grid_rowconfigure(0, weight=1) # Notifications/Events (EXPAND)
        right_panel_frame.grid_rowconfigure(1, weight=0) # Minimap (FIXED HEIGHT, ALIGNED BOTTOM)

        # 2a. Event Notifications Area (Row 0 - Takes up remaining vertical space)
        self.notification_area = scrolledtext.ScrolledText(right_panel_frame, state='disabled', wrap=tk.WORD, height=5, 
                                                     bg='#1C1C1C', fg='#FFFF00', font=('Courier', 9), 
                                                     width=20, # <--- FIX: Explicitly set a small width
                                                     relief=tk.FLAT, highlightthickness=1, highlightbackground='#444444')
        self.notification_area.insert(tk.END, "Event/Lure Notifications Here.\n(e.g., Teleport Offers)")
        self.notification_area.grid(row=0, column=0, sticky='nsew', pady=(0, 5))

        # 2b. Minimap Wrapper (Row 1 - Fixed at the bottom and forces square aspect)
        # Give it an initial size but let the grid manage its width
        self.minimap_wrapper = ttk.Frame(right_panel_frame, style='BlackGlass.TFrame') # <--- FIX: Removed explicit width=200
        self.minimap_wrapper.grid(row=1, column=0, sticky='sew') # Aligned bottom (s), expands horizontally (ew)
        
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
        
        self.message_entry = tk.Entry(input_frame, font=('Helvetica', 12), 
                                      bg='#2C2C2C', fg='#FFFFFF', 
                                      insertbackground='white', relief=tk.FLAT, highlightthickness=1, highlightbackground='#555555')
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message_event)
        
        self.send_button = ttk.Button(input_frame, text="Send", command=self.send_message, style='BlackGlass.TButton')
        self.send_button.pack(side=tk.RIGHT)
        
        # --- FIX: Set initial status to a generic placeholder. The login process will update it. ---
        self._update_status(f"Initialized.")
        # --- END FIX ---

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
            self._append_notification("[SUCCESS] Map tile loaded and displayed.")
            
        except ImportError:
            # Should not happen if Pillow is installed
            self._append_notification("[FATAL] PIL/Pillow missing. Cannot display map image.")
            self.minimap.update_map_image(None) 
        except Exception as e:
            self._append_notification(f"[ERROR] Failed to process map image data: {e}")
            self.minimap.update_map_image(None)

        
    def handle_debug_log_callback(self, message):
        """Processes the debug log message, checking for special minimap update triggers."""
        
        # --- FIX: Add HANDSHAKE_COMPLETE to the log handler ---
        if message.startswith("HANDSHAKE_COMPLETE"):
            _, region_name = message.split(", ", 1)
            self.after(0, self._update_status, f"🟢 Successfully logged in to {region_name.strip()}!")
            self.after(0, self._append_notification, f"[INFO] Logged in to {region_name.strip()}.")
            
            # --- FIX: Trigger Map Fetch with Delay ---
            # Wait 2 seconds to ensure coordinates are stable and UI is ready
            self.after(2000, lambda: self.sl_agent.fetch_map(region_name.strip()))
            
        # --- KICKED LOG HANDLER (NEW) ---
        elif message.startswith("KICKED"):
            _, reason = message.split(", ", 1)
            # Pass the kick reason to the status update
            self.after(0, self._update_status, f"🔴 Kicked: {reason.strip()}")
            self.after(0, self._set_disconnected_ui)
        # --- END KICKED LOG HANDLER ---
            
        elif message == "MINIMAP_UPDATE":
             # Use self.after to redraw safely from the main thread
             self.after(0, self.minimap.draw_map) 
        else:
             # Pass on to the application's central debug handler
             self.tab_manager.handle_debug_log(message)


    def update_ui(self, update_type, message):
        """Thread-safe update of the GUI."""
        if update_type == "chat":
            self.after(0, self._append_chat, message)
        elif update_type == "chat_ack":
            # message is the sequence number
            seq_id = message
            if seq_id in self.pending_chat:
                confirmed_msg = self.pending_chat.pop(seq_id)
                self.after(0, self._append_chat, f"[{self.my_first_name} {self.my_last_name}]: {confirmed_msg}")
        elif update_type == "status":
            # This is primarily used for connection/teleport status updates
            self.after(0, self._update_status, message)
        elif update_type == "notification": # NEW: Generic notification handler
             self.after(0, self._append_notification, message)
        elif update_type == "error":
            # Use custom ThemedMessageBox for critical errors
            self.after(0, lambda: ThemedMessageBox(self.master, f"{self.my_first_name} Error", message, 'error'))
            self.after(0, self._update_status, f"Error: {message}")
            self.after(0, self._set_disconnected_ui) # Disable chat/send on error
        elif update_type == "teleport_offer":
            # Use the notification area for a non-critical alert, but keep the standard dialog for user action
            self.after(0, self._append_notification, f"[ALERT] Teleport offer received to {message['region']}.")
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


    def _append_chat(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END) 
                
    def _append_notification(self, message):
        self.notification_area.config(state='normal')
        self.notification_area.insert(tk.END, message + "\n", 'alert')
        self.notification_area.config(state='disabled')
        self.notification_area.see(tk.END) 
        
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
    def handle_debug_log_callback(self, message):
        """Handles debug messages from the agent."""
        if message == "MINIMAP_UPDATE":
            self.minimap.after(0, self.minimap.update_map)
            return
            
        if message.startswith("[CHAT]"):
            clean = message.replace("[CHAT]", "").strip()
            self.after(0, self._append_chat, clean)
            return
            
        if message.startswith("DEBUG: "):
            # Optional: direct to notification
            pass
            
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
            self.sl_agent.teleport(region_name.strip())

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
                                             args=(first, last, password, formatted_region_name, self), 
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
        self.title("Second Life Multi-Client Chat Viewer")
        self.geometry("800x650") 
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.resizable(True, True)
        self.eval('tk::PlaceWindow . center')
        
        # Global Enter Key Binding
        self.bind("<Return>", self.handle_global_return)

        self.active_agents = {} 
        self.login_panel = None # Will hold the instance of LoginPanel
        
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

    # --- FIXED METHOD: Added robust error handling and simplified selection ---
    def reload_login_tab(self):
        """Reloads the login panel to refresh the saved profiles dropdown."""
        
        # 1. Save old reference and state
        old_panel = self.login_panel
        is_selected = self.notebook.select() == str(old_panel)
        
        # 2. Remove the old panel
        try:
             # Use the old instance reference to ensure removal
             self.notebook.forget(old_panel) 
        except tk.TclError:
             pass
        
        # 3. Create the new panel and update the class attribute
        self.login_panel = LoginPanel(self.notebook, self)

        # 4. Insert the new panel, with a robust fallback
        try:
             # Attempt the preferred insertion at index 0
             self.notebook.insert(0, self.login_panel, text="➕ New Login")
        except tk.TclError:
             # If index 0 fails, safely add it to the end (will be index -1)
             self.notebook.add(self.login_panel, text="➕ New Login")
        
        # 5. Set focus back, using the widget instance
        if is_selected:
             self.notebook.select(self.login_panel)
    # --- END FIXED METHOD ---


    def login_task(self, first, last, password, region_name, login_panel_instance):
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
        """Central debug log handler (currently passive)."""
        # This is where you could insert code to print debug messages or log them to a file.
        # For now, we will simply pass, but the logic relies on this existing.
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
        # MODIFIED: Use ThemedMessageBox instead of messagebox.askyesno
        dialog_result = ThemedMessageBox(self, "Quit", "Are you sure you want to log out all agents and exit?", 'yesno').result
        
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