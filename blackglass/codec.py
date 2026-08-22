"""Encoding/decoding utilities: typed values, zerocoding, hex dumps."""

import struct
import traceback

from .lltypes import (IPAddr, IPPort, LLUUID, fixed, null, quaternion,
                      variable, vector3, vector3d, vector4)


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
