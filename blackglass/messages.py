"""Second Life UDP message templates and the message registry."""

import struct

from .codec import baseTypes, typeLengths, llDecodeType, llEncodeType


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

# --- INSTANT MESSAGE PACKETS ---
class ImprovedInstantMessage(BaseMessage):
    """
    Received from the simulator when another avatar sends us a private IM.
    Dialog types: 0 = plain IM, 9 = group notice, 19 = friendship offer, etc.
    """
    name = "ImprovedInstantMessage"; id = 254; freq = 2; trusted = True; zero_coded = True
    blocks = [("AgentData", 1), ("MessageBlock", 1)]
    structure = {
        "AgentData": [("AgentID", "LLUUID"), ("SessionID", "LLUUID")],
        "MessageBlock": [
            ("FromGroup", "BOOL"),
            ("ToAgentID", "LLUUID"),
            ("ParentEstateID", "U32"),
            ("RegionID", "LLUUID"),
            ("Position", "LLVector3"),
            ("Offline", "U8"),
            ("Dialog", "U8"),
            ("ID", "LLUUID"),
            ("Timestamp", "U32"),
            ("FromAgentName", "Variable", 1),
            ("Message", "Variable", 2),
            ("BinaryBucket", "Variable", 2),
        ]
    }
registerMessage(ImprovedInstantMessage)
