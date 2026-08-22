"""Authentication, LLSD helpers and the RegionClient circuit layer."""

import socket
import threading
import time
import hashlib
import xmlrpc.client
from uuid import UUID, getnode as get_mac
import json
import struct
import sys
import urllib.parse
import urllib.request

from .codec import packetErrorTrace
from .imaging import PIL_AVAILABLE
from .lltypes import LLUUID, quaternion, variable, vector3
from .messages import getMessageByName
from .packet import Packet


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
                        full_name = f"{first} {last}".replace(" Resident", "").strip()
                        
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

