"""SecondLifeAgent: high-level agent behaviour driving a region session."""

import threading
import time
import sys
import json
from uuid import UUID
import html as html_parser
import random
import re
import urllib.parse
import urllib.request

from .imaging import PIL_AVAILABLE
from .lltypes import LLUUID, const, variable
from .messages import getMessageByName
from .network import (RegionClient, SL_USER_AGENT, login_to_simulator,
                      parse_llsd_xml, render_llsd_xml, safe_decode_llvariable)


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

        # Group Name Caching
        self.group_name_cache = {}   # UUID -> group name string
        self.group_data_cache = {}   # UUID -> full group data dict
        self.fetching_groups = set() # group UUIDs currently being fetched

        # Parcel Name Caching
        self.parcel_name_cache = {}   # UUID -> parcel name string
        self.parcel_data_cache = {}  # UUID -> full parcel data dict
        self.fetching_parcels = set() # parcel UUIDs currently being fetched
        
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
        # We start this immediately using the UUID; the username is only for the UI link.
        uid_key = str(avatar_id).lower()
        uname = self.username_cache.get(uid_key)
        threading.Thread(target=self._fetch_web_profile_task, args=(avatar_id, uname), daemon=True).start()

        # If we don't have the username/display name yet, request them too
        if not uname or uid_key not in self.display_name_cache:
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

    def get_group_name(self, group_id, force=False):
        """
        Return the cached group name for *group_id*, or kick off a background
        web-scrape fetch and return None so the caller can emit a sentinel.
        If force=True, re-fetches even if cached.
        """
        key = str(group_id).lower()
        cached_name = self.group_name_cache.get(key)
        cached_data = self.group_data_cache.get(key)
        
        # Start fetch if forced, missing name altogether, or if we only have the name but not rich data
        if force or not cached_name or not cached_data:
            if key not in self.fetching_groups:
                self.fetching_groups.add(key)
                threading.Thread(
                    target=self._fetch_group_name_task,
                    args=(key,), daemon=True).start()
        
        return cached_name if not force else None

    def _fetch_group_name_task(self, group_uuid):
        """
        Scrape https://world.secondlife.com/group/<uuid> for the group name.
        The <title> tag contains the group name directly (e.g. "Second Life Birthday").
        Fires ui_callback('update_group_name', (uuid, name)) on success so the
        UI can retroactively patch Resolving… spans in old chat messages.
        """
        url = f'https://world.secondlife.com/group/{group_uuid}'
        try:
            self.log(f'Fetching group name from: {url}')
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html'
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.getcode() == 200:
                    html = resp.read().decode('utf-8', errors='replace')
                    
                    # Strip comments to avoid matching commented-out meta tags
                    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
                    
                    # The <title> tag holds the group name on this page
                    title_m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
                    if title_m:
                        name = html_parser.unescape(title_m.group(1).strip())
                        # Strip any " | Second Life" or " - Second Life" suffix
                        for suffix in (' | Second Life', ' - Second Life'):
                            if name.endswith(suffix):
                                name = name[:-len(suffix)].strip()
                                break
                    else:
                        # Fallback: <meta name="description" content="..."> first line
                        desc_m = re.search(
                            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
                            html, re.IGNORECASE)
                        name = html_parser.unescape(
                            desc_m.group(1).split('\n')[0].strip()) if desc_m else ''
                    if name:
                        self.group_name_cache[group_uuid] = name
                        # Robust meta-tag parser: iterate each <meta> tag, check attrs separately
                        def _meta(attr_name, _html=html):
                            for _tag in re.findall(r'<meta\b[^>]*>', _html, re.IGNORECASE):
                                _nm = re.search(r'\b(?:name|property)=["\']([^"\']+)["\']', _tag, re.IGNORECASE)
                                _ct = re.search(r'\bcontent=["\']([^"\']*)["\']', _tag, re.IGNORECASE)
                                if _nm and _nm.group(1).strip().lower() == attr_name.lower() and _ct:
                                    content = html_parser.unescape(_ct.group(1).strip())
                                    if content:
                                        return content
                            return ''
                        data = {
                            'name': name,
                            'description': _meta('description') or _meta('og:description'),
                            'member_count': _meta('member_count'),
                            'open_enrollment': _meta('open_enrollment'),
                            'membership_fee': _meta('membership_fee'),
                            'founder': _meta('founder'),
                            'founder_id': _meta('founderid'),
                            'image_id': _meta('imageid'),
                            'id': group_uuid,
                        }
                        self.group_data_cache[group_uuid] = data
                        self.ui_callback('update_group_name', (group_uuid, data))
                    else:
                        self.log(f'Could not parse group name from {url}')
        except Exception as e:
            err = str(e).encode('ascii', errors='replace').decode('ascii')
            self.log(f'Error fetching group name: {err}')
        finally:
            self.fetching_groups.discard(group_uuid)

    def get_parcel_name(self, parcel_id, force=False):
        """
        Return the cached parcel name for *parcel_id* (a UUID string), or kick
        off a background web-scrape fetch and return None for a sentinel.
        If force=True, re-fetches even if cached.
        """
        key = str(parcel_id).lower()
        cached_name = self.parcel_name_cache.get(key)
        cached_data = self.parcel_data_cache.get(key)

        # Start fetch if forced, missing name altogether, or if we only have the name but not rich data
        if force or not cached_name or not cached_data:
            if key not in self.fetching_parcels:
                self.fetching_parcels.add(key)
                threading.Thread(
                    target=self._fetch_parcel_name_task,
                    args=(key,), daemon=True).start()
        
        return cached_name if not force else None

    def _fetch_parcel_name_task(self, parcel_uuid):
        """
        Scrape https://world.secondlife.com/place/<uuid> for the parcel name.
        The page title has the form  "Parcel Name | Second Life"  or just the
        parcel name — we strip the " | Second Life" suffix if present.
        Fires ui_callback('update_parcel_name', (uuid, name)) on success.
        """
        url = f'https://world.secondlife.com/place/{parcel_uuid}'
        try:
            self.log(f'Fetching parcel name from: {url}')
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'BlackGlass',
                    'Accept': 'text/html'
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.getcode() == 200:
                    html = resp.read().decode('utf-8', errors='replace')
                    
                    # Strip comments to avoid matching commented-out meta tags
                    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
                    
                    # Try og:title, then meta parcel, then <title> tag
                    name = ''
                    og_m = re.search(
                        r'<meta[^>]+(?:property|name)=["\']og:title["\'][^>]+content=["\']([^"\']+)',
                        html, re.IGNORECASE)
                    if og_m:
                        name = html_parser.unescape(og_m.group(1).strip())
                    
                    if not name:
                        parcel_m = re.search(
                            r'<meta[^>]+name=["\']parcel["\'][^>]+content=["\']([^"\']+)',
                            html, re.IGNORECASE)
                        if parcel_m:
                            name = html_parser.unescape(parcel_m.group(1).strip())

                    if not name:
                        title_m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
                        if title_m:
                            title = html_parser.unescape(title_m.group(1).strip())
                            for suffix in (' | Second Life', ' - Second Life'):
                                if title.endswith(suffix):
                                    title = title[:-len(suffix)].strip()
                                    break
                            name = title

                    if name:
                        self.parcel_name_cache[parcel_uuid] = name
                        # Parse rich meta data
                        def _pmeta(attr_name, _html=html):
                            for _tag in re.findall(r'<meta\b[^>]*>', _html, re.IGNORECASE):
                                _nm = re.search(r'\b(?:name|property)=["\']([^"\']+)["\']', _tag, re.IGNORECASE)
                                _ct = re.search(r'\bcontent=["\']([^"\']*)["\']', _tag, re.IGNORECASE)
                                if _nm and _nm.group(1).strip().lower() == attr_name.lower() and _ct:
                                    content = html_parser.unescape(_ct.group(1).strip())
                                    if content: # Only return if not empty
                                        return content
                            return ''
                        
                        desc = _pmeta('description') or _pmeta('og:description')
                        if not desc or desc.strip().lower() in ('second life', ''):
                            # Primary: Scrape <p class="desc"> — the actual SL place page element
                            desc_match = re.search(r'<p[^>]+class=["\'][^"\']*\bdesc\b[^"\']*["\'][^>]*>(.*?)</p>', html, re.S | re.I)
                            if desc_match:
                                raw_desc = desc_match.group(1)
                                raw_desc = re.sub(r'<br\s*/?>', '\n', raw_desc, flags=re.I)
                                raw_desc = re.sub(r'<[^>]+>', '', raw_desc)
                                desc = html_parser.unescape(raw_desc).strip()

                        if not desc or desc.strip().lower() in ('second life', ''):
                            # Fallback: Scrape <div class="description"> from body
                            desc_match = re.search(r'<div[^>]+class=["\'][^"\']*description[^"\']*["\'][^>]*>(.*?)</div>', html, re.S | re.I)
                            if desc_match:
                                raw_desc = desc_match.group(1)
                                raw_desc = re.sub(r'<br\s*/?>', '\n', raw_desc, flags=re.I)
                                raw_desc = re.sub(r'<[^>]+>', '', raw_desc)
                                desc = html_parser.unescape(raw_desc).strip()

                        if not desc or desc.strip().lower() in ('second life', ''):
                            # Fallback: Scrape the main content body paragraph (SL place pages
                            # put the parcel description as a standalone <p> in a content area)
                            # Look for a paragraph inside an id/class that sounds like content
                            body_p = re.search(
                                r'<(?:div|section)[^>]+(?:id|class)=["\'][^"\']*(content|main|place|about|info)[^"\']["\'][^>]*>.*?<p[^>]*>([^<]{20,})</p>',
                                html, re.S | re.I)
                            if body_p:
                                desc = html_parser.unescape(body_p.group(2).strip())

                        if not desc or desc.strip().lower() in ('second life', ''):
                            # Last resort: grab the first substantial <p> in the whole body
                            # that is not navigation boilerplate
                            all_ps = re.findall(r'<p[^>]*>([^<]{30,})</p>', html, re.I)
                            for candidate in all_ps:
                                clean = html_parser.unescape(candidate.strip())
                                # Skip LL boilerplate phrases
                                if not any(skip in clean.lower() for skip in ('second life', 'linden', 'join now', 'quick start', 'marketplace')):
                                    desc = clean
                                    break

                        # Improved image scraping
                        snapshot = _pmeta('snapshot') or _pmeta('og:image')
                        if not snapshot:
                            # Try <link rel="image_src" ...>
                            img_src_m = re.search(r'<link[^>]+rel=["\']image_src["\'][^>]+href=["\']([^"\']+)["\']', html, re.I)
                            if img_src_m:
                                snapshot = html_parser.unescape(img_src_m.group(1).strip())
                        if not snapshot:
                            # Primary: Scrape <img class="parcelimg" src="..."> — the actual SL place page image element
                            img_m = re.search(r'<img[^>]+class=["\'][^"\']*\bparcelimg\b[^"\']*["\'][^>]+src=["\']([^"\']+)["\']', html, re.I)
                            if not img_m:
                                # Also try src before class attribute order
                                img_m = re.search(r'<img[^>]+src=["\']([^"\']+)["\'][^>]+class=["\'][^"\']*\bparcelimg\b[^"\']*["\']', html, re.I)
                            if img_m:
                                snapshot = html_parser.unescape(img_m.group(1).strip())

                        data = {
                            'name': name,
                            'description': desc or '',
                            'region': _pmeta('region'),
                            'location': _pmeta('location'),
                            'snapshot': snapshot,
                            'image_id': _pmeta('imageid'),
                            'mat': _pmeta('mat'),
                            'category': _pmeta('category'),
                            'owner': _pmeta('owner'),
                            'area': _pmeta('area'),
                            'id': parcel_uuid,
                            'source': 'web'
                        }
                        self.parcel_data_cache[parcel_uuid] = data
                        self.ui_callback('update_parcel_name', (parcel_uuid, data))
                    else:
                        self.log(f'Could not parse parcel name from {url}')
        except Exception as e:
            err = str(e).encode('ascii', errors='replace').decode('ascii')
            self.log(f'Error fetching parcel name: {err}')
        finally:
            self.fetching_parcels.discard(parcel_uuid)

    def _fetch_web_profile_task(self, avatar_id, username=None):
        """Background task to fetch profile data from world.secondlife.com (no login required)."""
        # Use world.secondlife.com/resident/{UUID} - publicly accessible, no login needed.
        # my.secondlife.com requires login cookies and returns an empty login redirect page.
        avatar_id = str(avatar_id).lower()
        public_url = f"https://world.secondlife.com/resident/{avatar_id}"
        
        # If we don't have a username, use the public URL as the web profile link too
        if username:
            web_url = f"https://my.secondlife.com/{username}"
        else:
            web_url = public_url
        
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
                "username": username or "",
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


