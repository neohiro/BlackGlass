"""ChatTab: the main per-session chat interface tab."""

import re
import time
import html as html_parser
import urllib.request
import tkinter as tk
from tkinter import ttk
from io import BytesIO
import math
import threading

from ..imaging import PIL_AVAILABLE, Image, ImageTk
from .minimap import MinimapCanvas
from .theme import (ThemedAskString, ThemedChoiceDialog, ThemedGroupDialog,
                    ThemedMessageBox, ThemedParcelDialog, ThemedProfileDialog)
from .widgets import LimitedScrolledText


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
        
        clean_name = f"{self.my_first_name} {self.my_last_name}".replace(" Resident", "")
        self.agent_name_label = ttk.Label(control_frame, text=f"Agent: {clean_name}", style='BlackGlass.TLabel', font=('Helvetica', 12, 'bold'))
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
        self.chat_display.bind("<Button-3>", self._show_chat_context_menu)
        
        # --- FIX: Configure tag for gray speaker name ---
        self.chat_display.tag_config('speaker_name', foreground='#AAAAAA')
        # ------------------------------------------------

        # --- Hyperlink base tag (style only; bindings go on per-link tags) ---
        self.chat_display.tag_config('hyperlink', foreground='#00BFFF', underline=True)
        self._link_counter = 0   # unique index for per-link tags

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
        self.message_entry.bind("<Button-3>", self._show_entry_context_menu)
        
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
                # Same-region move: in-session teleport with relog failover
                region = self.sl_agent.current_region_name
                self.sl_agent.soft_teleport(region, px, py, pz)
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
                clean_from_name = from_name.replace(" Resident", "")
                display_name = self.sl_agent.get_display_name(agent_id, from_name)
                
                # FIX: Avoid printing the same name twice
                if display_name and display_name != from_name:
                    name_label = f"{display_name} ({clean_from_name})"
                    self.after(0, self.agent_name_label.config, {'text': f"Agent: {name_label}"})
                else:
                    name_label = clean_from_name
                    
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

        elif update_type == "update_group_name":
            uid, data = message
            gname = data['name'] if isinstance(data, dict) else data
            def _patch_group(u=uid, n=gname, d=data):
                self.sl_agent.group_name_cache[u] = n
                if isinstance(d, dict):
                    self.sl_agent.group_data_cache[u] = d
                self._replace_resolving_spans(f'sluri_group_{u}', n)
                # Update open dialog if it exists
                key = f'group_{u}'
                if key in self.active_profiles:
                    dialog = self.active_profiles[key]
                    if dialog.winfo_exists() and hasattr(dialog, 'update_data'):
                        dialog.update_data(d)
            self.after(0, _patch_group)

        elif update_type == "update_parcel_name":
            uid, data = message
            pname = data['name'] if isinstance(data, dict) else data
            def _patch_parcel(u=uid, n=pname, d=data):
                self.sl_agent.parcel_name_cache[u] = n
                if isinstance(d, dict):
                    self.sl_agent.parcel_data_cache[u] = d
                self._replace_resolving_spans(f'sluri_parcel_{u}', n)
                # Update open dialog if it exists
                key = f'parcel_{u}'
                if key in self.active_profiles:
                    dialog = self.active_profiles[key]
                    if dialog.winfo_exists() and hasattr(dialog, 'update_data'):
                        dialog.update_data(d)
            self.after(0, _patch_parcel)
            
        elif update_type == "clear_map":
            # Clear the minimap image (e.g. on logout/teleport start)
            self.after(0, lambda: self.minimap.update_map_image(None))

    def _open_sl_entity_popup(self, entity_type, uid):
        """Open the appropriate info popup for an agent, group, or parcel UUID."""
        uid = uid.lower()
        if entity_type == 'agent':
            name = self.sl_agent.display_name_cache.get(uid, 'Unknown')
            # Open a 'Loading...' dialog immediately so the user sees something right away
            loading_data = {
                "id": uid,
                "name": name,
                "about": "Loading profile...",
                "born": "...",
                "url": "",
                "image_id": "",
                "source": "loading"
            }
            self.update_ui("show_profile", loading_data)
            
            # Kick off the async profile fetch (will call update_ui('show_profile', ...) when done)
            self.sl_agent.request_avatar_properties(uid)
        elif entity_type == 'group':
            # Trigger fetch if data is missing or incomplete
            self.sl_agent.get_group_name(uid)
            data = self.sl_agent.group_data_cache.get(uid, {})
            if not data:
                data = {'name': self.sl_agent.group_name_cache.get(uid, uid), 'id': uid, 'description': 'Loading group info...'}
            key = f'group_{uid}'
            if key in self.active_profiles and self.active_profiles[key].winfo_exists():
                self.active_profiles[key].lift()
            else:
                self.active_profiles[key] = ThemedGroupDialog(self.master, data, self, key)
        elif entity_type == 'parcel':
            # Trigger fetch if data is missing or incomplete
            self.sl_agent.get_parcel_name(uid)
            data = self.sl_agent.parcel_data_cache.get(uid, {})
            if not data:
                data = {'name': self.sl_agent.parcel_name_cache.get(uid, uid), 'id': uid, 'description': 'Loading parcel info...'}
            key = f'parcel_{uid}'
            if key in self.active_profiles and self.active_profiles[key].winfo_exists():
                dialog = self.active_profiles[key]
                # If the dialog is open but was showing loading state, refresh it now
                # (handles the race condition where fetch completed after dialog opened
                #  but _patch_parcel's update_data wasn't called yet)
                cached_data = self.sl_agent.parcel_data_cache.get(uid, {})
                if cached_data and cached_data.get('source') == 'web':
                    if dialog.data.get('source') != 'web':
                        dialog.update_data(cached_data)
                dialog.lift()
            else:
                self.active_profiles[key] = ThemedParcelDialog(self.master, data, self, key)

    def update_display_name(self, uid, display_name):
        """Updates the UI when a display name is resolved."""
        # 0. Sync back to the agent's central cache so the Nearby List sees it
        uid_lower = str(uid).lower()
        self.sl_agent.display_name_cache[uid_lower] = display_name
        
        # Derive potential username for web profile link if missing
        if uid_lower not in self.sl_agent.username_cache:
            parts = display_name.lower().split()
            if len(parts) >= 2 and parts[1] != 'resident':
                # Modern account: first.last
                self.sl_agent.username_cache[uid_lower] = f"{parts[0]}.{parts[1]}"
            elif len(parts) >= 1:
                # Legacy account: first
                self.sl_agent.username_cache[uid_lower] = parts[0]

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
                
        # 2. Retroactively replace any 'Resolving…' spans tagged with this UUID
        self._replace_resolving_spans(f'sluri_agent_{uid_lower}', display_name)

    def _replace_resolving_spans(self, tag, display_name):
        """
        Find every 'Resolving\u2026' span in chat_display tagged with *tag*
        and replace it in-place with display_name, then style it as a link.
        """
        widget = self.chat_display
        ranges = widget.tag_ranges(tag)
        if not ranges:
            return
        widget.config(state='normal')
        # Parse entity type + uuid from tag name: sluri_<type>_<uuid>
        parts = tag.split('_', 2)  # ['sluri', type, uuid]
        entity_type = parts[1] if len(parts) >= 3 else 'agent'
        entity_uuid = parts[2] if len(parts) >= 3 else parts[-1]
        # Style as cyan underlined clickable link
        widget.tag_config(tag, foreground='#00BFFF', underline=True,
                          font=('Courier', 12))
        widget.tag_bind(tag, '<Button-1>',
            lambda e, t=entity_type, u=entity_uuid: self._open_sl_entity_popup(t, u))
        widget.tag_bind(tag, '<Enter>',
            lambda e: widget.config(cursor='hand2'))
        widget.tag_bind(tag, '<Leave>',
            lambda e: widget.config(cursor=''))
        # Process pairs (start, end) in REVERSE order so earlier indices stay valid
        pairs = list(zip(ranges[::2], ranges[1::2]))
        for start, end in reversed(pairs):
            widget.delete(start, end)
            widget.insert(start, display_name, (tag,))
        widget.config(state='disabled')


    def _resolve_sl_uris(self, text):
        """
        Resolve all known secondlife:// and secondlife:///app/ URI namespaces
        into human-readable text, based on:
        https://wiki.secondlife.com/wiki/Viewer_URI_Name_Space
        """
        UUID_RE = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

        # Sentinel characters that cannot appear in SL chat
        _STX, _ETX = '\x02', '\x03'

        def lookup_name(uid_str, fallback=None):
            """
            Return a typed sentinel placeholder '\x02R:agent:<uuid>\x03'.
            _insert_with_uri_tags will check the cache and either insert the 
            name immediately as a link or show 'Resolving…'.
            """
            key = uid_str.lower()
            if self.sl_agent:
                # Trigger fetch if not cached (non-blocking)
                cached = self.sl_agent.display_name_cache.get(key)
                if not cached or cached in ('Resolving\u2026', ''):
                    self.sl_agent.get_display_name(uid_str, fallback or '')
            return f'{_STX}R:agent:{key}{_ETX}'

        def repl_agent_action(m):
            uid, action = m.group(1), m.group(2).rstrip('/')
            name = lookup_name(uid)
            actions = {
                'about':          f'[Profile: {name}]',
                'inspect':        f'[Avatar: {name}]',
                'im':             f'[IM: {name}]',
                'mention':        f'@{name}',
                'offerteleport':  f'[Offer TP to: {name}]',
                'pay':            f'[Pay: {name}]',
                'requestfriend':  f'[Friend Request: {name}]',
                'mute':           f'[Mute: {name}]',
                'unmute':         f'[Unmute: {name}]',
                'completename':   name,
                'complete':       name,
                'displayname':    name,
                'username':       lookup_name(uid, uid),
            }
            return actions.get(action, f'[Avatar({action}): {name}]')

        # /app/agent/<uuid>/<action>
        text = re.sub(
            rf'secondlife:///app/agent/({UUID_RE})/([a-z]+)/?',
            repl_agent_action, text, flags=re.IGNORECASE)

        # /app/agent/<uuid> (no action)
        text = re.sub(
            rf'secondlife:///app/agent/({UUID_RE})/?',
            lambda m: lookup_name(m.group(1)), text, flags=re.IGNORECASE)

        def lookup_group_name(uid_str):
            """Return a typed sentinel for the group."""
            key = uid_str.lower()
            if self.sl_agent:
                if not self.sl_agent.group_name_cache.get(key):
                    self.sl_agent.get_group_name(key)
            return f'{_STX}R:group:{key}{_ETX}'

        # /app/group/<uuid>/about  and  /app/group/<uuid>/inspect
        def repl_group_action(m):
            uid, action = m.group(1), m.group(2).rstrip('/')
            gname = lookup_group_name(uid)
            labels = {'about': f'[Group: {gname}]', 'inspect': f'[Group Info: {gname}]'}
            return labels.get(action, f'[Group({action}): {gname}]')
        text = re.sub(
            rf'secondlife:///app/group/({UUID_RE})/([a-z]+)/?',
            repl_group_action, text, flags=re.IGNORECASE)

        # /app/group/<uuid> (no action)
        text = re.sub(
            rf'secondlife:///app/group/({UUID_RE})/?',
            lambda m: lookup_group_name(m.group(1)), text, flags=re.IGNORECASE)

        # /app/group/create
        text = re.sub(
            r'secondlife:///app/group/create/?',
            '[Create Group]', text, flags=re.IGNORECASE)

        # /app/group/list/show
        text = re.sub(
            r'secondlife:///app/group/list/show/?',
            '[My Groups]', text, flags=re.IGNORECASE)

        # /app/classified/<id>/about
        text = re.sub(
            rf'secondlife:///app/classified/({UUID_RE})/about/?',
            r'[Classified]', text, flags=re.IGNORECASE)

        # /app/event/<id>/about
        text = re.sub(
            r'secondlife:///app/event/(\d+)/about/?',
            r'[Event]', text, flags=re.IGNORECASE)

        # /app/experience/<id>/profile
        text = re.sub(
            rf'secondlife:///app/experience/({UUID_RE})/profile/?',
            r'[Experience]', text, flags=re.IGNORECASE)

        # /app/inventory/<id>/select
        text = re.sub(
            rf'secondlife:///app/inventory/({UUID_RE})/select/?',
            r'[Inventory Item]', text, flags=re.IGNORECASE)

        # /app/inventory/show
        text = re.sub(
            r'secondlife:///app/inventory/show/?',
            '[Open Inventory]', text, flags=re.IGNORECASE)

        # /app/objectim/<id>?name=...&owner=...&slurl=...
        def repl_objectim(m):
            params_str = m.group(2) or ''
            params = {}
            for part in params_str.split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
            obj_name = params.get('name', 'Object')
            slurl    = params.get('slurl', '')
            owner_id = params.get('owner', '')
            owner    = lookup_name(owner_id, owner_id) if owner_id else ''
            parts = [f'[Object: {obj_name}']
            if slurl:
                parts.append(f'@ {slurl}')
            if owner:
                parts.append(f'owner: {owner}')
            return ' '.join(parts) + ']'
        text = re.sub(
            rf'secondlife:///app/objectim/({UUID_RE})(\?[^\s]*)?',
            repl_objectim, text, flags=re.IGNORECASE)

        # /app/parcel/<uuid>/about  — parcel UUID, resolvable via world.secondlife.com/place/<uuid>
        def lookup_parcel_name(uid_str):
            """Return typed sentinel for the parcel."""
            key = uid_str.lower()
            if self.sl_agent:
                if not self.sl_agent.parcel_name_cache.get(key):
                    self.sl_agent.get_parcel_name(key)
            return f'{_STX}R:parcel:{key}{_ETX}'

        # /app/parcel/<uuid>/about or /app/place/<uuid>/about
        def repl_parcel_action(m):
            uid = m.group(1)
            pname = lookup_parcel_name(uid)
            return f'[Parcel: {pname}]'
        text = re.sub(
            rf'secondlife:///app/(?:parcel|place)/({UUID_RE})/(?:about|inspect)/?',
            repl_parcel_action, text, flags=re.IGNORECASE)

        # /app/parcel/<uuid> or /app/place/<uuid> (no action)
        text = re.sub(
            rf'secondlife:///app/(?:parcel|place)/({UUID_RE})/?',
            lambda m: lookup_parcel_name(m.group(1).lower()), text, flags=re.IGNORECASE)

        # /app/search/<category>/<term>
        def repl_search(m):
            cat, term = m.group(1), urllib.parse.unquote_plus(m.group(2))
            return f'[Search ({cat}): {term}]'
        text = re.sub(
            r'secondlife:///app/search/([^/\s]+)/([^\s]*)',
            repl_search, text, flags=re.IGNORECASE)

        # /app/sharewithavatar/<uuid>
        def repl_sharewith(m):
            name = lookup_name(m.group(1))
            return f'[Share with: {name}]'
        text = re.sub(
            rf'secondlife:///app/sharewithavatar/({UUID_RE})/?',
            repl_sharewith, text, flags=re.IGNORECASE)

        # /app/teleport/<region>/<x>/<y>/<z>
        def repl_teleport(m):
            region = urllib.parse.unquote_plus(m.group(1).replace('+', ' '))
            coords = '/'.join(filter(None, [m.group(2), m.group(3), m.group(4)]))
            return f'[Teleport to: {region} ({coords})]' if coords else f'[Teleport to: {region}]'
        text = re.sub(
            r'secondlife:///app/teleport/([^/\s]+)(?:/(\d+)(?:/(\d+)(?:/(\d+))?)?)?/?',
            repl_teleport, text, flags=re.IGNORECASE)

        # /app/worldmap/<region>/<x>/<y>/<z>
        def repl_worldmap(m):
            region = urllib.parse.unquote_plus(m.group(1).replace('+', ' '))
            coords = '/'.join(filter(None, [m.group(2), m.group(3), m.group(4)]))
            return f'[Map: {region} ({coords})]' if coords else f'[Map: {region}]'
        text = re.sub(
            r'secondlife:///app/worldmap/([^/\s]+)(?:/(\d+)(?:/(\d+)(?:/(\d+))?)?)?/?',
            repl_worldmap, text, flags=re.IGNORECASE)

        # /app/maptrackavatar/<uuid>
        def repl_maptrack(m):
            name = lookup_name(m.group(1))
            return f'[Track on Map: {name}]'
        text = re.sub(
            rf'secondlife:///app/maptrackavatar/({UUID_RE})/?',
            repl_maptrack, text, flags=re.IGNORECASE)

        # /app/voicecallavatar/<uuid>
        def repl_voicecall(m):
            name = lookup_name(m.group(1))
            return f'[Voice Call: {name}]'
        text = re.sub(
            rf'secondlife:///app/voicecallavatar/({UUID_RE})/?',
            repl_voicecall, text, flags=re.IGNORECASE)

        # /app/openfloater/<name>
        text = re.sub(
            r'secondlife:///app/openfloater/([^\s?]+)/?',
            lambda m: f'[Open: {m.group(1)}]', text, flags=re.IGNORECASE)

        # /app/help/<topic>
        text = re.sub(
            r'secondlife:///app/help/([^\s]*)/?',
            lambda m: f'[Help: {urllib.parse.unquote_plus(m.group(1))}]' if m.group(1) else '[Help]',
            text, flags=re.IGNORECASE)

        # /app/balance/request
        text = re.sub(
            r'secondlife:///app/balance/request/?',
            '[L$ Balance Update]', text, flags=re.IGNORECASE)

        # /app/appearance/show
        text = re.sub(
            r'secondlife:///app/appearance/show/?',
            '[Appearance]', text, flags=re.IGNORECASE)

        # /app/wear_folder/?folder_id=<uuid>  or  /?folder_name=<name>
        def repl_wear(m):
            qs = m.group(1) or ''
            params = {}
            for part in qs.lstrip('?').split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    params[k] = urllib.parse.unquote_plus(v)
            label = params.get('folder_name') or params.get('folder_id', 'folder')
            return f'[Wear Folder: {label}]'
        text = re.sub(
            r'secondlife:///app/wear_folder/?(\?[^\s]*)?',
            repl_wear, text, flags=re.IGNORECASE)

        # /app/login  (bare)
        text = re.sub(
            r'secondlife:///app/login/?',
            '[Login]', text, flags=re.IGNORECASE)

        # /app/chat/<channel>/<text>
        def repl_chat_uri(m):
            channel, chat_text = m.group(1), urllib.parse.unquote_plus(m.group(2))
            return f'[Chat ch{channel}: {chat_text}]'
        text = re.sub(
            r'secondlife:///app/chat/(\d+)/([^\s]*)',
            repl_chat_uri, text, flags=re.IGNORECASE)

        # /app/keybinding/<action>  (just label it)
        text = re.sub(
            r'secondlife:///app/keybinding/([^\s?]+)(?:\?[^\s]*)?',
            lambda m: f'[Keybinding: {m.group(1)}]', text, flags=re.IGNORECASE)

        # Classic SLURL: secondlife://<region>/<x>/<y>/<z>
        def repl_classic_slurl(m):
            region = urllib.parse.unquote_plus(m.group(1).replace('+', ' '))
            coords = '/'.join(filter(None, [m.group(2), m.group(3), m.group(4)]))
            return f'[SLURL: {region} ({coords})]' if coords else f'[SLURL: {region}]'
        text = re.sub(
            r'secondlife://([^/\s]+)(?:/(\d+)(?:/(\d+)(?:/(\d+))?)?)?/?',
            repl_classic_slurl, text, flags=re.IGNORECASE)

        return text

    # Sentinel pattern: \x02R:<type>:<uuid>\x03  (type = agent | group | parcel)
    _SENTINEL_RE = re.compile(r'\x02R:(agent|group|parcel):([0-9a-f\-]{36})\x03')

    # Regex for http/https URLs AND bare www. URLs.
    # www. branch: requires www. + hostname label(s) + '.' + TLD (>=2 letters),
    # with an optional path — prevents false positives on random words.
    _URL_RE = re.compile(
        r'(?:https?://[^\s<>"\')\]}]+'          # full URL with scheme
        r'|(?<![\w.])www\.[a-zA-Z0-9][a-zA-Z0-9\-]*'
        r'(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)*'
        r'\.[a-zA-Z]{2,}(?:[/\?#][^\s<>"\')\]}]*)?)'
    )

    def _insert_chunk_with_links(self, chunk, base_tags):
        """
        Insert a plain-text *chunk* into chat_display, detecting http/https URLs
        and rendering them as clickable cyan underlined hyperlinks.
        *base_tags* is a tuple of any already-active tags to apply to plain text.
        """
        segments = self._URL_RE.split(chunk)
        urls = self._URL_RE.findall(chunk)

        for idx, seg in enumerate(segments):
            if seg:
                self.chat_display.insert(tk.END, seg, base_tags)
            if idx < len(urls):
                url = urls[idx]
                # Create a unique tag for this specific link instance
                self._link_counter += 1
                link_tag = f'link_{self._link_counter}'
                all_link_tags = (link_tag, 'hyperlink') + base_tags
                self.chat_display.tag_config(link_tag, foreground='#00BFFF', underline=True)
                # Bind click to open URL in browser
                self.chat_display.tag_bind(
                    link_tag, '<Button-1>',
                    lambda e, u=url: self._open_url(u)
                )
                # Cursor changes on hover for clear affordance
                self.chat_display.tag_bind(
                    link_tag, '<Enter>',
                    lambda e: self.chat_display.config(cursor='hand2')
                )
                self.chat_display.tag_bind(
                    link_tag, '<Leave>',
                    lambda e: self.chat_display.config(cursor='')
                )
                self.chat_display.insert(tk.END, url, all_link_tags)

    def _open_url(self, url):
        """Open *url* in the system default browser.
        Prepends https:// for bare www. URLs that have no scheme.
        """
        import webbrowser
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        webbrowser.open(url)

    def _insert_with_uri_tags(self, text, extra_tag=None):
        """
        Insert *text* into chat_display, expanding \x02R:<type>:<uuid>\x03 sentinels
        into grey italic 'Resolving\u2026' spans tagged 'sluri_<type>_<uuid>'.
        When the name resolves, _replace_resolving_spans() patches the span and
        turns it into a cyan clickable hyperlink.
        Also converts http/https URLs into clickable hyperlinks.
        """
        parts = self._SENTINEL_RE.split(text)
        # split gives: [plain, type, uuid, plain, type, uuid, ...] (2 capture groups)
        base_tags = (extra_tag,) if extra_tag else ()
        i = 0
        while i < len(parts):
            chunk = parts[i]
            if chunk:
                self._insert_chunk_with_links(chunk, base_tags)
            i += 1
            if i + 1 < len(parts):          # need both type and uuid
                entity_type = parts[i]      # 'agent' | 'group' | 'parcel'
                entity_uuid = parts[i + 1]  # the UUID
                tag = f'sluri_{entity_type}_{entity_uuid}'
                
                # Check cache for immediate resolution
                cached_name = None
                if entity_type == 'agent':
                    cached_name = self.sl_agent.display_name_cache.get(entity_uuid.lower())
                elif entity_type == 'group':
                    cached_name = self.sl_agent.group_name_cache.get(entity_uuid.lower())
                elif entity_type == 'parcel':
                    cached_name = self.sl_agent.parcel_name_cache.get(entity_uuid.lower())
                
                if cached_name and cached_name not in ('Resolving\u2026', ''):
                    # Style as cyan link immediately
                    self.chat_display.tag_config(tag, foreground='#00BFFF', underline=True,
                                                  font=('Courier', 12))
                    self.chat_display.tag_bind(tag, '<Button-1>',
                        lambda e, t=entity_type, u=entity_uuid: self._open_sl_entity_popup(t, u))
                    self.chat_display.tag_bind(tag, '<Enter>',
                        lambda e: self.chat_display.config(cursor='hand2'))
                    self.chat_display.tag_bind(tag, '<Leave>',
                        lambda e: self.chat_display.config(cursor=''))
                    
                    self.chat_display.insert(tk.END, cached_name, (tag,) + base_tags)
                else:
                    # Grey italic while unresolved
                    self.chat_display.tag_config(
                        tag, foreground='#888888', font=('Courier', 10, 'italic'))
                    display_tags = (tag,) + base_tags
                    self.chat_display.insert(tk.END, 'Resolving\u2026', display_tags)
                i += 2

    def _append_chat(self, message, name=None):
        message = self._resolve_sl_uris(message)
        self.chat_display.config(state='normal')

        if name:
            self.chat_display.insert(tk.END, '[')
            self.chat_display.insert(tk.END, name, 'speaker_name')
            self.chat_display.insert(tk.END, ']: ')
            self._insert_with_uri_tags(message)
            self.chat_display.insert(tk.END, '\n')
        else:
            self._insert_with_uri_tags(message)
            self.chat_display.insert(tk.END, '\n')
            
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
        
        self.sl_agent.log(f"Teleport offer received for {region_name}.")
        
        # MODIFIED: Use ThemedMessageBox instead of messagebox.askyesno
        dialog_result = ThemedMessageBox(self.master, "Teleport Offer Received", dialog_text, 'yesno').result
        
        if dialog_result:
            self.sl_agent.accept_teleport_offer(teleport_id, cost)
            self._update_status(f"✅ Accepting teleport to {region_name}...")
        else:
            self._update_status("Teleport offer declined.")
            self._append_notification(f"[INFO] Teleport offer to {region_name} declined.")

    # ------------------------------------------------------------------ #
    #  Right-click context menus                                         #
    # ------------------------------------------------------------------ #

    def _make_context_menu(self):
        """Create a themed popup menu matching the BlackGlass dark style."""
        menu = tk.Menu(self, tearoff=0,
                       bg='#2C2C2C', fg='#E0E0E0',
                       activebackground='#444444', activeforeground='#FFFFFF',
                       relief=tk.FLAT, bd=1)
        return menu

    def _show_chat_context_menu(self, event):
        """Right-click menu for the read-only chat display (copy / select-all)."""
        menu = self._make_context_menu()

        def do_copy():
            try:
                selected = self.chat_display.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.master.clipboard_clear()
                self.master.clipboard_append(selected)
            except tk.TclError:
                pass  # Nothing selected

        def do_select_all():
            self.chat_display.tag_add(tk.SEL, '1.0', tk.END)
            self.chat_display.mark_set(tk.INSERT, '1.0')
            self.chat_display.see(tk.INSERT)

        menu.add_command(label='Copy', command=do_copy)
        menu.add_separator()
        menu.add_command(label='Select All', command=do_select_all)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_entry_context_menu(self, event):
        """Right-click menu for the message Entry (cut / copy / paste / select-all)."""
        menu = self._make_context_menu()

        def do_cut():
            try:
                selected = self.message_entry.selection_get()
                self.master.clipboard_clear()
                self.master.clipboard_append(selected)
                self.message_entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
            except tk.TclError:
                pass

        def do_copy():
            try:
                selected = self.message_entry.selection_get()
                self.master.clipboard_clear()
                self.master.clipboard_append(selected)
            except tk.TclError:
                pass

        def do_paste():
            try:
                text = self.master.clipboard_get()
                # Insert at cursor, replacing any active selection
                try:
                    self.message_entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
                except tk.TclError:
                    pass
                self.message_entry.insert(tk.INSERT, text)
            except tk.TclError:
                pass

        def do_select_all():
            self.message_entry.select_range(0, tk.END)
            self.message_entry.icursor(tk.END)

        menu.add_command(label='Cut',        command=do_cut)
        menu.add_command(label='Copy',       command=do_copy)
        menu.add_command(label='Paste',      command=do_paste)
        menu.add_separator()
        menu.add_command(label='Select All', command=do_select_all)

        # Focus the entry so clipboard operations target it
        self.message_entry.focus_set()
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ------------------------------------------------------------------ #

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
            # In-session teleport; falls back to quick relog automatically on failure.
            self.sl_agent.soft_teleport(region_name.strip())

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
            
