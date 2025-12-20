import tkinter as tk

from tkinter import scrolledtext, messagebox, ttk

import threading

import time

import sys

import struct

import socket

from uuid import UUID

import urllib.request

import io

import json

import base64

import os

import traceback



# --- Third Party Imports ---

try:

    from PIL import Image, ImageTk

except ImportError:

    print("Error: Pillow is required. Please run: pip install pillow")

    sys.exit(1)



# Note: Ensure pyverse is installed or in the same directory

try:

    import pyverse

    from pyverse import UDPStream, authentication

except ImportError:

    print("Error: pyverse library not found. Please ensure it is installed.")

    sys.exit(1)



# --- CONFIGURATION ---

THEME = {

    "bg_dark": "#121212",

    "bg_panel": "#1E1E1E",

    "fg_text": "#E0E0E0",

    "fg_dim": "#A0A0A0",

    "accent": "#00BCD4",

    "border": "#333333",

    "font_main": ("Segoe UI", 10),

    "font_mono": ("Consolas", 9),

    "font_head": ("Segoe UI", 12, "bold")

}



CREDENTIALS_FILE = "credentials_sl.json"

SIDEBAR_WIDTH = 250



# --- SL CONSTANTS ---

CHAT_TYPE_WHISPER = 0

CHAT_TYPE_NORMAL = 1

CHAT_TYPE_SHOUT = 2

CHAT_TYPE_START_TYPING = 4

CHAT_TYPE_STOP_TYPING = 5

CHAT_TYPE_DEBUG = 6



# --- CREDENTIALS MANAGER ---

class CredentialManager:

    @staticmethod

    def _encode(text):

        return base64.b64encode(text.encode()).decode()



    @staticmethod

    def _decode(encoded_text):

        try:

            return base64.b64decode(encoded_text).decode()

        except:

            return ""



    @staticmethod

    def load():

        if not os.path.exists(CREDENTIALS_FILE):

            return []

        try:

            with open(CREDENTIALS_FILE, 'r') as f:

                data = json.load(f)

                for entry in data:

                    entry['password'] = CredentialManager._decode(entry.get('password', ''))

                return data

        except Exception as e:

            print(f"Failed to load credentials: {e}")

            return []



    @staticmethod

    def save(first, last, password, region):

        data = CredentialManager.load()

        data = [d for d in data if not (d['first'] == first and d['last'] == last)]

        

        new_entry = {

            "first": first,

            "last": last,

            "password": password,

            "region": region,

            "display": f"{first} {last}"

        }

        data.insert(0, new_entry)

        

        try:

            with open(CREDENTIALS_FILE, 'w') as f:

                save_data = []

                for entry in data:

                    entry_copy = entry.copy()

                    entry_copy['password'] = CredentialManager._encode(entry_copy['password'])

                    save_data.append(entry_copy)

                json.dump(save_data, f, indent=4)

        except Exception as e:

            print(f"Failed to save credentials: {e}")



# --- Core Second Life Agent Class ---

class SecondLifeAgent:

    def __init__(self, ui_callback, debug_callback):

        self.client = None

        self.ui_callback = ui_callback

        self.debug_callback = debug_callback

        self.running = False

        self.event_thread = None

        self.current_region_name = "Unknown Region"

        

        # Position Tracking

        self.pos_x = 128.0

        self.pos_y = 128.0

        self.region_global_x = 0

        self.region_global_y = 0

        

        # Tracking other avatars: { UUID: (x, y) }

        self.nearby_avatars = {}

        

        # Connection credentials

        self.agent_id = None

        self.session_id = None

        self.circuit_code = None

        self.sim_ip = None

        self.sim_port = None

        self.raw_socket = None

        self.first_name = ""



    def log(self, message):

        if self.debug_callback:

            self.debug_callback(message)



    def _get_attr_robust(self, obj, attr_names, default=None):

        """Try multiple attribute names to retrieve a value."""

        for name in attr_names:

            if hasattr(obj, name):

                val = getattr(obj, name)

                if hasattr(val, 'data'): return val.data

                return val

            if isinstance(obj, dict) and name in obj:

                return obj[name]

        return default



    def _parse_u8(self, val):

        """Force conversion of U8 coordinate values to int."""

        if hasattr(val, 'data'): val = val.data

        if isinstance(val, int): return val

        if isinstance(val, float): return int(val)

        if isinstance(val, (bytes, bytearray)):

            if len(val) > 0: return val[0]

            return 0

        try:

            return int(val)

        except:

            return 0



    def _event_handler(self):

        self.log("DEBUG: Event handler thread started.")

        

        while self.running and self.client:

            try:

                packet = self.client.recv()



                if packet:

                    packet_name = getattr(packet, 'name', 'Unknown')

                    if packet_name == 'Unknown' and hasattr(packet, 'body'):

                        packet_name = getattr(packet.body, 'name', 'Unknown')

                    

                    # --- PACKET HANDLERS ---

                    

                    if packet_name == "RegionHandshake":

                        self.log("DEBUG: Received RegionHandshake")

                        self.send_region_handshake_reply_raw(packet)

                        self.ui_callback("status", f"🟢 Connected to {self.current_region_name}!")

                        self.ui_callback("region_name", self.current_region_name)

                        self.ui_callback("map_update", (self.region_global_x, self.region_global_y))

                        time.sleep(0.1)

                        self.send_complete_movement_raw()



                    elif packet_name == "CoarseLocationUpdate":

                        # Updated Handler: Handles Variable Blocks 'Location' and 'Index'

                        try:

                            body = getattr(packet, 'body', packet)

                            

                            # Get blocks. In pyverse/template/SL, these are usually 'Location' and 'Index'

                            # or sometimes 'AgentData'. We try to be flexible.

                            loc_block = getattr(body, 'Location', [])

                            idx_block = getattr(body, 'Index', [])

                            

                            if not isinstance(loc_block, list): loc_block = [loc_block]

                            if not isinstance(idx_block, list): idx_block = [idx_block]



                            # The count should match

                            count = min(len(loc_block), len(idx_block))

                            

                            temp_nearby = {}

                            

                            for i in range(count):

                                loc_data = loc_block[i]

                                idx_data = idx_block[i]

                                

                                # Extract ID: Try 'AgentID', 'Prey', 'Target'

                                uid_raw = self._get_attr_robust(idx_data, ['AgentID', 'Prey', 'Target'])

                                if uid_raw is None: 

                                    # Sometimes the block itself is the ID if it's not a structured object

                                    uid_raw = idx_data



                                try:

                                    if hasattr(uid_raw, 'data'): uid_raw = uid_raw.data

                                    uid = UUID(bytes=uid_raw)

                                except:

                                    continue 



                                # Extract Coords: Try 'X', 'x', 'Y', 'y'

                                raw_x = self._get_attr_robust(loc_data, ['X', 'x', 'PositionX'])

                                raw_y = self._get_attr_robust(loc_data, ['Y', 'y', 'PositionY'])

                                

                                lx = float(self._parse_u8(raw_x))

                                ly = float(self._parse_u8(raw_y))

                                

                                if uid == self.agent_id:

                                    self.pos_x = lx

                                    self.pos_y = ly

                                else:

                                    temp_nearby[uid] = (lx, ly)

                            

                            self.nearby_avatars = temp_nearby

                            self.ui_callback("agent_moved", (self.pos_x, self.pos_y))

                            

                        except Exception as e:

                            # Use traceback only if really needed to debug crashes

                            # traceback.print_exc()

                            pass



                    elif packet_name == "ChatFromSimulator":

                        chat_data = getattr(packet, 'ChatData', None)

                        if not chat_data and hasattr(packet, 'body'):

                             chat_data = getattr(packet.body, 'ChatData', None)

                             

                        if chat_data:

                            if isinstance(chat_data, list):

                                block = chat_data[0]

                            else:

                                block = chat_data



                            def safe_decode(val):

                                if hasattr(val, 'data'): val = val.data

                                if isinstance(val, (bytes, bytearray)):

                                    return val.decode('utf-8', 'ignore').strip('\x00')

                                return str(val).strip('\x00')



                            raw_name = getattr(block, 'FromName', 'Unknown')

                            raw_message = getattr(block, 'Message', '')

                            chat_type = getattr(block, 'ChatType', 1)

                            

                            try:

                                if hasattr(chat_type, 'data'): chat_type = int(chat_type.data)

                                else: chat_type = int(chat_type)

                            except: chat_type = 1



                            name_str = safe_decode(raw_name)

                            msg_str = safe_decode(raw_message)



                            if chat_type not in [CHAT_TYPE_START_TYPING, CHAT_TYPE_STOP_TYPING]:

                                prefix = ""

                                if chat_type == CHAT_TYPE_WHISPER: prefix = "(Whisper) "

                                elif chat_type == CHAT_TYPE_SHOUT: prefix = "(Shout) "

                                elif chat_type == CHAT_TYPE_DEBUG: prefix = "(Debug) "

                                self.ui_callback("chat", f"{prefix}[{name_str}]: {msg_str}")



                    elif packet_name == "TeleportFinish":

                        self.ui_callback("status", "🚀 Teleport finished!")



                    elif packet_name == "CloseCircuit":

                        self.ui_callback("status", "👋 Disconnected.")

                        self.running = False

                        break

                

            except Exception as e:

                if self.running and "timed out" not in str(e):

                    # print(f"Event Loop Error: {e}")

                    pass

                if not self.running: break

            

            time.sleep(0.005)



    # --- PACKET HELPERS ---

    def get_socket(self):

        for attr in ['socket', 'sock', '_socket', 'udp_socket']:

            if hasattr(self.client, attr): return getattr(self.client, attr)

        return None



    def _get_next_sequence(self):

        try:

            self.client.sequence += 1

            return self.client.sequence

        except AttributeError:

            self.client.sequence = 1

            return 1



    def send_raw_packet(self, data):

        try:

            if not self.raw_socket: self.raw_socket = self.get_socket()

            if self.raw_socket and self.sim_ip and self.sim_port:

                self.raw_socket.sendto(data, (self.sim_ip, self.sim_port))

                return True

            return False

        except Exception: return False



    def send_use_circuit_code_raw(self):

        try:

            header = struct.pack('>BLBL', 0x40, 1, 0x00, 0xFFFF0003)

            payload = struct.pack('<L', self.circuit_code) + self.session_id.bytes + self.agent_id.bytes

            self.send_raw_packet(header + payload)

        except Exception as e:

            self.log(f"Error sending UseCircuitCode: {e}")

    

    def send_region_handshake_reply_raw(self, handshake_packet):

        try:

            body = getattr(handshake_packet, 'body', None)

            if not body: body = handshake_packet

            region_info_list = getattr(body, 'RegionInfo', [])

            if not region_info_list: return

            region_info = region_info_list[0] if isinstance(region_info_list, list) else region_info_list

            r_flags = getattr(region_info, 'RegionFlags', 0)

            flags_val = 0

            if hasattr(r_flags, 'data'): flags_val = int(r_flags.data)

            else:

                try: flags_val = int(r_flags)

                except: pass

            next_seq = self._get_next_sequence()

            header = struct.pack('>BLBL', 0x40, next_seq, 0x00, 0xFFFF00FE)

            payload = self.agent_id.bytes + self.session_id.bytes + struct.pack('<L', flags_val)

            self.send_raw_packet(header + payload)

        except Exception as e:

            self.log(f"ERROR in Handshake Reply: {e}")



    def send_complete_movement_raw(self):

        try:

            next_seq = self._get_next_sequence()

            header = struct.pack('>BLBL', 0x40, next_seq, 0x00, 0xFFFF00F9)

            payload = self.agent_id.bytes + self.session_id.bytes + struct.pack('<L', self.circuit_code)

            self.send_raw_packet(header + payload)

        except Exception as e:

            self.log(f"Error sending CompleteMovement: {e}")



    def send_chat_raw(self, message, channel=0, chat_type=1): 

        try:

            message_bytes = message.encode('utf-8') + b'\x00'

            msg_len = len(message_bytes)

            next_seq = self._get_next_sequence()

            header = struct.pack('>BLBL', 0x40, next_seq, 0x00, 0xFFFF00F8)

            agent_data = self.agent_id.bytes + self.session_id.bytes

            chat_block = struct.pack('<H', msg_len) + message_bytes + struct.pack('<Bi', chat_type, channel)

            self.send_raw_packet(header + agent_data + chat_block)

        except Exception as e:

            self.log(f"Error sending Chat: {e}")



    def login(self, first, last, password, region_name):

        self.ui_callback("status", "🌐 Connecting to grid...")

        try:

            authentication.LOGIN_URI = "https://login.agni.secondlife.com/cgi-bin/login.cgi"

            login_token = pyverse.login(first, last, password, start=region_name)



            if login_token.get("login") != "true":

                 raise ConnectionError(login_token.get("message", "Unknown login error"))

            

            self.circuit_code = int(login_token['circuit_code'])

            self.agent_id = UUID(login_token['agent_id'])

            self.session_id = UUID(login_token['session_id'])

            self.sim_ip = login_token.get('sim_ip')

            self.sim_port = int(login_token.get('sim_port'))

            self.first_name = first

            

            # Extract Region Name: check multiple keys

            # 'sim_name' is standard but sometimes it's 'region'

            possible_keys = ['sim_name', 'region_name', 'region', 'message']

            self.current_region_name = "Unknown Region"

            for k in possible_keys:

                if k in login_token and isinstance(login_token[k], str):

                     # Filter out generic messages if they aren't names

                     val = login_token[k]

                     if len(val) < 50 and "Welcome" not in val:

                         self.current_region_name = val

                         break

            

            # Send name immediately to UI

            self.ui_callback("region_name", self.current_region_name)



            try:

                rx_str = login_token.get('region_x', '0')

                ry_str = login_token.get('region_y', '0')

                self.region_global_x = int(float(rx_str)) // 256

                self.region_global_y = int(float(ry_str)) // 256

            except: pass



            self.client = UDPStream.region(login_token, host="0.0.0.0", port=0)

            self.raw_socket = self.get_socket()

            

            self.running = True

            self.event_thread = threading.Thread(target=self._event_handler, daemon=True)

            self.event_thread.start()

            

            time.sleep(0.5)

            self.send_use_circuit_code_raw()

            return True

        except Exception as e:

            self.ui_callback("error", f"❌ Connection Error: {e}")

            self.stop()

            return False



    def send_chat(self, message, channel=0, chat_type=1):

        if self.client and self.running: 

            self.send_chat_raw(message, channel, chat_type)

        

    def stop(self):

        self.running = False

        if self.client:

            try: self.client.logout() 

            except: pass 



# --- UI COMPONENTS ---



class MinimapWidget(tk.Canvas):

    def __init__(self, master, size=SIDEBAR_WIDTH):

        super().__init__(master, width=size, height=size, bg="black", highlightthickness=0)

        self.size = size

        self.bg_image = None

        self.create_text(size/2, size/2, text="Waiting for Login...", fill="white", tags="loading")



    def load_region_tile(self, grid_x, grid_y):

        self.delete("loading")

        self.create_text(self.size/2, self.size/2, text="Loading Map...", fill="white", tags="loading")

        

        def fetch():

            try:

                url = f"http://map.secondlife.com/map-1-{grid_x}-{grid_y}-objects.jpg"

                with urllib.request.urlopen(url, timeout=10) as u:

                    raw_data = u.read()

                image = Image.open(io.BytesIO(raw_data))

                image = image.resize((self.size, self.size), Image.Resampling.LANCZOS)

                self.bg_image = image

                self.after(0, self.display_map)

            except Exception as e: 

                print(f"Map Fetch Error: {e}")

                self.after(0, self.cleanup_loading)

                

        threading.Thread(target=fetch, daemon=True).start()



    def cleanup_loading(self):

        self.delete("loading")

        self.create_text(self.size/2, self.size/2, text="Map Unavailable", fill="gray", tags="bg")



    def display_map(self):

        self.delete("loading")

        if self.bg_image:

            self.tk_image = ImageTk.PhotoImage(self.bg_image)

            self.delete("bg")

            self.create_image(0, 0, anchor=tk.NW, image=self.tk_image, tags="bg")

            self.tag_lower("bg")



    def update_positions(self, self_x, self_y, nearby_dict):

        self.delete("agent_marker")

        self.delete("nearby_marker")

        

        scale = self.size / 256.0

        

        # Draw Other Avatars (Black dots)

        for uid, pos in nearby_dict.items():

            nx = pos[0] * scale

            ny = self.size - (pos[1] * scale)

            r = 3

            self.create_oval(nx-r, ny-r, nx+r, ny+r, fill="black", outline="#444444", width=1, tags="nearby_marker")

            

        # Draw Self (Cyan dot, no text)

        sx = self_x * scale

        sy = self.size - (self_y * scale)

        r_self = 5

        self.create_oval(sx-r_self, sy-r_self, sx+r_self, sy+r_self, fill="#00BCD4", outline="white", width=2, tags="agent_marker")



class ChatWindow(tk.Toplevel):

    def __init__(self, master, sl_agent, first, last):

        super().__init__(master)

        self.master.withdraw() 

        self.title(f"Viewer - {first} {last}")

        self.geometry("1100x750") 

        self.configure(bg=THEME["bg_dark"])

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        

        self.sl_agent = sl_agent

        self.my_first_name = first

        

        self._setup_styles()

        self._create_layout()

        

        if self.sl_agent.region_global_x > 0:

            self.update_ui("map_update", (self.sl_agent.region_global_x, self.sl_agent.region_global_y))

        

        # Initialize region name immediately

        self.loc_label.config(text=self.sl_agent.current_region_name)



    def _setup_styles(self):

        style = ttk.Style()

        style.theme_use('clam')

        style.configure("Dark.TFrame", background=THEME["bg_dark"])

        style.configure("Glass.TFrame", background=THEME["bg_panel"], relief="flat")

        style.configure("TCombobox", fieldbackground="#2A2A2A", background="#333", foreground="white", arrowcolor="white")



    def _create_layout(self):

        self.columnconfigure(0, weight=1) 

        self.columnconfigure(1, weight=0) 

        self.rowconfigure(0, weight=1)



        chat_container = tk.Frame(self, bg=THEME["bg_dark"], padx=10, pady=10)

        chat_container.grid(row=0, column=0, sticky="nsew")

        

        self.chat_display = scrolledtext.ScrolledText(

            chat_container, state='disabled', wrap=tk.WORD, 

            bg=THEME["bg_panel"], fg=THEME["fg_text"],

            insertbackground="white", font=THEME["font_main"], bd=0, highlightthickness=0

        )

        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        

        input_frame = tk.Frame(chat_container, bg=THEME["bg_panel"], pady=5, padx=5)

        input_frame.pack(fill=tk.X)

        

        self.chat_type_var = tk.StringVar(value="Say")

        self.type_combo = ttk.Combobox(

            input_frame, textvariable=self.chat_type_var, 

            values=["Whisper", "Say", "Shout"], 

            state="readonly", width=8

        )

        self.type_combo.pack(side=tk.LEFT, padx=(0, 5))



        tk.Label(input_frame, text="Ch:", bg=THEME["bg_panel"], fg="white").pack(side=tk.LEFT)

        self.channel_entry = tk.Entry(input_frame, bg="#2A2A2A", fg="white", width=4, relief=tk.FLAT, insertbackground="white")

        self.channel_entry.insert(0, "0")

        self.channel_entry.pack(side=tk.LEFT, padx=(2, 5))

        

        self.message_entry = tk.Entry(input_frame, bg="#2A2A2A", fg="white", insertbackground="white", relief=tk.FLAT, font=THEME["font_main"])

        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), ipady=5)

        self.message_entry.bind("<Return>", lambda e: self.send_message())

        

        tk.Button(

            input_frame, text="SEND", command=self.send_message, 

            bg=THEME["accent"], fg="white", relief=tk.FLAT, font=("Segoe UI", 9, "bold")

        ).pack(side=tk.RIGHT)



        sidebar = tk.Frame(self, bg=THEME["bg_dark"], width=SIDEBAR_WIDTH)

        sidebar.grid(row=0, column=1, sticky="nsew", padx=(0,10), pady=10)

        sidebar.grid_propagate(False) 



        sidebar.columnconfigure(0, weight=1)

        sidebar.rowconfigure(1, weight=1)



        tk.Label(sidebar, text="SYSTEM LOG", bg=THEME["bg_dark"], fg=THEME["fg_dim"], font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", pady=(0,5))

        

        self.debug_text = scrolledtext.ScrolledText(

            sidebar, bg=THEME["bg_panel"], fg="#00FF00", 

            font=THEME["font_mono"], bd=0, highlightthickness=0, width=1

        )

        self.debug_text.grid(row=1, column=0, sticky="nsew", pady=(0, 15))

        

        self.loc_label = tk.Label(sidebar, text="Unknown Region", bg=THEME["bg_dark"], fg=THEME["accent"], font=THEME["font_main"])

        self.loc_label.grid(row=2, column=0, sticky="ew", pady=(0, 5))



        self.minimap = MinimapWidget(sidebar, size=SIDEBAR_WIDTH)

        self.minimap.grid(row=3, column=0, sticky="s")



    def update_ui(self, update_type, message):

        if update_type == "chat":

            self.chat_display.config(state='normal')

            self.chat_display.insert(tk.END, message + "\n")

            self.chat_display.config(state='disabled')

            self.chat_display.see(tk.END) 

        elif update_type == "status":

            self.add_debug_log(message)

        elif update_type == "error":

            messagebox.showerror("Agent Error", message)

            self.add_debug_log(f"ERROR: {message}")

        elif update_type == "region_name":

            self.loc_label.config(text=message)

        elif update_type == "map_update":

            if isinstance(message, tuple):

                gx, gy = message

                self.minimap.load_region_tile(gx, gy)

        elif update_type == "agent_moved":

            self.minimap.update_positions(self.sl_agent.pos_x, self.sl_agent.pos_y, self.sl_agent.nearby_avatars)



    def add_debug_log(self, msg):

        self.debug_text.config(state='normal')

        self.debug_text.insert(tk.END, f"> {msg}\n")

        self.debug_text.config(state='disabled')

        self.debug_text.see(tk.END)



    def send_message(self):

        message = self.message_entry.get().strip()

        if not message: return

        type_str = self.chat_type_var.get()

        c_type = CHAT_TYPE_NORMAL

        if type_str == "Whisper": c_type = CHAT_TYPE_WHISPER

        elif type_str == "Shout": c_type = CHAT_TYPE_SHOUT

        try:

            channel = int(self.channel_entry.get().strip())

        except:

            channel = 0

        self.chat_display.config(state='normal')

        prefix = ""

        if c_type == CHAT_TYPE_WHISPER: prefix = "(Whisper) "

        elif c_type == CHAT_TYPE_SHOUT: prefix = "(Shout) "

        self.chat_display.insert(tk.END, f"{prefix}[{self.my_first_name}]: {message}\n")

        self.chat_display.config(state='disabled')

        self.chat_display.see(tk.END)

        self.sl_agent.send_chat(message, channel, c_type)

        self.message_entry.delete(0, tk.END)



    def on_closing(self):

        if messagebox.askyesno("Quit", "Log out and exit?"):

            self.sl_agent.stop()

            self.destroy()

            self.master.destroy()



# --- LOGIN WINDOW ---

class LoginWindow(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title("Second Life Login")

        self.geometry("400x600") 

        self.configure(bg=THEME["bg_dark"])

        self.sl_agent = SecondLifeAgent(self.handle_agent_update, self.handle_debug_log)

        self.saved_creds = CredentialManager.load()

        self._create_widgets()

        self.eval('tk::PlaceWindow . center')

        self.chat_win = None



    def _create_widgets(self):

        tk.Label(self, text="SL CONNECT", bg=THEME["bg_dark"], fg=THEME["accent"], font=("Segoe UI", 20, "bold")).pack(pady=20)

        if self.saved_creds:

            top_frame = tk.Frame(self, bg=THEME["bg_dark"], pady=10)

            top_frame.pack(fill=tk.X, padx=40)

            tk.Label(top_frame, text="SAVED ACCOUNTS", bg=THEME["bg_dark"], fg=THEME["fg_dim"], font=("Segoe UI", 8)).pack(anchor="w")

            style = ttk.Style()

            style.theme_use('clam')

            self.profile_var = tk.StringVar()

            self.combo = ttk.Combobox(top_frame, textvariable=self.profile_var, state="readonly")

            self.combo['values'] = [x['display'] for x in self.saved_creds]

            self.combo.pack(fill=tk.X)

            self.combo.bind("<<ComboboxSelected>>", self.autofill_creds)



        form_frame = tk.Frame(self, bg=THEME["bg_dark"])

        form_frame.pack(pady=10)

        

        def entry_field(lbl, show=None):

            f = tk.Frame(form_frame, bg=THEME["bg_dark"], pady=5)

            f.pack(fill=tk.X)

            tk.Label(f, text=lbl.upper(), bg=THEME["bg_dark"], fg=THEME["fg_dim"], font=("Segoe UI", 8)).pack(anchor="w")

            e = tk.Entry(f, bg="#2A2A2A", fg="white", insertbackground="white", relief=tk.FLAT, width=30, show=show)

            e.pack(ipady=4)

            return e



        self.first_name_entry = entry_field("First Name")

        self.last_name_entry = entry_field("Last Name")

        self.password_entry = entry_field("Password", show="*")

        self.region_entry = entry_field("Start Region")

        self.region_entry.insert(0, "last")

        

        self.login_button = tk.Button(

            self, text="LOGIN", command=self.start_login_thread,

            bg=THEME["accent"], fg="white", relief=tk.FLAT,

            font=("Segoe UI", 11, "bold"), width=25

        )

        self.login_button.pack(pady=30)

        

        self.status_label = tk.Label(self, text="Ready", bg=THEME["bg_dark"], fg=THEME["fg_dim"])

        self.status_label.pack(side=tk.BOTTOM, pady=10)

        self.log_cache = []



    def autofill_creds(self, event):

        idx = self.combo.current()

        if idx >= 0:

            data = self.saved_creds[idx]

            self.first_name_entry.delete(0, tk.END)

            self.first_name_entry.insert(0, data['first'])

            self.last_name_entry.delete(0, tk.END)

            self.last_name_entry.insert(0, data['last'])

            self.password_entry.delete(0, tk.END)

            self.password_entry.insert(0, data['password'])

            self.region_entry.delete(0, tk.END)

            self.region_entry.insert(0, data.get('region', 'last'))



    def handle_debug_log(self, message):

        self.log_cache.append(message)

        print(message) 



    def handle_agent_update(self, update_type, message):

        if update_type == "status":

            self.status_label.config(text=message, fg=THEME["accent"])

            if "Connected to" in message or "Logged in" in message:

                self.withdraw()

                first = self.first_name_entry.get().strip()

                last = self.last_name_entry.get().strip()

                CredentialManager.save(first, last, self.password_entry.get(), self.region_entry.get().strip())

                self.chat_win = ChatWindow(self, self.sl_agent, first, last)

                for log in self.log_cache: self.chat_win.add_debug_log(log)

        elif update_type == "error":

            messagebox.showerror("Login Error", message)

            self.status_label.config(text=message, fg="#FF5252")

            self.login_button.config(state=tk.NORMAL, text="LOGIN")

        elif self.chat_win: 

             self.chat_win.update_ui(update_type, message)

            

    def login_task(self, first, last, password, region_name):

        success = self.sl_agent.login(first, last, password, region_name)

        if not success:

            self.after(100, lambda: self.login_button.config(state=tk.NORMAL, text="LOGIN"))



    def start_login_thread(self):

        first = self.first_name_entry.get().strip()

        last = self.last_name_entry.get().strip()

        password = self.password_entry.get()

        raw_region_name = self.region_entry.get().strip() 

        lower_reg = raw_region_name.lower()

        if lower_reg in ["last", "home"]:

             formatted_region_name = lower_reg

        else:

             formatted_region_name = f"uri:{raw_region_name}&128&128&30"

        if not first or not last or not password:

            self.status_label.config(text="All fields are required.", fg="#FF5252")

            return

        self.login_button.config(state=tk.DISABLED, text="CONNECTING...")

        self.status_label.config(text="Authenticating...", fg="white")

        threading.Thread(target=self.login_task, args=(first, last, password, formatted_region_name), daemon=True).start()



if __name__ == "__main__":

    app = LoginWindow()

    app.mainloop()