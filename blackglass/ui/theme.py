"""Themed dialogs: consistent BlackGlass-styled popups and image panels."""

import os
import urllib.request
import tkinter as tk
from tkinter import Toplevel, ttk
from io import BytesIO
import re
import threading

from ..imaging import PIL_AVAILABLE, Image, ImageTk
from ..network import SL_USER_AGENT


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

class ThemedGroupDialog(Toplevel):
    """Displays Second Life group information scraped from world.secondlife.com/group/<uuid>."""

    def __init__(self, parent, data, chat_tab, uid_key):
        super().__init__(parent)
        self.data = data
        self.chat_tab = chat_tab
        self.uid_key = uid_key
        self.transient(parent)
        self.title(f"Group: {data.get('name', 'Unknown')}")
        self.configure(bg='#0A0A0A')
        self.resizable(False, False)
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self._setup_ui()
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        self.geometry(f'+{px+(pw-w)//2}+{py+(ph-h)//2}')
        self.focus_set()

    def _setup_ui(self):
        for c in self.winfo_children(): c.destroy()
        d = self.data
        pad = {'padx': 20, 'pady': 20}
        f = ttk.Frame(self, style='BlackGlass.TFrame')
        f.pack(fill=tk.BOTH, expand=True, **pad)

        # ── Header ──────────────────────────────────────────────────
        ttk.Label(f, text=d.get('name', 'Unknown Group'),
                  style='BlackGlass.TLabel',
                  font=('Helvetica', 14, 'bold')).pack(anchor='w')
        ttk.Label(f, text=f"ID: {d.get('id', '')}",
                  style='BlackGlass.TLabel',
                  font=('Courier', 8), foreground='#888888').pack(anchor='w', pady=(0, 10))

        # ── Content row: image left, details right ───────────────────
        row = ttk.Frame(f, style='BlackGlass.TFrame')
        row.pack(fill=tk.BOTH, expand=True)

        # Group image
        self._img_label = ttk.Label(row, background='#1C1C1C',
                                    text='\nNo Image\n', anchor='center', width=16)
        self._img_label.pack(side=tk.LEFT, padx=(0, 15), anchor='n')
        image_id = d.get('image_id', '')
        if image_id and image_id != '00000000-0000-0000-0000-000000000000':
            self._img_label.configure(text='Loading…')
            threading.Thread(target=self._fetch_image, args=(image_id,), daemon=True).start()

        # Details column
        right = ttk.Frame(row, style='BlackGlass.TFrame')
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        def lbl(parent, label, value, fg=None):
            is_loading = d.get('source') != 'web'
            display_value = value if value else ('...' if is_loading else None)
            if not display_value: return

            ttk.Label(parent, text=label, style='BlackGlass.TLabel',
                      font=('Helvetica', 10, 'bold')).pack(anchor='w')
            kw = {'style': 'BlackGlass.TLabel', 'anchor': 'w'}
            if fg: kw['foreground'] = fg
            ttk.Label(parent, text=display_value, **kw).pack(anchor='w', pady=(0, 6), padx=5)

        # Group Description (About / Charter)
        desc = d.get('description', '').strip()
        is_loading = d.get('source') != 'web'
        if desc or is_loading:
            ttk.Label(right, text='Group Information:', style='BlackGlass.TLabel',
                      font=('Helvetica', 10, 'bold')).pack(anchor='w')
            txt = tk.Text(right, height=12, width=42,
                          bg='#1E1E1E', fg='#CCCCCC', font=('Helvetica', 10),
                          relief=tk.FLAT, highlightthickness=1,
                          highlightbackground='#333333', wrap=tk.WORD, cursor='arrow')
            txt.tag_config('hyperlink', foreground='#00BFFF', underline=True)
            txt.insert(tk.END, desc or 'Loading group info...')
            
            if desc:
                # Detect and tag URLs in the group description
                url_pattern = re.compile(r'https?://[^\s\]\[<>\"\']+', re.I)
                for match in url_pattern.finditer(desc):
                    start_i = f"1.0 + {match.start()} chars"
                    end_i = f"1.0 + {match.end()} chars"
                    link_tag = f"link_{match.start()}"
                    url = match.group(0)
                    txt.tag_add(link_tag, start_i, end_i)
                    txt.tag_config(link_tag, foreground='#00BFFF', underline=True)
                    txt.tag_bind(link_tag, '<Button-1>', lambda e, u=url: __import__('webbrowser').open(u))
                    txt.tag_bind(link_tag, '<Enter>', lambda e: txt.config(cursor='hand2'))
                    txt.tag_bind(link_tag, '<Leave>', lambda e: txt.config(cursor='arrow'))

            txt.config(state='disabled')
            txt.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        else:
            ttk.Label(right, text='No group information provided.', 
                      style='BlackGlass.TLabel', font=('Helvetica', 10, 'italic')).pack(anchor='w')

        # Web link
        uid = d.get('id', '')
        web_url = f'https://world.secondlife.com/group/{uid}' if uid else ''
        if web_url:
            link = ttk.Label(f, text=web_url, style='BlackGlass.TLabel',
                             foreground='#00BFFF', cursor='hand2')
            link.pack(anchor='w', pady=(4, 0))
            link.bind('<Button-1>', lambda e, u=web_url: __import__('webbrowser').open(u))

        ttk.Button(self, text='Close', width=12, command=self.on_close,
                   style='BlackGlass.TButton').pack(pady=(0, 10))

    def update_data(self, new_data):
        self.data.update(new_data)
        self.title(f"Group: {self.data.get('name', 'Unknown')}")
        self._setup_ui()
        self.lift()

    def _fetch_image(self, image_id):
        if not PIL_AVAILABLE:
            self._img_label.after(0, lambda: self._img_label.configure(text='\nPIL missing\n'))
            return
        url = f'https://picture-service.secondlife.com/{image_id}/256x192.jpg'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': SL_USER_AGENT})
            with urllib.request.urlopen(req, timeout=10) as r:
                if r.getcode() == 200:
                    img = Image.open(BytesIO(r.read()))
                    img.thumbnail((128, 128), Image.Resampling.LANCZOS
                                  if hasattr(Image, 'Resampling') else Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self._photo = photo
                    self._img_label.after(0, lambda p=photo:
                        self._img_label.configure(image=p, text=''))
        except Exception:
            self._img_label.after(0, lambda: self._img_label.configure(text='\nNo Image\n'))

    def on_close(self):
        self.chat_tab.active_profiles.pop(self.uid_key, None)
        self.destroy()


class ThemedParcelDialog(Toplevel):
    """Displays Second Life parcel information scraped from world.secondlife.com/place/<uuid>."""

    def __init__(self, parent, data, chat_tab, uid_key):
        super().__init__(parent)
        self.data = data
        self.chat_tab = chat_tab
        self.uid_key = uid_key
        self.transient(parent)
        self.title(f"Parcel: {data.get('name', 'Unknown')}")
        self.configure(bg='#0A0A0A')
        self.resizable(False, False)
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self._setup_ui()
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        self.geometry(f'+{px+(pw-w)//2}+{py+(ph-h)//2}')
        self.focus_set()

    def _setup_ui(self):
        for c in self.winfo_children(): c.destroy()
        d = self.data
        f = ttk.Frame(self, style='BlackGlass.TFrame')
        f.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # ── Header ──────────────────────────────────────────────────
        ttk.Label(f, text=d.get('name', 'Unknown Parcel'),
                  style='BlackGlass.TLabel',
                  font=('Helvetica', 14, 'bold')).pack(anchor='w')
        ttk.Label(f, text=f"ID: {d.get('id', '')}",
                  style='BlackGlass.TLabel',
                  font=('Courier', 8), foreground='#888888').pack(anchor='w', pady=(0, 10))

        # ── Content row: snapshot left, details right ────────────────
        row = ttk.Frame(f, style='BlackGlass.TFrame')
        row.pack(fill=tk.BOTH, expand=True)

        self._img_label = ttk.Label(row, background='#1C1C1C',
                                    text='\nNo Image\n', anchor='center', width=16)
        self._img_label.pack(side=tk.LEFT, padx=(0, 15), anchor='n')

        # Try snapshot URL first, then imageid
        snap_url = d.get('snapshot', '')
        image_id = d.get('image_id', '')
        if snap_url and snap_url.startswith('http'):
            self._img_label.configure(text='Loading…')
            threading.Thread(target=self._fetch_url_image, args=(snap_url,), daemon=True).start()
        elif image_id and image_id != '00000000-0000-0000-0000-000000000000':
            self._img_label.configure(text='Loading…')
            pic_url = f'https://picture-service.secondlife.com/{image_id}/256x192.jpg'
            threading.Thread(target=self._fetch_url_image, args=(pic_url,), daemon=True).start()

        # Details column
        right = ttk.Frame(row, style='BlackGlass.TFrame')
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        def lbl(label, value, fg=None):
            display_value = value if value else ('...' if is_loading else None)
            if not display_value: return

            ttk.Label(right, text=label, style='BlackGlass.TLabel',
                      font=('Helvetica', 10, 'bold')).pack(anchor='w')
            kw = {'style': 'BlackGlass.TLabel', 'anchor': 'w'}
            if fg: kw['foreground'] = fg
            ttk.Label(right, text=display_value, **kw).pack(anchor='w', pady=(0, 6), padx=5)

        is_loading = d.get('source') != 'web'

        region   = d.get('region', '')
        location = d.get('location', '')
        mat      = d.get('mat', '')
        category = d.get('category', '')
        owner    = d.get('owner', '')
        area     = d.get('area', '')

        lbl('Region:', region)
        lbl('Location:', location)
        if mat:
            mat_labels = {'PG': 'General', 'M_AO': 'Moderate', 'A_AO': 'Adult'}
            lbl('Maturity:', mat_labels.get(mat.upper(), mat))
        # Filter out the placeholder 'Loading...' owner value from the SL website
        if owner and owner.strip().lower() != 'loading...':
            lbl('Owner:', owner)
        if category:
            lbl('Category:', category)
        if area:
            try:
                lbl('Area:', f'{int(area):,} m\u00b2')
            except ValueError:
                lbl('Area:', area)

        desc = d.get('description', '').strip()
        if desc or is_loading:
            ttk.Label(right, text='Description:', style='BlackGlass.TLabel',
                      font=('Helvetica', 10, 'bold')).pack(anchor='w')
            txt = tk.Text(right, height=6, width=42,
                          bg='#1E1E1E', fg='#CCCCCC', font=('Helvetica', 10),
                          relief=tk.FLAT, highlightthickness=1,
                          highlightbackground='#333333', wrap=tk.WORD, cursor='arrow')
            txt.insert(tk.END, desc or 'Loading parcel info...')
            txt.config(state='disabled')
            txt.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        uid = d.get('id', '')
        web_url = f'https://world.secondlife.com/place/{uid}' if uid else ''
        if web_url:
            link = ttk.Label(f, text=web_url, style='BlackGlass.TLabel',
                             foreground='#00BFFF', cursor='hand2')
            link.pack(anchor='w', pady=(4, 0))
            link.bind('<Button-1>', lambda e, u=web_url: __import__('webbrowser').open(u))

        # ── Button row ───────────────────────────────────────────────
        btn_row = ttk.Frame(self, style='BlackGlass.TFrame')
        btn_row.pack(pady=(0, 10))

        region = d.get('region', '')
        location = d.get('location', '')   # "X/Y/Z"

        def _do_teleport(r=region, loc=location):
            if not r:
                return
            try:
                parts = [int(v) for v in loc.split('/')]
                x, y, z = parts[0], parts[1], parts[2] + 1  # +1 to avoid floor clip
            except Exception:
                x, y, z = 128, 128, 30
            self.chat_tab.sl_agent.soft_teleport(r, x, y, z)
            self.on_close()

        tp_btn = ttk.Button(btn_row, text='Teleport To', width=14,
                            command=_do_teleport, style='BlackGlass.TButton')
        tp_btn.pack(side=tk.LEFT, padx=(0, 8))
        if not region:
            tp_btn.config(state='disabled')

        ttk.Button(btn_row, text='Close', width=12, command=self.on_close,
                   style='BlackGlass.TButton').pack(side=tk.LEFT)


    def update_data(self, new_data):
        self.data.update(new_data)
        self.title(f"Parcel: {self.data.get('name', 'Unknown')}")
        self._setup_ui()
        self.lift()


    def _fetch_url_image(self, url):
        if not PIL_AVAILABLE:
            self._img_label.after(0, lambda: self._img_label.configure(text='\nPIL missing\n'))
            return
        try:
            req = urllib.request.Request(url, headers={'User-Agent': SL_USER_AGENT})
            with urllib.request.urlopen(req, timeout=10) as r:
                if r.getcode() == 200:
                    img = Image.open(BytesIO(r.read()))
                    img.thumbnail((128, 128), Image.Resampling.LANCZOS
                                  if hasattr(Image, 'Resampling') else Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self._photo = photo
                    self._img_label.after(0, lambda p=photo:
                        self._img_label.configure(image=p, text=''))
        except Exception:
            self._img_label.after(0, lambda: self._img_label.configure(text='\nNo Image\n'))

    def on_close(self):
        self.chat_tab.active_profiles.pop(self.uid_key, None)
        self.destroy()


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
            txt.tag_bind(tag_name, '<Button-1>', lambda e, u=link_url: __import__('webbrowser').open(u))
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
             link.bind("<Button-1>", lambda e: __import__('webbrowser').open(url))
        
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

