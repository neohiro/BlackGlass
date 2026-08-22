"""LoginPanel: grid login form with credential management."""

import tkinter as tk
from tkinter import ttk
import threading
import urllib.parse
import urllib.request

from ..credentials import load_credentials, save_credentials


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
        
        self.profile_names = ["-- New Login --"] + [f"{c['first']} {c['last']} ({c['region']})".replace(" Resident", "") for c in self.credentials]
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
        self.profile_names = ["-- New Login --"] + [f"{c['first']} {c['last']} ({c['region']})".replace(" Resident", "") for c in self.credentials]
        
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
