"""MultiClientApp: main window hosting login and chat tabs."""

import os
import tkinter as tk
from tkinter import ttk

from ..agent import SecondLifeAgent
from ..credentials import CREDENTIALS_FILE
from .chat import ChatTab
from .lists import ListsTab
from .login import LoginPanel
from .theme import ThemedMessageBox


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
        tab_name = f"{first} {last}".replace(" Resident", "")
        
        # 2. Add to notebook and select it (+ per-user Lists tab)
        self.notebook.add(chat_tab, text=tab_name)
        lists_tab = ListsTab(self.notebook, chat_tab, self)
        self.notebook.insert(chat_tab, lists_tab, text=f"☷ {tab_name}")
        chat_tab.lists_tab = lists_tab
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
            lists_tab = getattr(chat_tab_instance, "lists_tab", None)
            if lists_tab is not None:
                try:
                    lists_tab.cancel_refresh()
                except Exception:
                    pass
                try:
                    self.notebook.forget(lists_tab)
                    lists_tab.destroy()
                except Exception:
                    pass
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


def main():
    """Ensure the credentials file exists, then start the application."""
    if not os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "w") as f:
                f.write("[]")
        except Exception:
            print(f"Warning: Could not create {CREDENTIALS_FILE}. Credentials will not be saved.")

    app = MultiClientApp()
    app.mainloop()


if __name__ == "__main__":
    main()
