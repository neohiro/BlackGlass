"""ListsTab: per-session Contacts / Groups / Chats directory."""
import tkinter as tk
from tkinter import ttk
import threading


class ListsTab(ttk.Frame):
    """A per-logged-in-user directory: contacts seen, known groups and open chats."""

    REFRESH_MS = 5000

    def __init__(self, master, chat_tab, app):
        super().__init__(master, style='BlackGlass.TFrame')
        self.chat_tab = chat_tab
        self.app = app
        self._refresh_job = None
        self._building = False

        agent = self.chat_tab.sl_agent
        title = f"{agent.first_name}'s Lists".replace("  ", " ")
        ttk.Label(self, text=title, style='BlackGlass.TLabel',
                  font=('Helvetica', 13, 'bold')).pack(anchor='w', padx=12, pady=(10, 4))

        pane = tk.PanedWindow(self, orient=tk.VERTICAL, sashwidth=3,
                              bg='#101010', bd=0)
        pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        style = ttk.Style()
        style.configure('Lists.Treeview', background='#161616', fieldbackground='#161616',
                        foreground='#DDDDDD', rowheight=24, borderwidth=0)
        style.map('Lists.Treeview', background=[('selected', '#2A4A5A')],
                  foreground=[('selected', '#FFFFFF')])

        # --- Contacts -----------------------------------------------------
        cframe = ttk.Frame(pane, style='BlackGlass.TFrame')
        pane.add(cframe, minsize=90, height=220)
        ttk.Label(cframe, text="Contacts (nearby avatars)", style='BlackGlass.TLabel',
                  font=('Helvetica', 10, 'bold')).pack(anchor='w', padx=4)
        self.contacts_tree = ttk.Treeview(cframe, columns=('dist',), show='tree headings',
                                          selectmode='extended', style='Lists.Treeview')
        self.contacts_tree.heading('#0', text='Name')
        self.contacts_tree.column('#0', width=220)
        self.contacts_tree.heading('dist', text='Distance')
        self.contacts_tree.column('dist', width=80, anchor='e')
        self.contacts_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=(2, 6))
        self.contacts_tree.bind('<Double-1>', self._open_contact_profile)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label='View profile', command=self._open_contact_profile)
        menu.add_command(label='Teleport to', command=self._teleport_to_contact)
        self.contacts_tree.bind('<Button-3>', lambda e: self._popup_menu(e, menu))
        self.contact_menu = menu

        # --- Groups ---------------------------------------------------------
        gframe = ttk.Frame(pane, style='BlackGlass.TFrame')
        pane.add(gframe, minsize=80, height=160)
        ttk.Label(gframe, text="Groups", style='BlackGlass.TLabel',
                  font=('Helvetica', 10, 'bold')).pack(anchor='w', padx=4)
        self.groups_tree = ttk.Treeview(gframe, show='tree', selectmode='browse',
                                        style='Lists.Treeview')
        self.groups_tree.column('#0', width=300)
        self.groups_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=(2, 6))
        self.groups_tree.bind('<Double-1>', self._open_group)

        # --- Chats ------------------------------------------------------------
        chframe = ttk.Frame(pane, style='BlackGlass.TFrame')
        pane.add(chframe, minsize=70, height=120)
        ttk.Label(chframe, text="Chats (logged-in sessions)", style='BlackGlass.TLabel',
                  font=('Helvetica', 10, 'bold')).pack(anchor='w', padx=4)
        self.chats_tree = ttk.Treeview(chframe, show='tree', selectmode='browse',
                                       style='Lists.Treeview')
        self.chats_tree.column('#0', width=300)
        self.chats_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=(2, 0))
        self.chats_tree.bind('<Double-1>', self._focus_chat)

        self.refresh()

    # ---------------------------------------------------------------- helpers
    def _popup_menu(self, event, menu):
        item = self.contacts_tree.identify_row(event.y)
        if item:
            self.contacts_tree.selection_set(item)
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

    def _selected_uid(self):
        sel = self.contacts_tree.selection()
        if not sel:
            return None
        return sel[0].split(':', 1)[1] if ':' in sel[0] else None

    def cancel_refresh(self):
        if self._refresh_job:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None

    # ---------------------------------------------------------------- refresh
    def refresh(self):
        if self._building or not self.winfo_exists():
            return
        self._building = True
        try:
            agent = self.chat_tab.sl_agent
            client = getattr(agent, 'client', None)

            # Contacts
            self.contacts_tree.delete(*self.contacts_tree.get_children())
            if client:
                entries = list(client.tracked_avatars.items())
                entries.sort(key=lambda kv: kv[1].get('distance', 9999))
                for uid, info in entries[:200]:
                    name = agent.display_name_cache.get(uid.lower()) or info.get('name', uid[:8])
                    dist = info.get('distance', 0)
                    try:
                        dist_txt = f"{float(dist):.0f} m"
                    except Exception:
                        dist_txt = "?"
                    self.contacts_tree.insert('', 'end', iid=f"contact:{uid}",
                                              text=str(name).replace(' Resident', ''),
                                              values=(dist_txt,))
                if not entries:
                    self.contacts_tree.insert('', 'end', text='(no avatars nearby)')

            # Groups
            self.groups_tree.delete(*self.groups_tree.get_children())
            groups = sorted(agent.group_name_cache.items(), key=lambda kv: str(kv[1]).lower())
            for gid, gname in groups[:200]:
                self.groups_tree.insert('', 'end', iid=f"group:{gid}", text=str(gname))
            if not groups:
                self.groups_tree.insert('', 'end', text='(no groups discovered yet)')

            # Chats
            self.chats_tree.delete(*self.chats_tree.get_children())
            for full_name, tab in self.app.active_agents.items():
                marker = '*' if tab is self.chat_tab else ''
                self.chats_tree.insert('', 'end', iid=f"chat:{full_name}",
                                       text=f"{marker}{full_name}")
        finally:
            self._building = False
            if self.winfo_exists():
                self._refresh_job = self.after(self.REFRESH_MS, self.refresh)

    # ---------------------------------------------------------------- actions
    def _open_contact_profile(self, event=None):
        uid = self._selected_uid()
        if uid:
            threading.Thread(target=lambda: self.chat_tab.update_ui(
                'show_profile', {'id': uid, 'about': 'Loading profile...', 'born': '',
                                 'url': '', 'image_id': '', 'source': 'loading'}),
                daemon=True).start()
            self.chat_tab.sl_agent.request_avatar_properties(uid)

    def _teleport_to_contact(self, event=None):
        uid = self._selected_uid()
        if not uid:
            return
        client = self.chat_tab.sl_agent.client
        info = client.tracked_avatars.get(uid) if client else None
        if not info:
            return
        region = self.chat_tab.sl_agent.current_region_name
        x, y, z = info.get('pos', (128, 128, 25))
        threading.Thread(target=self.chat_tab.sl_agent.soft_teleport,
                         args=(region, x, y, z), daemon=True).start()

    def _open_group(self, event=None):
        item = self.groups_tree.focus()
        if item and ':' in item:
            self.chat_tab._open_sl_entity_popup('group', item.split(':', 1)[1])

    def _focus_chat(self, event=None):
        item = self.chats_tree.focus()
        if item and ':' in item:
            full = item.split(':', 1)[1]
            tab = self.app.active_agents.get(full)
            if tab:
                self.app.notebook.select(tab)
