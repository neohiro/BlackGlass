"""MinimapCanvas: interactive in-world map rendering for a chat tab."""

import math
import time
import tkinter as tk
from tkinter import ttk

from ..imaging import PIL_AVAILABLE, Image, ImageTk
from ..lltypes import vector3


class MinimapCanvas(tk.Canvas):
    def __init__(self, master, agent, **kwargs):
        # We remove explicit width/height here, as the wrapper manages the size.
        # FIX: We restore explicit width=256, height=256 to prevent default Canvas sizing from expanding the column.
        kwargs.setdefault('width', 256)
        kwargs.setdefault('height', 256)
        super().__init__(master, **kwargs)
        self.agent = agent
        self.configure(bg='#1C1C1C', highlightthickness=1, highlightbackground='#444444')
        self.size = 256 # SL regions are 256x256 meters
        self.source_image = None # NEW: Store original PIL image
        self.map_image = None # Tkinter PhotoImage object for the map tile
        self.last_size = (0, 0) # NEW: Track size to avoid redundant resizing
        self.bind("<Configure>", self.on_resize)
        self.bind("<Double-Button-1>", self.on_double_click)
        self.after(1000, self.draw_map) # Start the drawing loop (1 FPS)

    def on_double_click(self, event):
        """Handles double-click to teleport within the region."""
        if not self.agent or not self.agent.client or not self.agent.running:
            return

        # Get canvas dimensions
        width = self.winfo_width()
        height = self.winfo_height()
        dest_size = min(width, height)
        
        # Calculate offsets
        offset_x = (width - dest_size) / 2
        offset_y = (height - dest_size) / 2
        
        # Get click position relative to the map area
        click_x_rel = event.x - offset_x
        click_y_rel = event.y - offset_y
        
        # Check if click is within the map area
        if click_x_rel < 0 or click_x_rel > dest_size or click_y_rel < 0 or click_y_rel > dest_size:
            return
            
        # Convert to SIM coordinates (0-256)
        # scale = dest_size / 256.0
        # sim_x = click_x_rel / scale
        # sim_y = (dest_size - click_y_rel) / scale (Y is inverted)
        
        scale = dest_size / 256.0
        sim_x = click_x_rel / scale
        sim_y = (dest_size - click_y_rel) / scale # Inverted Y for SL
        
        # Clamp coordinates to 0-255.9
        sim_x = max(0.0, min(255.9, sim_x))
        sim_y = max(0.0, min(255.9, sim_y))
        
        # Keep current altitude (Z)
        current_z = getattr(self.agent.client, 'agent_z', 30.0)
        
        # Calculate RegionHandle
        # Handle = (grid_y * 256) << 32 | (grid_x * 256)
        gx = getattr(self.agent.client, 'grid_x', 0)
        gy = getattr(self.agent.client, 'grid_y', 0)
        
        if gx == 0 and gy == 0:
             self.agent.ui_callback("status", "❌ Cannot teleport: Unknown region coordinates.")
             return

        region_handle = (gy * 256) << 32 | (gx * 256)
        
        self.agent.log(f"DEBUG: LocalTeleport - Grid: {gx},{gy} Sim: {sim_x:.1f},{sim_y:.1f} Handle: {region_handle} (0x{region_handle:X})")
        
        # Create target position vector
        vector3(sim_x, sim_y, current_z)
        
        
        region_name = self.agent.current_region_name
        if not region_name and self.agent.client:
             # Fallback to RegionClient's captured sim name (raw)
             # We might need to clean it if it wasn't decoded safely
             raw_name = self.agent.client.sim.get('name', '')
             if raw_name:
                 # It might be a variable object str() representation or a raw string
                 # Attempt to clean it if it looks like variable(...)
                 region_name = raw_name
                 if "variable(" in str(region_name):
                     # If we can't easily parse it, we might be stuck, but usually RegionClient uses str()
                     # If RegionClient used str(variable), it might be messy. 
                     # Let's hope RegionHandshake handler in SecondLifeAgent fired.
                     pass
                 else:
                     # Strip nulls
                     region_name = region_name.replace('\x00', '')

        if region_name and region_name.lower() != "home":
             self.agent.ui_callback("status", f"🏃 Hard Teleport (Relog) to {sim_x:.0f}, {sim_y:.0f}...")
             self.agent.hard_teleport(region_name, sim_x, sim_y, current_z)
        else:
             self.agent.ui_callback("status", "❌ Cannot teleport: Unknown region name.")

    def set_map_image(self, pil_image):
        """Sets the source PIL image for the map."""
        self.source_image = pil_image
        self.last_size = (0, 0) # Force re-render
        self.draw_map()




    def on_resize(self, event):
        # The canvas relies on its parent wrapper enforcing the square size.
        self.draw_map()

    def update_map_image(self, img_tk):
        """Sets the Tkinter PhotoImage to be displayed. Deprecated for set_map_image."""
        if img_tk is None:
            self.source_image = None
            self.map_image = None
            self.last_size = (0, 0)
        self.draw_map()

    def draw_map(self):
        # Clear canvas
        self.delete("all")
        
        # Get the actual dimensions of the canvas
        width = self.winfo_width()
        height = self.winfo_height()
        
        if width <= 1 or height <= 1:
             # Widget not fully initialized
             if self.agent.running:
                 self.after(100, self.draw_map)
             return

        dest_size = min(width, height)
        # Calculate offsets to center the map content
        offset_x = (width - dest_size) / 2
        offset_y = (height - dest_size) / 2

        # --- Handle Image Resizing ---
        if PIL_AVAILABLE and self.source_image:
             if (width, height) != self.last_size:
                 # Resize needed
                 try:
                     # High quality resize
                     resample = Image.Resampling.LANCZOS if hasattr(Image, 'Resampling') else Image.LANCZOS
                     resized = self.source_image.resize((int(dest_size), int(dest_size)), resample)
                     self.map_image = ImageTk.PhotoImage(resized)
                     self.last_size = (width, height)
                 except Exception:
                     pass

        # --- Map Image/Placeholder Drawing ---
        if self.map_image and PIL_AVAILABLE: # Only use image if PIL is available
            # Display the actual image centered
            self.create_image(width/2, height/2, image=self.map_image, anchor=tk.CENTER)
            # Draw the region boundary over the image
            self.create_rectangle(offset_x, offset_y, offset_x+dest_size, offset_y+dest_size, outline='#444444')
        else:
            # General placeholder when map is not loaded or failed
            self.create_rectangle(offset_x, offset_y, offset_x+dest_size, offset_y+dest_size, fill='#303030', outline='#444444')
            
            # --- FIX: Show debug info on the canvas ---
            gx = getattr(self.agent.client, 'grid_x', '?')
            gy = getattr(self.agent.client, 'grid_y', '?')
            debug_text = f"Map Unavailable\nGrid: {gx}, {gy}"
            
            center_x = width / 2
            center_y = height / 2
            if not PIL_AVAILABLE:
                self.create_text(center_x, center_y, text="Pillow Missing!", fill='#FF0000')
            else:
                self.create_text(center_x, center_y, text=debug_text, fill='#888888', justify=tk.CENTER)
        # --- End Map Image/Placeholder Drawing ---
        
        # --- Scale Factor ---
        # 1.0 means 256 meters = dest_size pixels
        scale = dest_size / self.size

        # --- Other Avatars Drawing (Black Dots) ---
        if self.agent.client and self.agent.running:
            for coords in self.agent.client.other_avatars:
                # Coarse coords are (x, y, z)
                ox, oy, _ = coords
                
                # Apply scaling and offsets
                x_other = ox * scale + offset_x
                y_other = (self.size - oy) * scale + offset_y
                
                # Draw small BLACK dot (radius 3)
                r = 3
                self.create_oval(x_other - r, y_other - r, x_other + r, y_other + r,
                                 fill="#000000", outline="#FFFFFF")
                                 
        # --- Agent Drawing (Own Location Indicator) ---
        if self.agent.client and self.agent.running: # Only draw agent if running
            # Agent Position (AgentUpdate/ImprovedTerseObjectUpdate is 0-256)
            agent_x_sl = self.agent.client.agent_x 
            agent_y_sl = self.agent.client.agent_y 
    
            # Map to Canvas: X is proportional, Y is inverted (256-Y)
            # Apply scaling and offsets
            x_on_canvas = agent_x_sl * scale + offset_x
            y_on_canvas = (self.size - agent_y_sl) * scale + offset_y
            
            # Draw Bullseye Indicator (Bright Cyan outer, White inner)
            # Sized to be distinct but not overly large
            r_outer = 3
            r_inner = 1
            
            # Outer Bright Cyan Circle
            self.create_oval(x_on_canvas - r_outer, y_on_canvas - r_outer, 
                             x_on_canvas + r_outer, y_on_canvas + r_outer,
                             fill="#00FFFF", outline="#000000", width=2)
            
            # Inner White Dot
            self.create_oval(x_on_canvas - r_inner, y_on_canvas - r_inner,
                             x_on_canvas + r_inner, y_on_canvas + r_inner,
                             fill="#FFFFFF", outline="#000000")

        # Schedule the next redraw
        if self.agent.running:
            self.after(1000, self.draw_map)
        
