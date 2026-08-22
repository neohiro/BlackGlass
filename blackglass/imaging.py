"""Optional Pillow support. Map/avatar imagery degrades gracefully without it."""
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    Image = None
    ImageTk = None
    PIL_AVAILABLE = False
    print("Warning: Pillow (PIL) not found. Map tiles will display a colored placeholder.")
