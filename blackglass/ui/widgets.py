"""LimitedScrolledText: memory-safe scrolling text widget."""

import tkinter as tk
from tkinter import scrolledtext


class LimitedScrolledText(scrolledtext.ScrolledText):
    """
    A ScrolledText widget that limits the number of lines it displays
    to prevent memory bloat and UI lag over time.
    """
    def __init__(self, master=None, max_lines=1000, **kw):
        super().__init__(master, **kw)
        self.max_lines = max_lines
        # Hide the built-in vertical scrollbar while keeping scroll functionality.
        # ScrolledText stores it as self.vbar; setting width=0 makes it invisible.
        self.vbar.config(width=0, takefocus=False)
        self.vbar.pack_forget()

    def insert(self, index, chars, *args):
        super().insert(index, chars, *args)
        self._prune()

    def _prune(self):
        """Removes the oldest lines if we exceed max_lines."""
        # Get the number of lines (returns string like "100.0")
        try:
            # "end-1c" because "end" includes the auto-newline at the end
            num_lines = int(float(self.index("end-1c")))
            if num_lines > self.max_lines:
                # Delete from start to the number of excess lines
                diff = num_lines - self.max_lines
                # We can delete chunks to be more efficient, but line-by-line 
                # or block deletion logic:
                # Delete from 1.0 to (1.0 + diff lines)
                self.delete("1.0", f"{float(diff + 1)}.0")
        except Exception:
            pass
# ---------------------------------------------
