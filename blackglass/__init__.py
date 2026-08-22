"""BlackGlass - multi-client chat viewer for Second Life.

The implementation is organised as:

- ``lltypes`` / ``codec`` / ``messages`` / ``packet`` : protocol stack
- ``network``   : login, circuits and LLSD helpers
- ``agent``     : high-level SecondLifeAgent
- ``credentials``: local credential storage
- ``ui``        : themed widgets, chat tabs, login panel and the main app
"""

__version__ = "1.5"
