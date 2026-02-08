# BlackGlass

Black Glass is a new chat viewer for Second Life, boasting a multi client login functionality.

It allows for local chat and teleportation (both by double clicking the minimap as to another region).

<img width="858" height="604" alt="image" src="https://github.com/user-attachments/assets/935c517c-f6cb-41d1-98d0-aad0d15f3879" />

<img width="801" height="679" alt="image" src="https://github.com/user-attachments/assets/33c46de1-8986-45ee-b47d-823e8a762595" />

BlackGlass is a lightweight, high-performance, and "completionist" Second Life client focused on multi-avatar chat management, navigation, and regional awareness. Built with a "Black Glass" aesthetic using Python and Tkinter, it provides a streamlined alternative to heavy 3D viewers for users who prioritize communication and efficiency.

🚀 Features
📨 Advanced Chat & Communication
Multi-Client Support: Log in with multiple accounts simultaneously using a tabbed interface.

Smart Filtering: Automatically filters out typing indicators and empty packets to keep your chat log clean.

Display Name Resolution: Asynchronously fetches and caches Second Life Display Names using the PeopleAPI/AvatarsDisplayName capabilities.

Reliable Messaging: Implements packet acknowledgement (ACK) tracking to ensure your messages are confirmed by the simulator.

🗺️ Navigation & Minimap
Dynamic Minimap: A real-time 2D radar displaying your position and the locations of nearby avatars.

Visual Map Tiles: Automatically fetches region map tiles from the Second Life Map API.

Double-Click Teleport: Double-click any location on the minimap to perform a "Hard Teleport" (relog) to those coordinates.

GridSurvey Integration: Uses the Gridsurvey API as a fallback to resolve region coordinates and handles when in-world lookups fail.

🛠️ Technical Prowess
Custom Protocol Implementation: Built-in support for Second Life's Zero-Coding scheme, Low/Medium/High frequency message IDs, and LLSD XML parsing.

Memory Efficiency: Utilizes a LimitedScrolledText widget to prune old chat lines, preventing memory bloat during long sessions.

Robust Connection: Features automated handshake retries (UseCircuitCode, CompleteAgentMovement) and reliable packet resending logic.

Credential Security: Saves profiles locally using a repeating-key XOR cipher and Base64 encoding for basic password persistence.

📸 Interface Preview
The UI features a high-contrast "Black Glass" theme with:

Cyan-on-Black accents for a futuristic terminal feel.

Interactive Sidebar: Real-time event notifications (teleport offers, lures) and the minimap radar.

Consolidated Login: A dedicated "New Login" tab with saved profile management.

🛠️ Requirements
Python: 3.7+

Pillow (PIL): Required for minimap image rendering.

Bash
pip install Pillow
Standard Libraries: tkinter, socket, threading, xmlrpc, ssl.

⌨️ Controls & Commands
Movement (While Chat Tab is Focused)
Arrow Keys: Move Forward/Backward/Left/Right.

E / C: Move Up / Move Down.

Space: Jump.

F: Toggle Fly Mode.

Special Chat Commands
/hardtp <Region Name>: Instantly logs out and logs back in at the center of the specified region.

/relog <Region Name>: Alias for hard teleport.

🚀 Getting Started
Clone the repository or download BlackGlass.py.

Run the script:

Bash
python BlackGlass.py
Login: Enter your avatar's First Name, Last Name, and Password.

Set the Start Region to last, home, or a specific region name.

Manage Profiles: Your credentials will be saved automatically for quick access in the "Saved Profile" dropdown.

⚖️ Disclaimer
BlackGlass is an independent project and is not affiliated with, endorsed by, or sponsored by Linden Research (Linden Lab). Use this client at your own risk and ensure compliance with the Second Life Terms of Service.
