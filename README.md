# BlackGlass 1.4

<img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/0bfe5e2b-0043-466c-afc4-141d5138b68d" />

Black Glass is a new chat viewer for Second Life, boasting a multi client login functionality.
It allows for local chat and teleportation (both by double clicking the minimap as to another region).
You can find a list of Nearby Avatars in which you can select each one for a "Teleport To" or "Profile" option.

Download and run the .exe file on the right in Releases to help test and improve this project!
###

###

Black Glass is a lightweight, high-performance Second Life client focused on multi-avatar chat management, navigation, and regional awareness. Built with a "Black Glass" aesthetic using Python and Tkinter, it provides a streamlined alternative to heavy 3D viewers for users who prioritize local communication and efficiency.

# 🚀Features 
###
###
## 📨Advanced Chat & Communication

Multi-Client Support: Log in with multiple accounts simultaneously using a tabbed interface.

Smart Filtering: Automatically filters out typing indicators and empty packets to keep your chat log clean.

Display Name Resolution: Asynchronously fetches and caches Second Life Display Names using the PeopleAPI/AvatarsDisplayName capabilities.

Reliable Messaging: Implements packet acknowledgement (ACK) tracking to ensure your messages are confirmed by the simulator.

## 🗺️ Navigation & Minimap

Dynamic Minimap: A real-time 2D radar displaying your position and the locations of nearby avatars.

Visual Map Tiles: Automatically fetches region map tiles from the Second Life Map API.

Double-Click Teleport: Double-click any location on the minimap to perform a "Hard Teleport" (relog) to those coordinates.

GridSurvey Integration: Uses the Gridsurvey API as a fallback to resolve region coordinates and handles when in-world lookups fail.

## 🛠️ Technical Prowess

Custom Protocol Implementation: Built-in support for Second Life's Zero-Coding scheme, Low/Medium/High frequency message IDs, and LLSD XML parsing.

Memory Efficiency: Utilizes a LimitedScrolledText widget to prune old chat lines, preventing memory bloat during long sessions.

Robust Connection: Features automated handshake retries (UseCircuitCode, CompleteAgentMovement) and reliable packet resending logic.

Credential Security: Saves profiles locally using a repeating-key XOR cipher and Base64 encoding for basic password persistence.

## 📸 Interface Preview

The UI features a high-contrast "Black Glass" theme with:

Cyan-on-Black accents for a futuristic terminal feel.

Interactive Sidebar: Real-time event notifications (teleport offers, lures) and the minimap radar.

Consolidated Login: A dedicated "New Login" tab with saved profile management.

<img width="795" height="675" alt="image" src="https://github.com/user-attachments/assets/5e4bb172-f206-4f56-b379-01e6d6fe45e4" />

<img width="799" height="681" alt="image" src="https://github.com/user-attachments/assets/542cee6d-2ee1-465d-b455-3541077ab319" />

<img width="799" height="677" alt="image" src="https://github.com/user-attachments/assets/ba1c358c-ff1f-4cfc-abf5-3e439991a523" />

# 🛠️ Requirements
Download and run the .exe compile at Releases or use Python: 3.7+

Pillow (PIL): Required for minimap image rendering.

pip install Pillow

Standard Libraries: tkinter, socket, threading, xmlrpc, ssl.

# 🚀 Getting Started
Download and run the .exe file in Releases or clone the repository or download BlackGlass.py.
###
###
Run the script:
###
python BlackGlass.py
###
Login: Enter your avatar's First Name, Last Name, and Password.
Set the Start Region to last, home, or a specific region name.
###
Manage Profiles: Your credentials will be saved automatically for quick access in the "Saved Profile" dropdown.

# 🪙 Credits
Used early draft version of following library >>> https://github.com/FelixWolf/pymetaverse/tree/master

# ⚖️ Disclaimer
BlackGlass is an independent project and is not affiliated with, endorsed by, or sponsored by Linden Research (Linden Lab). Use this client at your own risk and ensure compliance with the Second Life Terms of Service.
