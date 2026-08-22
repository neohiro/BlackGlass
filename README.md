# BlackGlass 1.5

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgray.svg)](https://github.com/)
[![Build Status](https://github.com/neohiro/BlackGlass/actions/workflows/release.yml/badge.svg)](https://github.com/neohiro/BlackGlass/actions)
[![CodeQL](https://github.com/neohiro/BlackGlass/actions/workflows/codeql.yml/badge.svg)](https://github.com/neohiro/BlackGlass/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

<img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/0bfe5e2b-0043-466c-afc4-141d5138b68d" />

Black Glass is a new chat viewer for Second Life, boasting a multi client login functionality.
It allows for local chat and teleportation (both by double clicking the minimap as to another region).

Download and run the .zip release for your operating system on the right in Releases to help test and improve this project!

Black Glass is a lightweight, high-performance Second Life client focused on multi-avatar chat management, navigation, and regional awareness. Built with a "Black Glass" aesthetic using Python and Tkinter, it provides a streamlined alternative to heavy 3D viewers for users who prioritize local communication and efficiency.

## 🚀 Features

## Updates

1.6: In-session teleporting everywhere - minimap double-clicks, the Teleport button, parcel modals and clickable `[Teleport to: ...]` chat links now move you without relogging (quick logout-login stays as automatic failover). New per-user **Lists tab** (contacts, groups, chats). Long-session memory hardening: bounded caches, stale-avatar pruning. On Windows, saved credentials are now sealed with **DPAPI**.

1.5: Multi-client login; minimap radar with map tiles.

1.4: URI namespaces are now resolved; groups, parcels and profiles are accessible in the viewer.

1.3: You can find a list of Nearby Avatars in which you can select each one for a "Teleport To" or "Profile" option.

1.2: The minimap now correctly renders dots for yourself and others

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

<img width="799" height="678" alt="image" src="https://github.com/user-attachments/assets/02ce1ed7-a5c5-499e-a63f-43ee1b0ea183" />

<img width="800" height="680" alt="image" src="https://github.com/user-attachments/assets/ea9b6f1b-f170-4d8b-b691-267409ede1b4" />

<img width="799" height="677" alt="image" src="https://github.com/user-attachments/assets/ba1c358c-ff1f-4cfc-abf5-3e439991a523" />

# 🛠️ Requirements
Download and run the .exe compile at Releases or use Python: 3.7+

Pillow (PIL): Required for minimap image rendering.

pip install -r requirements.txt

Standard Libraries: tkinter, socket, threading, xmlrpc.

# 🚀 Getting Started
Download and run the .zip release for your operating system in Releases, or run from source:

    git clone https://github.com/neohiro/BlackGlass.git
    cd BlackGlass
    pip install -r requirements.txt
    python BlackGlass.py

Login: Enter your avatar's First Name, Last Name, and Password.
Set the Start Region to last, home, or a specific region name.

Manage Profiles: Your credentials will be saved automatically for quick access in the "Saved Profile" dropdown.

# 🧩 Architecture

The codebase is organised as a package so it is easy to navigate and contribute to:

```
BlackGlass.py            # thin launcher (python BlackGlass.py)
blackglass/
├── lltypes.py           # wire-format data types (vectors, quaternions, LLUUID, ...)
├── codec.py             # typed encode/decode, zerocoding, hex dumps
├── messages.py          # SL message templates + message registry
├── packet.py            # UDP packet framing & reliability (ACKs)
├── network.py           # login, region circuits (RegionClient), LLSD helpers
├── agent.py             # SecondLifeAgent — high-level session behaviour
├── credentials.py       # local profile storage
├── imaging.py           # optional Pillow support flag
└── ui/
    ├── widgets.py       # LimitedScrolledText (memory-safe chat log)
    ├── theme.py         # themed dialogs & image panels
    ├── minimap.py       # MinimapCanvas radar
    ├── chat.py          # ChatTab — per-session chat UI
    ├── login.py         # LoginPanel with saved profiles
    └── app.py           # MultiClientApp main window
```

Protocol layers never import UI code; `ui/` sits on top of the `agent` API. A good first contribution is often a new message template in `messages.py` or a UI improvement in one tab file.

## 🤝 Contributing

Issues and pull requests are welcome! For code changes:

1. Fork & create a branch.
2. Keep changes focused; test against the live grid where possible.
3. Run `python BlackGlass.py` from source to verify before opening a PR.

# 🪙 Credits
Used early draft version of following library >>> https://github.com/FelixWolf/pymetaverse/tree/master

# ⚖️ Disclaimer
BlackGlass is an independent project and is not affiliated with, endorsed by, or sponsored by Linden Research (Linden Lab). Use this client at your own risk and ensure compliance with the Second Life Terms of Service.

## 📄 License

Released under the [MIT License](LICENSE).

## 📦 Installation

You can download the compiled standalone release for your operating system (Windows, macOS, or Linux) directly from the **[Releases](../../releases)** tab. No Python installation is required! Just download the .zip for your OS, extract, and run.


---

<p align="center">
  <a href="https://github.com/sponsors/neohiro"><img src="https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-EA4AAA?logo=githubsponsors&style=for-the-badge" alt="GitHub Sponsors"></a>&nbsp;&nbsp;
  <a href="https://www.patreon.com/frenzypenguin_media"><img src="https://img.shields.io/badge/Patreon-frenzypenguin__media-F96854?logo=patreon&style=for-the-badge" alt="Support on Patreon"></a>
</p>
