# Contributing to **BlackGlass**

Thanks for helping out! This project accepts issues and pull requests.

## Reporting bugs

Open a **Bug report** issue and fill in every field of the form - OS version,
app version and reproduction steps make the difference between a fix and a
close. For anything you believe is exploitable, use **Report a vulnerability**
on the Security tab instead (see SECURITY.md).

## Development setup

```bash
pip install -r requirements.txt
python BlackGlass.py
```

Requires Python 3.7+; Pillow is optional (map tiles degrade gracefully without it).

## Code layout

```
blackglass/
├── lltypes / codec / messages / packet   # protocol stack
├── network                               # login, circuits, LLSD
├── agent                                 # SecondLifeAgent session logic
├── credentials                           # local profile storage
└── ui/                                   # widgets, theme, minimap, chat, login, app
```

Protocol layers must never import UI code. A great first contribution is a
new message template in `messages.py` or an improvement confined to a single
file under `ui/`.

## Pull requests

1. Fork and create a topic branch.
2. Keep changes focused - one fix or feature per PR.
3. Test against the live target (Windows / grid) before submitting where feasible.
4. Describe **what** and **why** in the PR body.

## Contact

[frenzypenguin.media](https://linktr.ee/frenzypenguin.media)
