# Changelog

All notable changes are documented here. The README keeps a short highlights
list only.

## 1.6 - 2026-08-22

### Added
- **In-session teleporting** (pymetaverse-style): minimap double-clicks, the
  Teleport button, parcel modals and clickable `[Teleport to: ...]` chat links
  move you without relogging. The quick logout-login method remains as
  automatic failover.
- Region name resolution via MapNameRequest/MapItemReply.
- Per-user **Lists tab**: contacts with distance, discovered groups and open
  chat sessions.
- SECURITY.md, CONTRIBUTING.md, structured issue forms, CodeQL scanning.

### Changed
- `blackglass` package split (protocol / network / agent / credentials / ui).

### Hardening
- Bounded caches, stale-avatar pruning and deterministic packet pruning fix
  long-session memory growth.
- Windows credential files sealed whole-file with DPAPI; POSIX files chmod
  600.

## 1.5 - 2026-07-23

Multi-client login tabbed interface; minimap radar with live map tiles;
double-click hard teleport; GridSurvey fallback; nearby-avatar list with
teleport/profile actions.

## 1.4 - earlier

URI namespace resolution; groups, parcels and profiles accessible in-viewer.

## 1.3

Nearby avatars list with per-avatar Teleport To / Profile options.

## 1.2

Minimap renders dots for yourself and others correctly.
