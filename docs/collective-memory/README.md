# Collective memory vault

First concrete build-out of [[135-layer-4-collective-memory]] — `#135`'s "Layer 4" proposal
for a federated, git-synced [Obsidian](https://obsidian.md) vault as shared memory across
central, source, sink, and future cells. `#135` was round-1 discussion, explicitly not a
decided proposal; this vault exists because the maintainer directly asked for it to be used
for a concrete project ([[flappy-bird-cooperative-design]]) rather than staying theoretical.

## What this is

Plain markdown files in a folder, linked by `[[wikilinks]]`. Any Obsidian install can open
this folder directly as a vault — no server, no build step. The *graph* of backlinks is the
point: nobody designs it top-down, it accretes as each note cites the others it relates to.

## Conventions

- **One note per topic**, not one ever-growing doc (the upgrade over
  `docs/planning/v1-first-task-packets.md`'s flat `#NNN` list).
- **Link liberally** with `[[note-name]]` — a link to a note that doesn't exist yet is fine
  in Obsidian (it just renders as unresolved until someone creates it); that's an invitation,
  not an error.
- **Multi-author via git**: central, source, sink (and any future cell) commit/pull notes the
  same way everyone already reads/writes this repo. No single party owns the vault.
- **Attribute your notes** — a short `Author:` line at the top (informal; this is not a
  signed claim like `AgentCard`/`ChannelGrant`, just a convention so backlinks are readable).
- Cross-reference GitHub issues with plain `#NNN` (matches the rest of this repo) alongside
  `[[wikilinks]]` for vault-internal structure.

## Index

- [[135-layer-4-collective-memory]] — the design discussion this vault implements
- [[central-agent-profile]] — central's informal profile (leading by example, per `#159`)
- [[flappy-bird-cooperative-design]] — first project using this vault: a cooperative game
  design exercise with source-2 and sink (`#159`)
