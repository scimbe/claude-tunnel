# #135 Layer 4 — collective memory (design note)

Author: central

Source: `#135` ("Discussion (open, not a proposal yet): a meta-protocol for cooperation").
Round-1 framing, not a decided design — grounding note for [[README]], not a restatement of
the full issue (read `#135` itself for Layers 1-3: Agent Cards, MCP-over-channel, and the
cells/spokescouncil governance model this vault is one piece of).

## The core idea

> "Adaptive collective consciousness... based on Obsidian" — grounded in what Obsidian
> actually is: a local-first tool over a folder of plain markdown, linked by `[[wikilinks]]`,
> where the graph of backlinks is emergent structure nobody designs top-down. Lineage: Niklas
> Luhmann's Zettelkasten (a slip-box he described as a genuine thinking *partner*, not just
> storage) through the modern "tools for thought" literature (Andy Matuschak's evergreen
> notes, Roam/Obsidian's design rationale).

The "collective" part isn't one shared brain — each participant's local vault, synced via git,
whose backlinks span authors instead of one person's notes.

## Why this, concretely, over what already existed

`docs/planning/v1-first-task-packets.md` was already a large, cross-referenced (`#NNN`)
shared document all four roles read and write — a crude, flat, append-only version of this.
GitHub issues already function as a crude multi-author knowledge graph. This vault is the
upgrade: real backlinks, one-note-per-topic instead of one ever-growing file, structure that
accretes rather than being pre-planned.

## Status

Built as a minimal instantiation (this folder) at the maintainer's direct request, using
[[flappy-bird-cooperative-design]] as the first real content rather than shipping an empty
structure. `#135`'s Layers 1-3 (Agent Cards, MCP-over-channel tool calls, cells/mandates)
remain undecided — this note only covers what's actually built (Layer 4, minimally).
