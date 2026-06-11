# jkvdf

A small FACEIT **CS2 highlights pipeline**. It tracks a fixed list of players,
finds their recent FACEIT matches, downloads each match demo, and extracts
multikill highlights into JSON files that can feed a highlights site or bot.

There is no UI yet — the project is a data pipeline that produces the JSON files
in `data/`.

## How it works

```
players.json ──► [ingest: Node]  ──► data/matches.json
                                     data/state.json
                         │
                         ▼
                 [parser: Go] ──► downloads match demo (.dem) from FACEIT
                         │         parses kills, detects multikills
                         ▼
                 data/highlights.json
                 data/leaderboards.json
```

1. **Ingest** — `scripts/ingest.mjs` (Node, zero dependencies). For every player
   in `players.json` it resolves their FACEIT player id, pulls their recent
   match history (CS2, falling back to CSGO), and appends new matches to
   `data/matches.json`. Per-player progress is tracked in `data/state.json`.
2. **Parser** — `parser/main.go` (Go). For each match in `data/matches.json`
   that has not been processed yet, it fetches a signed demo download URL from
   the FACEIT downloads API, streams + decompresses the `.dem`, and uses
   [`demoinfocs-golang`](https://github.com/markus-wa/demoinfocs-golang) to
   detect 2+ kill sequences by tracked players. Results are written to
   `data/highlights.json`, and ranked views (last game / last 10 / all-time top)
   to `data/leaderboards.json`.
3. **Automation** — `.github/workflows/ingest.yml` runs both steps every 10
   minutes and commits the updated `data/` files.

## Prerequisites

- **Node.js >= 20** (uses `fetch` and `--env-file`; CI pins Node 20 — see `.nvmrc`)
- **Go >= 1.21** (for the demo parser)
- **A FACEIT server-side API key** — create one at
  <https://developers.faceit.com/> (App → API Keys → Server-side).

## Setup

```bash
# 1. Create your local env file and add your key
make setup            # copies .env.example -> .env
$EDITOR .env          # set FACEIT_API_KEY=...

# 2. (optional) pre-fetch Go modules
make tidy
```

## Running locally

The `Makefile` loads `.env` and exports `FACEIT_API_KEY` to both the Node script
and the Go binary, so once `.env` is filled in:

```bash
make ingest        # fetch recent matches  -> data/matches.json, data/state.json
make parse         # build + parse demos   -> data/highlights.json, data/leaderboards.json
make pipeline      # ingest, then parse (the full run)

make build-parser  # just compile the Go parser -> parser.bin
make clean         # remove parser.bin
make help          # list all targets
```

You can also run the ingest step directly via npm (it loads `.env` itself):

```bash
npm run ingest
```

> Note: every match the parser hasn't seen triggers a real demo download
> (hundreds of MB each). The first full run against a populated
> `data/matches.json` can be slow and bandwidth-heavy. Demos are streamed to a
> temp file and deleted after parsing.

## Data files

| File | Produced by | Contents |
| --- | --- | --- |
| `data/matches.json` | ingest | Flat list of matches per tracked player |
| `data/state.json` | ingest | Last processed match id per player |
| `data/highlights.json` | parser | Detected multikill highlights (kept: 500) |
| `data/leaderboards.json` | parser | `lastGame`, `last10`, `allTimeTop` views |

These files are committed so the pipeline is incremental — delete them to force
a full re-process.

## Configuration

Tracked players live in `players.json`:

```json
[
  { "faceitNickname": "Cr4mer", "steamId": "STEAM_0:1:125547" }
]
```

- `faceitNickname` — used by the ingest step to resolve the FACEIT player id.
- `steamId` — `STEAM_0:Y:Z` form; the parser converts it to a SteamID64 to match
  the killer in the demo. Both fields are required for a player to get highlights.

## Repository layout

```
players.json                 # tracked players (nickname + steamId)
scripts/ingest.mjs           # Node ingest step
parser/                      # Go demo parser (main.go, go.mod, go.sum)
data/                        # generated JSON (committed)
.github/workflows/ingest.yml # scheduled CI pipeline
Makefile                     # local dev tasks
.env.example                 # FACEIT_API_KEY template
```
