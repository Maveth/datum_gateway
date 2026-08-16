# BIP-110 / Blake2b V2 (DATUM Gateway)

Experimental support for [Knots PR #359](https://github.com/bitcoinknots/bitcoin/pull/359) (`pow_hf_blake2b`): DATUM builds host-side PoW fields, packs Sia-class Blake2b work for miners, and submits **V2** blocks to a compatible node.

**This is a working lab fork for testing and review — not an official OCEAN release.**

Branch: **`bip110-pow-v2`** on https://github.com/Maveth/datum_gateway

---

## Documentation status (read this)

| Document | Updated? |
|----------|----------|
| **This file** (`README.BIP110.md`) | **Yes** — describes the BIP-110 work |
| Upstream **`README.md`** and the rest of OCEAN docs | **No** — left as stock Gateway docs |
| Inline comments in new/changed C sources | **Yes** (host module + V2 Stratum hooks) |

We did **not** rewrite the full OCEAN manual, config guide, or website. If something only appears in the stock README, assume SHA256d behavior unless `datum.bip110_pow_v2` is on and you follow **this** file.

---

## What was actually done (for reviewers)

Three kinds of work — so you can see what is a **port**, what is **replumb**, and what is **new**.

### 1. Ported (from node PR GetHash-side math)

Mirrored into `src/datum_pow_v2.c` / `src/datum_pow_v2.h` so DATUM can build the same host construction the node will CheckPoW:

- TaggedHash tags / field order (header 1, merge-mining hook, XOR key/mask)
- Mid = Blake2b-256 over host stream
- 80-byte ASIC region + profiles (`reserved & 3`)
- Final digest order + mask
- 164-byte V2 header serialization

This is **not** a full copy of the Bitcoin tree — only what the template/host needs to match PR #359.

### 2. Changed (existing DATUM SHA256d path → Blake2b V2)

Same Gateway jobs as today (template, coinbase, Stratum, submit), rewired when `bip110_pow_v2` is true:

| Area | Before (stock) | After (this branch) |
|------|----------------|---------------------|
| Share hash | SHA256d classic 80B header | Blake2b **final** from host construction |
| Block assemble | 80-byte header | **164-byte** V2 header |
| H-not-zero gate | SHA256d share filter | Skipped for V2 (Blake2b path) |
| Job prep | N/A for mid | `bip110_pow_v2_fill_job` after template/merkle |
| Config | — | `datum.bip110_pow_v2` |
| Build | — | `CMakeLists.txt` compiles `datum_pow_v2.c` |

Files touched for plumbing: `src/datum_stratum.c`, `src/datum_stratum.h`, `src/datum_conf.c`, `src/datum_conf.h`, `CMakeLists.txt`.

### 3. Added (miner-facing pack — provisional)

So a **frozen Sia-class** Blake2b miner (GPU/ASIC-style 80B grind) can be pointed at DATUM without rewriting the miner core:

```text
mining.notify:
  [job_id, prev_hex, mid_hex, "", [], version, nbits, ntime8_hex, clean]

header80 (profile 0):
  prev32 || nonce8_le || ntime8_le || mid32

mining.submit:
  [user, job_id, extranonce2, ntime8_hex, nonce8_hex]
```

Official OCEAN/Luke dialect may replace this layout; treat it as a **lab contract** until upstream freezes one.

### Not in this fork

- Node / Knots patches (use PR #359 yourself)
- TrueNAS / deploy ops / lab passwords
- Full pool-protocol V2 extensions (Ocean wire may need more later)
- Rewrite of stock OCEAN HTML docs / main README body

---

## Roles (unchanged ethos)

| Component | Responsibility |
|-----------|----------------|
| **Node** (PR #359) | Consensus: GetHash, CheckPoW, V2 headers, **network difficulty** |
| **DATUM** (this branch) | Templates, coinbase, Stratum, miner pack, assemble + `submitblock` |
| **Miner** | Blake2b-256 over the **80-byte** region only |

DATUM does **not** reimplement chain retarget. It uses compact **nBits** from the node template (GBT).

### Coupling to the node PR

Any change to GetHash field order, tags, ASIC profiles, mask/XOR rules, header wire layout, or Blake2b difficulty in PR #359 must be re-checked against:

- `src/datum_pow_v2.c` / `src/datum_pow_v2.h`
- V2 hooks in `src/datum_stratum.c`

Freeze reference when last aligned:

```text
luke-jr/bitcoin  pow_hf_blake2b  @ 7be6568  (multiple ASIC profiles)
```

---

## Enable

Under `datum` in the JSON config:

```json
"bip110_pow_v2": true
```

Point `bitcoind` RPC at a node built from `pow_hf_blake2b` (or equivalent) that accepts V2 headers. Use normal DATUM settings for pool address and tags — **do not commit secrets**.

---

## Files (diff map)

| File | Kind |
|------|------|
| `src/datum_pow_v2.c`, `.h` | **New** — port of host math + helpers |
| `src/datum_stratum.c`, `.h` | **Modified** — fill job, V2 notify/submit, 164B submit |
| `src/datum_conf.c`, `.h` | **Modified** — `bip110_pow_v2` flag |
| `CMakeLists.txt` | **Modified** — compile new unit |
| `README.BIP110.md` | **New** — this document |
| `README.md` (upstream) | **Unchanged** — stock OCEAN Gateway docs |

See `git log` / `git diff master...bip110-pow-v2` for the exact patch.

---

## Build

Same as upstream DATUM Gateway (CMake, libcurl, jansson, libsodium, libmicrohttpd if API enabled):

```bash
cmake -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
```

---

## Network difficulty

- **Source of truth:** node compact `nBits` on the template.  
- **Node:** retarget / first-Blake2b `Blake2bTargetShift` (`pow.cpp` in the PR).  
- **DATUM:** pass-through nBits; share difficulty via existing vardiff; compare **Blake2b final** to share and block targets.  
- When the PR changes difficulty policy, re-test this fork — do not add a second retarget here.

---

## Status

Lab-proven on private regtest against a Blake2b PR node: share accept + tip advance via `submitblock`. Pool protocol V2 fields and the official miner dialect may still evolve.

**For reviewers:** start with this file, then `src/datum_pow_v2.*`, then the `bip110_pow_v2` conditionals in `datum_stratum.c`.

## Unit tests

Host math tests (Blake2b vectors + fixed GetHash-style job + Sia nonce map + profile 1 layout):

```bash
# after build
./datum_gateway --test
```

Runs existing DATUM tests plus `datum_pow_v2_tests`. Exit non-zero on failure. Re-generate vectors if PR #359 GetHash changes.
