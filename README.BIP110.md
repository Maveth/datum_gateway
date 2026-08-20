# BIP-110 / Blake2b V2 (DATUM Gateway)

**Blake2b-only Gateway** for [Knots PR #359](https://github.com/bitcoinknots/bitcoin/pull/359) (`pow_hf_blake2b`).

DATUM builds host-side PoW, packs Sia-class Blake2b work, and submits **164-byte V2** blocks. There is **no SHA256d PoW path** and no `bip110_pow_v2` toggle — this fork never serves classic SHA ASICs.

**Lab / review fork — not an official OCEAN release.**

Branch: **`bip110-pow-v2`** on https://github.com/Maveth/datum_gateway

Direction aligns with Luke (Discord): Gateway should be Blake2b-only; we’re not going back to SHA2 for PoW.

---

## Activation: first Blake2b on last SHA tip

```text
… SHA256d blocks (node V1) …
        ↓  prev = last SHA tip
   first Blake2b block (V2 header + Blake2b PoW + headline)
        ↓
   Blake2b-only thereafter
```

- **PoW:** always Blake2b V2 from this Gateway  
- **Merkle / addresses / scripts:** still SHA256d Bitcoin plumbing  
- **Node** height gate decides when V2 is required (`Blake2bHeight` / `DEPLOYMENT_BLAKE2B`)

---

## What this fork does

### Ported (node GetHash)

`src/datum_pow_v2.c` / `.h` mirrors tip GetHash host construction:

- TaggedHash (xor key/mask, prevblock hidden, header1, merge-mine hook)
- Mid = Blake2b-256 over host stream  
- ASIC region (profile 0/1 lab; 2/3 exist on node)  
- Final digest ⊕ mask  
- 164B V2 header serialize  

### Changed (Gateway PoW)

| Area | Stock OCEAN | This branch |
|------|-------------|-------------|
| Share hash | SHA256d 80B | Blake2b final |
| Block header | 80B | **164B V2** |
| Miners | SHA ASICs | **Blake2b only** (Sia-Sv1 default + lab-mid UA) |
| Config switch | — | **None** for PoW (always V2); dialect by subscribe UA |

Merkle still uses `double_sha256` (Bitcoin tx tree) — that is **not** PoW.

### Miner pack (two Blake2b Stratum dialects → one GetHash)

**Default — Sia-Sv1** (stock Sia GPU miners, Antminer A3, Goldshell-class):

```text
mining.notify:
  [job_id, prev_asic_hex, coinb1_39hex, "", [], version, nbits, ntime8_hex, clean]

coinb1 = 3×0x00 || h2(32) || 4×0x00   (39 bytes; Luke Sv1 hint)
miner mid = Blake2b(0x00 || coinb1 || en1 || en2)
header80  = prev_asic || nonce8_le || ntime8_le || mid
```

**Lab-mid** (opt-in via subscribe UA containing `gpu-lab` / `sia-class-frozen` / `bip110-lab`):

```text
mining.notify:
  [job_id, prev_asic_hex, mid32_hex, "", [], version, nbits, ntime8_hex, clean]
```

Both rebuild the same tip GetHash on submit (`m_extranonce = 4×0x00 || sid_inv||en2`).

**Merkle freeze:** `pow_v2_merkle` / h2 / coinb1 are frozen at job fill from
`subsidy_only_coinbase` + 12×0x00 EN (+ template branches). Stratum en2 must
**not** mutate the Bitcoin coinbase (it only feeds `m_extranonce`). Block
assemble always uses that same subsidy coinbase so the node accepts
(`bad-txnmrklroot` otherwise).

```text
mining.submit:
  [user, job_id, extranonce2, ntime8_hex, nonce8_hex]
```

---

## Roles

| Component | Responsibility |
|-----------|----------------|
| **Node** | Consensus GetHash, CheckPoW, V2, difficulty, headline |
| **DATUM** | Templates, coinbase (+ headline inject), Stratum, assemble, submitblock |
| **Miner** | Blake2b-256 over ASIC region only |

### Freeze tip

```text
luke-jr/bitcoin  pow_hf_blake2b  @ 5a3f788e84
  (GetHash identical to ca52286218; tip also WrappingAdd/Sub for time_offset)

GetHash notes:
  - h1: version‖prev_ordered‖height‖merkle‖time‖u8(0)… (119B; was 122)
  - prevblock_hidden TaggedHash; profile0 clears 6 leading bytes
  - h2: two zero uint128 pads before mm_rhs
  - profile1 ASIC ends with h2_hash (not prev)
  - blake2b_headline on first Blake2b coinbase (no premine)
  - time_on_wire / nTime: uint32 wrap (WrappingAdd/WrappingSubtract)
  - vectors: src/test/data/block_header_v2.json
```

### Lab: `blake2b_headline`

```text
bitcoind:  -blake2b_headline=BIP110-LAB
DATUM:     mining.coinbase_tag_primary = "BIP110-LAB"
           (+ GBT aux.blake2b_headline inject when present)
```

---

## Build

```bash
cmake -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
./datum_gateway --test
```

---

## Community ports (credited)

We bend to Luke’s node tip first. When other Gateway forks have useful fixes, we prefer **git cherry-pick** when clean; otherwise re-apply with credit.

| Change | Source | How we took it | Adjust / revert |
|--------|--------|----------------|-----------------|
| String JSON-RPC request ids | [connorslab](https://github.com/connorslab/datum_gateway) `927d7e1` | `git cherry-pick -x` | Revert; `datum_stratum_request_id` |
| Dashboard homepage heap buffer | [connorslab](https://github.com/connorslab/datum_gateway) `e745328` | `git cherry-pick -x` | Revert; `datum_api_homepage` |
| Local / solo share counters | [justinfilip](https://github.com/justinfilip/datum_gateway) | Re-implemented (not their full PoW commit) | `stratum_note_share` / `STRATUM_SHARES_*` |
| Sia-Sv1 coinb1 notify (default) | Luke tip comment + justinfilip A3 path | Tip-accurate `coinb1`/`en12` mid equivalence | `DATUM_POW_DIALECT_*` / `datum_pow_v2_sia_coinb1` |

**Skipped:** SHA256d PoW path; connorslab `accept_sia_regtest_shares` default-on.

### Dashboard meaning (solo lab)

- **Local Shares Accepted/Rejected** — gateway Stratum validation (shows work with no pool).
- **Pool Shares …** — DATUM pool protocol counters; **N/A** when `datum_pool_host` is blank.

---

## Follow-ups (not done here)

Per Luke: **bdiff→pdiff**, optionally ignore xor_key early. String JSON-RPC ids ([OCEAN#96](https://github.com/OCEAN-xyz/datum_gateway/pull/96)) are now ported (connorslab cherry-pick).

---

## Status

Lab-proven on private regtest against a Blake2b PR node (share/block via host path; tip advance). Official miner dialect may still evolve.
