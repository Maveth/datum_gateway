# BIP-110 / Blake2b V2 (DATUM Gateway)

Experimental support for [Knots PR #359](https://github.com/bitcoinknots/bitcoin/pull/359) (`pow_hf_blake2b`): DATUM builds host-side PoW fields, packs Sia-class Blake2b work for miners, and submits **V2** blocks to a compatible node.

**This is a working lab fork for testing and review — not an official OCEAN release.**

## Roles

| Component | Responsibility |
|-----------|----------------|
| **Node** (PR #359) | Consensus: GetHash, CheckPoW, V2 headers, **network difficulty** (`GetNextWorkRequired` / `ApplyBlake2bTargetShift` in `pow.cpp`) |
| **DATUM** (this branch) | Templates, coinbase, Stratum, miner work pack, assemble + `submitblock` |
| **Miner** | Blake2b-256 over the **80-byte** ASIC region only |

DATUM does **not** reimplement chain retarget. It uses compact **nBits** from the node template (GBT).

### Coupling to the node PR

Any change to GetHash field order, tags, ASIC profiles (`m_reserved&3`), mask/XOR rules, header wire layout, or Blake2b difficulty in PR #359 must be re-checked against:

- `src/datum_pow_v2.c` / `src/datum_pow_v2.h`
- V2 hooks in `src/datum_stratum.c`

Freeze reference used when last aligned:

```text
luke-jr/bitcoin  pow_hf_blake2b  @ 7be6568  (multiple ASIC profiles)
```

## Enable

Config (JSON), under `datum`:

```json
"bip110_pow_v2": true
```

Point `bitcoind.rpcurl` / RPC credentials at a **regtest or test** node built from `pow_hf_blake2b` (or equivalent) that accepts V2 headers. Use normal DATUM config for `mining.pool_address`, tags, etc. — **do not commit secrets**.

## Miner-facing pack (provisional)

Until OCEAN/Luke publish an official dialect:

```text
mining.notify:
  [job_id, prev_hex, mid_hex, "", [], version, nbits, ntime8_hex, clean]

header80 (profile 0):
  prev32 || nonce8_le || ntime8_le || mid32

mining.submit:
  [user, job_id, extranonce2, ntime8_hex, nonce8_hex]
```

- `nBits` is the **network** compact target from the node.
- Share difficulty remains DATUM’s existing vardiff path; PoW digest is **Blake2b final** (not SHA256d).

## Files touched

| File | Change |
|------|--------|
| `src/datum_pow_v2.c`, `.h` | Host math port + Sia-class nonce helpers |
| `src/datum_stratum.c`, `.h` | Job fill, V2 notify/submit, 164-byte submitblock |
| `src/datum_conf.c`, `.h` | `datum.bip110_pow_v2` |
| `CMakeLists.txt` | Build `datum_pow_v2.c` |

## Build

Same as upstream DATUM Gateway (CMake, libcurl, jansson, libsodium, libmicrohttpd if API enabled):

```bash
cmake -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
```

## Network difficulty (placeholder)

Node applies Blake2b-era retarget / first-block target shift (`ApplyBlake2bTargetShift`). DATUM **passes through** GBT `nBits` and scores shares against share targets and that block target. When the PR changes difficulty policy, re-test this fork; do not add a second retarget here.

## Status

Lab-proven against a private regtest node running the Blake2b PR: share accept + tip advance via `submitblock`. Pool protocol V2 fields and official miner dialect may still evolve.
