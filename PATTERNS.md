# Vulnerability Detection Patterns

This document describes the 58 regex patterns used in Phase 2 of the labeling pipeline. All patterns listed here are extracted directly from `phase2_pattern_labeler.py`.

## Pattern Development

The patterns are consistent with vulnerability examples documented in the SWC-120 Registry, Slither's weak-prng detector, and security articles from SlowMist and ImmuneBytes.

We ran initial patterns on the SmartBugs-Wild dataset. When we found vulnerable contracts that were not matched, we examined them manually and added new patterns. We repeated this process until no new patterns were needed.

## Block Attribute Keywords

| Keyword | Status | Notes |
|---------|--------|-------|
| `block.timestamp` | Current | |
| `now` | Removed in v0.7.0 | Alias for block.timestamp |
| `blockhash()` | Current | |
| `block.blockhash()` | Removed in v0.5.0 | Old syntax |
| `block.difficulty` | Deprecated | Returns prevrandao after The Merge |
| `block.prevrandao` | Added in v0.8.18 | Replaced difficulty |
| `block.number` | Current | |
| `block.coinbase` | Current | |
| `block.gaslimit` | Current | |

## Pattern Groups

### Group 1: Direct Modulo Operations (10 patterns)

These patterns detect when block attributes are used directly with the modulo operator.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `block.timestamp %` | |
| 2 | `now %` | |
| 3 | `block.number %` | |
| 4 | `block.difficulty %` | |
| 5 | `block.coinbase %` | |
| 6 | `blockhash(...) %` | |
| 7 | `block.blockhash(...) %` | |
| 8 | `block.prevrandao %` | |
| 9 | `block.gaslimit %` | |
| 10 | `gasleft() %` | |

---

### Group 2: Type Cast from keccak256/sha3 (11 patterns)

These patterns detect when the result of keccak256 or sha3 is cast to uint. The hash function does not add security because hashing predictable inputs produces predictable outputs.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `uint(keccak256(...block.blockhash...))` | |
| 2 | `uint(keccak256(...block.timestamp...))` | |
| 3 | `uint(keccak256(...now...))` | |
| 4 | `uint(keccak256(...block.number...))` | |
| 5 | `uint(keccak256(...blockhash(...)))` | |
| 6 | `uint(keccak256(...block.difficulty...))` | |
| 7 | `uint(sha3(...block.*...))` | |
| 8 | `uint(sha3(...now...))` | |
| 9 | `uint(keccak256(...block.prevrandao...))` | |
| 10 | `uint(keccak256(...block.gaslimit...))` | |
| 11 | `uint(keccak256(...gasleft()...))` | |

---

### Group 3: keccak256/sha3 with Modulo (15 patterns)

These patterns detect when keccak256 or sha3 output is used with the modulo operator.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `keccak256(...block.timestamp...) %` | |
| 2 | `keccak256(...now...) %` | |
| 3 | `keccak256(...block.number...) %` | |
| 4 | `keccak256(...blockhash...) %` | |
| 5 | `keccak256(...block.blockhash...) %` | |
| 6 | `keccak256(...block.difficulty...) %` | |
| 7 | `sha3(...block.*...) %` | |
| 8 | `sha3(...now...) %` | |
| 9 | `keccak256(abi.encodePacked(...now...))` | |
| 10 | `keccak256(abi.encodePacked(...block.number...))` | |
| 11 | `keccak256(abi.encodePacked(...block.timestamp...))` | |
| 12 | `keccak256(abi.encodePacked(...blockhash...))` | |
| 13 | `keccak256(...block.prevrandao...) %` | |
| 14 | `keccak256(...block.gaslimit...) %` | |
| 15 | `keccak256(...gasleft()...) %` | |

---

### Group 4: keccak256 with block.blockhash (1 pattern)

This pattern detects the deprecated block.blockhash syntax used inside keccak256.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `keccak256...block.blockhash` | Deprecated syntax from Solidity < 0.5.0 |

---

### Group 5: blockhash as Answer (4 patterns)

These patterns detect when blockhash is assigned to variables typically used for answers or results.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `answer = blockhash(...)` | Also matches `result` and `random*` |
| 2 | `answer = block.blockhash(...)` | Also matches `result` and `random*` |
| 3 | `blockhash(...) ==` | Comparison with blockhash |
| 4 | `block.blockhash(...) ==` | Comparison with block.blockhash |

---

### Group 6: Seed/Random Variable Assignment (10 patterns)

These patterns detect when variables named `seed` or `random` are assigned from block attributes.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `seed/random = ...block.difficulty` | |
| 2 | `seed/random = ...block.coinbase` | |
| 3 | `seed/random = ...block.number` | Not followed by `-` |
| 4 | `seed/random = ...block.timestamp` | |
| 5 | `seed/random = ...block.blockhash` | |
| 6 | `seed/random = ...blockhash(` | |
| 7 | `seed/random += now` or `+= block.` | |
| 8 | `seed/random = ...block.prevrandao` | |
| 9 | `seed/random = ...block.gaslimit` | |
| 10 | `seed/random = ...gasleft(` | |

---

### Group 7: Winner Selection (2 patterns)

These patterns detect when a winner variable is set using block attributes.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `winner = ...block.*` | |
| 2 | `winner = ...now` | |

---

### Group 8: Stored Block Number and uint(blockhash) (3 patterns)

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `*BlockNumber* = block.number` | Variable name contains "BlockNumber" |
| 2 | `uint(blockhash...)` | |
| 3 | `uint(block.blockhash...)` | |

---

### Group 9: Context Keywords with keccak256 (2 patterns)

These patterns detect functions or variables with randomness-related names that use keccak256 with block attributes.

| # | Pattern | Description |
|---|---------|-------------|
| 1 | `random/rand/seed/winner/lottery/bet/gambl + keccak256 + block.*` | |
| 2 | `random/rand/seed/winner/lottery/bet/gambl + keccak256 + now` | |

---

## Summary

| Group | Description | Count |
|-------|-------------|-------|
| G1 | Direct modulo | 10 |
| G2 | Type cast from keccak256/sha3 | 11 |
| G3 | keccak256/sha3 with modulo | 15 |
| G4 | keccak256 with block.blockhash | 1 |
| G5 | blockhash as answer | 4 |
| G6 | Seed/random assignment | 10 |
| G7 | Winner selection | 2 |
| G8 | Stored block number | 3 |
| G9 | Context keywords | 2 |
| **Total** | | **58** |

## References

1. SWC-120 Registry: https://swcregistry.io/docs/SWC-120/
2. Slither weak-prng: https://github.com/crytic/slither/wiki/Detector-Documentation
3. SlowMist: https://www.slowmist.com/articles/solidity-security/Common-Vulnerabilities-in-Solidity-Randomness.html
4. ImmuneBytes: https://immunebytes.com/blog/bad-randomness-in-solidity-smart-contracts/
