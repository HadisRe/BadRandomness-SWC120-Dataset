# BadRandomness-SWC120-Dataset

A Risk-Stratified Benchmark Dataset for Bad Randomness (SWC-120) Vulnerabilities in Ethereum Smart Contracts.

## Overview

This repository provides a comprehensive benchmark dataset for evaluating tools that detect bad randomness vulnerabilities in Ethereum smart contracts. The dataset contains **17,466 contracts** extracted from the SmartBugs-Wild collection, with each contract labeled according to a four-level risk classification system.

Bad randomness (SWC-120) occurs when smart contracts use predictable blockchain values such as `block.timestamp`, `blockhash`, or `block.difficulty` to generate random numbers. Attackers can exploit this weakness to predict outcomes and steal funds.

## Key Features

- **Large Scale**: 17,466 labeled contracts, significantly larger than existing datasets
- **Risk Stratification**: Four-level classification based on exploitability
- **Function-Level Validation**: Verifies that mitigations actually protect vulnerable code
- **Context-Aware Analysis**: Distinguishes Mining Tokens from vulnerable lottery contracts

## Dataset Statistics

| Risk Level | Count | Percentage | Description |
|------------|-------|------------|-------------|
| HIGH_RISK | 1,543 | 88.3% | No protection, anyone can exploit |
| MEDIUM_RISK | 37 | 2.1% | tx.origin check, only miners can exploit |
| LOW_RISK | 172 | 9.8% | onlyOwner modifier, only owner can exploit |
| SAFE | 6 | 0.3% | Chainlink VRF or Commit-Reveal scheme |

Total vulnerable contracts: 1,752

## Risk Level Definitions

**HIGH_RISK**: Contracts with no mitigation. The randomness function is publicly callable and relies on predictable block attributes. Any attacker can deploy a contract to predict the outcome within the same transaction.

**MEDIUM_RISK**: Contracts with `tx.origin == msg.sender` check or future block pattern. This blocks contract-based attacks, but miners can still manipulate block attributes within protocol limits.

**LOW_RISK**: Contracts with `onlyOwner` or similar access control on the randomness function. External attackers cannot invoke the function; exploitation requires the owner to act maliciously.

**SAFE**: Contracts using Chainlink VRF or Commit-Reveal scheme. These provide cryptographically secure randomness that cannot be predicted or manipulated.

## Repository Structure

```
BadRandomness-SWC120-Dataset/
├── README.md
├── LICENSE
├── requirements.txt
├── scripts/
│   ├── phase1_keyword_filter.py
│   ├── phase2_pattern_labeler.py
│   ├── phase3_mitigation_analyzer.py
│   ├── phase4_low_risk_validator.py
│   ├── phase4_medium_risk_validator.py
│   ├── phase5_context_aware.py
│   └── test_ground_truth.py
├── dataset/
│   └── final_dataset.json
└── ground_truth/
    ├── vulnerable/
    └── safe/
```

## Methodology

Our dataset construction follows a five-phase pipeline:

### Phase 1: Keyword Filtering

Filter contracts containing block attributes commonly used as weak randomness sources:
- `block.timestamp` / `now`
- `blockhash` / `block.blockhash`
- `block.difficulty` / `block.prevrandao`
- `block.number`
- `block.coinbase`
- `block.gaslimit`

This reduces 47,398 contracts to 17,466 candidates.

### Phase 2: Pattern Labeling

Apply 58 regex patterns across 9 semantic groups to identify vulnerable randomness usage:

| Group | Pattern Category | Count |
|-------|------------------|-------|
| G1 | Direct modulo with block attributes | 10 |
| G2 | Type cast from keccak256/sha3 to uint | 11 |
| G3 | keccak256 hash with modulo operator | 15 |
| G4 | keccak256 with block.blockhash | 1 |
| G5 | blockhash as answer/comparison | 4 |
| G6 | Seed/random variable with predictable source | 10 |
| G7 | Winner selection using block attributes | 2 |
| G8 | Stored block number and uint cast | 3 |
| G9 | Randomness context with keccak256 | 2 |

### Phase 3: Risk Classification

Classify contracts based on detected mitigation mechanisms:
- Chainlink VRF or Commit-Reveal → SAFE
- onlyOwner modifier → LOW_RISK
- tx.origin check or future block → MEDIUM_RISK
- No mitigation → HIGH_RISK

### Phase 4: Function-Level Validation

Verify that mitigations actually protect the vulnerable code. A contract may contain both `onlyOwner` and a bad randomness pattern, but if they appear in different functions, the vulnerability remains exploitable.

This phase revealed that **49% of contracts initially classified as LOW_RISK were actually HIGH_RISK** because the modifier was not applied to the vulnerable function.

### Phase 5: Context-Aware Refinement

Distinguish legitimate uses of block attributes from vulnerable randomness:
- **Mining Tokens**: Use block attributes for Proof-of-Work puzzles (excluded from dataset)
- **Lottery/Gambling**: Use block attributes for randomness (vulnerable)

## Installation

```bash
git clone https://github.com/HadisRe/BadRandomness-SWC120-Dataset.git
cd BadRandomness-SWC120-Dataset
pip install -r requirements.txt
```

## Usage

### Download Dataset

The smart contract files are available in the [Releases](https://github.com/HadisRe/BadRandomness-SWC120-Dataset/releases) section:
- `HIGH_RISK.zip`
- `MEDIUM_RISK.zip`
- `LOW_RISK.zip`
- `SAFE.zip`
- `final_dataset.json`

### Run Analysis Scripts

Each script accepts command-line arguments. Use `--help` for details.

**Phase 1: Filter contracts by keywords**
```bash
python scripts/phase1_keyword_filter.py /path/to/contracts -o filtered.json -v
```

**Phase 2: Label contracts with vulnerability patterns**
```bash
python scripts/phase2_pattern_labeler.py /path/to/filtered_contracts -o labels.json
```

**Phase 3: Classify by risk level**
```bash
python scripts/phase3_mitigation_analyzer.py labels.json /path/to/contracts -o risk.json
```

**Phase 4: Validate function-level protection**
```bash
python scripts/phase4_low_risk_validator.py /path/to/low_risk_contracts -o validation.json
python scripts/phase4_medium_risk_validator.py /path/to/medium_risk_contracts -o validation.json
```

**Phase 5: Context analysis**
```bash
python scripts/phase5_context_aware.py /path/to/contracts -o context.json
```

**Test with ground truth**
```bash
python scripts/test_ground_truth.py /path/to/ground_truth
```

## Dataset Format

The `final_dataset.json` file contains:

```json
{
  "metadata": {
    "name": "BadRandomness-SWC120-Dataset",
    "version": "1.0",
    "created_at": "2025-01-09T...",
    "description": "..."
  },
  "statistics": {
    "total_contracts": 17466,
    "vulnerable_contracts": 1752,
    "risk_distribution": {
      "HIGH_RISK": 1543,
      "MEDIUM_RISK": 37,
      "LOW_RISK": 172,
      "SAFE": 6
    }
  },
  "contracts": [
    {
      "filename": "0x1234...abcd.sol",
      "risk_level": "HIGH_RISK",
      "label": "VULNERABLE",
      "exploitable_by": ["anyone", "miner", "owner"]
    }
  ]
}
```

## Comparison with Existing Datasets

| Dataset | Vulnerable | Safe | Risk Levels | Function Validation |
|---------|------------|------|-------------|---------------------|
| SWC Registry | 2 | - | No | No |
| SmartBugs Curated | 8 | - | No | Partial |
| RNVulDet | 34 | 214 | No | No |
| **Ours** | **1,752** | **6** | **Yes** | **Yes** |

Our dataset provides **51x more vulnerable contracts** than RNVulDet and is the first to include risk-level classification with function-level validation.

## Citation

If you use this dataset in your research, please cite:

```bibtex
@article{rezaei2025badrandomness,
  title={A Risk-Stratified Benchmark Dataset for Bad Randomness (SWC-120) Vulnerabilities in Ethereum Smart Contracts},
  author={Rezaei, Hadis and Taheri, Rahim and Palmieri, Francesco},
  journal={...},
  year={2025}
}
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- SmartBugs team for the SmartBugs-Wild dataset
- Ethereum community for vulnerability documentation

## Contact

- Hadis Rezaei - hrezaei@unisa.it
- University of Salerno, Italy
