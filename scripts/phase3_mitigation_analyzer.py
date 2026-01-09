#!/usr/bin/env python3
"""
Phase 3: Risk Level Classifier

This script analyzes vulnerable contracts identified in Phase 2 and classifies
them into risk levels based on the presence of mitigation mechanisms.

Risk Levels:
- SAFE: Uses Chainlink VRF or Commit-Reveal scheme (cryptographically secure)
- LOW_RISK: Has onlyOwner modifier (only contract owner can exploit)
- MEDIUM_RISK: Has tx.origin check or future block pattern (miner can exploit)
- HIGH_RISK: No protection (anyone can exploit by deploying a malicious contract)

Input: JSON file from Phase 2 labeler + directory containing .sol files
Output: JSON file with risk analysis for each contract
"""

import os
import re
import json
from typing import Dict, List
from datetime import datetime
import argparse


def remove_comments(content: str) -> str:
    """
    Remove comments from Solidity source code.

    Handles both single-line comments (//) and multi-line comments (/* */).

    Args:
        content: Raw Solidity source code

    Returns:
        Code with comments removed
    """
    content = re.sub(r'/\*[\s\S]*?\*/', '', content)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    return content


def detect_mitigations(content: str) -> Dict[str, bool]:
    """
    Detect protection mechanisms present in the contract code.

    Checks for various mitigation strategies that can reduce the
    exploitability of bad randomness vulnerabilities.

    Args:
        content: Solidity source code with comments removed

    Returns:
        Dictionary with boolean flags for each mitigation type
    """
    mitigations = {
        'chainlink_vrf': False,
        'commit_reveal': False,
        'only_owner': False,
        'tx_origin_check': False,
        'is_contract_check': False,
        'future_block': False,
    }

    # Chainlink VRF provides cryptographically secure randomness
    # This is the gold standard for on-chain randomness
    if re.search(r'VRFConsumerBase|VRFCoordinator|requestRandomWords|fulfillRandomness|'
                 r'rawFulfillRandomness|requestRandomness', content, re.IGNORECASE):
        mitigations['chainlink_vrf'] = True

    # Commit-Reveal is a two-phase protocol that prevents prediction
    # Participants first commit a hash, then reveal the actual value
    has_commit = re.search(r'function\s+commit|commits\[|commitment|sealed', content, re.IGNORECASE)
    has_reveal = re.search(r'function\s+reveal|revealed|revealHash', content, re.IGNORECASE)
    if has_commit and has_reveal:
        mitigations['commit_reveal'] = True

    # onlyOwner restricts function access to contract owner
    # This limits exploitation to the owner only
    if re.search(r'onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender\s*==\s*owner|'
                 r'require\s*\(\s*owner\s*==\s*msg\.sender|'
                 r'modifier\s+onlyOwner|Ownable', content, re.IGNORECASE):
        mitigations['only_owner'] = True

    # tx.origin check ensures caller is an EOA, not a contract
    # This blocks contract-based attacks but miners can still manipulate
    if re.search(r'require\s*\(\s*msg\.sender\s*==\s*tx\.origin|'
                 r'require\s*\(\s*tx\.origin\s*==\s*msg\.sender|'
                 r'msg\.sender\s*==\s*tx\.origin', content):
        mitigations['tx_origin_check'] = True

    # isContract check can be bypassed but shows developer awareness
    if re.search(r'isContract|extcodesize|code\.length', content, re.IGNORECASE):
        mitigations['is_contract_check'] = True

    # Future block pattern uses a block number in the future
    # This prevents same-transaction attacks but miners can still manipulate
    if re.search(r'block\.number\s*\+|commitBlock|revealBlock|futureBlock|'
                 r'storedBlock.*blockhash|blockhash.*storedBlock', content, re.IGNORECASE):
        mitigations['future_block'] = True

    return mitigations


def determine_risk_level(mitigations: Dict[str, bool]) -> str:
    """
    Determine the risk level based on detected mitigations.

    The risk level indicates who can potentially exploit the vulnerability:
    - SAFE: No one (secure randomness source)
    - LOW_RISK: Only the contract owner
    - MEDIUM_RISK: Miners/validators
    - HIGH_RISK: Anyone

    Args:
        mitigations: Dictionary of detected mitigation mechanisms

    Returns:
        Risk level string
    """
    # VRF or Commit-Reveal means the randomness is cryptographically secure
    if mitigations['chainlink_vrf']:
        return "SAFE"
    if mitigations['commit_reveal']:
        return "SAFE"

    # onlyOwner means only the owner can call the vulnerable function
    if mitigations['only_owner']:
        return "LOW_RISK"

    # tx.origin check or future block pattern blocks contract attacks
    # but miners can still manipulate the outcome
    if mitigations['tx_origin_check'] or mitigations['future_block']:
        return "MEDIUM_RISK"

    # No protection means anyone can exploit
    return "HIGH_RISK"


def analyze_vulnerable_contracts(labeling_results_file: str, contracts_dir: str, output_file: str):
    """
    Analyze vulnerable contracts and classify them by risk level.

    Args:
        labeling_results_file: Path to JSON output from Phase 2
        contracts_dir: Directory containing the .sol files
        output_file: Path for the output JSON file
    """
    # Load labeling results from Phase 2
    with open(labeling_results_file, 'r', encoding='utf-8') as f:
        labeling_data = json.load(f)

    # Filter to only vulnerable contracts
    vulnerable_files = [r for r in labeling_data['results'] if r['label'] == 'VULNERABLE']
    print(f"Total VULNERABLE files: {len(vulnerable_files)}")

    # Analyze each contract
    results = []
    stats = {
        'SAFE': 0,
        'LOW_RISK': 0,
        'MEDIUM_RISK': 0,
        'HIGH_RISK': 0
    }

    for i, item in enumerate(vulnerable_files):
        filepath = os.path.join(contracts_dir, item['file'])

        if not os.path.exists(filepath):
            continue

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            continue

        clean = remove_comments(content)

        # Detect mitigation mechanisms
        mitigations = detect_mitigations(clean)

        # Determine risk level based on mitigations
        risk_level = determine_risk_level(mitigations)
        stats[risk_level] += 1

        results.append({
            'file': item['file'],
            'original_pattern': item['reason'],
            'risk_level': risk_level,
            'mitigations': mitigations,
            'active_mitigations': [k for k, v in mitigations.items() if v]
        })

        if (i + 1) % 500 == 0:
            print(f"Analyzed {i + 1}/{len(vulnerable_files)}...")

    # Save results
    output_data = {
        'metadata': {
            'created_at': datetime.now().isoformat(),
            'source_file': labeling_results_file,
            'total_analyzed': len(results)
        },
        'statistics': stats,
        'results': results
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    # Print summary
    print("\n" + "=" * 60)
    print("RISK ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total analyzed: {len(results)}")
    print("\nRisk Level Distribution:")
    for level in ['SAFE', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK']:
        count = stats[level]
        pct = count / len(results) * 100 if results else 0
        print(f"  {level:12s}: {count:5d} ({pct:5.1f}%)")

    print(f"\nSaved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Classify vulnerable contracts by risk level based on mitigation mechanisms"
    )
    parser.add_argument(
        "labeling_file",
        help="JSON file from Phase 2 labeler containing vulnerability labels"
    )
    parser.add_argument(
        "contracts_dir",
        help="Directory containing the Solidity (.sol) files"
    )
    parser.add_argument(
        "-o", "--output",
        default="risk_analysis.json",
        help="Output JSON file path (default: risk_analysis.json)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.labeling_file):
        print(f"Error: Labeling file not found: {args.labeling_file}")
        return

    if not os.path.isdir(args.contracts_dir):
        print(f"Error: Contracts directory not found: {args.contracts_dir}")
        return

    analyze_vulnerable_contracts(args.labeling_file, args.contracts_dir, args.output)


if __name__ == "__main__":
    main()