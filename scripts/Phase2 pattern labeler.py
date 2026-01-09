#!/usr/bin/env python3
"""
Phase 2: Bad Randomness Pattern Labeler

This script analyzes Solidity smart contracts to detect bad randomness
vulnerabilities (SWC-120). It uses 58 regex patterns organized into 9
semantic groups to identify contracts that use predictable blockchain
values for random number generation.

The patterns cover various dangerous practices including direct modulo
operations with block attributes, keccak256 hashing of predictable values,
blockhash misuse, and unsafe seed generation.

Input: Directory containing .sol files
Output: JSON file with labels (VULNERABLE or SAFE) for each contract
"""

import os
import re
import json
from typing import Tuple, List
from datetime import datetime
import argparse


def remove_comments_and_strings(source_code: str) -> str:
    """
    Remove comments and string literals from Solidity source code.

    This function implements a state machine that properly handles:
    - Single-line comments starting with //
    - Multi-line comments wrapped in /* */
    - String literals in double or single quotes

    Newlines are preserved to maintain correct line numbering for
    error reporting and debugging purposes.

    Args:
        source_code: Raw Solidity source code

    Returns:
        Cleaned code with comments removed and strings emptied
    """
    result = []
    i = 0
    n = len(source_code)

    while i < n:
        # Check for single-line comment
        if i < n - 1 and source_code[i:i + 2] == '//':
            while i < n and source_code[i] != '\n':
                i += 1
            if i < n:
                result.append('\n')
                i += 1

        # Check for multi-line comment
        elif i < n - 1 and source_code[i:i + 2] == '/*':
            i += 2
            while i < n - 1 and source_code[i:i + 2] != '*/':
                if source_code[i] == '\n':
                    result.append('\n')
                i += 1
            if i < n - 1:
                i += 2

        # Check for double-quoted string
        elif source_code[i] == '"':
            result.append('"')
            i += 1
            while i < n and source_code[i] != '"':
                if source_code[i] == '\\' and i + 1 < n:
                    i += 2
                elif source_code[i] == '\n':
                    result.append('\n')
                    i += 1
                else:
                    i += 1
            if i < n:
                result.append('"')
                i += 1

        # Check for single-quoted string
        elif source_code[i] == "'":
            result.append("'")
            i += 1
            while i < n and source_code[i] != "'":
                if source_code[i] == '\\' and i + 1 < n:
                    i += 2
                elif source_code[i] == '\n':
                    result.append('\n')
                    i += 1
                else:
                    i += 1
            if i < n:
                result.append("'")
                i += 1

        # Regular character, keep as is
        else:
            result.append(source_code[i])
            i += 1

    return ''.join(result)


def label_contract(filepath: str) -> Tuple[str, float, str]:
    """
    Analyze a single contract for bad randomness vulnerabilities.

    This function checks for Chainlink VRF usage first (which is safe),
    then scans for 58 vulnerability patterns across 9 semantic groups.

    Args:
        filepath: Path to the .sol file

    Returns:
        Tuple of (label, confidence, reason) where:
        - label is either "VULNERABLE" or "SAFE"
        - confidence is a float between 0 and 1
        - reason describes why this label was assigned
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return "SAFE", 0.0, f"Error: {e}"

    clean = remove_comments_and_strings(content)

    # First check for Chainlink VRF, which provides secure randomness
    if re.search(r'VRFConsumerBase|VRFCoordinator|requestRandomWords|fulfillRandomness', clean, re.IGNORECASE):
        return "SAFE", 0.95, "Chainlink VRF"

    # Group 1: Direct modulo operations with block attributes
    # These are the most obvious vulnerable patterns where block values
    # are directly used with modulo to generate a "random" index
    modulo_patterns = [
        (r'block\.timestamp\s*%', 'block.timestamp %'),
        (r'(?<![a-zA-Z])now(?![a-zA-Z])\s*%', 'now %'),
        (r'block\.number\s*%', 'block.number %'),
        (r'block\.difficulty\s*%', 'block.difficulty %'),
        (r'block\.coinbase\s*%', 'block.coinbase %'),
        (r'blockhash\s*\([^)]*\)\s*%', 'blockhash() %'),
        (r'block\.blockhash\s*\([^)]*\)\s*%', 'block.blockhash() %'),
        (r'block\.prevrandao\s*%', 'block.prevrandao %'),
        (r'block\.gaslimit\s*%', 'block.gaslimit %'),
        (r'gasleft\s*\(\s*\)\s*%', 'gasleft() %'),
    ]
    for pattern, desc in modulo_patterns:
        if re.search(pattern, clean, re.IGNORECASE):
            return "VULNERABLE", 0.95, desc

    # Group 2: Type casting from keccak256 or sha3 to uint
    # Developers often think hashing makes values unpredictable,
    # but hashing predictable inputs still gives predictable outputs
    uint_cast_patterns = [
        (r'uint\d*\s*\([^;]*keccak256[^;]*block\.blockhash', 'uint(keccak256(block.blockhash))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*block\.timestamp', 'uint(keccak256(block.timestamp))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*(?<![a-zA-Z])now(?![a-zA-Z])', 'uint(keccak256(now))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*block\.number', 'uint(keccak256(block.number))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*blockhash\s*\(', 'uint(keccak256(blockhash))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*block\.difficulty', 'uint(keccak256(block.difficulty))'),
        (r'uint\d*\s*\([^;]*sha3[^;]*block\.', 'uint(sha3(block.*))'),
        (r'uint\d*\s*\([^;]*sha3[^;]*(?<![a-zA-Z])now(?![a-zA-Z])', 'uint(sha3(now))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*block\.prevrandao', 'uint(keccak256(block.prevrandao))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*block\.gaslimit', 'uint(keccak256(block.gaslimit))'),
        (r'uint\d*\s*\([^;]*keccak256[^;]*gasleft\s*\(', 'uint(keccak256(gasleft()))'),
    ]
    for pattern, desc in uint_cast_patterns:
        if re.search(pattern, clean, re.IGNORECASE):
            return "VULNERABLE", 0.95, desc

    # Group 3: keccak256 or sha3 hash with modulo operator
    # Similar to Group 2, but the modulo is applied after hashing
    keccak_modulo_patterns = [
        (r'keccak256\s*\([^;]*block\.timestamp[^;]*\)[^;]*%', 'keccak256(block.timestamp) %'),
        (r'keccak256\s*\([^;]*(?<![a-zA-Z])now(?![a-zA-Z])[^;]*\)[^;]*%', 'keccak256(now) %'),
        (r'keccak256\s*\([^;]*block\.number[^;]*\)[^;]*%', 'keccak256(block.number) %'),
        (r'keccak256\s*\([^;]*blockhash[^;]*\)[^;]*%', 'keccak256(blockhash) %'),
        (r'keccak256\s*\([^;]*block\.blockhash[^;]*\)[^;]*%', 'keccak256(block.blockhash) %'),
        (r'keccak256\s*\([^;]*block\.difficulty[^;]*\)[^;]*%', 'keccak256(block.difficulty) %'),
        (r'sha3\s*\([^;]*block\.[^;]*\)[^;]*%', 'sha3(block.*) %'),
        (r'sha3\s*\([^;]*(?<![a-zA-Z])now(?![a-zA-Z])[^;]*\)[^;]*%', 'sha3(now) %'),
        (r'keccak256\s*\(\s*abi\.encodePacked\s*\([^;]*(?<![a-zA-Z])now(?![a-zA-Z])',
         'keccak256(abi.encodePacked(now))'),
        (r'keccak256\s*\(\s*abi\.encodePacked\s*\([^;]*block\.number', 'keccak256(abi.encodePacked(block.number))'),
        (r'keccak256\s*\(\s*abi\.encodePacked\s*\([^;]*block\.timestamp',
         'keccak256(abi.encodePacked(block.timestamp))'),
        (r'keccak256\s*\(\s*abi\.encodePacked\s*\([^;]*blockhash', 'keccak256(abi.encodePacked(blockhash))'),
        (r'keccak256\s*\([^;]*block\.prevrandao[^;]*\)[^;]*%', 'keccak256(block.prevrandao) %'),
        (r'keccak256\s*\([^;]*block\.gaslimit[^;]*\)[^;]*%', 'keccak256(block.gaslimit) %'),
        (r'keccak256\s*\([^;]*gasleft\s*\([^;]*\)[^;]*%', 'keccak256(gasleft()) %'),
    ]
    for pattern, desc in keccak_modulo_patterns:
        if re.search(pattern, clean, re.IGNORECASE):
            return "VULNERABLE", 0.95, desc

    # Group 4: keccak256 with block.blockhash (deprecated syntax)
    if re.search(r'keccak256[^;]*block\.blockhash', clean, re.IGNORECASE):
        return "VULNERABLE", 0.90, "keccak256(block.blockhash)"

    # Group 5: blockhash used as answer or in comparison
    # Often seen in guessing games where the answer is derived from blockhash
    blockhash_answer = [
        (r'(?:answer|result|random\w*)\s*=\s*blockhash\s*\(', 'blockhash as answer'),
        (r'(?:answer|result|random\w*)\s*=\s*block\.blockhash\s*\(', 'block.blockhash as answer'),
        (r'blockhash\s*\([^)]+\)\s*==', 'blockhash comparison'),
        (r'block\.blockhash\s*\([^)]+\)\s*==', 'block.blockhash comparison'),
    ]
    for pattern, desc in blockhash_answer:
        if re.search(pattern, clean, re.IGNORECASE):
            return "VULNERABLE", 0.90, desc

    # Group 6: Seed or random variable assigned from predictable source
    # Variable names like seed or random being set from block attributes
    seed_patterns = [
        (r'(?:seed|random)\w*\s*=\s*[^;]*block\.difficulty', 'seed = block.difficulty'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*block\.coinbase', 'seed = block.coinbase'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*block\.number(?!\s*-)', 'seed = block.number'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*block\.timestamp', 'seed = block.timestamp'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*block\.blockhash', 'random = block.blockhash'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*blockhash\s*\(', 'random = blockhash'),
        (r'(?:seed|random)\w*\s*\+\s*=\s*(?:now|block\.)', 'random += now/block'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*block\.prevrandao', 'seed = block.prevrandao'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*block\.gaslimit', 'seed = block.gaslimit'),
        (r'(?:seed|random)\w*\s*=\s*[^;]*gasleft\s*\(', 'seed = gasleft()'),
    ]
    for pattern, desc in seed_patterns:
        if re.search(pattern, clean, re.IGNORECASE):
            return "VULNERABLE", 0.90, desc

    # Group 7: Winner selection using block attributes
    # Common in lottery contracts where winner is chosen using block values
    winner_patterns = [
        (r'winner\w*\s*=\s*[^;]*block\.', 'winner = block.*'),
        (r'winner\w*\s*=\s*[^;]*(?<![a-zA-Z])now(?![a-zA-Z])', 'winner = now'),
    ]
    for pattern, desc in winner_patterns:
        if re.search(pattern, clean, re.IGNORECASE):
            return "VULNERABLE", 0.90, desc

    # Group 8: Stored block number pattern and uint cast from blockhash
    # Storing block.number for later use with blockhash is a known vulnerability
    if re.search(r'\w*[Bb]lock[Nn]umber\w*\s*=\s*block\.number', clean):
        return "VULNERABLE", 0.85, "Stored block.number"

    if re.search(r'uint\d*\s*\(\s*blockhash', clean):
        return "VULNERABLE", 0.90, "uint(blockhash)"
    if re.search(r'uint\d*\s*\(\s*block\.blockhash', clean):
        return "VULNERABLE", 0.90, "uint(block.blockhash)"

    # Group 9: Randomness context keywords combined with keccak256
    # Functions or variables with names suggesting randomness that use block attributes
    keccak_context = [
        (r'(?:random|rand|seed|winner|lottery|bet|gambl)\w*[^;]*keccak256[^;]*block\.', 'random + keccak256(block.*)'),
        (r'(?:random|rand|seed|winner|lottery|bet|gambl)\w*[^;]*keccak256[^;]*(?<![a-zA-Z])now(?![a-zA-Z])',
         'random + keccak256(now)'),
    ]
    for pattern, desc in keccak_context:
        if re.search(pattern, clean, re.IGNORECASE):
            return "VULNERABLE", 0.85, desc

    # No vulnerable pattern found
    return "SAFE", 0.75, "No bad randomness pattern"


def label_dataset(input_dir: str, output_file: str):
    """
    Process all Solidity files in a directory and generate labels.

    Args:
        input_dir: Directory containing .sol files
        output_file: Path for the output JSON file
    """
    sol_files = []
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            if f.endswith('.sol'):
                sol_files.append(os.path.join(root, f))

    print(f"Found {len(sol_files)} Solidity files")

    results = []
    vuln_count = 0
    safe_count = 0

    for i, filepath in enumerate(sol_files):
        label, conf, reason = label_contract(filepath)

        if label == "VULNERABLE":
            vuln_count += 1
        else:
            safe_count += 1

        results.append({
            "file": os.path.relpath(filepath, input_dir),
            "label": label,
            "confidence": conf,
            "reason": reason
        })

        if (i + 1) % 1000 == 0:
            print(f"Processed {i + 1}/{len(sol_files)}...")

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "total_files": len(results),
                "vulnerable_count": vuln_count,
                "safe_count": safe_count
            },
            "results": results
        }, f, indent=2, ensure_ascii=False)

    print(f"\nTotal: {len(results)}")
    print(f"VULNERABLE: {vuln_count} ({vuln_count / len(results) * 100:.1f}%)")
    print(f"SAFE: {safe_count} ({safe_count / len(results) * 100:.1f}%)")
    print(f"Saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Label Solidity contracts for bad randomness vulnerabilities (SWC-120)"
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing Solidity (.sol) files"
    )
    parser.add_argument(
        "-o", "--output",
        default="labeling_results.json",
        help="Output JSON file path (default: labeling_results.json)"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: Directory not found: {args.input_dir}")
        return

    label_dataset(args.input_dir, args.output)


if __name__ == "__main__":
    main()