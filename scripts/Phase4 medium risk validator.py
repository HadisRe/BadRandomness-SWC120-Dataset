#!/usr/bin/env python3
"""
Phase 4: MEDIUM_RISK Function-Level Validator

This script validates contracts classified as MEDIUM_RISK in Phase 3 by checking
whether the tx.origin check or future block pattern is actually applied to the
function containing the bad randomness pattern.

Similar to the LOW_RISK validator, a contract may contain both a mitigation
mechanism and a vulnerable pattern in different functions, leaving the
vulnerability fully exploitable.

Validation Logic:
1. Find all functions containing bad randomness patterns
2. For each vulnerable function, check if the mitigation is applied directly
3. For internal/private functions, trace the call chain to public callers

Verdicts:
- CORRECT: The mitigation properly protects the vulnerable function
- FALSE_POSITIVE: The mitigation exists but does not protect the vulnerable code
- NO_BAD_RANDOMNESS: No bad randomness pattern found in any function body

Input: Directory containing MEDIUM_RISK .sol files
Output: JSON file with validation results
"""

import os
import re
import json
from datetime import datetime
from typing import List, Dict
import argparse

# Bad randomness patterns from Phase 2 labeler
BAD_RANDOMNESS_PATTERNS = [
    # Group 1: Direct modulo
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

    # Group 2: uint cast from keccak256
    (r'uint\d*\s*\([^;]*keccak256[^;]*block\.', 'uint(keccak256(block.*))'),
    (r'uint\d*\s*\([^;]*keccak256[^;]*(?<![a-zA-Z])now(?![a-zA-Z])', 'uint(keccak256(now))'),
    (r'uint\d*\s*\([^;]*keccak256[^;]*blockhash', 'uint(keccak256(blockhash))'),
    (r'uint\d*\s*\([^;]*sha3[^;]*block\.', 'uint(sha3(block.*))'),

    # Group 3: keccak256 with modulo
    (r'keccak256\s*\([^;]*block\.[^;]*\)[^;]*%', 'keccak256(block.*) %'),
    (r'keccak256\s*\([^;]*(?<![a-zA-Z])now(?![a-zA-Z])[^;]*\)[^;]*%', 'keccak256(now) %'),
    (r'keccak256\s*\([^;]*blockhash[^;]*\)[^;]*%', 'keccak256(blockhash) %'),
    (r'keccak256\s*\(\s*abi\.encodePacked\s*\([^;]*block\.', 'keccak256(abi.encodePacked(block.*))'),
    (r'keccak256\s*\(\s*abi\.encodePacked\s*\([^;]*(?<![a-zA-Z])now(?![a-zA-Z])', 'keccak256(abi.encodePacked(now))'),

    # Group 4-5: blockhash patterns
    (r'keccak256[^;]*block\.blockhash', 'keccak256(block.blockhash)'),
    (r'(?:answer|result|random\w*)\s*=\s*blockhash\s*\(', 'blockhash as answer'),
    (r'(?:answer|result|random\w*)\s*=\s*block\.blockhash\s*\(', 'block.blockhash as answer'),
    (r'uint\d*\s*\(\s*blockhash', 'uint(blockhash)'),
    (r'uint\d*\s*\(\s*block\.blockhash', 'uint(block.blockhash)'),

    # Group 6: seed/random with bad source
    (r'(?:seed|random)\w*\s*=\s*[^;]*block\.difficulty', 'seed = block.difficulty'),
    (r'(?:seed|random)\w*\s*=\s*[^;]*block\.coinbase', 'seed = block.coinbase'),
    (r'(?:seed|random)\w*\s*=\s*[^;]*block\.number(?!\s*-)', 'seed = block.number'),
    (r'(?:seed|random)\w*\s*=\s*[^;]*block\.timestamp', 'seed = block.timestamp'),
    (r'(?:seed|random)\w*\s*=\s*[^;]*blockhash\s*\(', 'random = blockhash'),
    (r'(?:seed|random)\w*\s*=\s*[^;]*block\.blockhash', 'random = block.blockhash'),

    # Group 7: winner with bad source
    (r'winner\w*\s*=\s*[^;]*block\.', 'winner = block.*'),
    (r'winner\w*\s*=\s*[^;]*(?<![a-zA-Z])now(?![a-zA-Z])', 'winner = now'),

    # Group 8: Stored block.number
    (r'\w*[Bb]lock[Nn]umber\w*\s*=\s*block\.number', 'Stored block.number'),

    # Group 9: Randomness context
    (r'(?:random|rand|seed|winner|lottery|bet|gambl)\w*[^;]*keccak256[^;]*block\.', 'random + keccak256(block.*)'),
    (r'(?:random|rand|seed|winner|lottery|bet|gambl)\w*[^;]*keccak256[^;]*(?<![a-zA-Z])now(?![a-zA-Z])',
     'random + keccak256(now)'),
]

# MEDIUM_RISK mitigation patterns
MEDIUM_RISK_MITIGATIONS = [
    # tx.origin check ensures caller is EOA not contract
    (r'require\s*\(\s*msg\.sender\s*==\s*tx\.origin', 'require(msg.sender == tx.origin)'),
    (r'require\s*\(\s*tx\.origin\s*==\s*msg\.sender', 'require(tx.origin == msg.sender)'),
    (r'msg\.sender\s*==\s*tx\.origin', 'msg.sender == tx.origin'),
    (r'tx\.origin\s*==\s*msg\.sender', 'tx.origin == msg.sender'),

    # Future block pattern adds delay before using blockhash
    (r'block\.number\s*\+', 'block.number + delay'),
    (r'commitBlock|revealBlock|futureBlock', 'future block variable'),
    (r'storedBlock.*blockhash|blockhash.*storedBlock', 'stored block + blockhash'),
]


def remove_comments(content: str) -> str:
    """Remove single-line and multi-line comments from Solidity code."""
    content = re.sub(r'/\*[\s\S]*?\*/', '', content)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    return content


def extract_functions(content: str) -> List[Dict]:
    """
    Extract all functions from the contract.

    Returns a list of dictionaries containing function name, visibility,
    modifiers string, body content, and position in the source.
    """
    functions = []

    func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{'

    for match in re.finditer(func_pattern, content):
        func_name = match.group(1)
        params = match.group(2)
        modifiers_str = match.group(3)

        # Determine visibility from modifiers
        if re.search(r'\bpublic\b', modifiers_str, re.IGNORECASE):
            visibility = 'public'
        elif re.search(r'\bexternal\b', modifiers_str, re.IGNORECASE):
            visibility = 'external'
        elif re.search(r'\binternal\b', modifiers_str, re.IGNORECASE):
            visibility = 'internal'
        elif re.search(r'\bprivate\b', modifiers_str, re.IGNORECASE):
            visibility = 'private'
        else:
            visibility = 'public'  # Default in older Solidity versions

        # Find function body using brace counting
        start = match.end() - 1
        brace_count = 0
        end = start

        for i in range(start, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break

        body = content[start:end]

        functions.append({
            'name': func_name,
            'visibility': visibility,
            'modifiers': modifiers_str,
            'body': body,
            'start': match.start(),
            'end': end
        })

    return functions


def find_bad_randomness_in_function(func_body: str) -> List[str]:
    """Find all bad randomness patterns present in a function body."""
    found = []
    for pattern, desc in BAD_RANDOMNESS_PATTERNS:
        if re.search(pattern, func_body, re.IGNORECASE):
            found.append(desc)
    return found


def find_mitigation_in_function(func_body: str, modifiers_str: str) -> List[str]:
    """
    Find MEDIUM_RISK mitigations in a function body or its modifiers.

    Checks both the function body and the modifier string since the
    mitigation could be in either location.
    """
    found = []

    # Check in function body
    for pattern, desc in MEDIUM_RISK_MITIGATIONS:
        if re.search(pattern, func_body, re.IGNORECASE):
            found.append(desc)

    # Check in modifiers string
    for pattern, desc in MEDIUM_RISK_MITIGATIONS:
        if re.search(pattern, modifiers_str, re.IGNORECASE):
            found.append(f"{desc} (in modifier)")

    return found


def find_function_calls(func_body: str, all_functions: List[Dict]) -> List[str]:
    """Find which other functions are called from this function body."""
    called = []
    for func in all_functions:
        if re.search(rf'\b{func["name"]}\s*\(', func_body):
            called.append(func['name'])
    return called


def analyze_contract(filepath: str) -> Dict:
    """
    Analyze a single contract to validate its MEDIUM_RISK classification.

    Checks whether the tx.origin or future block mitigation is actually
    applied to functions containing bad randomness patterns.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return {
            'file': os.path.basename(filepath),
            'verdict': 'ERROR',
            'reason': str(e)
        }

    clean = remove_comments(content)
    functions = extract_functions(clean)

    # Find functions with bad randomness patterns
    vulnerable_functions = []
    for func in functions:
        bad_patterns = find_bad_randomness_in_function(func['body'])
        if bad_patterns:
            vulnerable_functions.append({
                'name': func['name'],
                'visibility': func['visibility'],
                'modifiers': func['modifiers'].strip(),
                'patterns': bad_patterns
            })

    # No vulnerable functions found
    if not vulnerable_functions:
        return {
            'file': os.path.basename(filepath),
            'verdict': 'NO_BAD_RANDOMNESS',
            'reason': 'Pattern not found in any function',
            'vulnerable_functions': []
        }

    # Check each vulnerable function for protection
    protected_functions = []
    unprotected_functions = []

    for vf in vulnerable_functions:
        func = next((f for f in functions if f['name'] == vf['name']), None)
        if not func:
            continue

        # Check for mitigation in the function itself
        mitigations = find_mitigation_in_function(func['body'], func['modifiers'])

        if mitigations:
            protected_functions.append({
                'name': vf['name'],
                'visibility': vf['visibility'],
                'patterns': vf['patterns'],
                'mitigations': mitigations,
                'protected_directly': True
            })
        elif vf['visibility'] in ['internal', 'private']:
            # For internal/private functions, check if public callers are protected
            is_protected = False
            protected_by = None

            for caller_func in functions:
                if caller_func['visibility'] in ['public', 'external']:
                    calls = find_function_calls(caller_func['body'], functions)
                    if vf['name'] in calls:
                        caller_mitigations = find_mitigation_in_function(
                            caller_func['body'],
                            caller_func['modifiers']
                        )
                        if caller_mitigations:
                            is_protected = True
                            protected_by = caller_func['name']
                            mitigations = caller_mitigations
                            break

            if is_protected:
                protected_functions.append({
                    'name': vf['name'],
                    'visibility': vf['visibility'],
                    'patterns': vf['patterns'],
                    'mitigations': mitigations,
                    'protected_directly': False,
                    'protected_by': protected_by
                })
            else:
                # Check if any public function calls this internal function
                has_public_caller = False
                for caller_func in functions:
                    if caller_func['visibility'] in ['public', 'external']:
                        calls = find_function_calls(caller_func['body'], functions)
                        if vf['name'] in calls:
                            has_public_caller = True
                            unprotected_functions.append({
                                'name': vf['name'],
                                'visibility': vf['visibility'],
                                'patterns': vf['patterns'],
                                'called_by': caller_func['name'],
                                'reason': 'internal function called by unprotected public function'
                            })
                            break

                if not has_public_caller:
                    # Internal function with no public caller might be safe
                    protected_functions.append({
                        'name': vf['name'],
                        'visibility': vf['visibility'],
                        'patterns': vf['patterns'],
                        'mitigations': ['No public caller found'],
                        'protected_directly': False,
                        'note': 'internal function with no public caller'
                    })
        else:
            # Public/external function without mitigation
            unprotected_functions.append({
                'name': vf['name'],
                'visibility': vf['visibility'],
                'patterns': vf['patterns'],
                'reason': 'public/external function without mitigation'
            })

    # Determine final verdict
    if unprotected_functions:
        verdict = 'FALSE_POSITIVE'
        reason = f"{len(unprotected_functions)} function(s) without mitigation"
    elif protected_functions:
        verdict = 'CORRECT'
        reason = f"All {len(protected_functions)} vulnerable function(s) protected"
    else:
        verdict = 'NO_BAD_RANDOMNESS'
        reason = 'No vulnerable functions found'

    return {
        'file': os.path.basename(filepath),
        'verdict': verdict,
        'reason': reason,
        'protected_functions': protected_functions,
        'unprotected_functions': unprotected_functions,
        'total_vulnerable_functions': len(vulnerable_functions)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate MEDIUM_RISK contracts by checking function-level mitigation application"
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing MEDIUM_RISK Solidity (.sol) files"
    )
    parser.add_argument(
        "-o", "--output",
        default="medium_risk_validation.json",
        help="Output JSON file path (default: medium_risk_validation.json)"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: Directory not found: {args.input_dir}")
        return

    print("=" * 70)
    print("MEDIUM_RISK Function-Level Validator")
    print("=" * 70)

    # Find all .sol files
    sol_files = [f for f in os.listdir(args.input_dir) if f.endswith('.sol')]
    print(f"\nFound {len(sol_files)} .sol files")

    if len(sol_files) == 0:
        print("No .sol files found!")
        return

    # Analyze each contract
    results = []
    stats = {
        'CORRECT': 0,
        'FALSE_POSITIVE': 0,
        'NO_BAD_RANDOMNESS': 0,
        'ERROR': 0
    }

    print("\nAnalyzing...")
    for i, filename in enumerate(sol_files):
        filepath = os.path.join(args.input_dir, filename)
        result = analyze_contract(filepath)
        results.append(result)
        stats[result['verdict']] = stats.get(result['verdict'], 0) + 1

        if (i + 1) % 10 == 0:
            print(f"  Processed {i + 1}/{len(sol_files)}")

    # Save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'input_folder': args.input_dir,
        'total_files': len(sol_files),
        'statistics': stats,
        'results': results
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Display results
    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    for verdict, count in stats.items():
        pct = count / len(sol_files) * 100 if sol_files else 0
        print(f"  {verdict:20}: {count:4} ({pct:5.1f}%)")

    # Sample CORRECT
    print("\n" + "=" * 70)
    print("Sample CORRECT (mitigation on randomness function)")
    print("=" * 70)
    correct = [r for r in results if r['verdict'] == 'CORRECT'][:3]
    for c in correct:
        print(f"  {c['file']}")
        if c.get('protected_functions'):
            pf = c['protected_functions'][0]
            print(f"    Function: {pf['name']}() - {pf['visibility']}")
            print(f"    Mitigations: {pf.get('mitigations', [])}")

    # Sample FALSE_POSITIVE
    print("\n" + "=" * 70)
    print("Sample FALSE_POSITIVE (mitigation elsewhere)")
    print("=" * 70)
    fp = [r for r in results if r['verdict'] == 'FALSE_POSITIVE'][:3]
    for f in fp:
        print(f"  {f['file']}")
        if f.get('unprotected_functions'):
            uf = f['unprotected_functions'][0]
            print(f"    Unprotected: {uf['name']}() - {uf['visibility']}")
            print(f"    Reason: {uf.get('reason', 'N/A')}")

    # Sample NO_BAD_RANDOMNESS
    print("\n" + "=" * 70)
    print("Sample NO_BAD_RANDOMNESS")
    print("=" * 70)
    nobad = [r for r in results if r['verdict'] == 'NO_BAD_RANDOMNESS'][:3]
    for n in nobad:
        print(f"  {n['file']}")
        print(f"    Reason: {n['reason']}")

    print(f"\nResults saved to: {args.output}")

    # Recommended actions
    print("\n" + "=" * 70)
    print("RECOMMENDED ACTIONS")
    print("=" * 70)
    if stats['FALSE_POSITIVE'] > 0:
        print(f"  - Move {stats['FALSE_POSITIVE']} FALSE_POSITIVE files to HIGH_RISK")
    if stats['NO_BAD_RANDOMNESS'] > 0:
        print(f"  - Review {stats['NO_BAD_RANDOMNESS']} NO_BAD_RANDOMNESS files")
    if stats['CORRECT'] > 0:
        print(f"  - Keep {stats['CORRECT']} CORRECT files in MEDIUM_RISK")


if __name__ == "__main__":
    main()