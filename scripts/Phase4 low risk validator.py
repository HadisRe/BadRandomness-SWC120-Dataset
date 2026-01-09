#!/usr/bin/env python3
"""
Phase 4: LOW_RISK Function-Level Validator

This script validates contracts classified as LOW_RISK in Phase 3 by checking
whether the onlyOwner modifier is actually applied to the function containing
the bad randomness pattern, not just existing somewhere else in the contract.

The key insight is that a contract may contain both an onlyOwner modifier and
a bad randomness pattern, but if they appear in different functions, the
vulnerability remains fully exploitable.

Validation Logic:
1. If the randomness function is public/external, it must have onlyOwner directly
2. If the randomness function is internal/private, check if its public callers
   have onlyOwner protection

Verdicts:
- CORRECT: The onlyOwner modifier properly protects the vulnerable function
- FALSE_POSITIVE: The modifier exists but does not protect the vulnerable code
- NO_BAD_RANDOMNESS: No bad randomness pattern found in any function body

Input: Directory containing LOW_RISK .sol files
Output: JSON file with validation results
"""

import os
import re
import json
from datetime import datetime
import argparse

BAD_RANDOMNESS_PATTERNS = [
    r'block\.timestamp\s*%',
    r'(?<![a-zA-Z])now(?![a-zA-Z])\s*%',
    r'block\.number\s*%',
    r'block\.difficulty\s*%',
    r'blockhash\s*\([^)]*\)',
    r'block\.blockhash\s*\([^)]*\)',
    r'keccak256[^;]*block\.',
    r'keccak256[^;]*(?<![a-zA-Z])now(?![a-zA-Z])',
    r'keccak256[^;]*blockhash',
    r'(?:seed|random)\w*\s*=\s*[^;]*block\.',
]


def remove_comments(content):
    """Remove single-line and multi-line comments from Solidity code."""
    content = re.sub(r'/\*[\s\S]*?\*/', '', content)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    return content


def extract_functions(content):
    """
    Extract all functions from the contract with their name, modifiers, and body.

    Uses brace counting to correctly identify function boundaries even with
    nested structures like if statements and loops.
    """
    functions = []
    pattern = r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\{'

    for match in re.finditer(pattern, content):
        func_name = match.group(1)
        modifiers = match.group(2)
        start_pos = match.end() - 1

        brace_count = 0
        end_pos = start_pos
        for i in range(start_pos, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break

        func_body = content[start_pos:end_pos]

        functions.append({
            'name': func_name,
            'modifiers': modifiers.strip(),
            'body': func_body,
        })

    return functions


def has_bad_randomness(code):
    """Check if the code contains any bad randomness pattern."""
    for pattern in BAD_RANDOMNESS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            return True
    return False


def is_protected(modifiers):
    """Check if the function has access control protection."""
    return bool(re.search(r'onlyOwner|onlyAdmin|internal|private', modifiers, re.IGNORECASE))


def is_public_or_external(modifiers):
    """
    Check if the function is callable from outside the contract.

    In older Solidity versions, functions without explicit visibility are public
    by default, so we only return False if internal or private is specified.
    """
    if re.search(r'\b(internal|private)\b', modifiers, re.IGNORECASE):
        return False
    return True


def calls_function(caller_body, callee_name):
    """Check if the caller function calls the callee function."""
    pattern = r'\b' + callee_name + r'\s*\('
    return bool(re.search(pattern, caller_body))


def analyze_contract(filepath):
    """
    Analyze a single contract to validate its LOW_RISK classification.

    Returns a dictionary with the validation verdict and details about
    which functions contain bad randomness and whether they are protected.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return None

    clean = remove_comments(content)
    functions = extract_functions(clean)

    result = {
        'file': os.path.basename(filepath),
        'bad_randomness_functions': [],
        'unprotected_paths': [],
        'verdict': 'UNKNOWN'
    }

    # Find functions containing bad randomness patterns
    bad_funcs = []
    for func in functions:
        if has_bad_randomness(func['body']):
            bad_funcs.append(func)
            result['bad_randomness_functions'].append({
                'name': func['name'],
                'modifiers': func['modifiers'][:50]
            })

    if not bad_funcs:
        result['verdict'] = 'NO_BAD_RANDOMNESS'
        return result

    # Check each function with bad randomness
    has_unprotected_path = False

    for bad_func in bad_funcs:
        # If function is public/external and not protected
        if is_public_or_external(bad_func['modifiers']) and not is_protected(bad_func['modifiers']):
            has_unprotected_path = True
            result['unprotected_paths'].append(f"{bad_func['name']}() is public without protection")

        # If function is internal/private, check who calls it
        elif not is_public_or_external(bad_func['modifiers']):
            for func in functions:
                if func['name'] != bad_func['name']:
                    if calls_function(func['body'], bad_func['name']):
                        # Another function calls this one
                        # Is that function public and unprotected?
                        if is_public_or_external(func['modifiers']) and not is_protected(func['modifiers']):
                            has_unprotected_path = True
                            result['unprotected_paths'].append(
                                f"{func['name']}() calls {bad_func['name']}() without protection"
                            )

    if has_unprotected_path:
        result['verdict'] = 'FALSE_POSITIVE'
    else:
        result['verdict'] = 'CORRECT'

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Validate LOW_RISK contracts by checking function-level modifier application"
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing LOW_RISK Solidity (.sol) files"
    )
    parser.add_argument(
        "-o", "--output",
        default="low_risk_validation.json",
        help="Output JSON file path (default: low_risk_validation.json)"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: Directory not found: {args.input_dir}")
        return

    print("=" * 60)
    print("LOW_RISK Function-Level Validator")
    print("=" * 60)

    files = [f for f in os.listdir(args.input_dir) if f.endswith('.sol')]
    print(f"\nTotal files: {len(files)}")

    results = []
    stats = {'CORRECT': 0, 'FALSE_POSITIVE': 0, 'NO_BAD_RANDOMNESS': 0, 'ERROR': 0}

    print("\nAnalyzing...")

    for i, filename in enumerate(files):
        filepath = os.path.join(args.input_dir, filename)
        result = analyze_contract(filepath)

        if result:
            results.append(result)
            stats[result['verdict']] += 1
        else:
            stats['ERROR'] += 1

        if (i + 1) % 100 == 0:
            print(f"  Processed: {i + 1}/{len(files)}")

    # Save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'total': len(files),
        'statistics': stats,
        'results': results
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Display results
    print("\n" + "=" * 60)
    print("VALIDATION RESULTS")
    print("=" * 60)

    for verdict, count in stats.items():
        pct = (count / len(files) * 100) if len(files) > 0 else 0
        print(f"  {verdict:20}: {count:5} ({pct:5.1f}%)")

    # Sample FALSE_POSITIVE
    fps = [r for r in results if r['verdict'] == 'FALSE_POSITIVE']
    if fps:
        print(f"\nSample FALSE_POSITIVE ({len(fps)} total):")
        for fp in fps[:5]:
            print(f"\n  {fp['file']}")
            for path in fp['unprotected_paths'][:2]:
                print(f"    - {path}")

    # Sample NO_BAD_RANDOMNESS
    nobad = [r for r in results if r['verdict'] == 'NO_BAD_RANDOMNESS']
    if nobad:
        print(f"\nSample NO_BAD_RANDOMNESS ({len(nobad)} total):")
        for nb in nobad[:5]:
            print(f"  {nb['file']}")

    print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()