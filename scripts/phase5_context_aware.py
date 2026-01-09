#!/usr/bin/env python3
"""
Phase 5: Context-Aware Analyzer

This script analyzes contracts that were flagged as NO_BAD_RANDOMNESS in Phase 4,
meaning the bad randomness pattern exists but was not found inside any callable
function body.

The goal is to understand where these patterns are located and what type of
contract they belong to. This helps identify false positives such as Mining
Tokens that use block attributes for Proof-of-Work rather than randomness.

Analysis performed:
1. Pattern Location: Where is the bad randomness pattern? (constructor, internal
   function, global variable)
2. Context Detection: What type of contract is this? (Mining Token, Lottery,
   Game, Unknown)

Mining Tokens are excluded from the final dataset because their use of block
attributes is for computational puzzles, not random number generation.

Input: Directory containing contracts to analyze
Output: JSON file with context analysis results
"""

import os
import re
import json
from datetime import datetime
import argparse

# Bad randomness patterns to locate
BAD_PATTERNS = [
    (r'block\.timestamp', 'block.timestamp'),
    (r'(?<![a-zA-Z])now(?![a-zA-Z])', 'now'),
    (r'block\.number', 'block.number'),
    (r'block\.difficulty', 'block.difficulty'),
    (r'blockhash\s*\(', 'blockhash()'),
    (r'block\.blockhash\s*\(', 'block.blockhash()'),
    (r'keccak256.*block\.', 'keccak256+block'),
    (r'uint.*keccak256', 'uint(keccak256)'),
]

# Keywords indicating a Mining Token contract
# These contracts use block attributes for Proof-of-Work puzzles
MINING_KEYWORDS = [
    'mint', 'mining', 'miner', 'nonce', 'challenge', 'PoW', 'proof of work',
    'difficulty', 'target', 'digest', 'hash rate', 'epoch', 'reward',
    'EIP918', 'mineable', 'getChallengeNumber', 'getMiningDifficulty',
    'getMiningTarget', 'getMiningReward', 'solutionForChallenge'
]

# Keywords indicating a Lottery or Gambling contract
# These contracts need randomness and are potentially vulnerable
LOTTERY_KEYWORDS = [
    'lottery', 'winner', 'prize', 'ticket', 'draw', 'jackpot', 'bet',
    'gambling', 'casino', 'dice', 'roll', 'spin', 'slot', 'roulette',
    'random winner', 'pick winner', 'select winner', 'lucky'
]

# Keywords indicating a Game contract
GAME_KEYWORDS = [
    'game', 'player', 'battle', 'fight', 'attack', 'defense', 'card',
    'breed', 'hatch', 'spawn', 'monster', 'dragon', 'pet', 'NFT'
]


def remove_comments(content):
    """Remove single-line and multi-line comments from Solidity code."""
    content = re.sub(r'/\*[\s\S]*?\*/', '', content)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    return content


def find_pattern_location(content):
    """
    Find where bad randomness patterns are located in the contract.

    Checks three locations:
    1. Constructor - patterns here only run once at deployment
    2. Internal/private functions - may or may not be callable
    3. Global variables - state variable initializations

    Returns a list of location descriptions.
    """
    locations = []

    # Check constructor
    constructor_match = re.search(r'constructor\s*\([^)]*\)[^{]*\{', content)
    if constructor_match:
        start = constructor_match.end() - 1
        brace_count = 0
        end = start
        for i in range(start, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i
                    break
        constructor_body = content[start:end]

        for pattern, name in BAD_PATTERNS:
            if re.search(pattern, constructor_body, re.IGNORECASE):
                locations.append(f"constructor: {name}")

    # Check internal and private functions
    func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\{'
    for match in re.finditer(func_pattern, content):
        func_name = match.group(1)
        modifiers = match.group(2)

        if re.search(r'\b(internal|private)\b', modifiers, re.IGNORECASE):
            start = match.end() - 1
            brace_count = 0
            end = start
            for i in range(start, len(content)):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i
                        break
            func_body = content[start:end]

            for pattern, name in BAD_PATTERNS:
                if re.search(pattern, func_body, re.IGNORECASE):
                    locations.append(f"internal {func_name}(): {name}")

    # Check global variables
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if '=' in line and 'function' not in line and not line.strip().startswith('//'):
            for pattern, name in BAD_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    locations.append(f"global variable: {name}")
                    break

    return locations


def detect_context(content):
    """
    Detect the contract context based on keyword frequency.

    Counts occurrences of keywords associated with different contract types
    and returns the most likely classification.

    Returns a tuple of (context_type, score).
    """
    content_lower = content.lower()

    mining_score = 0
    lottery_score = 0
    game_score = 0

    for keyword in MINING_KEYWORDS:
        if keyword.lower() in content_lower:
            mining_score += 1

    for keyword in LOTTERY_KEYWORDS:
        if keyword.lower() in content_lower:
            lottery_score += 1

    for keyword in GAME_KEYWORDS:
        if keyword.lower() in content_lower:
            game_score += 1

    # Determine context based on scores
    if mining_score >= 5:
        return 'MINING', mining_score
    elif lottery_score >= 3:
        return 'LOTTERY', lottery_score
    elif game_score >= 3:
        return 'GAME', game_score
    elif mining_score >= 2:
        return 'PROBABLY_MINING', mining_score
    elif lottery_score >= 1:
        return 'PROBABLY_LOTTERY', lottery_score
    elif game_score >= 1:
        return 'PROBABLY_GAME', game_score
    else:
        return 'UNKNOWN', 0


def analyze_file(filepath):
    """
    Analyze a single contract file.

    Returns a dictionary with context classification and pattern locations.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return None

    clean = remove_comments(content)

    locations = find_pattern_location(clean)
    context, score = detect_context(content)

    return {
        'file': os.path.basename(filepath),
        'context': context,
        'context_score': score,
        'pattern_locations': locations,
        'location_count': len(locations)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze contract context to identify Mining Tokens vs Lottery/Gambling contracts"
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing Solidity (.sol) files to analyze"
    )
    parser.add_argument(
        "-o", "--output",
        default="context_analysis.json",
        help="Output JSON file path (default: context_analysis.json)"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: Directory not found: {args.input_dir}")
        return

    print("=" * 60)
    print("Context-Aware Analyzer")
    print("=" * 60)

    files = [f for f in os.listdir(args.input_dir) if f.endswith('.sol')]
    print(f"\nTotal files: {len(files)}")

    results = []
    context_stats = {}
    location_stats = {
        'constructor': 0,
        'internal': 0,
        'global': 0,
        'not_found': 0
    }

    print("\nAnalyzing...")

    for i, filename in enumerate(files):
        filepath = os.path.join(args.input_dir, filename)
        result = analyze_file(filepath)

        if result:
            results.append(result)

            # Update context statistics
            ctx = result['context']
            context_stats[ctx] = context_stats.get(ctx, 0) + 1

            # Update location statistics
            if result['location_count'] == 0:
                location_stats['not_found'] += 1
            else:
                for loc in result['pattern_locations']:
                    if 'constructor' in loc:
                        location_stats['constructor'] += 1
                    elif 'internal' in loc:
                        location_stats['internal'] += 1
                    elif 'global' in loc:
                        location_stats['global'] += 1

        if (i + 1) % 50 == 0:
            print(f"  Processed: {i + 1}/{len(files)}")

    # Save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'total': len(files),
        'context_statistics': context_stats,
        'location_statistics': location_stats,
        'results': results
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Display results
    print("\n" + "=" * 60)
    print("CONTEXT ANALYSIS")
    print("=" * 60)
    for ctx, count in sorted(context_stats.items(), key=lambda x: -x[1]):
        pct = count / len(files) * 100
        print(f"  {ctx:20}: {count:4} ({pct:5.1f}%)")

    print("\n" + "=" * 60)
    print("PATTERN LOCATIONS")
    print("=" * 60)
    for loc, count in location_stats.items():
        print(f"  {loc:15}: {count:4}")

    # Sample Mining contracts
    print("\n" + "=" * 60)
    print("Sample MINING contracts (to be excluded)")
    print("=" * 60)
    mining = [r for r in results if r['context'] == 'MINING'][:3]
    for m in mining:
        print(f"  {m['file']}")
        print(f"    Locations: {m['pattern_locations'][:2]}")

    # Sample Lottery contracts
    print("\n" + "=" * 60)
    print("Sample LOTTERY contracts (vulnerable)")
    print("=" * 60)
    lottery = [r for r in results if 'LOTTERY' in r['context']][:3]
    for l in lottery:
        print(f"  {l['file']}")
        print(f"    Locations: {l['pattern_locations'][:2]}")

    # Sample Unknown contracts
    print("\n" + "=" * 60)
    print("Sample UNKNOWN contracts (need manual review)")
    print("=" * 60)
    unknown = [r for r in results if r['context'] == 'UNKNOWN'][:3]
    for u in unknown:
        print(f"  {u['file']}")
        print(f"    Locations: {u['pattern_locations'][:2]}")

    print(f"\nResults saved to: {args.output}")

    # Summary of actions
    mining_count = context_stats.get('MINING', 0) + context_stats.get('PROBABLY_MINING', 0)
    lottery_count = context_stats.get('LOTTERY', 0) + context_stats.get('PROBABLY_LOTTERY', 0)

    print("\n" + "=" * 60)
    print("RECOMMENDED ACTIONS")
    print("=" * 60)
    print(f"  - Exclude {mining_count} Mining Token contracts from dataset")
    print(f"  - Label {lottery_count} Lottery/Gambling contracts as HIGH_RISK")
    print(f"  - Manually review {context_stats.get('UNKNOWN', 0)} Unknown contracts")


if __name__ == "__main__":
    main()