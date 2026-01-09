#!/usr/bin/env python3
"""
Phase 1: Bad Randomness Keyword Filter

This script filters Solidity smart contracts from the SmartBugs-Wild dataset
to identify contracts that contain block attributes commonly used as weak
randomness sources.

The filtering is based on 6 keywords defined in SWC-120:
- block.timestamp
- blockhash
- block.difficulty
- block.number
- block.coinbase
- block.gaslimit

Note that the presence of these keywords does not imply vulnerability.
Many contracts use block attributes for legitimate purposes such as time
tracking. The subsequent phases distinguish between safe and vulnerable
usage patterns.

Input: Directory containing .sol files
Output:
    1. JSON file with list of contracts containing bad randomness sources
    2. Statistics about source distribution
    3. Optionally, copy filtered contracts to a new directory
"""

import os
import re
import json
import argparse
import shutil
from datetime import datetime
from typing import Dict, List
from dataclasses import dataclass, asdict

# The 6 main bad randomness sources based on SWC-120
BAD_RANDOMNESS_SOURCES = {
    "block.timestamp": {
        "patterns": [
            r'\bblock\.timestamp\b',
            r'(?<![a-zA-Z_0-9])now(?![a-zA-Z_0-9])'
        ],
        "category": "BLOCK_PROPERTY",
        "risk_level": "HIGH",
        "description": "Miner can manipulate within approximately 15 seconds"
    },

    "blockhash": {
        "patterns": [
            r'\bblockhash\s*\(',
            r'\bblock\.blockhash\s*\('
        ],
        "category": "BLOCK_PROPERTY",
        "risk_level": "HIGH",
        "description": "Only available for 256 recent blocks, miner can withhold"
    },

    "block.difficulty": {
        "patterns": [
            r'\bblock\.difficulty\b',
            r'\bblock\.prevrandao\b'
        ],
        "category": "BLOCK_PROPERTY",
        "risk_level": "HIGH",
        "description": "Predictable by miner in PoW or validator in PoS"
    },

    "block.number": {
        "patterns": [r'\bblock\.number\b'],
        "category": "BLOCK_PROPERTY",
        "risk_level": "MEDIUM",
        "description": "Sequential and fully predictable"
    },

    "block.coinbase": {
        "patterns": [r'\bblock\.coinbase\b'],
        "category": "BLOCK_PROPERTY",
        "risk_level": "MEDIUM",
        "description": "Miner address, known to miner before block is mined"
    },

    "block.gaslimit": {
        "patterns": [r'\bblock\.gaslimit\b'],
        "category": "BLOCK_PROPERTY",
        "risk_level": "LOW",
        "description": "Publicly known and relatively stable"
    }
}

# Additional patterns that often indicate randomness usage
DANGEROUS_PATTERNS = {
    "modulo_randomness": {
        "pattern": r'%\s*(?:players|participants|entries|length|count|size|\d+)',
        "description": "Modulo operation often indicates randomness usage"
    },
    "winner_selection": {
        "pattern": r'\b(?:winner|selected|random|index|pick|choice)\s*=',
        "description": "Variable names suggesting randomness"
    },
    "lottery_keywords": {
        "pattern": r'\b(?:lottery|gambl|bet|casino|dice|roulette|jackpot|prize)\b',
        "description": "Domain keywords suggesting randomness need"
    }
}


def remove_comments_and_strings(source_code: str) -> str:
    """
    Remove comments and string literals from Solidity source code.

    This function implements a state machine that properly handles:
    - Single-line comments starting with //
    - Multi-line comments wrapped in /* */
    - String literals in double or single quotes

    Newlines are preserved to maintain correct line numbering.

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

        # Regular character
        else:
            result.append(source_code[i])
            i += 1

    return ''.join(result)


@dataclass
class SourceMatch:
    """Represents a single match of a bad randomness source in code."""
    source_name: str
    line_number: int
    line_content: str
    category: str
    risk_level: str


@dataclass
class ContractAnalysis:
    """Contains the analysis results for a single contract."""
    filename: str
    filepath: str
    has_bad_source: bool
    sources_found: List[Dict]
    dangerous_patterns: List[Dict]
    total_lines: int
    source_count: int


class BadRandomnessExtractor:
    """Extracts contracts containing bad randomness sources."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stats = {
            "total_contracts": 0,
            "contracts_with_sources": 0,
            "source_distribution": {},
            "category_distribution": {},
            "risk_distribution": {}
        }

    def extract_sources(self, content: str) -> List[SourceMatch]:
        """
        Extract all bad randomness sources from contract content.

        Args:
            content: Raw Solidity source code

        Returns:
            List of SourceMatch objects for each found source
        """
        matches = []

        # Remove comments and strings before searching
        clean_content = remove_comments_and_strings(content)

        # Keep original lines for display purposes
        original_lines = content.split('\n')
        clean_lines = clean_content.split('\n')

        for source_name, source_info in BAD_RANDOMNESS_SOURCES.items():
            for pattern in source_info["patterns"]:
                regex = re.compile(pattern, re.IGNORECASE)
                for line_num, clean_line in enumerate(clean_lines, 1):
                    if regex.search(clean_line):
                        original_line = original_lines[line_num - 1] if line_num <= len(original_lines) else clean_line
                        matches.append(SourceMatch(
                            source_name=source_name,
                            line_number=line_num,
                            line_content=original_line.strip()[:100],
                            category=source_info["category"],
                            risk_level=source_info["risk_level"]
                        ))

        return matches

    def extract_dangerous_patterns(self, content: str) -> List[Dict]:
        """
        Extract dangerous patterns that suggest randomness usage.

        Args:
            content: Raw Solidity source code

        Returns:
            List of dictionaries describing found patterns
        """
        patterns_found = []

        clean_content = remove_comments_and_strings(content)

        original_lines = content.split('\n')
        clean_lines = clean_content.split('\n')

        for pattern_name, pattern_info in DANGEROUS_PATTERNS.items():
            regex = re.compile(pattern_info["pattern"], re.IGNORECASE)
            for line_num, clean_line in enumerate(clean_lines, 1):
                if regex.search(clean_line):
                    original_line = original_lines[line_num - 1] if line_num <= len(original_lines) else clean_line
                    patterns_found.append({
                        "pattern_name": pattern_name,
                        "line_number": line_num,
                        "line_content": original_line.strip()[:100],
                        "description": pattern_info["description"]
                    })

        return patterns_found

    def analyze_contract(self, filepath: str) -> ContractAnalysis:
        """
        Analyze a single contract for bad randomness sources.

        Args:
            filepath: Path to the .sol file

        Returns:
            ContractAnalysis object with results, or None if file cannot be read
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            if self.verbose:
                print(f"Error reading {filepath}: {e}")
            return None

        sources = self.extract_sources(content)
        patterns = self.extract_dangerous_patterns(content)

        return ContractAnalysis(
            filename=os.path.basename(filepath),
            filepath=filepath,
            has_bad_source=len(sources) > 0,
            sources_found=[asdict(s) for s in sources],
            dangerous_patterns=patterns,
            total_lines=len(content.split('\n')),
            source_count=len(sources)
        )

    def analyze_directory(self, directory: str) -> List[ContractAnalysis]:
        """
        Analyze all Solidity contracts in a directory.

        Args:
            directory: Path to directory containing .sol files

        Returns:
            List of ContractAnalysis objects
        """
        results = []
        sol_files = []

        # Find all .sol files recursively
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.sol'):
                    sol_files.append(os.path.join(root, file))

        print(f"Found {len(sol_files)} Solidity files")
        self.stats["total_contracts"] = len(sol_files)

        # Analyze each file
        for i, filepath in enumerate(sol_files):
            if self.verbose and i % 1000 == 0:
                print(f"Processing {i}/{len(sol_files)}...")

            analysis = self.analyze_contract(filepath)
            if analysis:
                results.append(analysis)

                if analysis.has_bad_source:
                    self.stats["contracts_with_sources"] += 1

                    # Update statistics
                    for source in analysis.sources_found:
                        name = source["source_name"]
                        cat = source["category"]
                        risk = source["risk_level"]

                        self.stats["source_distribution"][name] = \
                            self.stats["source_distribution"].get(name, 0) + 1
                        self.stats["category_distribution"][cat] = \
                            self.stats["category_distribution"].get(cat, 0) + 1
                        self.stats["risk_distribution"][risk] = \
                            self.stats["risk_distribution"].get(risk, 0) + 1

        return results

    def filter_contracts_with_sources(self, results: List[ContractAnalysis]) -> List[ContractAnalysis]:
        """Filter to keep only contracts that have bad randomness sources."""
        return [r for r in results if r.has_bad_source]

    def export_results(self, results: List[ContractAnalysis], output_path: str):
        """
        Save analysis results to a JSON file.

        Args:
            results: List of ContractAnalysis objects
            output_path: Path for the output JSON file
        """
        output = {
            "metadata": {
                "extraction_date": datetime.now().isoformat(),
                "total_analyzed": self.stats["total_contracts"],
                "contracts_with_sources": self.stats["contracts_with_sources"],
                "extraction_rate": f"{100 * self.stats['contracts_with_sources'] / max(1, self.stats['total_contracts']):.2f}%"
            },
            "statistics": self.stats,
            "contracts": [asdict(r) for r in results]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"\nResults saved to: {output_path}")

    def copy_filtered_contracts(self, results: List[ContractAnalysis], output_dir: str):
        """
        Copy filtered contracts to a new directory.

        Args:
            results: List of ContractAnalysis objects
            output_dir: Destination directory for filtered contracts
        """
        os.makedirs(output_dir, exist_ok=True)

        for r in results:
            if r.has_bad_source:
                dest = os.path.join(output_dir, r.filename)
                # Handle duplicate filenames by adding a counter
                if os.path.exists(dest):
                    base, ext = os.path.splitext(r.filename)
                    counter = 1
                    while os.path.exists(dest):
                        dest = os.path.join(output_dir, f"{base}_{counter}{ext}")
                        counter += 1
                try:
                    shutil.copy2(r.filepath, dest)
                except Exception as e:
                    if self.verbose:
                        print(f"Error copying {r.filepath}: {e}")

        print(f"Copied {self.stats['contracts_with_sources']} contracts to: {output_dir}")

    def print_summary(self):
        """Print a summary of the extraction statistics."""
        print("\n" + "=" * 60)
        print("EXTRACTION SUMMARY")
        print("=" * 60)
        print(f"Total contracts analyzed: {self.stats['total_contracts']}")
        print(f"Contracts with bad sources: {self.stats['contracts_with_sources']}")
        print(
            f"Extraction rate: {100 * self.stats['contracts_with_sources'] / max(1, self.stats['total_contracts']):.2f}%")

        print("\nSource Distribution:")
        for source, count in sorted(self.stats["source_distribution"].items(),
                                    key=lambda x: x[1], reverse=True):
            print(f"  {source}: {count}")

        print("\nCategory Distribution:")
        for cat, count in sorted(self.stats["category_distribution"].items(),
                                 key=lambda x: x[1], reverse=True):
            print(f"  {cat}: {count}")

        print("\nRisk Level Distribution:")
        for risk, count in sorted(self.stats["risk_distribution"].items(),
                                  key=lambda x: x[1], reverse=True):
            print(f"  {risk}: {count}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Extract contracts with bad randomness sources from SmartBugs-Wild"
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing Solidity contracts"
    )
    parser.add_argument(
        "-o", "--output",
        default="phase1_filtered_contracts.json",
        help="Output JSON file path (default: phase1_filtered_contracts.json)"
    )
    parser.add_argument(
        "-c", "--copy-dir",
        help="Directory to copy filtered contracts (optional)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"Error: Directory not found: {args.input_dir}")
        return

    extractor = BadRandomnessExtractor(verbose=args.verbose)

    print(f"Analyzing contracts in: {args.input_dir}")
    results = extractor.analyze_directory(args.input_dir)

    # Filter contracts with bad sources
    filtered = extractor.filter_contracts_with_sources(results)

    # Save results
    extractor.export_results(filtered, args.output)

    # Copy files if requested
    if args.copy_dir:
        extractor.copy_filtered_contracts(results, args.copy_dir)

    # Print summary
    extractor.print_summary()


if __name__ == "__main__":
    main()