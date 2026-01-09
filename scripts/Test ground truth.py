#!/usr/bin/env python3
"""
Ground Truth Test

This script tests the pattern labeler against a ground truth dataset to
measure accuracy, precision, recall, and F1-score.

The ground truth should be organized in folders where each folder name
indicates the expected label:
- bad_randomness/ or vulnerable/ -> VULNERABLE
- safe/ or Safe/ -> SAFE

The script imports the label_contract function from phase2_pattern_labeler
and runs it on each contract in the ground truth folders.

Input: Directory containing ground truth folders
Output: Metrics and list of misclassified contracts
"""

import os
import argparse
from phase2_pattern_labeler import label_contract


# Mapping from folder names to expected labels
FOLDER_LABELS = {
    "bad_randomness": "VULNERABLE",
    "vulnerable": "VULNERABLE",
    "unsafe": "VULNERABLE",
    "Safe": "SAFE",
    "safe": "SAFE",
}


def main():
    parser = argparse.ArgumentParser(
        description="Test the pattern labeler against ground truth dataset"
    )
    parser.add_argument(
        "ground_truth_dir",
        help="Directory containing ground truth folders (e.g., bad_randomness/, safe/)"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.ground_truth_dir):
        print(f"Error: Directory not found: {args.ground_truth_dir}")
        return

    print("=" * 70)
    print("GROUND TRUTH TEST")
    print("=" * 70)

    # Collect all test files
    print("\nScanning folders...")
    all_files = []

    for folder in os.listdir(args.ground_truth_dir):
        folder_path = os.path.join(args.ground_truth_dir, folder)
        if os.path.isdir(folder_path):
            expected = FOLDER_LABELS.get(folder, None)
            if expected is None:
                print(f"  {folder}: SKIPPED (unknown folder name)")
                continue

            sol_files = [f for f in os.listdir(folder_path) if f.endswith('.sol')]
            print(f"  {folder}: {len(sol_files)} files -> {expected}")

            for f in sol_files:
                all_files.append({
                    "folder": folder,
                    "filename": f,
                    "filepath": os.path.join(folder_path, f),
                    "expected": expected
                })

    print(f"\nTotal test files: {len(all_files)}")

    if len(all_files) == 0:
        print("No test files found!")
        return

    # Run tests
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    tp = fp = tn = fn = 0
    wrong_list = []

    print(f"\n{'Folder':<16} {'File':<35} {'Exp':<5} {'Got':<5} {'Reason':<25}")
    print("-" * 95)

    for f in all_files:
        pred, conf, reason = label_contract(f["filepath"])
        exp = f["expected"]
        correct = (pred == exp)

        if exp == "VULNERABLE" and pred == "VULNERABLE":
            tp += 1
        elif exp == "SAFE" and pred == "VULNERABLE":
            fp += 1
        elif exp == "SAFE" and pred == "SAFE":
            tn += 1
        elif exp == "VULNERABLE" and pred == "SAFE":
            fn += 1

        status = "OK" if correct else "WRONG"
        fname = f["filename"][:33] + ".." if len(f["filename"]) > 35 else f["filename"]
        short_reason = reason[:23] + ".." if len(reason) > 25 else reason
        print(f"{f['folder']:<16} {fname:<35} {exp[:4]:<5} {pred[:4]:<5} {status:<5} {short_reason}")

        if not correct:
            wrong_list.append({
                "file": f"{f['folder']}/{f['filename']}",
                "exp": exp,
                "got": pred,
                "reason": reason
            })

    # Calculate metrics
    total = len(all_files)
    correct_count = tp + tn
    accuracy = correct_count / total * 100 if total > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("\n" + "=" * 70)
    print("METRICS")
    print("=" * 70)
    print(f"\nAccuracy:  {accuracy:.1f}% ({correct_count}/{total})")
    print(f"Precision: {precision:.1f}%")
    print(f"Recall:    {recall:.1f}%")
    print(f"F1-Score:  {f1:.1f}%")
    print(f"\nConfusion Matrix:")
    print(f"  TP={tp}  FP={fp}")
    print(f"  FN={fn}  TN={tn}")

    if wrong_list:
        print("\n" + "=" * 70)
        print(f"MISCLASSIFIED ({len(wrong_list)} files)")
        print("=" * 70)
        for w in wrong_list:
            print(f"\n  {w['file']}")
            print(f"    Expected: {w['exp']}, Got: {w['got']}")
            print(f"    Reason: {w['reason']}")
    else:
        print("\nAll predictions correct!")


if __name__ == "__main__":
    main()