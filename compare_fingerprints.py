from pathlib import Path
import argparse
import csv
import math


CsvRow = dict[str, str]
EXCLUDED_FEATURE_COLUMNS = {
    "session_id",
    "victim_label",
    "victim_host",
    "_source_path",
}

def parse_args(): 
    parser = argparse.ArgumentParser(description="Compare session fingerprint_features.csv files.")

    parser.add_argument(
        "analysis_root",
        type=Path,
        help="Path to the analysis root directory.",
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/combined"),
        help="Path to save the output to.",
    )
    return parser.parse_args()


def read_single_csv_row(path: Path) -> CsvRow:
    with path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    if len(rows) != 1:
        raise ValueError(f"Too many rows in {path}, currently has {len(rows)} rows.")

    row = rows[0]
    row["_source_path"] = str(path)
    return row




def load_fingerprints(analysis_root: Path) -> list[CsvRow]:
    rows = []
    for path in sorted(analysis_root.rglob("fingerprint_features.csv")):
        if "combined" in path.parts:
            continue

        rows.append(read_single_csv_row(path))

    if not rows:
        raise FileNotFoundError(f"fingerprint_features.csv not files found in {analysis_root}.")
    return rows

def collect_all_columns(rows: list[CsvRow]) -> list[str]: # compare the headers of the csv files to make a master key.
    columns = []
    for row in rows:
        for key in row.keys():
            if key not in columns:
                columns.append(key)
    return columns

def csv_writer(path: Path, rows: list[CsvRow], headings: list[str] = None):
    path.parent.mkdir(parents=True, exist_ok=True)

    if headings is None:
        headings = collect_all_columns(rows)

    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headings)
        writer.writeheader()
        writer.writerows(rows)

def is_number(value):
    if value in (None, ""):
        return True
    try:
        float(value)
        return True
    except ValueError:
        return False

def get_feature_columns(rows: list[CsvRow]) -> list[str]:
    columns = []
    all_columns = collect_all_columns(rows)

    for column in all_columns:
        if column in EXCLUDED_FEATURE_COLUMNS:
            continue
        values = [row.get(column, "") for row in rows]


        # include only columns that are numeric or blank in every row.
        if all(is_number(value) for value in values):
            columns.append(column)

    return columns

def row_to_vector(row: CsvRow, feature_columns: list[str]) -> list[float]: # turn a csv row into a vector of floats
    vector = []
    for column in feature_columns:
        value = row.get(column, "")
        if value in (None, ""):
            vector.append(0.0)
        else:
            vector.append(float(value))
    return vector

def min_max_normalise(vectors: list[list[float]]) -> list[list[float]]:
    if not vectors:
        return []

    column_count = len(vectors[0])
    mins = []
    maxs = []

    for col in range(column_count):
        values = [vector[col] for vector in vectors]
        mins.append(min(values))
        maxs.append(max(values))

    normalised = []

    for vector in vectors:
        new_vector = []

        for col, value in enumerate(vector):
            min_value = mins[col]
            max_value = maxs[col]

            if max_value == min_value:
                new_vector.append (0.0)
            else:
                new_vector.append((value - min_value) / (max_value - min_value))

        normalised.append(new_vector)
    return normalised

def cosine_similarity(vector_a: list[float], vector_b: list[float]) -> float:
    dot_product = sum(
        value_a * value_b
        for value_a, value_b in zip(vector_a, vector_b)
    )

    magnitude_a = math.sqrt(sum(value * value for value in vector_a))
    magnitude_b = math.sqrt(sum(value * value for value in vector_b))

    if magnitude_a == 0 or magnitude_b == 0:
        return 0.0

    return dot_product / (magnitude_a * magnitude_b)

def mean(values):
    values = [float(value) for value in values if value not in (None, "")]
    if not values:
        return 0.0
    return sum(values) / len(values)

def build_pairwise_similarity(rows: list[CsvRow], vectors: list[list[float]]) -> list[dict]:
    pairwise_rows = []

    for i, query in enumerate(rows):
        for j, candidate in enumerate(rows):
            if i == j:
                continue

            similarity = cosine_similarity(vectors[i], vectors[j])
            same_victim = query["victim_label"] == candidate["victim_label"]
            pairwise_rows.append({
                "query_session_id": query["session_id"],
                "candidate_session_id": candidate["session_id"],
                "query_victim": query["victim_label"],
                "candidate_victim": candidate["victim_label"],
                "similarity": round(similarity, 6),
                "same_victim": same_victim,
            })
    return pairwise_rows

def build_query_results(pairwise_rows: list[dict]) -> list[dict]:
    by_query = {}

    for row in pairwise_rows:
        by_query.setdefault(row["query_session_id"], []).append(row)

    results = []

    for query_session_id, candidates in by_query.items():
        candidates = sorted(
            candidates,
            key=lambda row: float(row["similarity"]),
            reverse=True,
        )
        if not candidates:
            continue

        best = candidates[0]
        same_victim_candidates = [
            row for row in candidates
            if row["same_victim"] is True
        ]

        different_victim_candidates = [
            row for row in candidates
            if row["same_victim"] is False
        ]

        rank_of_first_same = None
        for rank, candidate in enumerate(candidates, start=1):
            if candidate["same_victim"]:
                rank_of_first_same = rank
                break

        top3 = candidates[:3]
        top3_contains_same = any(row["same_victim"] is True for row in top3)

        has_same_victim_candidate = bool(same_victim_candidates)
        top1_correct = best["same_victim"] is True

        results.append({
            "query_session": query_session_id,
            "query_victim": best["query_victim"],
            "best_match_session": best["candidate_session_id"],
            "best_match_victim": best["candidate_victim"],
            "best_similarity": best["similarity"],
            "has_same_victim_candidate": has_same_victim_candidate,
            "top1_correct": top1_correct if has_same_victim_candidate else "",
            "top3_contains_same_victim": top3_contains_same if has_same_victim_candidate else "",
            "rank_of_first_same_victim": rank_of_first_same if rank_of_first_same is not None else "",
            "false_positive": (not top1_correct) if has_same_victim_candidate else "",
            "mean_same_victim_similarity": round(
                mean([row["similarity"] for row in same_victim_candidates]), 6)
                if same_victim_candidates else "",
            "mean_different_victim_similarity": round(
                mean([row["similarity"] for row in different_victim_candidates]), 6)
                if different_victim_candidates else "",
        })
    return results

def linkability_report_writer(path: Path, fingerprint_rows: list[CsvRow], pairwise_rows: list[dict], query_results: list[dict], feature_columns: list[str]):
    victim_labels = sorted(set(row["victim_label"] for row in fingerprint_rows))

    same_scores = [
        float(row["similarity"])
        for row in pairwise_rows
        if row["same_victim"] is True
    ]

    different_scores = [
        float(row["similarity"])
        for row in pairwise_rows
        if row["same_victim"] is False
    ]

    evaluable_results = [
        row for row in query_results
        if row["has_same_victim_candidate"] == True
    ]

    top1_correct = sum(1 for row in evaluable_results if row["top1_correct"] is True)
    top3_correct = sum(1 for row in evaluable_results if row["top3_contains_same_victim"] is True)
    false_positives = sum(1 for row in evaluable_results if row["false_positive"] is True)

    lines = []
    lines.append("# Linkability Report")
    lines.append("")
    lines.append("## Dataset")
    lines.append(f"- Sessions compared: {len(fingerprint_rows)}")
    lines.append(f"- Victims represented: {len(victim_labels)}")
    lines.append(f"- Victim labels: {', '.join(victim_labels)}")
    lines.append(f"- Fingerprint feature columns: {len(feature_columns)}")
    lines.append("")
    lines.append("## Similarity summary")
    lines.append(f"- Same-victim comparisons: {len(same_scores)}")
    lines.append(f"- Different-victim comparisons: {len(different_scores)}")
    lines.append(f"- Mean same-victim similarity: {mean(same_scores):.3f}")
    lines.append(f"- Mean different-victim similarity: {mean(different_scores):.3f}")
    lines.append("")
    lines.append("## Query Against Historical Data")
    lines.append(f"- Evaluable query sessions: {len(evaluable_results)}")
    lines.append(f"- Top-1 correct matches: {top1_correct}/{len(evaluable_results)}")
    lines.append(f"- Top-3 contained same victim: {top3_correct}/{len(evaluable_results)}")
    lines.append("")
    lines.append("## Explanation")

    if same_scores and different_scores and mean(same_scores) > mean(different_scores):
        lines.append(
            "Same-victim sessions were more similar on average than different-victim sessions."
            " This supports the hypothesis that adversary-visible timing and flow features can provide cross-session linkability in the tested setup."
        )
    else:
        lines.append(
            "Same-victim sessions were not clearly more similar than different-victim sessions."
            " This means the current dataset or selected features are not sufficient to demonstrate a strong linkability claim."
        )
    lines.append("")
    lines.append(
        "Explicit identifiers like session ID, victim label, and victim host/IP are excluded from the similarity calculation."
        " However, they are kept only as references for deciding whether a match is correct."
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")




def main():
    args = parse_args()

    analysis_root = args.analysis_root
    output_dir = args.out
    output_dir.mkdir(parents=True, exist_ok=True)

    fingerprint_rows = load_fingerprints(analysis_root)
    all_fingerprints_path = output_dir / "all_fingerprints.csv"
    csv_writer(all_fingerprints_path, fingerprint_rows)

    feature_columns = get_feature_columns(fingerprint_rows)
    if not feature_columns:
        raise SystemExit("No numeric fingerprint feature columns found.")

    raw_vectors = [
        row_to_vector(row, feature_columns)
        for row in fingerprint_rows
    ]
    normalised_vectors = min_max_normalise(raw_vectors)

    pairwise_rows = build_pairwise_similarity(fingerprint_rows, normalised_vectors)
    csv_writer(output_dir / "pairwise_similarity.csv", pairwise_rows)

    query_results = build_query_results(pairwise_rows)

    linkability_report_writer(
        output_dir / "linkability_report.md",
        fingerprint_rows,
        pairwise_rows,
        query_results,
        feature_columns,
    )

    print(f" loaded {len(fingerprint_rows)} fingerprint files.")
    print(f" used {len(feature_columns)} numeric fingerprint features.")
    print(f" saved all data to {output_dir}")

if __name__ == "__main__":
    raise SystemExit(main())
