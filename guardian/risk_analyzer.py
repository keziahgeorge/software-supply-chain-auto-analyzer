
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "output" / "vulnerabilities.json"

OUTPUT_DIR = BASE_DIR / "output"

RISK_FILE = OUTPUT_DIR / "risk_findings.json"
REMEDIATION_FILE = OUTPUT_DIR / "remediation_priorities.json"
SUMMARY_FILE = OUTPUT_DIR / "risk_summary.json"

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "UNKNOWN": 1
}


# ============================================================
# FILE HANDLING
# ============================================================

def load_findings():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}\n"
            "Run vulnerability_scanner.py first."
        )

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        findings = json.load(file)

    if not isinstance(findings, list):
        raise ValueError(
            "vulnerabilities.json must contain a JSON list."
        )

    return findings


def save_json(filepath, data):

    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )


# ============================================================
# CVSS V3.0 / V3.1 CALCULATION
# ============================================================

def round_up_cvss(value):
    """
    CVSS rounding method: round upward to one decimal place.
    """

    return math.ceil(value * 10 - 1e-10) / 10


def calculate_cvss_score(vector):

    if not isinstance(vector, str):
        return None

    parts = vector.split("/")

    if not parts:
        return None

    version = parts[0]

    if version not in ("CVSS:3.0", "CVSS:3.1"):
        return None

    metrics = {}

    for part in parts[1:]:

        if ":" not in part:
            continue

        key, value = part.split(":", 1)
        metrics[key] = value

    required_metrics = [
        "AV", "AC", "PR", "UI", "S", "C", "I", "A"
    ]

    if not all(metric in metrics for metric in required_metrics):
        return None

    weights = {

        "AV": {
            "N": 0.85,
            "A": 0.62,
            "L": 0.55,
            "P": 0.20
        },

        "AC": {
            "L": 0.77,
            "H": 0.44
        },

        "PR": {
            "N": {"U": 0.85, "C": 0.85},
            "L": {"U": 0.62, "C": 0.68},
            "H": {"U": 0.27, "C": 0.50}
        },

        "UI": {
            "N": 0.85,
            "R": 0.62
        },

        "CIA": {
            "N": 0.0,
            "L": 0.22,
            "H": 0.56
        }
    }

    try:

        scope = metrics["S"]

        if scope not in ("U", "C"):
            return None

        av = weights["AV"][metrics["AV"]]
        ac = weights["AC"][metrics["AC"]]
        pr = weights["PR"][metrics["PR"]][scope]
        ui = weights["UI"][metrics["UI"]]

        confidentiality = weights["CIA"][metrics["C"]]
        integrity = weights["CIA"][metrics["I"]]
        availability = weights["CIA"][metrics["A"]]

    except KeyError:
        return None

    exploitability = (
        8.22 * av * ac * pr * ui
    )

    impact_subscore = (
        1
        - (1 - confidentiality)
        * (1 - integrity)
        * (1 - availability)
    )

    if scope == "U":

        impact = 6.42 * impact_subscore

    else:

        impact = (
            7.52 * (impact_subscore - 0.029)
            - 3.25 * ((impact_subscore - 0.02) ** 15)
        )

    if impact <= 0:
        return 0.0

    if scope == "U":

        base_score = min(
            impact + exploitability,
            10
        )

    else:

        base_score = min(
            1.08 * (impact + exploitability),
            10
        )

    return round_up_cvss(base_score)


# ============================================================
# SEVERITY CLASSIFICATION
# ============================================================

def classify_cvss(score):

    if score is None:
        return None

    if score == 0:
        return "LOW"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    return "LOW"


def normalize_severity(value):

    if not isinstance(value, str):
        return "UNKNOWN"

    value = value.strip().upper()

    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "MINIMAL": "LOW",
        "NEGLIGIBLE": "LOW"
    }

    return mapping.get(value, "UNKNOWN")


def extract_severity(advisory):

    cvss_vector = None
    cvss_type = None
    cvss_score = None

    severity_records = advisory.get("severity", [])

    if isinstance(severity_records, list):

        for record in severity_records:

            if not isinstance(record, dict):
                continue

            vector = record.get("score")
            vector_type = record.get("type", "")

            if (
                isinstance(vector, str)
                and vector.startswith(("CVSS:3.0/", "CVSS:3.1/"))
            ):

                score = calculate_cvss_score(vector)

                if score is not None:

                    cvss_vector = vector
                    cvss_type = vector_type
                    cvss_score = score

                    break

    if cvss_score is not None:

        severity = classify_cvss(cvss_score)
        severity_source = "calculated_cvss"

    else:

        database_specific = advisory.get(
            "database_specific", {}
        )

        database_severity = database_specific.get("severity")

        severity = normalize_severity(database_severity)

        severity_source = (
            "database_specific"
            if severity != "UNKNOWN"
            else "unavailable"
        )

    return {
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_type": cvss_type,
        "severity_source": severity_source
    }


# ============================================================
# AFFECTED PACKAGE AND FIXED VERSION EXTRACTION
# ============================================================

def extract_affected_information(package, advisory):

    package_name = package.get("name")
    ecosystem = package.get("ecosystem")

    matching_affected_entries = []

    for affected in advisory.get("affected", []):

        affected_package = affected.get("package", {})

        if (
            affected_package.get("name") == package_name
            and affected_package.get("ecosystem") == ecosystem
        ):

            matching_affected_entries.append(affected)

    fixed_versions = set()
    affected_ranges = []

    for affected in matching_affected_entries:

        for version_range in affected.get("ranges", []):

            range_type = version_range.get("type")

            events = version_range.get("events", [])

            range_fixed_versions = []

            for event in events:

                if "fixed" in event:

                    fixed_version = event["fixed"]

                    fixed_versions.add(fixed_version)
                    range_fixed_versions.append(fixed_version)

            affected_ranges.append({
                "type": range_type,
                "events": events,
                "fixed_versions": range_fixed_versions
            })

    explicit_versions = []

    for affected in matching_affected_entries:

        explicit_versions.extend(
            affected.get("versions", [])
        )

    return {
        "matching_affected_entries": len(
            matching_affected_entries
        ),

        "affected_ranges": affected_ranges,

        "fixed_versions": sorted(fixed_versions),

        "explicit_affected_versions": sorted(
            set(explicit_versions)
        )
    }


# ============================================================
# BUILD RISK FINDINGS
# ============================================================

def build_risk_findings(findings):

    risk_findings = []

    for finding in findings:

        package = finding.get("package_instance", {})
        advisory = finding.get("advisory", {})

        severity_information = extract_severity(advisory)

        affected_information = extract_affected_information(
            package,
            advisory
        )

        aliases = advisory.get("aliases", [])

        cve_ids = [
            alias
            for alias in aliases
            if isinstance(alias, str)
            and alias.startswith("CVE-")
        ]

        if not cve_ids:
            cve_ids = []

        risk_record = {

            "package_instance": package,

            "vulnerability": {
                "id": finding.get("vulnerability_id"),

                "cve_ids": cve_ids,

                "aliases": aliases,

                "summary": advisory.get("summary"),

                "published": advisory.get("published"),

                "modified": advisory.get("modified"),

                "references": advisory.get("references", [])
            },

            "risk": severity_information,

            "remediation": {
                "fixed_versions": (
                    affected_information["fixed_versions"]
                ),

                "affected_ranges": (
                    affected_information["affected_ranges"]
                ),

                "explicit_affected_versions": (
                    affected_information[
                        "explicit_affected_versions"
                    ]
                ),

                "fix_available": bool(
                    affected_information["fixed_versions"]
                ),

                "recommendation": (
                    "Upgrade to a suitable fixed version listed "
                    "in the advisory, after compatibility testing."
                    if affected_information["fixed_versions"]
                    else
                    "No fixed version was identified in the "
                    "matching advisory ranges. Review the "
                    "advisory and available vendor guidance."
                )
            },

            "evidence": {
                "source": "OSV",
                "advisory_id": finding.get("vulnerability_id"),
                "details": advisory.get("details"),
                "affected_package_entries": (
                    affected_information[
                        "matching_affected_entries"
                    ]
                ),
                "advisory_details_available": not (
                    advisory.get("details_unavailable", False)
                )
            }
        }

        risk_findings.append(risk_record)

    return risk_findings


# ============================================================
# REMEDIATION PRIORITIZATION
# ============================================================

def build_remediation_priorities(risk_findings):

    priorities = []

    for finding in risk_findings:

        package = finding["package_instance"]
        vulnerability = finding["vulnerability"]
        risk = finding["risk"]
        remediation = finding["remediation"]

        severity = risk["severity"]

        priority = {

            "package_instance_id": package.get("id"),

            "package_path": package.get("package_path"),

            "package_name": package.get("name"),

            "installed_version": package.get("version"),

            "dependency_type": package.get("dependency_type"),

            "is_direct": package.get("is_direct"),

            "vulnerability_id": vulnerability.get("id"),

            "cve_ids": vulnerability.get("cve_ids"),

            "summary": vulnerability.get("summary"),

            "severity": severity,

            "cvss_score": risk.get("cvss_score"),

            "fixed_versions": remediation.get("fixed_versions"),

            "fix_available": remediation.get("fix_available"),

            "recommendation": remediation.get("recommendation")
        }

        priorities.append(priority)

    priorities.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severity"], 1),

            # Direct dependencies come first within the same
            # severity classification.
            -(1 if item["is_direct"] else 0),

            # Higher numerical CVSS score comes first.
            -(
                item["cvss_score"]
                if item["cvss_score"] is not None
                else -1
            ),

            item["package_name"] or "",

            item["package_path"] or ""
        )
    )

    for index, priority in enumerate(priorities, start=1):

        priority["priority_rank"] = index

    return priorities


# ============================================================
# PACKAGE-LEVEL RISK SUMMARY
# ============================================================

def build_package_summary(risk_findings):

    package_groups = defaultdict(list)

    for finding in risk_findings:

        package = finding["package_instance"]

        key = (
            package.get("id"),
            package.get("name"),
            package.get("version")
        )

        package_groups[key].append(finding)

    package_summary = []

    for key, group in package_groups.items():

        package_id, package_name, package_version = key

        severities = [
            item["risk"]["severity"]
            for item in group
        ]

        highest_severity = max(
            severities,
            key=lambda severity: SEVERITY_ORDER.get(
                severity, 1
            )
        )

        scores = [
            item["risk"]["cvss_score"]
            for item in group
            if item["risk"]["cvss_score"] is not None
        ]

        package = group[0]["package_instance"]

        fixed_versions = set()

        for item in group:

            fixed_versions.update(
                item["remediation"]["fixed_versions"]
            )

        package_summary.append({

            "package_instance_id": package_id,

            "package_name": package_name,

            "installed_version": package_version,

            "package_path": package.get("package_path"),

            "dependency_type": package.get("dependency_type"),

            "is_direct": package.get("is_direct"),

            "vulnerability_count": len(group),

            "highest_severity": highest_severity,

            "highest_cvss_score": (
                max(scores) if scores else None
            ),

            "vulnerability_ids": [
                item["vulnerability"]["id"]
                for item in group
            ],

            "fixed_versions": sorted(fixed_versions)
        })

    package_summary.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(
                item["highest_severity"], 1
            ),
            -(
                item["highest_cvss_score"]
                if item["highest_cvss_score"] is not None
                else -1
            )
        )
    )

    return package_summary


# ============================================================
# OVERALL SUMMARY
# ============================================================

def build_summary(original_findings, risk_findings):

    severity_counts = Counter(
        finding["risk"]["severity"]
        for finding in risk_findings
    )

    direct_findings = sum(
        finding["package_instance"].get("is_direct") is True
        for finding in risk_findings
    )

    transitive_findings = sum(
        finding["package_instance"].get("is_direct") is False
        for finding in risk_findings
    )

    scored_findings = sum(
        finding["risk"]["cvss_score"] is not None
        for finding in risk_findings
    )

    unique_vulnerabilities = {
        finding["vulnerability"]["id"]
        for finding in risk_findings
    }

    affected_instances = {
        finding["package_instance"].get("id")
        for finding in risk_findings
    }

    return {

        "input_findings": len(original_findings),

        "processed_findings": len(risk_findings),

        "unique_vulnerability_ids": len(
            unique_vulnerabilities
        ),

        "affected_package_instances": len(
            affected_instances
        ),

        "cvss_scored_findings": scored_findings,

        "findings_without_cvss_score": (
            len(risk_findings) - scored_findings
        ),

        "severity_distribution": {
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "unknown": severity_counts["UNKNOWN"]
        },

        "direct_dependency_findings": direct_findings,

        "transitive_dependency_findings": transitive_findings,

        "findings_with_fixed_versions": sum(
            finding["remediation"]["fix_available"]
            for finding in risk_findings
        ),

        "findings_without_fixed_versions": sum(
            not finding["remediation"]["fix_available"]
            for finding in risk_findings
        ),

        "risk_analysis_complete": (
            len(original_findings) == len(risk_findings)
        )
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("SOFTWARE SUPPLY CHAIN GUARDIAN")
    print("VULNERABILITY RISK ANALYZER")
    print("=" * 60)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("\nLoading OSV vulnerability findings...")

    findings = load_findings()

    print(f"Loaded {len(findings)} findings.")

    print("\nCalculating risk classifications...")

    risk_findings = build_risk_findings(findings)

    print(
        f"Processed {len(risk_findings)} findings."
    )

    print("\nGenerating remediation priorities...")

    remediation_priorities = build_remediation_priorities(
        risk_findings
    )

    print("\nGenerating package-level summary...")

    package_summary = build_package_summary(
        risk_findings
    )

    summary = build_summary(
        findings,
        risk_findings
    )

    summary["unique_affected_packages"] = len(
        package_summary
    )

    # --------------------------------------------------------
    # SAVE OUTPUT FILES
    # --------------------------------------------------------

    save_json(
        RISK_FILE,
        risk_findings
    )

    save_json(
        REMEDIATION_FILE,
        {
            "total_prioritized_findings": len(
                remediation_priorities
            ),
            "priorities": remediation_priorities
        }
    )

    save_json(
        SUMMARY_FILE,
        {
            "summary": summary,
            "affected_packages": package_summary
        }
    )

    # --------------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("RISK ANALYSIS SUMMARY")
    print("=" * 60)

    for key, value in summary.items():

        print(f"{key}: {value}")

    print("\nSeverity distribution:")

    for severity, count in summary[
        "severity_distribution"
    ].items():

        print(f"  {severity.upper()}: {count}")

    print("\nTop 10 remediation priorities:")

    for item in remediation_priorities[:10]:

        score = item["cvss_score"]

        score_text = (
            str(score) if score is not None else "N/A"
        )

        print(
            f"\n{item['priority_rank']}. "
            f"{item['package_name']} "
            f"({item['installed_version']})"
        )

        print(
            f"   Severity: {item['severity']} "
            f"| CVSS: {score_text}"
        )

        print(
            f"   Dependency: {item['dependency_type']}"
        )

        print(
            f"   Vulnerability: {item['vulnerability_id']}"
        )

        print(
            f"   Fixed versions: "
            f"{item['fixed_versions']}"
        )

    print("\nGenerated files:")

    print(f"  {RISK_FILE}")
    print(f"  {REMEDIATION_FILE}")
    print(f"  {SUMMARY_FILE}")

    print("\nRisk analysis completed successfully.")


if __name__ == "__main__":

    try:
        main()

    except Exception as error:

        print("\nFATAL ERROR:")
        print(error)

        raise
