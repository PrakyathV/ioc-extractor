
import re
import ipaddress
import argparse
import json

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# -------------------- IOC PATTERNS --------------------

IP_PATTERN = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)

HASH_PATTERNS = {
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}


# -------------------- DOMAIN FILTERING --------------------

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil",
    "int", "in", "uk", "us", "de", "fr", "jp",
    "cn", "ru", "it", "io", "co", "ai", "dev",
    "app", "info", "biz", "me", "xyz", "online",
    "tech", "cloud", "site", "shop", "website"
}


# -------------------- IP EXTRACTION --------------------

def extract_ips(text):
    """Extract and validate IPv4 addresses."""

    candidates = IP_PATTERN.findall(text)
    valid_ips = []

    for candidate in candidates:
        try:
            ip = ipaddress.ip_address(candidate)

            if isinstance(ip, ipaddress.IPv4Address):
                valid_ips.append(str(ip))

        except ValueError:
            continue

    return Counter(valid_ips)


# -------------------- IP CLASSIFICATION --------------------

def classify_ip(ip_address):
    """Classify an IPv4 address into a network category."""

    ip = ipaddress.ip_address(ip_address)

    if ip.is_unspecified:
        return "unspecified"

    if ip.is_loopback:
        return "loopback"

    if ip.is_multicast:
        return "multicast"

    if ip.is_link_local:
        return "link-local"

    if ip.is_reserved:
        return "reserved"

    if ip.is_private:
        return "private"

    if ip.is_global:
        return "public"

    return "special"


# -------------------- DOMAIN EXTRACTION --------------------

def extract_domains(text):
    """Extract domain candidates with basic TLD filtering."""

    candidates = DOMAIN_PATTERN.findall(text)
    valid_domains = []

    for candidate in candidates:
        domain = candidate.lower().rstrip(".")
        parts = domain.split(".")

        if len(parts) < 2:
            continue

        if parts[-1] not in COMMON_TLDS:
            continue

        valid_domains.append(domain)

    return Counter(valid_domains)


# -------------------- URL EXTRACTION --------------------

def extract_urls(text):
    """Extract HTTP and HTTPS URLs."""

    urls = URL_PATTERN.findall(text)
    cleaned_urls = []

    for url in urls:
        cleaned_url = url.rstrip(".,;:!?)]}\\")
        cleaned_urls.append(cleaned_url)

    return Counter(cleaned_urls)


# -------------------- HASH EXTRACTION --------------------

def extract_hashes(text):
    """Extract MD5, SHA1 and SHA256 candidates."""

    hash_counts = {}

    for hash_type, pattern in HASH_PATTERNS.items():
        matches = pattern.findall(text)

        hash_counts[hash_type] = Counter(
            match.lower() for match in matches
        )

    return hash_counts


# -------------------- LOG ANALYSIS --------------------

def analyze_log(log_path):
    """Analyze a log file and extract IOC candidates."""

    path = Path(log_path)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    ip_counts = Counter()
    domain_counts = Counter()
    url_counts = Counter()

    hash_counts = {
        "MD5": Counter(),
        "SHA1": Counter(),
        "SHA256": Counter(),
    }

    total_lines = 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as log_file:

        for line in log_file:
            total_lines += 1

            ip_counts.update(extract_ips(line))
            domain_counts.update(extract_domains(line))
            url_counts.update(extract_urls(line))

            extracted_hashes = extract_hashes(line)

            for hash_type in hash_counts:
                hash_counts[hash_type].update(
                    extracted_hashes[hash_type]
                )

    # Classify IP occurrences.

    ip_classification = Counter()

    for ip, count in ip_counts.items():
        category = classify_ip(ip)
        ip_classification[category] += count

    return {
        "total_lines": total_lines,

        "total_ip_occurrences": sum(ip_counts.values()),
        "unique_ip_count": len(ip_counts),
        "top_ips": ip_counts.most_common(20),
        "all_ips": dict(ip_counts),

        "ip_classification": dict(ip_classification),

        "total_domain_occurrences": sum(domain_counts.values()),
        "unique_domain_count": len(domain_counts),
        "top_domains": domain_counts.most_common(20),
        "all_domains": dict(domain_counts),

        "total_url_occurrences": sum(url_counts.values()),
        "unique_url_count": len(url_counts),
        "top_urls": url_counts.most_common(20),
        "all_urls": dict(url_counts),

        "hashes": hash_counts,
    }


# -------------------- DISPLAY RESULTS --------------------

def display_results(results, log_path):
    """Display the IOC analysis report."""

    print("\n========================================")
    print("           IOC EXTRACTOR")
    print("========================================")

    print(f"\nAnalyzed file: {log_path}")
    print(f"Total log lines: {results['total_lines']}")

    print("\n========== IP ADDRESSES ==========")

    print(f"Total occurrences : {results['total_ip_occurrences']}")
    print(f"Unique IPs        : {results['unique_ip_count']}")

    print("\nTop IP addresses:")

    for ip, count in results["top_ips"]:
        print(f"{ip:<20} {count:>10}")

    print("\n========== IP CLASSIFICATION ==========")
    print("Counts below represent IP occurrences.")

    for category, count in sorted(
        results["ip_classification"].items()
    ):
        print(f"{category:<20} {count:>10}")

    print("\n========== DOMAINS ==========")

    print(f"Total occurrences : {results['total_domain_occurrences']}")
    print(f"Unique domains    : {results['unique_domain_count']}")

    print("\nTop domains:")

    for domain, count in results["top_domains"]:
        print(f"{domain:<45} {count:>10}")

    print("\n========== URLs ==========")

    print(f"Total occurrences : {results['total_url_occurrences']}")
    print(f"Unique URLs       : {results['unique_url_count']}")

    print("\nTop URLs:")

    for url, count in results["top_urls"]:
        print(f"{url:<55} {count:>10}")

    print("\n========== HASH CANDIDATES ==========")

    for hash_type, counts in results["hashes"].items():

        print(f"\n{hash_type}:")
        print(f"Total occurrences : {sum(counts.values())}")
        print(f"Unique candidates : {len(counts)}")

        for value, count in counts.most_common(10):
            print(f"{value}  {count}")

    print("\n========================================")
    print("         ANALYSIS COMPLETED")
    print("========================================\n")


# -------------------- JSON REPORT EXPORT --------------------

def save_json_report(results, log_path, report_path):
    """Export all extracted IOC candidates to a JSON report."""

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(log_path),

        "summary": {
            "total_lines": results["total_lines"],

            "total_ip_occurrences": results["total_ip_occurrences"],
            "unique_ip_count": results["unique_ip_count"],

            "total_domain_occurrences": results["total_domain_occurrences"],
            "unique_domain_count": results["unique_domain_count"],

            "total_url_occurrences": results["total_url_occurrences"],
            "unique_url_count": results["unique_url_count"],
        },

        "ip_classification": results["ip_classification"],

        "indicators": {
            "ipv4": results["all_ips"],
            "domains": results["all_domains"],
            "urls": results["all_urls"],

            "hashes": {
                hash_type: dict(counts)
                for hash_type, counts in results["hashes"].items()
            },
        },

        "analysis_note": (
            "Extracted indicators are candidates and have not "
            "been confirmed as malicious."
        ),
    }

    path = Path(report_path)

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as report_file:
        json.dump(
            report,
            report_file,
            indent=4,
            sort_keys=True
        )

    print(f"JSON report saved to: {path}")


# -------------------- MAIN FUNCTION --------------------

def main():

    datasets = {
        "historical": "data/real_logs/SSH.log",
        "local": "data/local_logs/system-journal.log",
    }

    parser = argparse.ArgumentParser(
        description="Extract IOC candidates from security log files."
    )

    parser.add_argument(
        "--source",
        choices=["historical", "local"],
        default="historical",
        help="Choose historical SSH logs or local system logs."
    )

    parser.add_argument(
        "--log",
        help="Provide a custom log file path."
    )

    parser.add_argument(
        "--report",
        help="Optional path for exporting a JSON report."
    )

    args = parser.parse_args()
    log_path = args.log or datasets[args.source]

    try:
        results = analyze_log(log_path)

        display_results(results, log_path)

        if args.report:
            save_json_report(
                results,
                log_path,
                args.report
            )

    except (FileNotFoundError, PermissionError, OSError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()

