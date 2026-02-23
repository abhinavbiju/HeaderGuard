import argparse
import sys
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Error: requests library required. Run: pip install requests")
    sys.exit(1)


# Security headers and their recommended configurations
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "severity": "critical",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "recommended": "default-src 'self'",
        "severity": "critical",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff",
        "severity": "high",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "recommended": "DENY or SAMEORIGIN",
        "severity": "high",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still useful)",
        "recommended": "1; mode=block",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "recommended": "strict-origin-when-cross-origin",
        "severity": "medium",
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "severity": "medium",
    },
}


def scan_url(url: str, timeout: int = 10) -> dict:
    """Scan a URL for security headers."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = {k: v for k, v in response.headers.items()}
        return {
            "success": True,
            "url": response.url,
            "status_code": response.status_code,
            "headers": headers,
            "https": response.url.startswith("https://"),
        }
    except requests.RequestException as e:
        return {"success": False, "error": str(e), "url": url}


def analyze_headers(headers: dict) -> list:
    """Analyze headers against security best practices."""
    results = []
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

    for header_name, config in SECURITY_HEADERS.items():
        header_key = header_name.lower()
        if header_key in headers_lower:
            orig_name, value = headers_lower[header_key]
            results.append(
                {
                    "header": header_name,
                    "present": True,
                    "value": value,
                    "status": "PASS",
                    "config": config,
                }
            )
        else:
            results.append(
                {
                    "header": header_name,
                    "present": False,
                    "value": None,
                    "status": "MISSING",
                    "config": config,
                }
            )
    return results


def calculate_score(results: list, https: bool) -> tuple[int, str]:
    """Calculate security score (0-100)."""
    if not results:
        return 0, "F"

    passed = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    base_score = int((passed / total) * 90)

    if https:
        base_score += 10
    else:
        base_score = min(base_score, 50)  # Cap if not HTTPS

    if base_score >= 90:
        grade = "A"
    elif base_score >= 80:
        grade = "B"
    elif base_score >= 70:
        grade = "C"
    elif base_score >= 50:
        grade = "D"
    else:
        grade = "F"

    return min(100, base_score), grade


def print_report(scan_result: dict, verbose: bool = False):
    """Print formatted security report."""
    if not scan_result.get("success"):
        print(f"\n[!] Error scanning {scan_result.get('url', 'URL')}:")
        print(f"   {scan_result.get('error', 'Unknown error')}")
        return

    url = scan_result["url"]
    headers = scan_result["headers"]
    https = scan_result["https"]

    results = analyze_headers(headers)
    score, grade = calculate_score(results, https)

    # Header
    print("\n" + "=" * 60)
    print("[*] HEADERGUARD - Security Header Report")
    print("=" * 60)
    print(f"\n[*] URL: {url}")
    print(f"[*] HTTPS: {'Yes [OK]' if https else 'No [!!]'}")
    print(f"\n[*] SECURITY SCORE: {score}/100 (Grade: {grade})")
    print("-" * 60)

    # Results table
    for r in results:
        status_icon = "[+]" if r["status"] == "PASS" else "[-]"
        status_color = "PASS" if r["status"] == "PASS" else "MISSING"
        print(f"\n{status_icon} {r['header']}: [{status_color}]")
        if r["present"]:
            print(f"   Value: {r['value'][:80]}{'...' if len(str(r['value'])) > 80 else ''}")
        else:
            print(f"   Recommendation: {r['config']['recommended']}")
            print(f"   Why: {r['config']['description']}")

    if verbose:
        print("\n" + "-" * 60)
        print("ALL RESPONSE HEADERS:")
        for k, v in headers.items():
            print(f"  {k}: {v}")

    print("\n" + "=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="HeaderGuard - Scan websites for security headers"
    )
    parser.add_argument("url", help="URL to scan (e.g., example.com or https://example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all response headers")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")

    args = parser.parse_args()
    result = scan_url(args.url, args.timeout)
    print_report(result, args.verbose)


if __name__ == "__main__":
    main()
