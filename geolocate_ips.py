"""
geolocate_ips.py

Looks up geolocation info for every unique attacker IP seen in the Cowrie
logs (excluding the operator's own self-test IP) using the free ip-api.com
JSON endpoint. Saves results to geolocation_report.json, prints a summary
table, and generates a "connections by country" bar chart.

Private/internal (RFC1918) addresses cannot be geolocated by a public API
and are reported as such rather than skipped silently.
"""

import glob
import ipaddress
import json
import os
import time
import urllib.request
import urllib.error

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LOGS_DIR = "logs"
CHARTS_DIR = "charts"
SELF_TEST_IP = "223.187.114.68"
REQUEST_DELAY_SECONDS = 1.5
OUTPUT_FILE = "geolocation_report.json"

API_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,regionName,city,isp,org,as,query"
)


def collect_unique_ips():
    ips = set()
    for path in sorted(glob.glob(os.path.join(LOGS_DIR, "cowrie.json*"))):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("eventid") == "cowrie.session.connect":
                    ip = event.get("src_ip")
                    if ip and ip != SELF_TEST_IP:
                        ips.add(ip)
    return sorted(ips)


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup_ip(ip):
    if is_private(ip):
        return {
            "query": ip,
            "status": "fail",
            "message": "private range",
            "country": None,
            "regionName": None,
            "city": None,
            "isp": None,
            "org": None,
            "as": None,
        }
    url = API_URL.format(ip=ip)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError) as e:
        data = {"query": ip, "status": "fail", "message": str(e)}
    return data


def main():
    ips = collect_unique_ips()
    print(f"Found {len(ips)} unique attacker IP(s) to geolocate (self-test IP excluded).")

    results = []
    for i, ip in enumerate(ips):
        print(f"  [{i + 1}/{len(ips)}] Looking up {ip} ...")
        result = lookup_ip(ip)
        results.append(result)
        if i < len(ips) - 1 and not is_private(ip):
            time.sleep(REQUEST_DELAY_SECONDS)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved geolocation results to {OUTPUT_FILE}")

    print("\n" + "-" * 90)
    print(f"{'IP':16s} {'Country':18s} {'City':16s} {'ISP':22s} {'ASN'}")
    print("-" * 90)
    for r in results:
        if r.get("status") == "success":
            print(f"{r.get('query', ''):16s} {str(r.get('country')):18s} {str(r.get('city')):16s} {str(r.get('isp')):22s} {str(r.get('as'))}")
        else:
            reason = r.get("message", "lookup failed")
            print(f"{r.get('query', ''):16s} [not geolocatable: {reason}]")
    print("-" * 90)

    # --- Chart: connections by country ---
    os.makedirs(CHARTS_DIR, exist_ok=True)
    country_counts = {}
    ungeolocated = 0
    for r in results:
        if r.get("status") == "success" and r.get("country"):
            country_counts[r["country"]] = country_counts.get(r["country"], 0) + 1
        else:
            ungeolocated += 1

    plt.figure(figsize=(7, 4))
    if country_counts:
        countries = list(country_counts.keys())
        counts = [country_counts[c] for c in countries]
        plt.bar(countries, counts, color="tab:blue")
        plt.ylabel("Unique attacker IPs")
        title = f"Attacker IPs by country (n={sum(counts)} geolocated)"
        if ungeolocated:
            title += f", {ungeolocated} not geolocatable (private range)"
        plt.title(title)
        plt.xticks(rotation=20, ha="right")
    else:
        plt.text(0.5, 0.5, "No geolocatable IPs\n(all sources were private/internal addresses)",
                  ha="center", va="center")
        plt.title("Attacker IPs by country")
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, "connections_by_country.png"), dpi=150)
    plt.close()
    print(f"\nChart saved to {CHARTS_DIR}/connections_by_country.png")


if __name__ == "__main__":
    main()
