#!/usr/bin/env python3
"""
Simple OFAC Update - Uses curated list from reliable sources

This downloads from chainalysis/ofac-sanctioned-digital-currency-addresses
which maintains the official OFAC list in an easy-to-parse format.

Source: https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses
(Mirror of official OFAC data)
"""

import json
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

# GitHub raw URL for curated OFAC list (updated automatically from treasury.gov)
OFAC_JSON_URL = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/master/sanctioned_addresses_ETH.json"
OFAC_BTC_URL = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/master/sanctioned_addresses_BTC.json"
OFAC_XMR_URL = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/master/sanctioned_addresses_XMR.json"
OFAC_LTC_URL = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/master/sanctioned_addresses_LTC.json"

def download(url):
    """Download file from URL"""
    print(f"Downloading {url}")
    req = Request(url, headers={'User-Agent': 'x402-rs/1.0'})
    with urlopen(req, timeout=30) as response:
        data = json.loads(response.read().decode('utf-8'))
        print(f"  Found {len(data)} addresses")
        return data

def main():
    output_path = Path("config/ofac_addresses.json")

    print("x402-rs OFAC Updater (Simple)")
    print("=" * 60)

    all_addresses = []
    currencies = set()

    # Download Ethereum addresses
    print("\n[1/4] Downloading Ethereum addresses...")
    try:
        eth_data = download(OFAC_JSON_URL)
        for addr in eth_data:
            all_addresses.append({
                "address": addr.lower(),
                "blockchain": "ethereum",
                "entity_name": "OFAC Sanctioned Entity",
                "entity_id": "ETH-" + addr[:8],
                "reason": "OFAC SDN List"
            })
        currencies.add("ethereum")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Download Bitcoin addresses
    print("\n[2/4] Downloading Bitcoin addresses...")
    try:
        btc_data = download(OFAC_BTC_URL)
        for addr in btc_data:
            all_addresses.append({
                "address": addr,
                "blockchain": "bitcoin",
                "entity_name": "OFAC Sanctioned Entity",
                "entity_id": "BTC-" + addr[:8],
                "reason": "OFAC SDN List"
            })
        currencies.add("bitcoin")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Download Monero addresses
    print("\n[3/4] Downloading Monero addresses...")
    try:
        xmr_data = download(OFAC_XMR_URL)
        for addr in xmr_data:
            all_addresses.append({
                "address": addr,
                "blockchain": "monero",
                "entity_name": "OFAC Sanctioned Entity",
                "entity_id": "XMR-" + addr[:8],
                "reason": "OFAC SDN List"
            })
        currencies.add("monero")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Download Litecoin addresses
    print("\n[4/4] Downloading Litecoin addresses...")
    try:
        ltc_data = download(OFAC_LTC_URL)
        for addr in ltc_data:
            all_addresses.append({
                "address": addr,
                "blockchain": "litecoin",
                "entity_name": "OFAC Sanctioned Entity",
                "entity_id": "LTC-" + addr[:8],
                "reason": "OFAC SDN List"
            })
        currencies.add("litecoin")
    except Exception as e:
        print(f"  ERROR: {e}")

    if not all_addresses:
        print("\n[ERROR] No addresses downloaded!")
        return 1

    # Generate JSON
    data = {
        "metadata": {
            "source": "OFAC SDN List (via 0xB10C/ofac-sanctioned-digital-currency-addresses)",
            "source_url": "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_addresses": len(all_addresses),
            "currencies": sorted(list(currencies))
        },
        "addresses": all_addresses
    }

    # Save
    output_path.parent.mkdir(parents=True, exist_ok=True)
    json_str = json.dumps(data, indent=2)
    output_path.write_text(json_str, encoding='utf-8')

    checksum = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    print("\n" + "=" * 60)
    print("SUCCESS!")
    print("=" * 60)
    print(f"Total addresses: {len(all_addresses)}")
    print(f"Currencies: {', '.join(sorted(currencies))}")
    print(f"Output: {output_path}")
    print(f"SHA-256: {checksum[:16]}...")
    print("=" * 60)

    return 0

if __name__ == "__main__":
    sys.exit(main())
