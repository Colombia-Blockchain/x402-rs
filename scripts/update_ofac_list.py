#!/usr/bin/env python3
"""
OFAC Sanctions List Updater for x402-rs Payment Facilitator

This script downloads the latest OFAC Specially Designated Nationals (SDN) list
with digital currency addresses and formats it for use by the x402-compliance module.

Data sources:
- OFAC SDN List (https://home.treasury.gov/policy-issues/financial-sanctions/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists)
- Digital Currency Addresses (https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml)

Usage:
    python scripts/update_ofac_list.py
    python scripts/update_ofac_list.py --output config/ofac_addresses.json
    python scripts/update_ofac_list.py --verify-only

Author: Ultravioleta DAO
License: MIT
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.request import Request, urlopen
from urllib.error import URLError
import xml.etree.ElementTree as ET

# OFAC Data Sources (Updated November 2025)
OFAC_SDN_XML_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_ADVANCED.XML"
OFAC_SDN_CSV_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
OFAC_ALTNAMES_CSV_URL = "https://www.treasury.gov/ofac/downloads/alt.csv"

# Blockchain/currency mappings
BLOCKCHAIN_ALIASES = {
    "XBT": "bitcoin",
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "LTC": "litecoin",
    "XMR": "monero",
    "ZEC": "zcash",
    "DASH": "dash",
    "XRP": "ripple",
    "BCH": "bitcoin-cash",
    "BSV": "bitcoin-sv",
    "USDT": "tether",
    "USDC": "usd-coin",
    "BSC": "binance-smart-chain",
    "BNB": "binance-coin",
    "Digital Currency Address - XBT": "bitcoin",
    "Digital Currency Address - ETH": "ethereum",
    "Digital Currency Address - LTC": "litecoin",
    "Digital Currency Address - XMR": "monero",
    "Digital Currency Address - ZEC": "zcash",
    "Digital Currency Address - DASH": "dash",
    "Digital Currency Address - XRP": "ripple",
    "Digital Currency Address - BCH": "bitcoin-cash",
    "Digital Currency Address - BSV": "bitcoin-sv",
    "Digital Currency Address - USDT": "tether",
    "Digital Currency Address - USDC": "usd-coin",
}

# Address validation patterns
ADDRESS_PATTERNS = {
    "bitcoin": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$",
    "ethereum": r"^0x[a-fA-F0-9]{40}$",
    "litecoin": r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$|^ltc1[a-z0-9]{39,59}$",
    "monero": r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",
    "zcash": r"^t1[a-zA-Z0-9]{33}$|^zs1[a-z0-9]{75}$",
    "ripple": r"^r[0-9a-zA-Z]{24,34}$",
}


class OfacAddress:
    """Represents a single OFAC-sanctioned cryptocurrency address"""

    def __init__(
        self,
        address: str,
        blockchain: str,
        entity_name: str,
        entity_id: str,
        reason: str = "OFAC SDN List",
    ):
        self.address = address.strip()
        self.blockchain = blockchain.lower()
        self.entity_name = entity_name.strip()
        self.entity_id = entity_id.strip()
        self.reason = reason

    def to_dict(self) -> Dict:
        """Convert to JSON-serializable dict"""
        return {
            "address": self.address.lower(),  # Normalize to lowercase
            "blockchain": self.blockchain,
            "entity_name": self.entity_name,
            "entity_id": self.entity_id,
            "reason": self.reason,
        }

    def is_valid(self) -> bool:
        """Validate address format"""
        # Check if blockchain has a known pattern
        if self.blockchain in ADDRESS_PATTERNS:
            pattern = ADDRESS_PATTERNS[self.blockchain]
            return bool(re.match(pattern, self.address))

        # For unknown blockchains, do basic validation
        # Must be alphanumeric, not empty, reasonable length
        if not self.address or len(self.address) < 10:
            return False

        return True


class OfacUpdater:
    """Downloads and processes OFAC sanctions lists"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.addresses: List[OfacAddress] = []
        self.currencies: Set[str] = set()
        self.entity_cache: Dict[str, str] = {}  # entity_id -> entity_name

    def log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(f"[INFO] {message}")

    def download_file(self, url: str) -> Optional[bytes]:
        """Download file from URL with proper headers"""
        self.log(f"Downloading {url}")

        try:
            # Add user agent to avoid 403 errors
            req = Request(
                url,
                headers={
                    "User-Agent": "x402-rs-compliance/1.0 (OFAC Compliance Tool)"
                },
            )

            with urlopen(req, timeout=30) as response:
                data = response.read()
                self.log(f"Downloaded {len(data)} bytes")
                return data

        except URLError as e:
            print(f"[ERROR] Failed to download {url}: {e}", file=sys.stderr)
            return None

    def parse_sdn_csv(self) -> bool:
        """Parse the SDN CSV file for entity information"""
        self.log("Parsing SDN CSV for entity names")

        csv_data = self.download_file(OFAC_SDN_CSV_URL)
        if not csv_data:
            return False

        try:
            # Decode and parse CSV
            csv_text = csv_data.decode("utf-8", errors="ignore")
            reader = csv.reader(csv_text.splitlines())

            # CSV format: ent_num, SDN_Name, SDN_Type, Program, Title, ...
            for row in reader:
                if len(row) < 2:
                    continue

                entity_id = row[0].strip()
                entity_name = row[1].strip()

                if entity_id and entity_name:
                    self.entity_cache[entity_id] = entity_name

            self.log(f"Cached {len(self.entity_cache)} entity names")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to parse SDN CSV: {e}", file=sys.stderr)
            return False

    def parse_sdn_xml(self) -> bool:
        """Parse the SDN Advanced XML file for digital currency addresses"""
        self.log("Parsing SDN Advanced XML for crypto addresses")

        xml_data = self.download_file(OFAC_SDN_XML_URL)
        if not xml_data:
            return False

        try:
            # Parse XML
            xml_text = xml_data.decode("utf-8", errors="ignore")
            root = ET.fromstring(xml_text)

            # Define namespace
            namespace = {"ns": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML"}

            # Build FeatureType mapping (ID -> Currency)
            feature_type_map = {}
            for ft in root.findall(".//ns:FeatureType", namespace):
                ft_id = ft.get("ID")
                ft_text = ft.text
                if ft_text and "Digital Currency Address" in ft_text:
                    blockchain = self._extract_blockchain(ft_text)
                    if blockchain:
                        feature_type_map[ft_id] = blockchain

            self.log(f"Found {len(feature_type_map)} crypto currency types")

            # Build Identity mapping (IdentityID -> Name)
            identity_map = {}
            for identity in root.findall(".//ns:DistinctParty", namespace):
                identity_id = identity.get("FixedRef")

                # Try to get name from Profile
                profile = identity.find(".//ns:Profile", namespace)
                if profile is not None:
                    # Individual
                    given_name = profile.findtext(".//ns:GivenName", "", namespace)
                    surname = profile.findtext(".//ns:Surname", "", namespace)
                    if given_name or surname:
                        identity_map[identity_id] = f"{given_name} {surname}".strip()
                    else:
                        # Organization
                        org_name = profile.findtext(".//ns:OrganisationName", "", namespace)
                        if org_name:
                            identity_map[identity_id] = org_name

            self.log(f"Built identity map for {len(identity_map)} entities")

            # Extract crypto addresses from Features
            for feature in root.findall(".//ns:Feature", namespace):
                feature_type_id = feature.get("FeatureTypeID")

                # Check if this is a crypto address
                if feature_type_id not in feature_type_map:
                    continue

                blockchain = feature_type_map[feature_type_id]

                # Get the address from VersionDetail
                version_detail = feature.findtext(".//ns:VersionDetail", "", namespace)
                if not version_detail:
                    continue

                address = version_detail.strip()

                # Get entity reference
                identity_ref = feature.find(".//ns:IdentityReference", namespace)
                identity_id = identity_ref.get("IdentityID") if identity_ref is not None else None

                # Get entity name
                entity_name = "Unknown Entity"
                if identity_id and identity_id in identity_map:
                    entity_name = identity_map[identity_id]
                elif identity_id:
                    entity_name = f"Entity {identity_id}"

                # Create address entry
                addr = OfacAddress(
                    address=address,
                    blockchain=blockchain,
                    entity_name=entity_name,
                    entity_id=identity_id or "unknown",
                    reason="OFAC SDN List",
                )

                # Basic validation
                if addr.is_valid():
                    self.addresses.append(addr)
                    self.currencies.add(blockchain)
                else:
                    self.log(f"Skipping invalid address: {address} ({blockchain})")

            self.log(f"Extracted {len(self.addresses)} valid crypto addresses")
            return True

        except ET.ParseError as e:
            print(f"[ERROR] Failed to parse XML: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error parsing XML: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return False

    def _extract_blockchain(self, id_type: str) -> Optional[str]:
        """Extract blockchain name from ID type string"""
        # Direct mapping
        if id_type in BLOCKCHAIN_ALIASES:
            return BLOCKCHAIN_ALIASES[id_type]

        # Extract currency code (e.g., "Digital Currency Address - XBT" -> "XBT")
        match = re.search(r"Digital Currency Address\s*-\s*([A-Z]+)", id_type)
        if match:
            currency_code = match.group(1)
            return BLOCKCHAIN_ALIASES.get(currency_code, currency_code.lower())

        return None

    def generate_json(self) -> Dict:
        """Generate final JSON structure"""
        return {
            "metadata": {
                "source": "OFAC Specially Designated Nationals (SDN) List",
                "source_url": OFAC_SDN_XML_URL,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_addresses": len(self.addresses),
                "currencies": sorted(list(self.currencies)),
            },
            "addresses": [addr.to_dict() for addr in self.addresses],
        }

    def save_to_file(self, output_path: Path):
        """Save addresses to JSON file"""
        data = self.generate_json()

        # Pretty print with indentation
        json_str = json.dumps(data, indent=2, ensure_ascii=False)

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")

        # Calculate checksum
        checksum = hashlib.sha256(json_str.encode("utf-8")).hexdigest()

        self.log(f"Saved {len(self.addresses)} addresses to {output_path}")
        self.log(f"File checksum (SHA-256): {checksum}")

        return checksum

    def print_summary(self):
        """Print summary statistics"""
        print("\n" + "=" * 60)
        print("OFAC Update Summary")
        print("=" * 60)
        print(f"Total addresses:     {len(self.addresses)}")
        print(f"Unique currencies:   {len(self.currencies)}")
        print(f"Currencies:          {', '.join(sorted(self.currencies))}")
        print()

        # Top entities by address count
        entity_counts: Dict[str, int] = {}
        for addr in self.addresses:
            entity_counts[addr.entity_name] = entity_counts.get(addr.entity_name, 0) + 1

        print("Top 10 entities by address count:")
        for entity, count in sorted(
            entity_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]:
            print(f"  {count:3d}  {entity}")

        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Download and process OFAC sanctions list for x402-rs"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("config/ofac_addresses.json"),
        help="Output JSON file path (default: config/ofac_addresses.json)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing file without downloading",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Verify mode
    if args.verify_only:
        if not args.output.exists():
            print(f"[ERROR] File not found: {args.output}", file=sys.stderr)
            return 1

        data = json.loads(args.output.read_text(encoding="utf-8"))
        print(f"File: {args.output}")
        print(f"Total addresses: {data['metadata']['total_addresses']}")
        print(f"Generated: {data['metadata']['generated_at']}")
        print(f"Currencies: {', '.join(data['metadata']['currencies'])}")
        return 0

    # Update mode
    print("x402-rs OFAC Sanctions List Updater")
    print("=" * 60)

    updater = OfacUpdater(verbose=args.verbose)

    # Step 1: Download entity names from CSV
    print("\n[1/3] Downloading SDN entity list...")
    if not updater.parse_sdn_csv():
        print("[WARN] Failed to download entity list, continuing anyway...")

    # Step 2: Download and parse digital currency addresses from XML
    print("\n[2/3] Downloading digital currency addresses...")
    if not updater.parse_sdn_xml():
        print("[ERROR] Failed to download OFAC data", file=sys.stderr)
        return 1

    if len(updater.addresses) == 0:
        print("[WARN] No addresses found in OFAC data", file=sys.stderr)
        return 1

    # Step 3: Save to file
    print(f"\n[3/3] Saving to {args.output}...")
    updater.save_to_file(args.output)

    # Print summary
    updater.print_summary()

    print(f"\n✅ OFAC list updated successfully!")
    print(f"   File: {args.output}")
    print(f"   Addresses: {len(updater.addresses)}")
    print(
        f"\nNext steps:\n"
        f"  1. Review the generated file\n"
        f"  2. Rebuild the facilitator: cargo build --release\n"
        f"  3. Restart the service to load the new list\n"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
