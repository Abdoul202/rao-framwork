#!/usr/bin/env python3
"""
RAO-Framework Demo - Run a reconnaissance mission.

Usage (requires authorized target):
    python examples/demo_scan.py <target_ip>

Example with a local test environment:
    # Start a vulnerable lab (e.g., DVWA in Docker)
    docker run -d -p 8080:80 vulnerables/web-dvwa

    # Run RAO against it
    python examples/demo_scan.py 127.0.0.1

IMPORTANT: Only use against systems you own or have explicit authorization to test.
"""

import logging
import sys

from rao.core.orchestrator import OCC


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target = sys.argv[1]

    print(f"\n[*] RAO-Framework v0.1.0")
    print(f"[*] Target: {target}")
    print(f"[*] DISCLAIMER: Authorized testing only.\n")

    occ = OCC()
    mission = occ.execute(target=target, scope=[target])

    print(f"\n[*] Mission complete.")
    print(f"    Hosts: {len(mission.hosts)}")
    print(f"    Findings: {len(mission.findings)}")
    print(f"    Validated: {len(mission.validated_findings)}")
    print(f"    Errors: {len(mission.errors)}")


if __name__ == "__main__":
    main()
