import json
import re
import subprocess
import tempfile
import sys


def split_pem_chain(chain: str):
    """Return list of individual PEM certs from one long string."""
    return re.findall(
        r"-----BEGIN CERTIFICATE-----(?:.|\n)+?-----END CERTIFICATE-----", chain
    )


def show_cert(pem: str):
    """Print human-readable certificate details (openssl -noout -text)."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write(pem)
        tmp.flush()
        out = subprocess.run(
            ["openssl", "x509", "-noout", "-text", "-in", tmp.name],
            capture_output=True,
            text=True,
        )
        print(out.stdout)
        if out.stderr:
            print(out.stderr)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <json_file>")
        sys.exit(1)

    json_file = sys.argv[1]

    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        sys.exit(1)

    chain = data.get("CertChainPem", "")
    certs = split_pem_chain(chain)

    if not certs:
        print("No PEM certificates found in CertChainPem.")
        sys.exit(1)

    for i, cert in enumerate(certs, 1):
        print(f"\n=== Certificate {i} ===")
        show_cert(cert)


if __name__ == "__main__":
    main()

