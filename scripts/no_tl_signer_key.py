#!/usr/bin/env python3
"""Check whether Norway's EU trusted list is still signed with an RSA key
below 2048 bits (issue #15).

Exit 0  : the signer key is still RSA < 2048 bits, so `rsa-verify-2032` is
          still needed.
Exit 1  : the signer key is now RSA >= 2048 bits or not RSA: drop
          `rsa-verify-2032` as described in issue #15.
Exit 2  : the LOTL or Norway's list could not be fetched or parsed.

Standard library only, plus the `openssl` command line tool.
Usage: no_tl_signer_key.py [--lotl URL] [--tl FILE_OR_URL]
"""
import argparse
import base64
import re
import subprocess
import sys
import urllib.request

LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
ISSUE = "https://github.com/ds-labs-org/ds-trusted-issuers-registry-rs/issues/15"
TSL_XML_MIME = "application/vnd.etsi.tsl+xml"


def gh(level, msg):
    """Print a message, as a GitHub Actions annotation when running in CI."""
    print(f"::{level}::{msg}", flush=True)


def fetch(src):
    if re.match(r"https?://", src):
        req = urllib.request.Request(src, headers={"User-Agent": "ds-labs-tl-check"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
    else:
        with open(src, "rb") as f:
            data = f.read()
    return data.decode("utf-8-sig")


def norway_tl_url(lotl):
    for block in re.findall(r"<(?:\w+:)?OtherTSLPointer>(.*?)</(?:\w+:)?OtherTSLPointer>", lotl, re.S):
        if not re.search(r"SchemeTerritory>\s*NO\s*<", block):
            continue
        mime = re.search(r"MimeType>\s*([^<\s]+)\s*<", block)
        loc = re.search(r"TSLLocation>\s*([^<\s]+)\s*<", block)
        if mime and loc and mime.group(1) == TSL_XML_MIME:
            return loc.group(1)
    return None


def signer_cert_der(tl):
    """The X.509 certificate in the list's own enveloped ds:Signature."""
    sig = re.search(r"<(?:\w+:)?Signature[\s>].*?</(?:\w+:)?Signature>", tl, re.S)
    if not sig:
        return None
    key_info = re.search(r"<(?:\w+:)?KeyInfo[\s>].*?</(?:\w+:)?KeyInfo>", sig.group(0), re.S)
    if not key_info:
        return None
    cert = re.search(r"X509Certificate>([^<]+)<", key_info.group(0))
    if not cert:
        return None
    return base64.b64decode("".join(cert.group(1).split()))


def describe_key(der):
    out = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-enddate", "-text"],
        input=der, capture_output=True, check=True,
    ).stdout.decode()
    alg = re.search(r"Public Key Algorithm:\s*(\S+)", out)
    bits = re.search(r"Public-Key:\s*\((\d+) bit\)", out)
    subject = re.search(r"^subject=(.*)$", out, re.M)
    not_after = re.search(r"^notAfter=(.*)$", out, re.M)
    return (
        alg.group(1) if alg else "unknown",
        int(bits.group(1)) if bits else None,
        subject.group(1).strip() if subject else "?",
        not_after.group(1).strip() if not_after else "?",
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lotl", default=LOTL_URL)
    ap.add_argument("--tl", help="Norway's list (file or URL); default: follow the LOTL")
    args = ap.parse_args()
    try:
        tl_src = args.tl
        if not tl_src:
            tl_src = norway_tl_url(fetch(args.lotl))
            if not tl_src:
                gh("error", f"No XML pointer for Norway (NO) in the LOTL {args.lotl}. Check the LOTL by hand; see {ISSUE}")
                return 2
        cert = signer_cert_der(fetch(tl_src))
        if not cert:
            gh("error", f"No signing certificate found in {tl_src}. Check the list by hand; see {ISSUE}")
            return 2
        alg, bits, subject, not_after = describe_key(cert)
    except Exception as exc:  # network, TLS, openssl or parse failure
        gh("error", f"Could not check Norway's trusted list: {exc!r}. See {ISSUE}")
        return 2

    print(f"Norway TL: {tl_src}")
    print(f"Signer: {subject} (notAfter {not_after}), key: {alg} {bits} bits")
    if alg == "rsaEncryption" and bits is not None and bits < 2048:
        gh("notice", f"Norway's trusted list is still signed with a {bits}-bit RSA key: keep rsa-verify-2032 ({ISSUE}).")
        return 0
    gh(
        "error",
        f"Norway's trusted list is now signed with a {alg} {bits}-bit key ({subject}). "
        f"The 2032-bit RSA exception is no longer needed: drop the rsa-verify-2032 feature "
        f"from the registry, bergshamra and kryptering, then delete this workflow, as described in {ISSUE}.",
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
