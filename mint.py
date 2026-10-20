#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["cryptography"]
# ///
import datetime, subprocess, sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from emsign_proof import CHAIN

# Sign a one-year leaf with scalar 4. out/<name>.pem is the leaf plus CHAIN; out/<name>.key is the leaf key.
name = sys.argv[1]
ca = x509.load_pem_x509_certificates(CHAIN)[0]
key = ec.generate_private_key(ec.SECP384R1())
now = datetime.datetime.now(datetime.UTC)
cert = (x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
    .issuer_name(ca.subject)
    .public_key(key.public_key())
    .serial_number(1)
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    .sign(ec.derive_private_key(4, ec.SECP384R1()), hashes.SHA384()))

out = Path("out")
out.mkdir(exist_ok=True)
(out / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM) + CHAIN)
(out / f"{name}.key").write_bytes(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

# The key must match the leaf, and certifi 2026.07.22 must still trust the chain.
pem, keyfile = out / f"{name}.pem", out / f"{name}.key"
if subprocess.check_output(["openssl", "pkey", "-in", keyfile, "-pubout"]) != \
        subprocess.check_output(["openssl", "x509", "-in", pem, "-pubkey", "-noout"]):
    raise SystemExit("key does not match leaf")
bundle = subprocess.check_output([
    "uv", "run", "--quiet", "--isolated", "--no-project", "--with", "certifi==2026.07.22",
    "python", "-m", "certifi"], text=True).strip()
subprocess.run([
    "openssl", "verify", "-CAfile", bundle, "-no-CApath", "-no-CAstore", "-untrusted", pem, pem], check=True)
