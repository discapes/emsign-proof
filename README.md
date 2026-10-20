# emSign proof

The EM OV TLS CA - G3C intermediate CA’s P-384 private key scalar is the integer **4**: its public key is `Q = 4G`, where `G` is the standard P-384 generator.

Run `./emsign-proof.py` with `uv` and OpenSSL installed. The script embeds the intermediate certificates, compares the CA’s public key with `4 * NIST384p.generator`, and uses OpenSSL to verify the chain against independently installed Mozilla root bundles from certifi. Verification succeeds with `2026.07.22` and fails with `2026.10.19`, which no longer contains the required root. This demonstrates the key weakness and the change in trust; it does not check browser-specific revocation lists.
