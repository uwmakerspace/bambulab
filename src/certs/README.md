# Bambu LAN MQTT trust material

When the `verify-tls` feature is enabled, `tls.rs` loads trust anchors from **`extracted/`**:

- **`extracted/cert_5.pem`** — BBL CA (root)
- **`extracted/cert_8.pem`** — `application_root.bambulab.com` (intermediate)

See **`extracted/README.md`** for the full extracted chain and provenance.
