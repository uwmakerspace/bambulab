# Extracted Certificates from main.jsc

Certificates and CRL extracted from the Bambu Connect.

## Certificate Chain

### Root CA

| File         | Subject                   | Valid                    |
| ------------ | ------------------------- | ------------------------ |
| `cert_5.pem` | BBL CA (self-signed root) | 2022-04-04 to 2032-04-01 |

### Intermediate CAs

| File         | Subject                       | Issuer      | Valid                    |
| ------------ | ----------------------------- | ----------- | ------------------------ |
| `cert_1.pem` | BBL CA2 RSA (self-signed)     | BBL CA2 RSA | 2025-06-17 to 2050-06-17 |
| `cert_2.pem` | BBL CA2 ECC (self-signed)     | BBL CA2 ECC | 2025-06-17 to 2050-06-17 |
| `cert_3.pem` | BBL CA2 RSA                   | BBL CA      | 2025-06-17 to 2035-06-15 |
| `cert_4.pem` | BBL CA2 ECC                   | BBL CA      | 2025-06-17 to 2035-06-15 |
| `cert_8.pem` | application_root.bambulab.com | BBL CA      | 2024-05-29 to 2034-05-27 |

### Device Certificates

| File         | Subject                     | Issuer                        | Valid                    |
| ------------ | --------------------------- | ----------------------------- | ------------------------ |
| `cert_7.pem` | GLOF3813734089.bambulab.com | application_root.bambulab.com | 2024-08-02 to 2034-07-31 |
| `cert_6.pem` | GLOF3813734089-524a37c80000 | GLOF3813734089.bambulab.com   | 2024-12-11 to 2025-12-12 |

### CRL

| File        | Issuer                      | Notes                  |
| ----------- | --------------------------- | ---------------------- |
| `crl_1.pem` | GLOF3813734089.bambulab.com | Revokes 2 certificates |

## Trust Chain

```text
BBL CA (root)
 +-- BBL CA2 RSA (intermediate)
 +-- BBL CA2 ECC (intermediate)
 +-- application_root.bambulab.com
      +-- GLOF3813734089.bambulab.com
           +-- GLOF3813734089-524a37c80000 (device leaf cert)
```

## Runtime trust (`verify-tls`)

The `bambulab` crate embeds **`cert_5.pem`** (BBL CA) and **`cert_8.pem`** (`application_root.bambulab.com`) as LAN MQTT trust anchors. Other files here are reference-only.
