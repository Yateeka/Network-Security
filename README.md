# Network Security: Secure Email Protocols (PGP vs S/MIME)

## Overview

This project presents a full implementation and evaluation of secure email communication protocols, focusing on Pretty Good Privacy (PGP) and S/MIME. Traditional email systems such as SMTP do not provide guarantees for confidentiality, integrity, authentication, or non-repudiation.

This work implements the PGP protocol using modern cryptographic techniques and compares it with S/MIME in terms of security, performance, and usability.

---

## Features

- Python-based implementation of the PGP protocol  
- Hybrid encryption using AES-GCM and RSA  
- SHA-256 hashing for message integrity  
- RSA-based digital signatures  
- Data compression using zlib  
- Performance benchmarking for AES and RSA  
- Simulation of real-world attacks including:
    - EFAIL  
    - Key spoofing  
    - Replay attacks  
    - Ciphertext manipulation  

---

## Project Structure

```
Network-Security/
│
├── main.py             # End-to-end workflow orchestration
├── encryption.py       # AES-GCM encryption and RSA-OAEP
├── signature.py        # RSA signature generation and verification
├── key_generation.py   # RSA and ECC key generation
├── hashing.py          # SHA-256 hashing
├── compression.py      # Data compression (zlib)
├── benchmark.py        # Performance measurement
├── attack_demo.py      # Security attack simulations
├── README.md
```

---

## System Workflow

### Sender Side
1. Compress the message  
2. Generate SHA-256 hash  
3. Sign the hash using RSA private key  
4. Encrypt the message using AES-GCM  
5. Encrypt the session key using RSA  

### Receiver Side
1. Decrypt session key using RSA  
2. Decrypt message using AES-GCM  
3. Verify digital signature  

---

## Installation

```
git clone https://github.com/Yateeka/Network-Security.git
cd Network-Security
pip install cryptography
```

---

## Usage

### Run Benchmarks

```
python benchmark.py
```

### Run Attack Demonstrations

```
python attack_demo.py
```

---

## Performance Summary

- AES-128 and AES-256 show similar performance across message sizes  
- AES-256 provides stronger long-term security  
- RSA-2048 operations are the main performance bottleneck  

---

## Security Analysis

### Strengths

- Ensures confidentiality, integrity, and authenticity  
- Resistant to ciphertext tampering using AES-GCM  
- Mitigates EFAIL-style vulnerabilities  

### Limitations

- Vulnerable to key spoofing due to decentralized trust model  
- No built-in replay attack protection  
- Complex key management for users  

---

## Comparison: PGP vs S/MIME

| Feature            | PGP (RFC 4880) | S/MIME (RFC 5751) |
|--------------------|----------------|-------------------|
| Trust Model        | Web of Trust   | PKI (CA-based)    |
| Key Distribution   | Decentralized  | Centralized       |
| Deployment         | Complex        | Moderate          |
| Enterprise Use     | Low            | High              |
| Cost               | Free           | Paid Certificates |

PGP offers stronger decentralization and privacy, while S/MIME provides easier deployment and better enterprise integration.

---

## Concepts Covered

- Hybrid encryption  
- AES-GCM and symmetric cryptography  
- RSA key exchange and digital signatures  
- SHA-256 hashing  
- Web of Trust vs PKI  
- Authenticated encryption (AEAD)  
- Cryptographic security models (IND-CCA2, UF-CMA)  

---

## Future Improvements

- Integration of elliptic curve cryptography (ECC)  
- Implementation of forward secrecy  
- Improved key distribution mechanisms  
- Enhanced usability for non-technical users  

---

## Authors

Yateeka Goyal  
Aditya Sharma  
Department of Computer Science  
Georgia State University  

---

## References

- RFC 4880 (OpenPGP)  
- RFC 5751 (S/MIME)  
- NIST SP 800-57  
- Python Cryptography Library  

---

## License

This project is intended for academic and educational use.
