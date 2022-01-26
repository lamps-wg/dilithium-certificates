# Algorithms and Identifiers for Post-Quantum Algorithms in the Internet X.509 Public Key Infrastructure

This repository is the working area for the Internet-Draft "Algorithms and Identifiers for Post-Quantum Algorithms in the Internet X.509 Public Key Infrastructure". 

This document updates [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279) to specify algorithm identifiers and ASN.1 encoding formats for post-quantum digital signatures and subject public keys used in the Internet X.509 Public Key Infrastructure (PKI).  The signature algorithms covered are Dilithium, TBD and TBD1.  The encoding for public key, private key, and Post-Quantum Digital Signature Algorithm (PQDSA) structures is provided.

- [Datatracker Page](https://tools.ietf.org/wg/lamps/) (to come)

## Compiling
The file is compiled using xml2rfc available at https://pypi.org/project/xml2rfc/ using the command:
```
xml2rfc draft-ietf-massimo-lamps-pq-pkix-00.xml
```
