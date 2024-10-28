---
title: >
  Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA
abbrev: ML-DSA in Certificates
category: std

docname: draft-ietf-lamps-dilithium-certificates-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: SEC
workgroup: LAMPS WG
keyword:
  ML-DSA
  KEM
  Certificate
  X.509
  PKIX
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME (lamps)"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "lamps-wg/kyber-certificates"
  latest: "https://lamps-wg.github.io/kyber-certificates/#go.draft-ietf-lamps-kyber-certificates.html"

author:
 -
    ins: J. Massimo
    name: Jake Massimo
    organization: AWS
    email: jakemas@amazon.com
    country: US
 -
    ins: P. Kampanakis
    name: Panos Kampanakis
    org: AWS
    email: kpanos@amazon.com
    country: US
 -
    name: Sean Turner
    organization: sn3rd
    email: sean@sn3rd.com
 -
    ins: B.E. Westerbaan
    name: Bas Westerbaan
    organization: Cloudflare
    email: bas@cloudflare.com

normative:
  X680:
    target: https://www.itu.int/rec/T-REC-X.680
    title: >
      Information Technology -- Abstract Syntax Notation One (ASN.1):
      Specification of basic notation
    date: 2021-02
    author:
    -  org: ITU-T
    seriesinfo:
      ITU-T Recommendation: X.680
      ISO/IEC: 8824-1:2021
  X690:
    target: https://www.itu.int/rec/T-REC-X.690
    title: >
      Information Technology -- Abstract Syntax Notation One (ASN.1):
      ASN.1 encoding rules: Specification of Basic Encoding Rules (BER),
      Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
    date: 2021-02
    author:
    -  org: ITU-T
    seriesinfo:
      ITU-T Recommendation: X.690
      ISO/IEC: 8825-1:2021
  FIPS204:
    target: https://csrc.nist.gov/projects/post-quantum-cryptography
    title: >
      Module-Lattice-based Digital Signature Standard
    author:
    - org: National Institute of Standards and Technology (NIST)
    date: 2023-08
    seriesinfo:
      "FIPS PUB": "204"

informative:
  Dilithium:
    target: https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
    title: >
      CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation
    author:
    -
      ins: S. Bai
    -
      ins: L. Ducas
    -
      ins: T. Lepoint
    -
      ins: V. Lyubashevsky
    -
      ins: P. Schwabe
    -
      ins: G. Seiler
    -
      ins: D. Stehlé
    date: 2021
  Fiat-Shamir:
    target: https://www.iacr.org/archive/asiacrypt2009/59120596/59120596.pdf
    title: >
       Fiat-Shamir with aborts: Applications to lattice and factoring-based signatures
    author:
    -
       ins: V. Lyubashevsky
    date: 2009
    seriesinfo:
      International Conference on the Theory and Application of Cryptology and Information Security
  CDFFJ21:
     target: https://eprint.iacr.org/2020/1525.pdf
     title: >
       BUFFing signature schemes beyond unforgeability and the case of post-quantum signatures
     author:
     -
       ins: C. Cremers
     -
       ins: S. Düzlü
     -
       ins: R. Fiedler
     -
       ins: M. Fischlin
     -
       ins: C. Janson
     date: 2021
     seriesinfo:
       In Proceedings of the 42nd IEEE Symposium on Security and Privacy
  NIST-PQC:
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography
    title: >
      Post-Quantum Cryptography Project
    author:
    - org: National Institute of Standards and Technology (NIST)
    date: 2016-12-20

--- abstract

Digital signatures are used within X.509 certificates, Certificate
Revocation Lists (CRLs), and to sign messages. This document describes
the conventions for using FIPS 204, the Module-Lattice-Based Digital
Signature Algorithm (ML-DSA) in Internet X.509 certificates and
certificate revocation lists.  The conventions for the associated
signatures, subject public keys, and private key are also described.

--- middle

# Introduction

The Module-Lattice-Based Digital Signature Algorithm (ML-DSA) is a
quantum-resistant digital signature scheme standardized by the US
National Institute of Standards and Technology (NIST) PQC project
{{NIST-PQC}} in {{FIPS204}}. This document
specifies the use of the ML-DSA in Public Key Infrastructure X.509 (PKIX)
certificates and Certificate Revocation Lists (CRLs) at three security
levels: ML-DSA-44, ML-DSA-65, and ML-DSA-87.

This specification includes conventions for the signatureAlgorithm,
signatureValue, signature, and subjectPublicKeyInfo fields within
Internet X.509 certificates and CRLs {{!RFC5280}} for ML-DSA, like
{{?RFC3279}} did for classic cryptography and {{?RFC5480}} did for
elliptic curve cryptography. The private key format is also specified.

## ASN.1 Module and ML-DSA Identifiers

An ASN.1 module {{X680}} is included for reference purposes. Note that
as per {{RFC5280}}, certificates use the Distinguished Encoding Rules;
see {{X690}}. Also note that NIST defined the object identifiers for
the ML-DSA algorithms in an ASN.1 module; see (TODO insert reference).

## Requirements Language

{::boilerplate bcp14-tagged}


# Identifiers {#oids}

The AlgorithmIdentifier type, which is included herein for convenience,
is defined as follows:

~~~
    AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet} ::=
      SEQUENCE {
        algorithm   ALGORITHM-TYPE.id({AlgorithmSet}),
        parameters  ALGORITHM-TYPE.
                      Params({AlgorithmSet}{@algorithm}) OPTIONAL
     }
~~~

<aside markdown="block">
NOTE: The above syntax is from {{!RFC5912}} and is compatible with
the 2021 ASN.1 syntax {{X680}}. See {{RFC5280}} for the 1988 ASN.1
syntax.
</aside>

The fields in AlgorithmIdentifier have the following meanings:

* algorithm identifies the cryptographic algorithm with an object
identifier.

* parameters, which are optional, are the associated parameters for the
algorithm identifier in the algorithm field.

The OIDs are:

~~~
   id-ML-DSA-44 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
            country(16) us(840) organization(1) gov(101) csor(3)
            nistAlgorithm(4) sigAlgs(3) id-ml-dsa-44(17) }

   id-ML-DSA-65 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
            country(16) us(840) organization(1) gov(101) csor(3)
            nistAlgorithm(4) sigAlgs(3) id-ml-dsa-65(18) }

   id-ML-DSA-87 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
            country(16) us(840) organization(1) gov(101) csor(3)
            nistAlgorithm(4) sigAlgs(3) id-ml-dsa-87(19) }
~~~

The contents of the parameters component for each algorithm MUST be
absent.

# ML-DSA Signatures in PKIX

ML-DSA is a digital signature scheme built upon the
Fiat-Shamir-with-aborts framework {{Fiat-Shamir}}. The security is based
upon the hardness of lattice problems over module lattices {{Dilithium}}.
ML-DSA provides three parameter sets for the NIST PQC security categories
2, 3 and 5.

Signatures are used in a number of different ASN.1 structures. As shown
in the ASN.1 representation from {{RFC5280}} below, in an X.509
certificate, a signature is encoded with an algorithm identifier in the
signatureAlgorithm attribute and a signatureValue attribute that contains
the actual signature.

~~~
   Certificate  ::=  SEQUENCE  {
      tbsCertificate       TBSCertificate,
      signatureAlgorithm   AlgorithmIdentifier,
      signatureValue       BIT STRING  }
~~~

Signatures are also used in the CRL list ASN.1 representation from
{{RFC5280}} below. In a X.509 CRL, a signature is encoded with an
algorithm identifier in the signatureAlgorithm attribute and a
signatureValue attribute that contains the actual signature.


~~~
   CertificateList  ::=  SEQUENCE  {
      tbsCertList          TBSCertList,
      signatureAlgorithm   AlgorithmIdentifier,
      signatureValue       BIT STRING  }
~~~

The identifiers defined in {{oids}} can be used as the
AlgorithmIdentifier in the signatureAlgorithm field in the sequence
Certificate/CertificateList and the signature field in the sequence
TBSCertificate/TBSCertList in certificates and CRLs, respectively,
{{RFC5280}}. The parameters of these signature algorithms MUST be
absent, as explained in {{oids}}.

The signatureValue field contains the corresponding ML-DSA signature
computed upon the ASN.1 DER encoded tbsCertificate/tbsCertList
{{RFC5280}}.

Conforming Certification Authority (CA) implementations MUST specify
the algorithms explicitly by using the OIDs specified in {{oids}} when
encoding ML-DSA signatures in certificates and CRLs. Conforming client
implementations that process certificates and CRLs using ML-DSA MUST
recognize the corresponding OIDs. Encoding rules for ML-DSA signature
values are specified {{oids}}.

When the id-ML-DSA identifier appears in the algorithm field as an
AlgorithmIdentifier, the encoding MUST omit the parameters field. That
is, the AlgorithmIdentifier SHALL be a SEQUENCE of one component, the
OID id-ML-DSA.


# ML-DSA Public Keys in PKIX {#ML-DSA-PubblicKey}

In the X.509 certificate, the subjectPublicKeyInfo field has the
SubjectPublicKeyInfo type, which has the following ASN.1 syntax:

~~~
  SubjectPublicKeyInfo  ::=  SEQUENCE  {
      algorithm         AlgorithmIdentifier,
      subjectPublicKey  BIT STRING
  }
~~~

The fields in SubjectPublicKeyInfo have the following meanings:

* algorithm is the algorithm identifier and parameters for the public
key (see above).

* subjectPublicKey contains the byte stream of the public key.  The
algorithms defined in this document always encode the public key as TODO.

The ML-DSA public key MUST be encoded using the ASN.1 type
MLDSAPublicKey:

~~~
  MLDSAPublicKey ::= OCTET STRING
~~~

where MLDSAPublicKey is a ML-DSA public key as specified by FIPS 204.
Sizes for the three security levels are specified are given in
{{ML-DSAParameters}}. These parameters MUST be encoded as a single
OCTET STRING.

The id-ML-DSA identifier defined in {{oids}} MUST be used as the
algorithm field in the SubjectPublicKeyInfo sequence {{RFC5280}} to
identify a ML-DSA public key.

The ML-DSA public key (a concatenation of rho and t1 that is an OCTET
STRING) is mapped to a subjectPublicKey (a value of type BIT STRING) as
follows: the most significant bit of the OCTET STRING value becomes
the most significant bit of the BIT STRING value, and so on; the least
significant bit of the OCTET STRING becomes the least significant
bit of the BIT STRING.

The following is an example of the ML-DSA-44 public key (for the
seed 000102...1e1f) encoded using the textual encoding defined in
{{!RFC7468}}.

<!-- examples/ML-DSA-44.pub -->
~~~
-----BEGIN PUBLIC KEY-----
MIIFMTAKBghghkgBZQMEEQOCBSEA17K0clSq4NtF55MNSpjSyX2PE5fReJ2voXAk
sxbpvslPyZRtQvGbeadBO7qjPnFJy0LtURVpOsBB+suYit61/g4dhjEYSZW1ksOX
0ilOLhT5CqQUujgmiZrEP0zMrLwm6agyuVEY1ctDPL75ZgsAE44IF/YediyidMNq
1VTrIqrBFi5KsBrLoeOMTv2PgLZbMz0PcuVd/nHOnB67mInnxWEGwP1zgDoq7P6v
3teqPLLO2lTRK9jNNqeM+XWUO0er0l6ICsRS5XQu0ejRqCr6huWQx1jBWuTShA2S
vKGlCQ9ASWWX/KfYuVE/GhvabpUKqpjeRnUH1KT1pPBZkhZYLDVy9i7aiQWrNYFn
DEoCd3oz4Mpylf2PT/bRoKOnaD1l9fX3/GDaAj6CbF+SFEwC99G6EHWYdVPqk2f8
122ZC3+pnNRa/biDbUPkWfUYffBYR5cJoB6mg1k1+nBGCZDNPcG6QBupS6sd3kGs
Z6szGdysoGBI1MTu8n7hOpwX0FOPQw8tZC3CQVZg3niHfY2KvHJSOXjAQuQoX0MZ
hGxEEmJCl2hEwQ5Va6IVtacZ5Z0MayqW05hZBx/cws3nUkp77a5U6FsxjoVOj+Ky
8+36yXGRKCcKr9HlBEw6T9r9n/MfkHhLjo5FlhRKDa9YZRHT2ZYrnqla8Ze05fxg
8rHtFd46W+9fib3HnZEFHZsoFudPpUUx79wcvnTUSIV/R2vNWPIcC2U7O3ak4Ham
VZowJxhVXMY/dIWaq6uSXwI4YcqM0Pe62yhx9n1VMm10URNa1F9KG6aRGPuyyKMO
7JOS7z+XcGbJrdXHEMxkexUU0hfZWMcBfD6Q/SDATmdLkEhuk3CjGgAdMvRzl55J
BnSefkd/oLdFCPil8jeDErg8Jb04jKCw//dHi69CtxZn7arJfEaxKWQ+WG5bBVoM
IRlG1PNuZ1vtWGD6BCoxXZgmFk1qkjfDWl+/SVSQpb1N8ki5XEqud4S2BWcxZqxC
RbW0sIKgnpMj5i8geMW3Z4NEbe/XNq06NwLUmwiYRJAKYYMzl7xEGbMNepegs4fB
kRR0xNQbU+Mql3rLbw6nXbZbs55Z5wHnaVfe9vLURVnDGncSK1IE47XCGfFoixTt
C8C4AbPm6C3NQ+nA6fQXRM2YFb0byIINi7Ej8E+s0bG2hd1aKxuNu/PtkzZw8JWh
gLTxktCLELj6u9/MKyRRjjLuoKXgyQTKhEeACD87DNLQuLavZ7w1W5SUAl3HsKeP
qA46Lb/rUTKIUdYHgZjpSTZRrnh+wCUfkiujDp9R32Km1yeEzz3SBTkxdt+jJKUS
vZSXCjbdNKUUqGeR8Os28BRbCatkZRtKAxOymWEaKhxIiRYnWYdooxFAYLpEQ0ht
9RUioc6IswmFwhb45u0XjdVnswSg1Mr7qIKig0LxepqiauWNtjAIPSw1j99WbD9d
YqQoVnvJ6ozpXKoPNUdLC/qPM5olCrTfzyCDvo7vvBBV4Y/hU3DuyyYFZtg/8Gsh
Gq7EPKKbVMzQD4gVokZe8LRlFcx+QfMSTwnv/3OTCatYspoUWaALzlA46TjJZ49y
6w5O5f2q5m2fhXP8l/xCtJWfS/i2HXhDPoawM11ukZHE2L9IezkFwQjP1qwksM63
3LfPUfhNDtaHuV6uscUzwG8NlwI9kqcIJYN7Wbpst9TlawqHwgOGKujzFbpZJejt
76Z5NpoiAnZhUfFqll+fgeznbMBwtVhp5NuXhM8FyDCzJCyDEg==
-----END PUBLIC KEY-----
~~~

Conforming CA implementations MUST specify the X.509 public key
algorithm explicitly by using the OIDs specified in {{oids}} when using
ML-DSA public keys in certificates and CRLs. Conforming client
implementations that process ML-DSA public keys when processing
certificates and CRLs MUST recognize the corresponding OIDs.

# Key Usage Bits

The intended application for the key is indicated in the keyUsage
certificate extension; see {{Section 4.2.1.3 of RFC5280}}. If the
keyUsage extension is present in a certificate that indicates id-ML-DSA
in the SubjectPublicKeyInfo, then the at least one of following MUST be
present:

~~~
  digitalSignature; or
  nonRepudiation; or
  keyCertSign; or
  cRLSign.
~~~

If the keyUsage extension is present in a certificate that indicates
id-ML-DSA in the SubjectPublicKeyInfo, then the following MUST NOT be
present:

~~~
   keyEncipherment; or
   dataEncipherment; or
   keyAgreement; or
   encipherOnly; or
   decipherOnly.
~~~

Requirements about the keyUsage extension bits defined in {{RFC5280}}
still apply.

# ML-DSA Private Keys

<aside markdown="block">
EDNOTE: This section is still under construction as we discuss the best
way to formulate the private key with the wider working group.
</aside>

An ML-DSA private key is encoded by storing its 32-byte seed in the
privateKey field as an OCTET STRING. FIPS 204 specifies two formats for
an ML-DSA private key: a 32-byte seed and an (expanded) private key. The
expanded private key (and public key) is computed from the seed using
ML-DSA.KeyGen_internal (algorithm 6).

The ASN.1 encoding for a ML-DSA private key is as follows:

~~~
  MLDSAPrivateKey ::= SEQUENCE {
      version                  Version,
      privateKeyAlgorithm      PrivateKeyAlgorithmIdentifier,
      privateKey               OCTET STRING,
  }
~~~

An example of an ML-DSA-44 private key for the seed 0001...1e1f is:

<!-- examples/ML-DSA-44.priv -->
~~~
-----BEGIN PRIVATE KEY-----
MDECAQAwCgYIYIZIAWUDBBEEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhsc
HR4f
-----END PRIVATE KEY-----
~~~


# ASN.1 Module

This section includes the ASN.1 module for the ML-DSA signature
algorithm. This module does not come from any previously existing RFC.
This module references {{RFC5912}}.

~~~
[ EDNOTE: Add ASN.1 here ]

  PKIX1-PQ-Algorithms { iso(1) identified-organization(3) dod(6)
     internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
     id-mod-pkix1-PQ-algorithms(X) }

  DEFINITIONS EXPLICIT TAGS ::=

  BEGIN

  -- EXPORTS ALL;

  IMPORTS

  -- FROM RFC 5912

  PUBLIC-KEY, SIGNATURE-ALGORITHM, DIGEST-ALGORITHM, SMIME-CAPS
  FROM AlgorithmInformation-2009
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-algorithmInformation-02(58) }

  --
  -- Public Key (pk-) Algorithms
  --
  PublicKeys PUBLIC-KEY ::= {
    -- This expands PublicKeys from RFC 5912
    pk-MLDSATBD |
    pk-TBD-TBD,
    ...
  }

  -- The hashAlgorithm is mda-shake256
  -- The XOF seed rho is 32 bytes
  -- The vector t1 is 320*k bytes
  -- These are encoded as a single string

  pk-MLDSA PUBLIC-KEY ::= {
    IDENTIFIER id-MLDSA
    -- KEY no ASN.1 wrapping --
    PARAMS ARE absent
    CERT-KEY-USAGE { nonRepudiation, digitalSignature,
                    keyCertSign, cRLSign }
    --- PRIVATE-KEY no ASN.1 wrapping --
  }

  END
~~~

# IANA Considerations

Extensions in certificates and CRLs are identified using object
Identifiers (OIDs). The creation and delegation of these arcs is to be
determined.

IANA is requested to register the id-mod-pkix1-PQ-algorithms OID for the
ASN.1 module identifier found in Section 5 in the "SMI Security for PKIX
Module Identifier" registry.

# Security Considerations

The Security Considerations section of {{RFC5280}} applies to this
specification as well.

The digital signature scheme defined within this document are modeled
under strongly existentially unforgeable under chosen message attack
(SUF-CMA). For the purpose of estimating security strength, it has
been assumed that the attacker has access to signatures for no more
than 2^{64} chosen messages.

<!--TODO: Add discussion about digests in classical signatures hash-then-sign
and how that does not apply to PQ like Dilithium. And how committing to a
message is additional security. Reference NIST discussion from Peiker and
Makku.-->
<aside markdown="block">
EDNOTE: Discuss deterministic vs randomized signing and the impact on
security.
</aside>

ML-DSA offers both deterministic and randomized signing. By default
ML-DSA signatures are non-deterministic. The private random seed (rho')
for the signature is pseudorandomly derived from the signer’s private
key, the message, and a 256-bit string, rnd - where rnd should be
generated by an approved RBG. In the deterministic version, rng is
instead a 256-bit constant string. The source of randomness in the
randomized mode has been "hedged" against sources of poor entropy, by
including the signers private key and message into the derivation. The
primary purpose of rnd is to facilitate countermeasures to side-channel
attacks and fault attacks on deterministic signatures.

<aside markdown="block">
EDNOTE: Discuss side-channels for ML-DSA.
</aside>


In the design of ML-DSA, care has been taken to make side-channel
resilience easier to achieve. For instance, ML-DSA does not depend
on Gaussian sampling. Implementations must still take great care
not to leak information via varius side channels. While deliberate
design decisions such as these can help to deliver a greater ease
of secure implementation - particularly against side-channel
attacks - it does not necessarily provide resistance to more
powerful attacks such as differential power analysis. Some amount
of side-channel leakage has been demonstrated in parts of the
signing algorithm (specifically the bit-unpacking function), from
which a demonstration of key recovery has been made over a large
sample of signatures. Masking countermeasures exist for
ML-DSA<!--[MGTF19]-->, but come with a performance overhead.

A fundamental security property also associated with digital
signatures is non-repudiation. Non-repudiation refers to the
assurance that the owner of a signature key pair that was
capable of generating an existing signature corresponding to
certain data cannot convincingly deny having signed the data.
The digital signature scheme ML-DSA possess three security
properties beyond unforgeability, that are associated with
non-repudiation. These are exclusive ownership, message-bound
signatures, and non-resignability. These properties are based
tightly on the assumed collision resistance of the hash
function used (in this case SHAKE-256).

Exclusive ownership is a property in which a signature sigma
uniquely determines the public key and message for which it
is valid. Message-bound signatures is the property that a
valid signature uniquely determines the message for which it
is valid, but not necessarily the public key.
Non-resignability is the property in which one cannot produce
a valid signature under another key given a signature sigma
for some unknown message m. These properties are not provided
by classical signature schemes such as DSA or ECDSA, and have
led to a variety of attacks such as Duplicate-Signature Key
Selection (DSKS) attacks <!--[BWM99, MS04]-->, and attacks on
the protocols for secure routing<!--[JCCS19]-->. A full
discussion of these properties in ML-DSA can be found at
{{CDFFJ21}}.

These properties are dependent, in part, on unambiguous public
key serialization. It for this reason the public key structure
defined in {{ML-DSA-PubblicKey}} is intentionally encoded as a
single OCTET STRING.


--- back

# Acknowledgments

We would like to thank ... <!--Markuu, Peikert -->for their
insightful comments.

# Security Strengths

Instead of defining the strength of a quantum algorithm
in a traditional manner using the imprecise notion of bits
of security, NIST has instead elected to define security
levels by picking a reference scheme, which NIST expects
to offer notable levels of resistance to both quantum and
classical attack. To wit, an algorithm that achieves NIST PQC
security level 1 must require computational resources to
break the relevant security property, which are greater than
those required for a brute-force key search on AES-128.
Levels 3 and 5 use AES-192 and AES-256 as reference respectively.
Levels 2 and 4 use collision search for SHA-256 and SHA-384
as reference.

The parameter sets defined for NIST security levels 2, 3 and 5
are listed in the Figure 1, along with the resulting signature
size, public key, and private key sizes in bytes.

<!-- full table, see page 15 of https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf -->
<!-- [JM] we can consider the usefulness of this table/domain parameter discussion here, since we do not want to include the parameter selection in the document -->
<!--<figure anchor="DilithiumParameters">
          <artwork align="left" name="" type="" alt=""><![CDATA[
|==========+=====+=========+=======+=====+========+========+========|
| Security |  n  |    q    | (k,l) | eta | gamma1 | Public | Private|
| Level    |     |         |       |     |        | Key(B) | Key(B) |
|==========+=====+=========+=======+=====+========+========+========|
| 2        | 256 | 8380417 | (4,4) |  2  |  2^17  |  1312  |   2528 |
| 3        | 256 | 8380417 | (6,5) |  4  |  2^19  |  1952  |   4000 |
| 5        | 256 | 8380417 | (8,7) |  2  |  2^19  |  2596  |   4864 |
|==========+=====+=========+=======+=====+========+========+========|]]>
</artwork>
</figure>-->
<!--<figure anchor="DilithiumParameters">
<artwork align="left" name="" type="" alt=""><![CDATA[
|=======+=========+=======+=====+========+======+========+==========|
|Level  |    q    | (k,l) | eta | gamma1 |  Sig.  | Public | Private|
|       |         |       |     |        |  (B)   | Key(B) | Key(B) |
|=======+=========+=======+=====+========+======+========+==========|
| 2     | 8380417 | (4,4) |  2  |  2^17  |  2420  |  1312  |  2528  |
| 3     | 8380417 | (6,5) |  4  |  2^19  |  3293  |  1952  |  4000  |
| 5     | 8380417 | (8,7) |  2  |  2^19  |  4595  |  2596  |  4864  |
|=======+=========+=======+=====+========+======+========+==========|]]>
</artwork>
</figure>-->
~~~
|=======+=======+=====+========+========+========|
| Level | (k,l) | eta |  Sig.  | Public | Private|
|       |       |     |  (B)   | Key(B) | Key(B) |
|=======+=======+=====+========+========+========|
|   2   | (4,4) |  2  |  2420  |  1312  |  32    |
|   3   | (6,5) |  4  |  3309  |  1952  |  32    |
|   5   | (8,7) |  2  |  4627  |  2592  |  32    |
|=======+=======+=====+========+========+========|
~~~
{: #ML-DSAParameters title="ML-DSA Parameters"}
