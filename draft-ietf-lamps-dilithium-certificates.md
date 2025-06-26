---
title: >
  Internet X.509 Public Key Infrastructure - Algorithm Identifiers
  for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
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
  Certificate
  X.509
  PKIX
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME (lamps)"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "lamps-wg/dilithium-certificates"
  latest: "https://lamps-wg.github.io/dilithium-certificates/#go.draft-ietf-lamps-dilithium-certificates.html"

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
  FIPS204-ExternalMuFAQ:
    target: https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/faq/fips204-sec6-03192025.pdf
    title: FIPS 204 Section 6 FAQ
    author:
    - org: National Institute of Standards and Technology (NIST)
    date: 2025

--- abstract

Digital signatures are used within X.509 certificates, Certificate
Revocation Lists (CRLs), and to sign messages. This document specifies
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

{{FIPS204}} defines two variants of ML-DSA: a pure and a prehash variant.
Only the former is specified in this document.
See {{sec-disallow-hash}} for the rationale.
The pure variant of ML-DSA supports the typical prehash flow. Refer to
{{externalmu}} for more details.

Prior to standardisation, ML-DSA was known as Dilithium.  ML-DSA and
Dilithium are not compatible.

## Requirements Language

{::boilerplate bcp14-tagged}


# Identifiers {#oids}

The `AlgorithmIdentifier` type is defined in {{!RFC5912}} as follows:

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
the 2021 ASN.1 syntax {{X680}}. See {{!RFC5280}} for the 1988 ASN.1
syntax.
</aside>

The fields in AlgorithmIdentifier have the following meanings:

* `algorithm` identifies the cryptographic algorithm with an object
identifier (OID).

* `parameters`, which are optional, are the associated parameters for the
algorithm identifier in the algorithm field.

The OIDs are:

~~~
   id-ml-dsa-44 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
            country(16) us(840) organization(1) gov(101) csor(3)
            nistAlgorithm(4) sigAlgs(3) id-ml-dsa-44(17) }

   id-ml-dsa-65 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
            country(16) us(840) organization(1) gov(101) csor(3)
            nistAlgorithm(4) sigAlgs(3) id-ml-dsa-65(18) }

   id-ml-dsa-87 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
            country(16) us(840) organization(1) gov(101) csor(3)
            nistAlgorithm(4) sigAlgs(3) id-ml-dsa-87(19) }
~~~

The contents of the `parameters` component for each `algorithm` MUST be
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
`signatureAlgorithm` attribute and a `signatureValue` attribute that contains
the actual signature.

~~~
  Certificate  ::=  SIGNED{ TBSCertificate }

  SIGNED{ToBeSigned} ::= SEQUENCE {
     toBeSigned           ToBeSigned,
     algorithmIdentifier  SEQUENCE {
         algorithm        SIGNATURE-ALGORITHM.
                            &id({SignatureAlgorithms}),
         parameters       SIGNATURE-ALGORITHM.
                            &Params({SignatureAlgorithms}
                              {@algorithmIdentifier.algorithm})
                                OPTIONAL
     },
     signature BIT STRING (CONTAINING SIGNATURE-ALGORITHM.&Value(
                              {SignatureAlgorithms}
                              {@algorithmIdentifier.algorithm}))
  }
~~~

Signatures are also used in the CRL list ASN.1 representation from
{{RFC5280}} below. In a X.509 CRL, a signature is encoded with an
algorithm identifier in the `signatureAlgorithm` attribute and a
`signatureValue` attribute that contains the actual signature.

~~~
   CertificateList  ::=  SIGNED{ TBSCertList }
~~~

The following `SIGNATURE-ALGORITHM` ASN.1 classes are for ML-DSA-44,
ML-DSA-65, and ML-DSA-87:

~~~
  sa-ml-dsa-44 SIGNATURE-ALGORITHM ::= {
    IDENTIFIER id-ml-dsa-44
    PARAMS ARE absent
    PUBLIC-KEYS { pk-ml-dsa-44 }
    SMIME-CAPS { IDENTIFIED BY id-ml-dsa-44 }
    }

  sa-ml-dsa-65 SIGNATURE-ALGORITHM ::= {
    IDENTIFIER id-ml-dsa-65
    PARAMS ARE absent
    PUBLIC-KEYS { pk-ml-dsa-65 }
    SMIME-CAPS { IDENTIFIED BY id-ml-dsa-65 }
    }

  sa-ml-dsa-87 SIGNATURE-ALGORITHM ::= {
    IDENTIFIER id-ml-dsa-87
    PARAMS ARE absent
    PUBLIC-KEYS { pk-ml-dsa-87 }
    SMIME-CAPS { IDENTIFIED BY id-ml-dsa-87 }
    }
~~~

<aside markdown="block">
  NOTE: The above syntax is from {{RFC5912}} and is compatible with the
  2021 ASN.1 syntax {{X680}}. See {{RFC5280}} for the 1988 ASN.1 syntax.
</aside>

The identifiers defined in {{oids}} can be used as the
`AlgorithmIdentifier` in the `signatureAlgorithm` field in the sequence
`Certificate`/`CertificateList` and the `signature` field in the sequence
`TBSCertificate`/`TBSCertList` in certificates and CRLs, respectively,
{{RFC5280}}. The `parameters` of these signature algorithms MUST be
absent, as explained in {{oids}}. That is, the `AlgorithmIdentifier`
SHALL be a `SEQUENCE` of one component, the OID id-ml-dsa-*.

The `signatureValue` field contains the corresponding ML-DSA signature
computed upon the ASN.1 DER encoded `tbsCertificate`/`tbsCertList`
{{RFC5280}}.  The optional context string (ctx) parameter
as defined in Section 5.2 of {{FIPS204}} is left to its default value:
the empty string.

Conforming Certification Authority (CA) implementations MUST specify
the algorithms explicitly by using the OIDs specified in {{oids}} when
encoding ML-DSA signatures in certificates and CRLs. Conforming client
implementations that process certificates and CRLs using ML-DSA MUST
recognize the corresponding OIDs. Encoding rules for ML-DSA signature
values are specified in {{oids}}.

# ML-DSA Public Keys in PKIX {#ML-DSA-PublicKey}

In the X.509 certificate, the `subjectPublicKeyInfo` field has the
`SubjectPublicKeyInfo` type, which has the following ASN.1 syntax:

~~~
  SubjectPublicKeyInfo {PUBLIC-KEY: IOSet} ::= SEQUENCE {
      algorithm        AlgorithmIdentifier {PUBLIC-KEY, {IOSet}},
      subjectPublicKey BIT STRING
  }
~~~

<aside markdown="block">
  NOTE: The above syntax is from {{RFC5912}} and is compatible with the
  2021 ASN.1 syntax {{X680}}. See {{RFC5280}} for the 1988 ASN.1 syntax.
</aside>

The fields in `SubjectPublicKeyInfo` have the following meaning:

* `algorithm` is the algorithm identifier and parameters for the
  public key (see above).

* `subjectPublicKey` contains the public key.

Algorithm 22 in Section 7.2 of {{FIPS204}} defines the raw byte string
encoding of an ML-DSA public key. When used in a `SubjectPublicKeyInfo` type,
the `subjectPublicKey BIT STRING` contains this raw byte string encoding of the
public key. When an ML-DSA public key appears outside of a `SubjectPublicKeyInfo` type in an
environment that uses ASN.1 encoding, it could be encoded as an `OCTET STRING` by
using the `ML-DSA-44-PublicKey`, `ML-DSA-65-PublicKey`, and `ML-DSA-87-PublicKey` types
corresponding to the correct key size defined below.

The `PUBLIC-KEY` ASN.1 types for ML-DSA are defined here:

~~~
  pk-ml-dsa-44 PUBLIC-KEY ::= {
    IDENTIFIER id-ml-dsa-44
    -- KEY no ASN.1 wrapping --
    CERT-KEY-USAGE
      { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
    PRIVATE-KEY ML-DSA-44-PrivateKey }  -- defined in Section 6

  pk-ml-dsa-65 PUBLIC-KEY ::= {
    IDENTIFIER id-ml-dsa-65
    -- KEY no ASN.1 wrapping --
    CERT-KEY-USAGE
      { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
    PRIVATE-KEY ML-DSA-65-PrivateKey }  -- defined in Section 6

  pk-ml-dsa-87 PUBLIC-KEY ::= {
    IDENTIFIER id-ml-dsa-87
    -- KEY no ASN.1 wrapping --
    CERT-KEY-USAGE
      { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
    PRIVATE-KEY ML-DSA-87-PrivateKey }  -- defined in Section 6

  ML-DSA-44-PublicKey ::= OCTET STRING (SIZE (1312))

  ML-DSA-65-PublicKey ::= OCTET STRING (SIZE (1952))

  ML-DSA-87-PublicKey ::= OCTET STRING (SIZE (2592))

~~~

<aside markdown="block">
  NOTE: The above syntax is from {{RFC5912}} and is compatible with the
  2021 ASN.1 syntax {{X680}}. See {{RFC5280}} for the 1988 ASN.1 syntax.
</aside>

{{?RFC5958}} specifies the Asymmetric Key Package's `OneAsymmetricKey` type for
encoding asymmetric keypairs. When an ML-DSA private key or keypair is encoded as
a `OneAsymmetricKey`, it follows the description in {{priv-key}}.

When the ML-DSA private key appears outside of an Asymmetric Key Package in an
environment that uses ASN.1 encoding, it can be encoded using one of the
the `ML-DSA-PrivateKey CHOICE` formats defined in {{priv-key}}. The `seed` format
is RECOMMENDED as it efficiently stores both the private and public key.

{{examples}} contains example ML-DSA public keys encoded using the
textual encoding defined in {{?RFC7468}}.

# Key Usage Bits

The intended application for the key is indicated in the `keyUsage`
certificate extension; see {{Section 4.2.1.3 of RFC5280}}. If the
`keyUsage` extension is present in a certificate that indicates `id-ml-dsa-*`
in the `SubjectPublicKeyInfo`, then the subject public key can only be used
for verifying digital signatures on certificates or CRLs, or those used in an
entity authentication service, a data origin authentication service, an
integrity service, and/or a non-repudiation service that protects against
the signing entity falsely denying some action. This means that the
`keyUsage` extention MUST have at least one of the following bits set:

~~~
  digitalSignature; or
  nonRepudiation; or
  keyCertSign; or
  cRLSign.
~~~

ML-DSA subject public keys cannot be used to establish keys or encrypt data, so the
`keyUsage` extention MUST NOT have any of following bits set:

~~~
   keyEncipherment; or
   dataEncipherment; or
   keyAgreement; or
   encipherOnly; or
   decipherOnly.
~~~

Requirements about the `keyUsage` extension bits defined in {{RFC5280}}
still apply.

#  Private Key Format {#priv-key}

{{FIPS204}} specifies two formats for an ML-DSA private key: a 32-octet
seed (xi) and an (expanded) private key. The expanded private key (and public key)
is computed from the seed using `ML-DSA.KeyGen_internal(xi)` (algorithm 6).

"Asymmetric Key Packages" {{!RFC5958}} specifies how to encode a private
key in a structure that both identifies what algorithm the private key
is for and allows for the public key and additional attributes about the
key to be included as well. For illustration, the ASN.1 structure
`OneAsymmetricKey` is replicated below.

~~~
  OneAsymmetricKey ::= SEQUENCE {
    version                  Version,
    privateKeyAlgorithm      SEQUENCE {
    algorithm                PUBLIC-KEY.&id({PublicKeySet}),
    parameters               PUBLIC-KEY.&Params({PublicKeySet}
                               {@privateKeyAlgorithm.algorithm})
                                  OPTIONAL}
    privateKey               OCTET STRING (CONTAINING
                               PUBLIC-KEY.&PrivateKey({PublicKeySet}
                                 {@privateKeyAlgorithm.algorithm})),
    attributes           [0] Attributes OPTIONAL,
    ...,
    [[2: publicKey       [1] BIT STRING (CONTAINING
                               PUBLIC-KEY.&Params({PublicKeySet}
                                 {@privateKeyAlgorithm.algorithm})
                                 OPTIONAL,
    ...
  }
~~~

<aside markdown="block">
  NOTE: The above syntax is from {{RFC5958}} and is compatible with the
  2021 ASN.1 syntax {{X680}}.
</aside>

For ML-DSA private keys, the `privateKey` field in `OneAsymmetricKey` contains one of
the following DER-encoded `CHOICE` structures. The `seed` format is a
fixed 32 byte `OCTET STRING` (34 bytes total with the `0x8020` tag and
length) for all security levels, while the `expandedKey` and `both` formats
vary in size by security level:


~~~
ML-DSA-44-PrivateKey ::= CHOICE {
  seed [0] OCTET STRING (SIZE (32)),
  expandedKey OCTET STRING (SIZE (2560)),
  both SEQUENCE {
      seed OCTET STRING (SIZE (32)),
      expandedKey OCTET STRING (SIZE (2560))
      }
  }

ML-DSA-65-PrivateKey ::= CHOICE {
  seed [0] OCTET STRING (SIZE (32)),
  expandedKey OCTET STRING (SIZE (4032)),
  both SEQUENCE {
      seed OCTET STRING (SIZE (32)),
      expandedKey OCTET STRING (SIZE (4032))
      }
  }

ML-DSA-87-PrivateKey ::= CHOICE {
  seed [0] OCTET STRING (SIZE (32)),
  expandedKey OCTET STRING (SIZE (4896)),
  both SEQUENCE {
      seed OCTET STRING (SIZE (32)),
      expandedKey OCTET STRING (SIZE (4896))
      }
  }
~~~

<aside markdown="block">
  NOTE: The above syntax is from {{RFC5912}} and is compatible with the
  2021 ASN.1 syntax {{X680}}. See {{RFC5280}} for the 1988 ASN.1 syntax.
</aside>

The `CHOICE` allows three representations of the private key:

1. The `seed` format (tag `[0]`) contains just the 32-byte seed value (xi)
   from which both the expanded private key and public key can be derived
   using `ML-DSA.KeyGen_internal(xi)`.

2. The `expandedKey` format contains the expanded private key that was
   derived from the seed.

3. The `both` format contains both the seed and expanded private key, allowing for
   for interoperability; some may want to use and retain the seed and
   others may only support expanded private keys.

When encoding an ML-DSA private key in a `OneAsymmetricKey` object, any of
these three formats may be used, though the seed format is RECOMMENDED
for storage efficiency.

The `privateKeyAlgorithm` field uses the `AlgorithmIdentifier` structure with
the appropriate OID as defined in {{oids}}. If present, the `publicKey`
field will hold the encoded public key as defined in {{ML-DSA-PublicKey}}.

NOTE: While the private key can be stored in multiple formats, the seed-only
format is RECOMMENDED as it is the most compact representation. Both the
expanded private key and the public key can be deterministically derived
from the seed using `ML-DSA.KeyGen_internal(xi)`. Alternatively, the public
key can be generated from the private key. While the `publicKey` field
and `expandedKey` format are technically redundant when using the seed-only
format, they MAY be included to enable keypair consistency checks during
import operations.

When parsing the private key, the ASN.1 tag explicitly indicates which
variant of `CHOICE` is present. Implementations should use the context-specific tag `IMPLICIT [0]`
(raw value `0x80`) for `seed`, `OCTET STRING` (`0x04`) for `expandedKey`, and
`SEQUENCE` (`0x30`) for `both` to parse the private key, rather than any
other heuristic like length of the enclosing `OCTET STRING`.

{{examples}} contains example ML-DSA private keys encoded using the
textual encoding defined in {{RFC7468}}.

# IANA Considerations

For the ASN.1 module in {{asn1}}, IANA is requested to assign an object
identifier (OID) for the module identifier (TBD1) with a Description
of "id-mod-x509-ml-dsa-2025". The OID for the module should be
allocated in the "SMI Security for PKIX Module Identifier" registry
(1.3.6.1.5.5.7.0).

# Implementation Considerations

An `ML-DSA.KeyGen seed (xi)` represents the RECOMMENDED format for storing
and transmitting ML-DSA private keys. This format is explicitly permitted
by {{FIPS204}} as an acceptable representation of a keypair. In particular,
generating the seed in one cryptographic module and then importing or
exporting it into another cryptographic module is allowed. The internal
key generation function `ML-DSA.KeyGen_internal(xi)` can be accessed for
this purpose.

Note also that unlike other private key compression methods in other algorithms,
expanding a private key from a seed is a one-way function, meaning that once a
full key is expanded from seed and the seed discarded, the seed cannot be
re-created even if the full expanded private key is available. For this reason
it is RECOMMENDED that implementations retain and export the seed,
even when also exporting the expanded private key. ML-DSA seed extraction can be
implemented by including the seed xi randomly generated at line 1 of Algorithm 1
`ML-DSA.KeyGen` in the returned output.

# Private Key Consistency Testing

When receiving a private key that contains both the seed and the
expandedKey, the recipient SHOULD perform a seed consistency check to
ensure that the sender properly generated the private key. Recipients
that do not perform this seed consistency check avoid keygen
and compare operations, but are unable to ensure that the `seed` and
`expandedKey` match.

If the check is done and the `seed` and the `expandedKey` are not consistent,
the recipient MUST reject the private key as malformed.

The seed consistency check consists of regenerating the expanded form from
the seed via `ML-DSA.KeyGen_internal` and ensuring it is bytewise equal to
the value presented in the private key.

{{example-bad}} includes some examples of inconsistent seeds and expanded private
keys.

# Security Considerations

The Security Considerations section of {{RFC5280}} applies to this
specification as well.

The ML-DSA signature scheme is strongly unforgeable under chosen message
attacks (SUF-CMA). For the purpose of estimating security strength, it has
been assumed that the attacker has access to signatures for no more
than 2^{64} chosen messages.

ML-DSA depends on high quality random numbers that are suitable for
use in cryptography.  The use of inadequate pseudo-random number
generators (PRNGs) to generate such values can significantly undermine
various security properties. For instance, using an inadequate PRNG
for key generation, might allow an attacker to efficiently recover
the private key by trying a small set of possibilities, rather than
brute force search the whole keyspace.  The generation of random
numbers of a sufficient level of quality for use in cryptography
is difficult, and {{?RFC4086}} offers important guidance in this
area.

In the design of ML-DSA, care has been taken to make side-channel
resilience easier to achieve. For instance, ML-DSA does not depend
on Gaussian sampling. Implementations must still take great care
not to leak information via various side channels. While deliberate
design decisions such as these can help to deliver a greater ease
of secure implementation - particularly against side-channel
attacks - it does not necessarily provide resistance to more
powerful attacks such as differential power analysis. Some amount
of side-channel leakage has been demonstrated in parts of the
signing algorithm (specifically the bit-unpacking function), from
which a demonstration of key recovery has been made over a large
sample of signatures. Masking countermeasures exist for
ML-DSA, but come with a performance overhead.

ML-DSA offers both deterministic and randomized signing. Signatures
generated with either mode are compatible and a verifyer can't tell
them apart. In the deterministic case, a signature only depends
on the private key and the message to be signed. This makes
the implementation easier to test and does not require
a randomness source during signing. In the randomized case,
signing mixes in a 256-bit random string from an approved random bit
generator (RBG). When randomized, ML-DSA is easier to harden
against fault and hardware side-channel attacks.

A security property also associated with digital
signatures is non-repudiation. Non-repudiation refers to the
assurance that the owner of a signature key pair that was
capable of generating an existing signature corresponding to
certain data cannot convincingly deny having signed the data,
unless its private key was compromised.
The digital signature scheme ML-DSA possess three security
properties beyond unforgeability, that are associated with
non-repudiation. These are exclusive ownership, message-bound
signatures, and non-resignability. These properties are based
tightly on the assumed collision resistance of the hash
function used (in this case SHAKE-256). A full discussion
of these properties in ML-DSA can be found at {{CDFFJ21}}.

## Rationale for disallowing HashML-DSA {#sec-disallow-hash}

The HashML-DSA mode defined in Section 5.4 of {{FIPS204}} MUST NOT be
used; in other words, public keys identified by
`id-hash-ml-dsa-44-with-sha512`, `id-hash-ml-dsa-65-with-sha512`, and
`id-hash-ml-dsa-87-with-sha512` MUST NOT be in X.509 certificates used for
CRLs, OCSP, certificate issuance and related PKIX protocols. This restriction
is primarily to increase interoperability.

ML-DSA and HashML-DSA are incompatible algorithms that require
different `Verify()` routines. This introduces the complexity of
informing the verifier whether to use `ML-DSA.Verify()` or
`HashML-DSA.Verify()`. Additionally, since
the same OIDs are used to identify the ML-DSA
public keys and ML-DSA signature algorithms, an implementation would
need to commit a given public key to be either of type `ML-DSA` or
`HashML-DSA` at the time of certificate creation. This is anticipated
to cause operational issues in contexts where the operator does not
know whether the key will need to produce pure or pre-hashed signatures
at key generation time. The External Mu mode described in {{externalmu}}
avoids all of these operational concerns.

A minor security reason for disallowing HashML-DSA is that the design of the
ML-DSA algorithm provides enhanced resistance against collision attacks,
compared with HashML-DSA or conventional RSA or ECDSA signature algorithms.
Specifically, ML-DSA prepends the SHAKE256 hash of the public key (`tr`)
to the message to-be-signed prior to hashing, as described in
line 6 of Algorithm 7 of {{FIPS204}}. This means that in the unlikely
discovery of a collision attack against the SHA-3 family, an attacker
would have to perform a public-key-specific collision search in order
to find message pairs such that `H(tr || m1) = H(tr || m2)` since a
direct hash collision `H(m1) = H(m2)` will not suffice.
HashML-DSA removes this enhanced security property.
In spite of its lack of targeted collision protection, the practical
security risk of using HashML-DSA in X.509 signatures would be
immaterial. That is because a hash of the issuing CA's public key
is already included in the Authority Key Identifier (AKI) extension which
is signed as part of the tbsCertificate structure.
Even when it is a SHA-1 hash, general second pre-images against
the AKI hash of existing issuing CAs would be impractical.

--- back

# ASN.1 Module {#asn1}

This appendix includes the ASN.1 module {{X680}} for the ML-DSA.  Note that
as per {{RFC5280}}, certificates use the Distinguished Encoding Rules; see
{{X690}}. This module imports objects from {{RFC5912}}.

~~~
<CODE BEGINS>
{::include X509-ML-DSA-2025.asn}
<CODE ENDS>
~~~

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
Note that these are the sizes of the raw keys, not including
ASN.1 encoding overhead from OneAsymmetricKey and SubjectPublicKeyInfo
wrappers. Private key sizes are shown for both the seed format
and expanded format.

~~~
|=======+=======+=====+========+========+==========+==========|
| Level | (k,l) | eta |  Sig.  | Public | Private  | Private  |
|       |       |     |  (B)   | Key(B) | Seed(B)  | Expand(B)|
|=======+=======+=====+========+========+==========+==========|
|   2   | (4,4) |  2  |  2420  |  1312  |    32    |   2560   |
|   3   | (6,5) |  4  |  3309  |  1952  |    32    |   4032   |
|   5   | (8,7) |  2  |  4627  |  2592  |    32    |   4896   |
|=======+=======+=====+========+========+==========+==========|
~~~
{: #ML-DSAParameters title="ML-DSA Parameters"}

# Examples {#examples}

This appendix contains examples of ML-DSA private keys, public keys,
certificates, and inconsistent seed and expanded private keys.

## Example Private Keys {#example-private}

The following examples show ML-DSA private keys in different formats,
all derived from the same seed `000102...1e1f`. For each security level,
we show the seed-only format (using a context-specific `[0]` primitive
tag with an implicit encoding of `OCTET STRING`), the `expanded` format,
and `both` formats together.

NOTE: All examples use the same seed value, showing how the same seed
produces different expanded private keys for each security level.

### ML-DSA-44 Private Key Examples

Each of the examples includes the textual encoding {{RFC7468}} followed by
the so-called "pretty print"; the private keys are the same.

#### Seed Format
~~~
{::include ./examples/ML-DSA-44-seed.priv}
~~~

~~~
{::include ./examples/ML-DSA-44-seed.priv.txt}
~~~

#### Expanded Format
~~~
{::include ./examples/ML-DSA-44-expanded.priv}
~~~

~~~
{::include ./examples/ML-DSA-44-expanded.priv.txt}
~~~

#### Both Format
~~~
{::include ./examples/ML-DSA-44-both.priv}
~~~

~~~
{::include ./examples/ML-DSA-44-both.priv.txt}
~~~

### ML-DSA-65 Private Key Examples

Each of the examples includes the textual encoding {{RFC7468}} followed by
the so-called "pretty print"; the private keys are the same.

#### Seed Format
~~~
{::include ./examples/ML-DSA-65-seed.priv}
~~~

~~~
{::include ./examples/ML-DSA-65-seed.priv.txt}
~~~

#### Expanded Format
~~~
{::include ./examples/ML-DSA-65-expanded.priv}
~~~

~~~
{::include ./examples/ML-DSA-65-expanded.priv.txt}
~~~

#### Both Format
~~~
{::include ./examples/ML-DSA-65-both.priv}
~~~

~~~
{::include ./examples/ML-DSA-65-both.priv.txt}
~~~

### ML-DSA-87 Private Key Examples

Each of the examples includes the textual encoding {{RFC7468}} followed by
the so-called "pretty print"; the private keys are the same.

#### Seed Format
~~~
{::include ./examples/ML-DSA-87-seed.priv}
~~~

~~~
{::include ./examples/ML-DSA-87-seed.priv.txt}
~~~

#### Expanded Format
~~~
{::include ./examples/ML-DSA-87-expanded.priv}
~~~

~~~
{::include ./examples/ML-DSA-87-expanded.priv.txt}
~~~

#### Both Format
~~~
{::include ./examples/ML-DSA-87-both.priv}
~~~

~~~
{::include ./examples/ML-DSA-87-both.priv.txt}
~~~


## Example Public Keys {#example-public}

The following is the ML-DSA-44 public key corresponding to the private
key in the previous section. The textual encoding {{RFC7468}} is
followed by the so-called "pretty print"; the public keys are the same.

~~~
{::include ./examples/ML-DSA-44.pub}
~~~

~~~
{::include ./examples/ML-DSA-44.pub.txt}
~~~

The following is the ML-DSA-65 public key corresponding to the private
key in the previous section.  The textual encoding {{RFC7468}} is
followed by the so-called "pretty print"; the public keys are the same.

~~~
{::include ./examples/ML-DSA-65.pub}
~~~

~~~
{::include ./examples/ML-DSA-65.pub.txt}
~~~

The following is the ML-DSA-87 public key corresponding to the private
key in the previous section.  The textual encoding {{RFC7468}} is
followed by the so-called "pretty print"; the public keys are the same.

~~~
{::include ./examples/ML-DSA-87.pub}
~~~

~~~
{::include ./examples/ML-DSA-87.pub.txt}
~~~


## Example Certificates {#example-certificates}

<aside markdown="block">
The example certificates in this section have key usage bits set to
`digitalSignature`, `keyCertSign`, and `cRLSign` to lessen the number of
examples, i.e., brevity. Certificate Policies (CPs) {{?RFC3647}}
for production CAs should consider whether this combination is
appropriate.
</aside>

The following is a self-signed certificate for the ML-DSA-44 public key in the
previous section. The textual encoding {{RFC7468}} is followed by the
so-called "pretty print"; the certificates are the same.

~~~
{::include ./examples/ML-DSA-44.crt}
~~~

~~~
{::include ./examples/ML-DSA-44.crt.txt}
~~~

The following is a self-signed certificate for the ML-DSA-65 public key in the
previous section. The textual encoding {{RFC7468}} is followed by the
so-called "pretty print"; the certificates are the same.

~~~
{::include ./examples/ML-DSA-65.crt}
~~~

~~~
{::include ./examples/ML-DSA-65.crt.txt}
~~~

The following is a self-signed certificate for the ML-DSA-87 public key in the
previous section. The textual encoding {{RFC7468}} is followed by the
so-called "pretty print"; the certificates are the same.

~~~
{::include ./examples/ML-DSA-87.crt}
~~~

~~~
{::include ./examples/ML-DSA-87.crt.txt}
~~~


## Example Inconsistent Seed and Expanded Private Keys {#example-bad}

<aside markdown="block">
  WARNING: These private keys are purposely bad do not use them in
  production systems.
</aside>

The following examples demonstrate inconsistent seed and expanded private keys.

Three `ML-DSA-44-PrivateKey` examples of inconsistent seed and
expanded private keys follow:

1. The first `ML-DSA-PrivateKey` example includes the `both CHOICE` , i.e., both `seed` and `expandedKey` are included. The `seed` and `expanded` values can be checked for inconsistencies.

2. The second `ML-DSA-PrivateKey` example includes only `expandedKey`.  The public key fails to match the `tr` hash value in the private key.

3. The third `ML-DSA-PrivateKey` example also includes only `expandedKey`. The private `s_1` and `s_2` vectors imply a `t` vector whose private low bits do not match the `t_0` vector portion of the private key (its high bits `t_1` are the primary content of the public key).

The second and third examples would not be detected by implementations
that do not regenerate the public key from the private key, or neglect to
then check consistency of `tr` or `t_0`.

The following is the first example:

~~~
{::include ./examples/bad-ML-DSA-44-1.priv}
~~~

The following is the second example:

~~~
{::include ./examples/bad-ML-DSA-44-2.priv}
~~~

The following is the third example:

~~~
{::include ./examples/bad-ML-DSA-44-3.priv}
~~~


# Pre-hashing (ExternalMu-ML-DSA) {#externalmu}

Some applications require pre-hashing that ease operational
requirements around large or inconsistently-sized payloads.
When signing with pre-hashing, the signature generation
process can be separated into a pre-hash step requiring only the message
and other public information, and a core signature
step which uses the public key.

In the context of ML-DSA, pre-hashing can be performed with
the HashML-DSA algorithm defined in Section 5.4 of {{FIPS204}}.
ML-DSA itself supports a External Mu pre-hashing mode which
externalizes the message pre-hashing originally performed inside
the signing operation. This mode is also laid out in
{{FIPS204-ExternalMuFAQ}}. This document specifies
only the use of ML-DSA's External Mu mode, and not HashML-DSA,
in PKIX for reasons laid out in {{sec-disallow-hash}}.

Implementations of ML-DSA using the External Mu pre-hashing mode requires the following
algorithms, which are modified versions of the algorithms presented in {{FIPS204}}.
The nomenclature used here has been modified from the NIST FAQ {{FIPS204-ExternalMuFAQ}}
for clarity.

Pre-hash operation:

~~~
ComputeMu(pk, M, ctx):

  # Referred to as 'ExternalMu-ML-DSA.Prehash(pk, M, ctx)'
  # in the FIPS 204 FAQ.
  # M is the message, a bit-string
  # mu and ctx are byte-strings.
  # ctx is the context string, which defaults to the empy string.

  mu = H(BytesToBits(H(pk, 64) || IntegerToBytes(0, 1) ||
                IntegerToBytes(|ctx|, 1) || ctx) || M, 64)
  # The functions `BytesToBits` and `IntegerToBytes` are defined in FIPS 204.
  return mu
~~~
{: #fig-externalmu-ml-dsa-external title="ComputeMu prehash operation"}

Sign operations:

~~~
SignMu(sk, mu):

  # Referred to as 'ExternalMu-ML-DSA.Sign(sk, mu)'
  # in the FIPS 204 FAQ.

  if |mu| != 64 then
    return error  # return an error indication if the input mu is not
                  # 64 bytes.
  end if

  rnd = rand(32)  # for the optional deterministic variant,
                  # set rnd to all zeroes
  if rnd = NULL then
    return error  # return an error indication if random bit
                  # generation failed
  end if

  sigma = SignMu_internal(sk, mu, rnd, isExternalMu=true)
  return sigma

ML-DSA.SignMu_internal(sk, M', rnd, isExternalMu=false):
    # mu can be passed as an argument instead of M'
    # defaulting is ExternalMu to false means that
    # this modified version of Sign_internal can be used
    # in place of the original without interfering with
    # functioning of pure ML-DSA mode.
    # ... identical to FIPS 204 Algorithm 7, but with Line 6 replaced with
  6: if (isExternalMu):
       mu = M'
     else:
       mu = H(BytesToBits(tr) || M', 64)
~~~
{: #fig-externalmu-ml-dsa-internal title="The operations for signing mu"}

There is no need to specify an External Mu `Verify()` routine because
this is identical to the original `ML-DSA.Verify()`. This makes External
Mu mode simply an internal optimization of the signer, and
allows an ML-DSA key to sometimes be used with the "one-shot" `Sign()`
API and sometimes the External Mu API without any interoperability concens.

The External Mu mode requires the `ComputeMu` routine to have access to the
hash of the signer's public key which may not be available in some architectures,
or require fetching it. That may allow for mismatches between `tr` and `sk`.
At worst, this will produce a signature which will fail to verify under the
intended public key since a compliant `Verify()` routine will
independently compute `tr` from the public key. That
is not believed to be a security concern since `mu` is never used as-is
within `ML-DSA.Sign_internal()` (Algorithm 7 in {{FIPS204}}). Rather,
it is hashed with values unknown to an attacker on lines 7 and 15.
Thus, a signing oracle exposing `SignMu()` does not leak any bits of the secret
key. The External Mu mode also requires SHAKE256 to be available to the
`ComputeMu` routine.

# Acknowledgments
{:numbered="false"}

The authors wish to thank the following people for their contributions
to this document: Corey Bonnell, Dierdre Connolly, Viktor Dukhovni, Russ Housley,
Alicja Kario, Mike Ounsworth, and Daniel Van Geest.

In addition, we would like to thank those who contributed to the private
key format discussion: Tony Arcieri, Bob Beck, Dmitry Belyavskiy, David
Benjamin, Daniel Bernstein, Uri Blumenthal, Theo Buehler, Stephen Farrell,
Jean-Pierre Fiset, Scott Fluhrer, Alex Gaynor, John Gray, Peter Gutmann,
David Hook, Tim Hudson, Paul Kehrer, John Kemp, Watson Ladd, Adam Langley,
John Mattsson, Damien Miller, Robert Relyea, Michael Richardson,
Markku-Juhani O. Saarinen, Rich Salz, Roland Shoemaker, Sophie Schmieg,
Simo Sorce, Michael St. Johns, Falko Strenzke, Filippo Valsorda, Loganaden
Velvindron, Carl Wallace, and Wei-Jun Wang.
