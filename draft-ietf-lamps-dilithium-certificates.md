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

{{FIPS204}} defines two variants of ML-DSA: a pure and a prehash variant.
Only the former is specified in this document.
See {{sec-disallow-hash}} for the rationale.
The pure variant of ML-DSA supports the typical prehash flow,
see {{prehash}}. In short: one cryptographic module can compute the hash *mu*
on line 6 of algorithm 7 of {{FIPS204}} and pass it to a second module
to finish the signature. The first module only needs access to the full
message and the public key, whereas the second module only needs access
to hash *mu* and the private key.

Prior to standardisation, ML-DSA was known as Dilithium.  ML-DSA and
Dilithium are not compatible.

## Requirements Language

{::boilerplate bcp14-tagged}


# Identifiers {#oids}

The AlgorithmIdentifier type is defined in {{!RFC5912}} as follows:

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

* algorithm identifies the cryptographic algorithm with an object
identifier.

* parameters, which are optional, are the associated parameters for the
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

The contents of the parameters component for each algorithm MUST be
absent. The ctx value used in the ML-DSA signing and verification
{{FIPS204}} of ML-DSA signatures defined in this specification
(X.509 certificates, CRLs) is the empty string.

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
algorithm identifier in the signatureAlgorithm attribute and a
signatureValue attribute that contains the actual signature.

~~~
   CertificateList  ::=  SIGNED{ TBSCertList }
~~~

The identifiers defined in {{oids}} can be used as the
AlgorithmIdentifier in the signatureAlgorithm field in the sequence
Certificate/CertificateList and the signature field in the sequence
TBSCertificate/TBSCertList in certificates and CRLs, respectively,
{{RFC5280}}. The parameters of these signature algorithms MUST be
absent, as explained in {{oids}}. That is, the AlgorithmIdentifier
SHALL be a SEQUENCE of one component, the OID id-ml-dsa-*.

The signatureValue field contains the corresponding ML-DSA signature
computed upon the ASN.1 DER encoded tbsCertificate/tbsCertList
{{RFC5280}}.

Conforming Certification Authority (CA) implementations MUST specify
the algorithms explicitly by using the OIDs specified in {{oids}} when
encoding ML-DSA signatures in certificates and CRLs. Conforming client
implementations that process certificates and CRLs using ML-DSA MUST
recognize the corresponding OIDs. Encoding rules for ML-DSA signature
values are specified {{oids}}.

# ML-DSA Public Keys in PKIX {#ML-DSA-PubblicKey}

In the X.509 certificate, the subjectPublicKeyInfo field has the
SubjectPublicKeyInfo type, which has the following ASN.1 syntax:

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

The fields in SubjectPublicKeyInfo have the following meaning:

* algorithm is the algorithm identifier and parameters for the
  public key (see above).

* subjectPublicKey contains the byte stream of the public key.

The PUBLIC-KEY ASN.1 types for ML-DSA are defined here:

~~~
  pk-ml-dsa-44 PUBLIC-KEY ::= {
    IDENTIFIER id-ml-dsa-44
    -- KEY no ASN.1 wrapping --
    CERT-KEY-USAGE
      { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
    -- PRIVATE-KEY no ASN.1 wrapping -- }

  pk-ml-dsa-65 PUBLIC-KEY ::= {
    IDENTIFIER id-ml-dsa-65
    -- KEY no ASN.1 wrapping --
    CERT-KEY-USAGE
      { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
    -- PRIVATE-KEY no ASN.1 wrapping -- }

  pk-ml-dsa-87 PUBLIC-KEY ::= {
    IDENTIFIER id-ml-dsa-87
    -- KEY no ASN.1 wrapping --
    CERT-KEY-USAGE
      { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
    -- PRIVATE-KEY no ASN.1 wrapping -- }

  ML-DSA-PublicKey ::= OCTET STRING (SIZE (1312 | 1952 | 2592))

  ML-DSA-PrivateKey ::= OCTET STRING (SIZE (32))
~~~

Algorithm 22 in Section 7.2 of {{FIPS204}} defines the raw byte string
encoding of an ML-DSA public key. When used in a SubjectPublicKeyInfo type,
the subjectPublicKey BIT STRING contains the raw byte string encoding of the
public key.

When an ML-DSA public key appears outside of a SubjectPublicKeyInfo type in an
environment that uses ASN.1 encoding, it can be encoded as an OCTET STRING by
using the ML-DSA-PublicKey type.

{{?RFC5958}} describes the Asymmetric Key Package's OneAsymmetricKey type for
encoding asymmetric keypairs. When an ML-DSA private key or keypair is encoded as
a OneAsymmetricKey, it follows the description in {{priv-key}}.

When the ML-DSA private key appears outside of an Asymmetric Key Package in an
environment that uses ASN.1 encoding, it can be encoded as an OCTET STRING by using
the ML-DSA-PrivateKey type.

{{examples}} contains example ML-DSA public keys encoded using the
textual encoding defined in {{?RFC7468}}.

# Key Usage Bits

The intended application for the key is indicated in the keyUsage
certificate extension; see {{Section 4.2.1.3 of RFC5280}}. If the
keyUsage extension is present in a certificate that indicates id-ml-dsa-*
in the SubjectPublicKeyInfo, then the at least one of following MUST be
present:

~~~
  digitalSignature; or
  nonRepudiation; or
  keyCertSign; or
  cRLSign.
~~~

If the keyUsage extension is present in a certificate that indicates
id-ml-dsa-* in the SubjectPublicKeyInfo, then the following MUST NOT be
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

#  Private Key Format {#priv-key}

An ML-DSA private key is encoded by storing its 32-octet seed in
the privateKey field as follows.

{{FIPS204}} specifies two formats for an ML-DSA private key: a 32-octet
seed (xi) and an (expanded) private key. The expanded private key (and public key)
is computed from the seed using `ML-DSA.KeyGen_internal(xi)` (algorithm 6).

"Asymmetric Key Packages" {{!RFC5958}} describes how to encode a private
key in a structure that both identifies what algorithm the private key
is for and allows for the public key and additional attributes about the
key to be included as well. For illustration, the ASN.1 structure
OneAsymmetricKey is replicated below.

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

When used in a OneAsymmetricKey type, the privateKey OCTET STRING contains
the raw octet string encoding of the 32-octet seed. The publicKey field
SHOULD be omitted because the public key can be computed as noted earlier
in this section.

{{examples}} contains example ML-DSA private keys encoded using the
textual encoding defined in {{RFC7468}}.

# IANA Considerations

For the ASN.1 module in {{asn1}}, IANA is requested to assign an object
identifier (OID) for the module identifier (TBD1) with a Description
of "id-mod-x509-ml-dsa-2024". The OID for the module should be
allocated in the "SMI Security for PKIX Module Identifier" registry
(1.3.6.1.5.5.7.0).

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
<!--<aside markdown="block">
EDNOTE: Discuss deterministic vs randomized signing and the impact on
security.
</aside>-->

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

<!--<aside markdown="block">
EDNOTE: Discuss side-channels for ML-DSA.
</aside>-->


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

## Rationale for disallowing HashML-DSA {#sec-disallow-hash}

The HashML-DSA mode defined in Section 5.4 of {{FIPS204}} MUST NOT be
used; in other words, public keys identified by
`id-hash-ml-dsa-44-with-sha512`, `id-hash-ml-dsa-65-with-sha512`, and
`id-hash-ml-dsa-87-with-sha512` MUST NOT be in X.509 certificates used for
CRLs, OCSP, certificate issuance and related PKIX protocols (e.g. TLS).
The use of HashML-DSA public keys within end entity certificates is not
prohibited, but conventions for doing so are outside the scope of this
document.

This restriction is for both implementation and security reasons.

The implementation reason for disallowing HashML-DSA stems from the fact
that ML-DSA and HashML-DSA are incompatible algorithms that require
different `Verify()` routines. This forwards to the protocol the
complexity of informing the client whether to use `ML-DSA.Verify()` or
`HashML-DSA.Verify()` along with the hash algorithm to use. Additionally, since
the same OIDs are used to identify the ML-DSA
public keys and ML-DSA signature algorithms, an implementation would
need to commit a given public key to be either of type `ML-DSA` or
`HashML-DSA` at the time of certificate creation. This is anticipated
to cause operational issues in contexts where the operator does not
know at key generation time whether the key will need to produce pure
or pre-hashed signatures. ExternalMu-ML-DSA avoids all of these
operational concerns by virtue of having keys and signatures that are
indistinguishable from ML-DSA (i.e., ML-DSA and ExternalMu-ML-DSA are
mathematically equivalent algorithms). The difference between ML-DSA
and ExternalMu-ML-DSA is merely an internal implementation detail of
the signer and has no impact on the verifier or network protocol.

The security reason for disallowing HashML-DSA is that the design of the
ML-DSA algorithm provides enhanced resistance against signature
collision attacks, compared with conventional RSA or ECDSA signature
algorithms. Specifically, ML-DSA binds the hash of the public key `tr`
to the message to-be-signed prior to hashing, as described in line 6 of
Algorithm 7 of {{FIPS204}}. In practice, this provides binding to the
indended verification public key, preventing some attacks that would
otherwise allow a signature to be successfully verified against a
non-intended public key. Also, this unlikely, theoretical binding means that in the unlikely
discovery of a collision attack against SHA-3, an attacker would
have to perform a public-key-specific collision search in order to find
message pairs such that `H(tr || m1) = H(tr || m2)` since a direct hash
collision `H(m1) = H(m2)` will not suffice. HashML-DSA removes both of
these enhanced security properties.

--- back

# ASN.1 Module {#asn1}

This appendix includes the ASN.1 module {{X680}} for the ML-DSA.  Note that
as per {{RFC5280}}, certificates use the Distinguished Encoding Rules; see
{{X690}}. This module imports objects from {{RFC5912}}.

~~~
<CODE BEGINS>
{::include X509-ML-DSA-2024.asn}
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
Note that these are the sizes of
    the plain private and public keys; and
    not the sizes of the resultant OneAsymmetricKey and SubjectPublicKeyInfo
        objects in which they are wrapped.

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

# Examples {#examples}

This appendix contains examples of ML-DSA public keys, private keys and certificates.

## Example Private Key {#example-private}

The following is an example of a ML-DSA-44 private key with hex seed `000102…1e1f`:

~~~
{::include ./examples/ML-DSA-44.priv}
~~~

~~~
{::include ./examples/ML-DSA-44.priv.txt}
~~~

The following is an example of a ML-DSA-65 private key with hex seed `000102…1e1f`:

~~~
{::include ./examples/ML-DSA-65.priv}
~~~

~~~
{::include ./examples/ML-DSA-65.priv.txt}
~~~

The following is an example of a ML-DSA-87 private key with hex seed `000102…1e1f`:

~~~
{::include ./examples/ML-DSA-87.priv}
~~~

~~~
{::include ./examples/ML-DSA-87.priv.txt}
~~~

NOTE: The private key is the seed and all three examples keys use the
same seed; therefore, the private above are the same except for the OID
used to represent the ML-DSA algorithm's security strength.

## Example Public Key {#example-public}

The following is the ML-DSA-44 public key corresponding to the private
key in the previous section.

~~~
{::include ./examples/ML-DSA-44.pub}
~~~

~~~
{::include ./examples/ML-DSA-44.pub.txt}
~~~

The following is the ML-DSA-65 public key corresponding to the private
key in the previous section.

~~~
{::include ./examples/ML-DSA-65.pub}
~~~

~~~
{::include ./examples/ML-DSA-65.pub.txt}
~~~

The following is the ML-DSA-87 public key corresponding to the private
key in the previous section.

~~~
{::include ./examples/ML-DSA-87.pub}
~~~

~~~
{::include ./examples/ML-DSA-87.pub.txt}
~~~


## Example Certificate {#example-certificate}

The following is a self-signed certificate for the ML-DSA-44 public key in the
previous section.

~~~
{::include ./examples/ML-DSA-44.crt}
~~~

~~~
{::include ./examples/ML-DSA-44.crt.txt}
~~~

# Pre-hashing (ExternalMu-ML-DSA) {#prehash}

Some applications require pre-hashing, where the signature generation
process can be separated into a pre-hash step and a core signature
step in order to ease operational requirements around large or
inconsistently-sized payloads. Pre-hashing can be performed at the
protocol layer, but not all protocols support it. Examples in
{{RFC5280}} are certificates and CRLs; these do not include message
digesting before signing. This can make signing large CRLs or a high
volume of certificates with large public keys challenging.

As mentioned in the introduction, pure ML-DSA signing itself
supports a pre-hashing flow by splitting the operation over two
modules. In this section, we make this "ExternalMu-ML-DSA"
more explicit.

There are two steps. First an `ExternalMu-ML-DSA.Prehash()`
followed by `ExternalMu-ML-DSA.Sign()`. Together these are functionally
equivalent to `ML-DSA.Sign()` from {{FIPS204}} in that used in sequence
they create exactly the same signatures as regular pure ML-DSA, which
can be verified by the unmodified `ML-DSA.Verify()`.

An ML-DSA key and certificate can be used with either ML-DSA
or ExternalMu-ML-DSA interchangeably.
Note that ExternalMu-ML-DSA describes a different signature API from ML-DSA
and therefore might require explicit support from hardware or
software cryptographic modules.

Note that the signing mode defined here is different from HashML-DSA
defined in Section 5.4 of {{FIPS204}}. This specification uses exclusively
ExternalMu-ML-DSA for pre-hashed use cases. See {{sec-disallow-hash}} for
additional discussion of why HashML-DSA is disallowed in PKIX.

All functions and notation used in {{fig-externalmu-ml-dsa-external}}
and {{fig-externalmu-ml-dsa-internal}} are defined in {{FIPS204}}.

External operations:

~~~
ExternalMu-ML-DSA.Prehash(pk, M, ctx):

  if |ctx| > 255 then
    return error  # return an error indication if the context string is
                  # too long
  end if

  M' = BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|ctx|, 1)
                                                        || ctx) || M
  mu = H(BytesToBits(H(pk, 64)) || M', 64)
  return mu
~~~
{: #fig-externalmu-ml-dsa-external title="External steps of ExternalMu-ML-DSA"}

Internal operations:

~~~
ExternalMu-ML-DSA.Sign(sk, mu):

  if |mu| != 512 then
    return error  # return an error indication if the input mu is not
                  # 64 bytes (512 bits).
  end if

  rnd = rand(32)  # for the optional deterministic variant,
                  # set rnd to all zeroes
  if rnd = NULL then
    return error  # return an error indication if random bit
                  # generation failed
  end if

  sigma = ExternalMu-ML-DSA.Sign_internal(sk, mu, rnd)
  return sigma

ExternalMu-ML-DSA.Sign_internal(sk, mu, rnd): # mu is passed as argument instead of M'
   ... identical to FIPS 204 Algorithm 7, but with Line 6 removed.
~~~
{: #fig-externalmu-ml-dsa-internal title="Internal steps of ExternalMu-ML-DSA"}

ExternalMu-ML-DSA requires the public key, or its prehash, as input to
the pre-digesting function. This assumes the signer generating the
pre-hash is in possession of the public key before signing and is
different from conventional pre-hashing which only requires the
message and the hash function as input.

Security-wise, during the signing operation of pure (or "one-step")
ML-DSA, the cryptographic module extracts the public key hash `tr` from
the secret key object, and thus there is no possibility of mismatch
between `tr` and `sk`. In ExternalMu-ML-DSA, the public key or its hash
needs to be provided to the `Prehash()` routine indpedendly of the secret
key, and while the exact mechanism by which it is delivered will be
implementation-specific, it does open a windown for mismatches between
`tr` and `sk`. First, this will produce a signature which will fail to
verify under the intended public key since a compliant `Verify()` routine
will independently compute `tr` from the public key. Implementors should pay careful
attention to how the public key or its hash is delivered to the
`ExternalMu-ML-DSA.Prehash()` routine, and from where they are sourcing
this data.

# Acknowledgments
{:numbered="false"}

We would like to thank ... <!--Markuu, Peikert -->for their
insightful comments.
