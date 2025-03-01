//go:generate go run generate.go
package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/schemes"
)

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type mldsaPrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func generatePrivateKeyBytes(format string, seed []byte, expandedKey []byte) ([]byte, error) {
		switch format {
			case "seed":
				// Create [0] OCTET STRING structure
				seedValue := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:       0,
					Bytes:     seed,
					IsCompound: false,
				}
				return asn1.Marshal(seedValue)
			case "expanded":
				// Create nested OCTET STRING structure
				innerOctetString := asn1.RawValue{
                    Class:      asn1.ClassUniversal,
                    Tag:       asn1.TagOctetString,
                    Bytes:     expandedKey,
                    IsCompound: false,
				}
				innerBytes, err := asn1.Marshal(innerOctetString)
				if err != nil {
                    return nil, err
				}
				// Wrap in outer OCTET STRING
				outerOctetString := asn1.RawValue{
					Class:      asn1.ClassUniversal,
					Tag:       asn1.TagOctetString,
					Bytes:     innerBytes,
					IsCompound: true,
				}
				return asn1.Marshal(outerOctetString)
			case "both":
				// Create [0] OCTET STRING for seed
				seedValue := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:       0,
					Bytes:     seed,
					IsCompound: false,
				}

				// Create nested OCTET STRING for expanded key
				innerOctetString := asn1.RawValue{
					Class:      asn1.ClassUniversal,
					Tag:       asn1.TagOctetString,
					Bytes:     expandedKey,
					IsCompound: false,
				}
				innerBytes, err := asn1.Marshal(innerOctetString)
				if err != nil {
					return nil, err
				}
				outerOctetString := asn1.RawValue{
					Class:      asn1.ClassUniversal,
					Tag:       asn1.TagOctetString,
					Bytes:     innerBytes,
					IsCompound: true,
				}

				// Create sequence containing both
				sequence := struct {
					Seed        asn1.RawValue
					ExpandedKey asn1.RawValue
				}{
					Seed:        seedValue,
					ExpandedKey: outerOctetString,
				}
				return asn1.Marshal(sequence)
			}
		return nil, fmt.Errorf("unknown format")
}

func generatePrivateKey(format string, alg pkix.AlgorithmIdentifier, seed []byte, expandedKey []byte) (mldsaPrivateKey, error) {
		ask := mldsaPrivateKey{
			Version:   0,
			Algorithm: alg,
        }

        // Generate the inner CHOICE structure
        innerBytes, err := generatePrivateKeyBytes(format, seed, expandedKey)
        if err != nil {
            return ask, err
        }

        // Set as the private key bytes
        ask.PrivateKey = innerBytes
        return ask, nil
}

func example(name string) {
	scheme := schemes.ByName(name)
	var seed [32]byte // 000102…1e1f

	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}

	pk, sk := scheme.DeriveKey(seed[:])
	expandedKey, _ := sk.MarshalBinary()
	var oid int
	switch name {
	case "ML-DSA-44":
		oid = 17
	case "ML-DSA-65":
		oid = 18
	case "ML-DSA-87":
		oid = 19
	default:
		panic("unknown algorithm")
	}

	ppk, _ := pk.MarshalBinary()

	// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
	alg := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, oid},
	}

	apk := subjectPublicKeyInfo{
		Algorithm: alg,
		PublicKey: asn1.BitString{
			BitLength: len(ppk) * 8,
			Bytes:     ppk,
		},
	}

	formats := []string{"seed", "expanded", "both"}
	for _, format := range formats {
		ask, err := generatePrivateKey(format, alg, seed[:], expandedKey)
        if err != nil {
            panic(err)
        }

        papk, err := asn1.Marshal(apk)
        if err != nil {
            panic(err)
        }

        pask, err := asn1.Marshal(ask)
        if err != nil {
            panic(err)
        }

        // Write public key
        f, err := os.Create(fmt.Sprintf("%s.pub", name))
        if err != nil {
            panic(err)
        }
        defer f.Close()

        if err = pem.Encode(f, &pem.Block{
            Type:  "PUBLIC KEY",
            Bytes: papk,
        }); err != nil {
            panic(err)
        }

        // Write private key with format indication
        f2, err := os.Create(fmt.Sprintf("%s-%s.priv", name, format))
        if err != nil {
            panic(err)
        }
        defer f2.Close()

        if err = pem.Encode(f2, &pem.Block{
            Type:  "PRIVATE KEY",
            Bytes: pask,
        }); err != nil {
            panic(err)
        }
    }
}

func main() {
	example("ML-DSA-44")
	example("ML-DSA-65")
	example("ML-DSA-87")
}
