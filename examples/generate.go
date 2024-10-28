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

func example(name string) {
	scheme := schemes.ByName(name)
	var seed [32]byte // 000102…1e1f

	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}

	pk, _ := scheme.DeriveKey(seed[:])
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

	ask := mldsaPrivateKey{
		Version:    0,
		Algorithm:  alg,
		PrivateKey: seed[:],
	}

	papk, err := asn1.Marshal(apk)
	if err != nil {
		panic(err)
	}

	pask, err := asn1.Marshal(ask)
	if err != nil {
		panic(err)
	}

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

	f2, err := os.Create(fmt.Sprintf("%s.priv", name))
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

func main() {
	example("ML-DSA-44")
	example("ML-DSA-65")
	example("ML-DSA-87")
}
