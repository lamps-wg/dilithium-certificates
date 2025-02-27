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
        PrivateKey []byte // OCTET STRING wrapper
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
            return asn1.Marshal(expandedKey)
        case "both":
            sequence := struct {
                Seed        []byte
                ExpandedKey []byte
            }{
                Seed:        seed,
                ExpandedKey: expandedKey,
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

        // Generate all three formats
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
