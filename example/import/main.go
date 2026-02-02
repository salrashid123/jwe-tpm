package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"

	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwetpm "github.com/salrashid123/jwe-tpm"
)

const ()

var (
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	tpmPublicKeyFile = flag.String("tpmPublicKeyFile", "/tmp/ekpubB.pem", "File to write the public key to (default ekPubB.pem)")

	skipPolicy = flag.Bool("skipPolicy", false, "Skip binding the duplicated key to any policy")

	keyName = flag.String("keyName", "", "User defined description of the key to export")

	password = flag.String("password", "", "Password for the created key")
)

func main() {
	os.Exit(run())
}

func run() int {
	flag.Parse()

	payload := []byte("Lorem Ipsum")

	ekey := make([]byte, 32)
	if _, err := rand.Read(ekey); err != nil {
		panic(err)
	}
	fmt.Printf("root encryption key: %s\n", hex.EncodeToString((ekey)))

	ep, err := os.ReadFile(*tpmPublicKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return 1
	}

	block, _ := pem.Decode(ep)
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}

	pubKey, ok := parsedKey.(crypto.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key to crypto.PublicKey : %v", err)
		return 1
	}
	encrypted, err := jwetpm.Encrypt(ekey, &jwetpm.EncryptConfig{
		TPMConfig: jwetpm.TPMConfig{
			TPMPath:     *tpmPath,
			KeyPassword: []byte(*password),
		},
		Name:                *keyName,
		EncryptingPublicKey: pubKey,
		Parent:              jwetpm.RSAEK,
		SkipPolicy:          *skipPolicy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}

	h := jwe.NewHeaders()
	h.Set("tpm_import_key", encrypted)

	fromRawKey, err := jwk.Import(ekey)
	if err != nil {
		log.Fatalf("failed to acquire raw key from jwk.Key: %s", err)
	}
	jweencrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.A128KW(), fromRawKey, jwe.WithPerRecipientHeaders(h)))
	if err != nil {
		panic(err)
	}

	jm, err := jwe.Parse(jweencrypted)
	if err != nil {
		panic(err)
	}
	b, err := jm.MarshalJSON()
	if err != nil {
		panic(err)
	}
	var prettyJSON bytes.Buffer

	err = json.Indent(&prettyJSON, b, "", "  ")
	if err != nil {
		log.Fatalf("indent error: %s", err)
	}

	fmt.Println(prettyJSON.String())

	// ***************************

	decryptedKey, err := jwetpm.Decrypt(encrypted, &jwetpm.DecryptConfig{
		TPMConfig: jwetpm.TPMConfig{
			TPMPath:     *tpmPath,
			KeyPassword: []byte(*password),
		},
		Parent:     jwetpm.RSAEK,
		SkipPolicy: *skipPolicy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}

	fmt.Printf("decrypted root key: %s\n", hex.EncodeToString(decryptedKey))

	rRawKey, err := jwk.Import(decryptedKey)
	if err != nil {
		log.Fatalf("failed to acquire raw key from jwk.Key: %s", err)
	}

	d, err := jwe.Decrypt(jweencrypted, jwe.WithKey(jwa.A128KW(), rRawKey))
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted %s\n", string(d))
	return 0
}
