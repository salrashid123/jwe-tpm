package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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
	tpmPublicKeyFile = flag.String("tpmPublicKeyFile", "/tmp/pub.pem", "File to write the public key to (default ekPubB.pem)")
	parentKeyType    = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2 (default rsa_ek)")
	keyName          = flag.String("keyName", "mykey", "User defined description of the key to export")
	password         = flag.String("password", "", "Password for the created key")
)

func main() {
	os.Exit(run())
}

func run() int {
	flag.Parse()

	payload := []byte("Lorem Ipsum")

	// first crate a random aes256 key to encrypt the content
	//   this is the key we're going to place inside the TPM proctected import/duplicate data
	rootEncryptionKey := make([]byte, 32)
	if _, err := rand.Read(rootEncryptionKey); err != nil {
		panic(err)
	}
	fmt.Printf("root encryption key: %s\n", hex.EncodeToString((rootEncryptionKey)))

	// read the public key of the target TPM
	encryptinPublicKey, err := os.ReadFile(*tpmPublicKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, " error reading tpmPublicKeyFile : %v", err)
		return 1
	}

	block, _ := pem.Decode(encryptinPublicKey)
	parsedEncryptingPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}

	pubKey, ok := parsedEncryptingPublicKey.(crypto.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key to crypto.PublicKey : %v", err)
		return 1
	}

	var ptype jwetpm.ParentType
	switch *parentKeyType {
	case "rsa_ek":
		ptype = jwetpm.RSAEK
	case "ecc_ek":
		ptype = jwetpm.ECCEK
	case "h2":
		ptype = jwetpm.H2
	default:
		fmt.Fprintf(os.Stderr, "unsupported --keyType must be either rsa or ecc or h2, got %s", *parentKeyType)
		return 1
	}

	// note: you don't need a TPM to encrypt
	encrypted, err := jwetpm.Encrypt(rootEncryptionKey, &jwetpm.EncryptConfig{
		TPMConfig: jwetpm.TPMConfig{
			KeyPassword: []byte(*password),
		},
		Name:                *keyName,
		EncryptingPublicKey: pubKey,
		Parent:              ptype,
		SkipPolicy:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}

	h := jwe.NewHeaders()
	h.Set("tpm_import_key", encrypted)
	h.Set("tpm_import_parent", *parentKeyType)

	fromRawKey, err := jwk.Import(rootEncryptionKey)
	if err != nil {
		log.Fatalf("failed to acquire raw key from jwk.Key: %s", err)
	}
	jweencrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), fromRawKey, jwe.WithPerRecipientHeaders(h)), jwe.WithContentEncryption(jwa.A256GCM()))
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

	json.NewEncoder(os.Stdout).Encode(jm.ProtectedHeaders())

	fmt.Println(prettyJSON.String())

	// ***************************

	// for each recipient in the payload
	//  (currently only one is supproted)
	var duplicated_key_byte []byte
	var parent_type jwetpm.ParentType
	for _, r := range jm.Recipients() {

		// read the headers and extract the sealed key and parent type
		h := r.Headers()
		var tkey string
		err := h.Get("tpm_import_key", &tkey)
		if err != nil {
			fmt.Printf("error getting tpm_import_key header  %v\n", err)
			return 1
		}

		// decode
		duplicated_key_byte, err = base64.StdEncoding.DecodeString(tkey)
		if err != nil {
			fmt.Printf("error decoding key %v\n", err)
			return 1
		}
		var pt string
		err = h.Get("tpm_import_parent", &pt)
		if err != nil {
			fmt.Printf("Error getting tpm_import_parent header  %v\n", err)
			return 1
		}
		switch pt {
		case "h2":
			parent_type = jwetpm.H2
		case "rsa_ek":
			parent_type = jwetpm.RSAEK
		case "ecc_ek":
			parent_type = jwetpm.ECCEK
		case "rsa_srk":
			parent_type = jwetpm.RSASRK
		case "ecc_srk":
			parent_type = jwetpm.ECCSRK
		default:
			fmt.Printf("unknown parent key type  %v\n", pt)
			return 1
		}
	}

	decryptedKey, err := jwetpm.Decrypt(duplicated_key_byte, &jwetpm.DecryptConfig{
		TPMConfig: jwetpm.TPMConfig{
			TPMPath:     *tpmPath, // <<< you need a tpm to decrypt, ofcourse
			KeyPassword: []byte(*password),
		},
		SkipPolicy: true,
		Parent:     parent_type,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}

	///

	fmt.Printf("decrypted root key: %s\n", hex.EncodeToString(decryptedKey))

	rRawKey, err := jwk.Import(decryptedKey)
	if err != nil {
		log.Fatalf("failed to acquire raw key from jwk.Key: %s", err)
	}

	d, err := jwe.Decrypt(jweencrypted, jwe.WithKey(jwa.DIRECT(), rRawKey))
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted %s\n", string(d))
	return 0
}
