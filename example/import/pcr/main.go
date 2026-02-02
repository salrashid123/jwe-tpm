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
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"

	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwetpm "github.com/salrashid123/jwe-tpm"
)

const ()

var (
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	tpmPublicKeyFile = flag.String("tpmPublicKeyFile", "/tmp/pub.pem", "File to write the public key to (default ekPubB.pem)")
	keyName          = flag.String("keyName", "mykey", "User defined description of the key to export")
	pcrValues        = flag.String("pcrValues", "", "PCR Bound value (increasing order, comma separated)")
	parentKeyType    = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2 (default rsa_ek)")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	flag.Parse()

	payload := []byte("Lorem Ipsum")

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

	pcrMap := make(map[uint][]byte)
	for _, v := range strings.Split(*pcrValues, ",") {
		entry := strings.Split(v, ":")
		if len(entry) == 2 {
			uv, err := strconv.ParseUint(entry[0], 10, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, " PCR key:value is invalid in parsing %s", v)
				return 1
			}
			hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
			if err != nil {
				fmt.Fprintf(os.Stderr, " PCR key:value is invalid in encoding %s", v)
				return 1
			}
			pcrMap[uint(uv)] = hexEncodedPCR
		}
	}

	// note: you don't need a TPM to encrypt
	encrypted, err := jwetpm.Encrypt(ekey, &jwetpm.EncryptConfig{
		TPMConfig:           jwetpm.TPMConfig{},
		Name:                *keyName,
		PcrMap:              pcrMap,
		EncryptingPublicKey: pubKey,
		Parent:              ptype,
		SkipPolicy:          false,
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

	fmt.Println(prettyJSON.String())

	// ***************************

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", *tpmPath, err)
		return 1
	}
	defer rwc.Close()

	rwr := transport.FromReadWriter(rwc)

	// note, its the rsaek we're using here
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	tc, err := jwetpm.NewPCRAndDuplicateSelectSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(23)),
		},
	}, tpm2.TPM2BDigest{}, nil, primaryKey.Name, primaryKey.ObjectHandle)

	decryptedKey, err := jwetpm.Decrypt(encrypted, &jwetpm.DecryptConfig{
		TPMConfig: jwetpm.TPMConfig{
			//TPMPath:     *tpmPath, // <<< you need a tpm to decrypt, ofcourse
			TPMDevice: rwc,
		},
		Parent:      ptype,
		SkipPolicy:  false,
		AuthSession: tc,
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
