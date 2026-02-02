package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"net"
	"slices"

	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	tpmseal "github.com/salrashid123/tpmseal"
)

const ()

var (
	kf       = flag.String("keyfile", "/tmp/private.pem", "TPM Encrypted private key")
	tpmPath  = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	password = flag.String("password", "mypassword", "password to seal the key to ")
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

	ekey := make([]byte, 32)
	if _, err := rand.Read(ekey); err != nil {
		panic(err)
	}
	fmt.Printf("root encryption key: %s\n", hex.EncodeToString((ekey)))
	tkey, err := tpmseal.Seal(&tpmseal.SealConfig{
		TPMConfig: tpmseal.TPMConfig{
			TPMPath:     *tpmPath,
			KeyPassword: []byte(*password),
		},
		Parent: tpmseal.H2,
		Key:    ekey,
	})
	if err != nil {
		fmt.Printf("error sealing %v\n", err)
		return 1
	}

	h := jwe.NewHeaders()
	h.Set("tpm_sealed_key", tkey)
	h.Set("tpm_sealed_parent", "h2")
	fromRawKey, err := jwk.Import(ekey)
	if err != nil {
		fmt.Printf("failed to acquire raw key from jwk.Key: %s", err)
		return 1
	}
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), fromRawKey, jwe.WithPerRecipientHeaders(h)), jwe.WithContentEncryption(jwa.A256GCM()))
	if err != nil {
		fmt.Printf("Error encrypting %v\n", err)
		return 1
	}

	jm, err := jwe.Parse(encrypted)
	if err != nil {
		fmt.Printf("Error parsing %v\n", err)
		return 1
	}
	b, err := jm.MarshalJSON()
	if err != nil {
		fmt.Printf("error marshalling json %v\n", err)
		return 1
	}
	var prettyJSON bytes.Buffer

	err = json.Indent(&prettyJSON, b, "", "  ")
	if err != nil {
		fmt.Printf("indent error: %s", err)
		return 1
	}

	fmt.Println(prettyJSON.String())

	/// now decrypt

	var sealed_key_byte []byte
	var parent_type tpmseal.ParentType
	for _, r := range jm.Recipients() {
		h := r.Headers()
		var tkey string
		err := h.Get("tpm_sealed_key", &tkey)
		if err != nil {
			fmt.Printf("error getting header  %v\n", err)
			return 1
		}

		sealed_key_byte, err = base64.RawStdEncoding.DecodeString(tkey)
		if err != nil {
			fmt.Printf("error decoding key %v\n", err)
			return 1
		}
		var pt string
		err = h.Get("tpm_sealed_parent", &pt)
		if err != nil {
			fmt.Printf("Error getting header  %v\n", err)
			return 1
		}
		switch pt {
		case "h2":
			parent_type = tpmseal.H2
		case "rsa_ek":
			parent_type = tpmseal.RSAEK
		case "ecc_ek":
			parent_type = tpmseal.ECCEK
		case "rsa_srk":
			parent_type = tpmseal.RSASRK
		case "ecc_srk":
			parent_type = tpmseal.ECCSRK
		default:
			fmt.Printf("unknown parent key type  %v\n", pt)
			return 1
		}

	}

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", *tpmPath, err)
		return 1
	}
	defer func() {
		rwc.Close()
	}()
	rwr := transport.FromReadWriter(rwc)
	s, err := tpmseal.NewPolicyPasswordSession(rwr, []byte(*password), 0)
	if err != nil {
		fmt.Printf("error creating key file %v\n", err)
		return 1
	}
	rkey, err := tpmseal.Unseal(&tpmseal.UnSealConfig{
		TPMConfig: tpmseal.TPMConfig{
			TPMDevice: rwc, // <<<<<<<<<<<<<< note, you have to initialize and pass an actual device refenrece in since you're setting up a policy externally
		},
		Parent:      parent_type,
		Key:         sealed_key_byte,
		AuthSession: s,
	})
	if err != nil {
		fmt.Printf("error sealing %v\n", err)
		return 1
	}
	fmt.Printf("decrypted root key: %s\n", hex.EncodeToString(rkey))

	rRawKey, err := jwk.Import(rkey)
	if err != nil {
		fmt.Printf("failed to acquire raw key from jwk.Key: %s", err)
		return 1
	}

	d, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.DIRECT(), rRawKey))
	if err != nil {
		fmt.Printf("Decrypt error %v\n", err)
		return 1
	}
	fmt.Printf("decrypted %s\n", string(d))

	// ****************

	return 0
}
