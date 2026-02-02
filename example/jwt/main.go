package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"slices"

	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpmsigner"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const ()

var (
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")
	in               = flag.String("in", "/tmp/private.pem", "privateKey File")
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

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", *tpmPath, err)
		return 1
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Printf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	c, err := os.ReadFile(*in)
	if err != nil {
		fmt.Printf("error reading private keyfile: %v", err)
		return 1
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		fmt.Printf("failed decoding key: %v", err)
		return 1
	}

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(key.Parent),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		fmt.Printf(" can't create primary: %v", err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	//fmt.Printf("primaryKey Name %s\n", base64.StdEncoding.EncodeToString(primaryKey.Name.Buffer))

	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't load rsa key: %v", err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()
	store := make(map[jwa.KeyAlgorithm]any)

	signingKey, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice: rwc,
		Handle:    tpm2.TPMHandle(regenRSAKey.ObjectHandle),
	})

	store[jwa.RS256()] = signingKey.Public()

	token := jwt.New()
	token.Set(`foo`, `bar`)

	serialized, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
	if err != nil {
		fmt.Printf(`failed to sign JWT: %s`, err)
		return 1
	}

	tok, err := jwt.Parse(serialized, jwt.WithKeyProvider(jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
		alg, ok := sig.ProtectedHeaders().Algorithm()
		if !ok {
			return nil
		}
		key, ok := store[alg]
		if !ok {
			// nothing found
			return nil
		}
		sink.Key(alg, key)
		return nil
	})))
	if err != nil {
		fmt.Printf(`failed to parse JWT: %s`, err)
		return 1
	}

	err = jwt.Validate(tok)
	if err != nil {
		fmt.Printf(`failed to validate JWT: %s`, err)
		return 1
	}

	fmt.Printf("%s\n", serialized)

	return 0
}
