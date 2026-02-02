package jwetpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/salrashid123/tpmcopy"
	duplicatepb "github.com/salrashid123/tpmcopy/duplicatepb"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	MAX_BUFFER = 128 // maximum bytes to seal/unseal
)

const ()

type ParentType int

// Declare the constants using iota
const (
	UNKNOWN ParentType = iota // 0
	RSAEK                     // 1
	ECCEK                     // 2
	H2                        // 3
	RSASRK                    // 4
	ECCSRK                    // 5
)

type HashScheme int

// Declare the constants using iota
const (
	SHA256 HashScheme = iota // 0
	SHA384                   // 1
	SHA512                   // 2
)

// Base configuration for seal and unseal functions
type TPMConfig struct {
	TPMPath   string             // path to initialize a TPM; seal/unseal and then close
	TPMDevice io.ReadWriteCloser // initialized transport for the TPM; does not close the readwriter

	Ownerpassword []byte // password for the owner
	KeyPassword   []byte // password for the owner

	SessionEncryptionHandle tpm2.TPMHandle // (optional) handle to use for transit encryption
}

// configuration  for sealing data
type EncryptConfig struct {
	TPMConfig
	Name                string
	EncryptingPublicKey crypto.PublicKey
	PcrMap              map[uint][]byte // list of pcr:hexvalues to bind to
	Parent              ParentType      // the parent key type (recommend h2)
	SkipPolicy          bool            // set this to true if no AuthPolicies should be applied to the key
}

type DecryptConfig struct {
	TPMConfig
	Parent      ParentType // the parent key type used during sealing
	AuthSession Session    // a session used for PCR or Password protected keys
	SkipPolicy  bool
}

// encrypts some data to the TPM for import
func Encrypt(secret []byte, val *EncryptConfig) ([]byte, error) {

	if len(secret) > MAX_BUFFER {
		return nil, fmt.Errorf("error max  key size is %d bytes", MAX_BUFFER)
	}

	// first find out what type of public key we're dealing with
	var ekPububFromPEMTemplate tpm2.TPMTPublic

	var pkt duplicatepb.Secret_ParentKeyType
	switch pub := val.EncryptingPublicKey.(type) {
	case *rsa.PublicKey:
		rsaPub, ok := val.EncryptingPublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("  error converting encryptingPublicKey to rsa")
		}
		switch val.Parent {
		case RSAEK:
			ekPububFromPEMTemplate = tpm2.RSAEKTemplate
			pkt = duplicatepb.Secret_EndorsementRSA
		case RSASRK:
			ekPububFromPEMTemplate = tpm2.RSASRKTemplate
			pkt = duplicatepb.Secret_RSASRK
		}
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: rsaPub.N.Bytes(),
			},
		)
	case *ecdsa.PublicKey:
		ecPub, ok := val.EncryptingPublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("  error converting encryptingPublicKey to ecdsa")
		}

		switch val.Parent {
		case H2:
			ekPububFromPEMTemplate = keyfile.ECCSRK_H2_Template
			pkt = duplicatepb.Secret_H2
		case ECCEK:
			ekPububFromPEMTemplate = tpm2.ECCEKTemplate
			pkt = duplicatepb.Secret_EndoresementECC
		case ECCSRK:
			ekPububFromPEMTemplate = tpm2.ECCSRKTemplate
			pkt = duplicatepb.Secret_ECCSRK
		}
		ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: ecPub.X.Bytes(),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: ecPub.Y.Bytes(),
				},
			},
		)
	default:
		return nil, fmt.Errorf("unsupported public key type %v", pub)
	}

	var dupKeyTemplate tpm2.TPMTPublic
	var sens2B tpm2.TPMTSensitive
	var kt duplicatepb.Secret_KeyType

	hsh := tpm2.TPMAlgSHA256
	hh, err := hsh.Hash()
	if err != nil {
		return nil, fmt.Errorf("  error converting hash: %v", err)
	}

	sv := make([]byte, hh.Size())
	io.ReadFull(rand.Reader, sv)
	privHash := crypto.SHA256.New()
	privHash.Write(sv)
	privHash.Write(secret)
	kt = duplicatepb.Secret_KEYEDHASH

	dupKeyTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: hsh, // tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        val.SkipPolicy,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{
				Buffer: privHash.Sum(nil),
			},
		),
	}

	sens2B = tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: sv,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BSensitiveData{Buffer: secret},
		),
	}

	if val.KeyPassword != nil {
		sens2B.AuthValue = tpm2.TPM2BAuth{
			Buffer: val.KeyPassword, // set any userAuth
		}
	}

	wrappb, err := tpmcopy.Duplicate(ekPububFromPEMTemplate, kt, pkt, val.Name, dupKeyTemplate, sens2B, val.PcrMap, val.SkipPolicy)
	if err != nil {
		return nil, fmt.Errorf("error duplicating %v", err)
	}

	tkey, err := protojson.Marshal(&wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap proto Key: %v", err)
	}

	return tkey, nil
}

func Decrypt(import_proto []byte, val *DecryptConfig) ([]byte, error) {

	var sec duplicatepb.Secret
	err := protojson.Unmarshal(import_proto, &sec)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal proto  %v", err)
	}

	if val.TPMConfig.TPMDevice == nil && val.TPMConfig.TPMPath == "" {
		return nil, fmt.Errorf("tpmseal can't set both TPMDevice and TPMPath")
	}

	if val.KeyPassword != nil && !val.SkipPolicy {
		return nil, fmt.Errorf("use a session if a password policy is set during decrypt and skipPolidy==false")
	}

	var rwc io.ReadWriteCloser
	if val.TPMConfig.TPMDevice != nil {
		rwc = val.TPMConfig.TPMDevice
	} else {
		var err error
		rwc, err = openTPM(val.TPMConfig.TPMPath)
		if err != nil {
			return nil, fmt.Errorf("tpmseal can't open TPM [%s]", val.TPMConfig.TPMPath)
		}
		defer rwc.Close()
	}
	rwr := transport.FromReadWriter(rwc)

	var t tpm2.TPMTPublic

	if val.Parent == RSAEK && sec.ParentKeyType == duplicatepb.Secret_EndorsementRSA {
		t = tpm2.RSAEKTemplate
	} else if val.Parent == RSASRK && sec.ParentKeyType == duplicatepb.Secret_RSASRK {
		t = tpm2.RSASRKTemplate
	} else if val.Parent == ECCEK && sec.ParentKeyType == duplicatepb.Secret_EndoresementECC {
		t = tpm2.ECCEKTemplate
	} else if val.Parent == ECCSRK && sec.ParentKeyType == duplicatepb.Secret_ECCSRK {
		t = tpm2.ECCSRKTemplate
	} else if val.Parent == H2 && sec.ParentKeyType == duplicatepb.Secret_H2 {
		t = keyfile.ECCSRK_H2_Template
	} else {
		return nil, fmt.Errorf(" keytype in file [%v] mismatched with command line: [%v]", val.Parent, sec.ParentKeyType)
	}

	var primaryParent tpm2.TPMHandle

	if sec.ParentKeyType == duplicatepb.Secret_H2 {
		primaryParent = tpm2.TPMRHOwner
	} else if sec.ParentKeyType == duplicatepb.Secret_EndorsementRSA || sec.ParentKeyType == duplicatepb.Secret_EndoresementECC {
		primaryParent = tpm2.TPMRHEndorsement
	} else if sec.ParentKeyType == duplicatepb.Secret_RSASRK || sec.ParentKeyType == duplicatepb.Secret_ECCSRK {
		primaryParent = tpm2.TPMRHOwner
	}

	cCreateEK, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: primaryParent,
			Name:   tpm2.HandleName(primaryParent),
			Auth:   tpm2.PasswordAuth(val.Ownerpassword),
		},
		InPublic: tpm2.New2B(t),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("can't create object TPM: %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cCreateEK.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)

	}()

	parentHandle := cCreateEK.ObjectHandle

	tpmKey, err := tpmcopy.Import(&tpmcopy.TPMConfig{
		TPMDevice:               rwc,
		Ownerpw:                 []byte(nil),
		SessionEncryptionHandle: cCreateEK.ObjectHandle}, parentHandle, sec)
	if err != nil {
		return nil, fmt.Errorf("failed to import Key: %v", err)
	}

	// create a new session to load
	load_session, load_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("error loading session %v", err)
	}
	defer load_session_cleanup()

	var khKey *tpm2.LoadResponse
	if val.Parent == RSAEK || val.Parent == ECCEK {
		_, err = tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
				Auth:   tpm2.PasswordAuth([]byte("")),
			},
			PolicySession: load_session.Handle(),
			NonceTPM:      load_session.NonceTPM(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("eror creating policysecret %v", err)
		}

		khKey, err = tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: cCreateEK.ObjectHandle,
				Name:   tpm2.TPM2BName(cCreateEK.Name),
				Auth:   load_session,
			},
			InPublic:  tpmKey.Pubkey,
			InPrivate: tpmKey.Privkey,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error loading key %v", err)
		}
	} else {
		khKey, err = tpm2.Load{
			ParentHandle: tpm2.NamedHandle{
				Handle: cCreateEK.ObjectHandle,
				Name:   tpm2.TPM2BName(cCreateEK.Name),
			},
			InPublic:  tpmKey.Pubkey,
			InPrivate: tpmKey.Privkey,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error loading key %v", err)
		}
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: khKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// construct the policy using the utility in this library

	var cleartext []byte

	if val.SkipPolicy {

		if val.SessionEncryptionHandle == 0 {
			sessionEncryptionRsp, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth(val.Ownerpassword), // << add we're using the default endorsement rsa key for session encryption. if it carries a passphrase, add it here
				},
				InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error creating EK Primary  %v", err)
			}
			defer func() {
				_, _ = tpm2.FlushContext{
					FlushHandle: sessionEncryptionRsp.ObjectHandle,
				}.Execute(rwr)
			}()
			val.SessionEncryptionHandle = sessionEncryptionRsp.ObjectHandle
		}
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: val.SessionEncryptionHandle,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error reading encrypting name %v", err)
		}
		ePubName, err := encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, fmt.Errorf("error getting name %v", err)
		}

		if val.KeyPassword == nil {
			dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(val.SessionEncryptionHandle, *ePubName))
			if err != nil {
				return nil, fmt.Errorf("error creating encrypting session %v", err)
			}
			defer dupselect_cleanup()
			unseaResp, err := tpm2.Unseal{
				ItemHandle: tpm2.NamedHandle{
					Handle: khKey.ObjectHandle,
					Name:   khKey.Name,
				},
			}.Execute(rwr, dupselect_sess)
			if err != nil {
				return nil, fmt.Errorf("error  unsealing %v", err)
			}
			cleartext = unseaResp.OutData.Buffer
		} else {
			unseaResp, err := tpm2.Unseal{
				ItemHandle: tpm2.AuthHandle{
					Handle: khKey.ObjectHandle,
					Name:   khKey.Name,
					Auth:   tpm2.PasswordAuth(val.KeyPassword),
				},
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error  unsealing %v", err)
			}
			cleartext = unseaResp.OutData.Buffer
		}

	} else {
		if val.AuthSession == nil {
			return nil, fmt.Errorf("error if skipPolicy is not set, an Auth policy must be specified")
		} else {
			or_sess, closersess, err := val.AuthSession.GetSession()
			if err != nil {
				return nil, fmt.Errorf("error getting session %v", err)
			}
			defer closersess()
			unseaResp, err := tpm2.Unseal{
				ItemHandle: tpm2.AuthHandle{
					Handle: khKey.ObjectHandle,
					Name:   khKey.Name,
					Auth:   or_sess,
				},
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("error unsealing %v", err)
			}
			cleartext = unseaResp.OutData.Buffer
		}

	}
	return cleartext, nil
}
