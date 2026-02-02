package jwetpm

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

const (
	swTPMPath = "127.0.0.1:2321"
)

var ()

const ()

func TestRSAEKPassword(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKB.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubB, err := pubEKB.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetailB, err := outPubB.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUniqueB, err := outPubB.Unique.RSA()
	require.NoError(t, err)

	rsaPubB, err := tpm2.RSAPub(rsaDetailB, rsaUniqueB)
	require.NoError(t, err)

	rB, err := x509.MarshalPKIXPublicKey(rsaPubB)
	require.NoError(t, err)
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	tempDirB := t.TempDir()
	filePathB := filepath.Join(tempDirB, "ekpub.pem")
	err = os.WriteFile(filePathB, pemdataB, 0644)
	require.NoError(t, err)

	ekey := []byte("somesecret")
	password := "somepassword"

	encrypted, err := Encrypt(ekey, &EncryptConfig{
		TPMConfig: TPMConfig{
			KeyPassword: []byte(password),
		},

		EncryptingPublicKey: rsaPubB,
		Parent:              RSAEK,
		SkipPolicy:          false,
	})

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: createEKB.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwrB)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwrB)

	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	tc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), primaryKey.Name, primaryKey.ObjectHandle)
	require.NoError(t, err)

	decryptedKey, err := Decrypt(encrypted, &DecryptConfig{
		TPMConfig: TPMConfig{
			//TPMPath:     *tpmPath, // <<< you need a tpm to decrypt, ofcourse
			TPMDevice: tpmDeviceB,
		},
		Parent:      RSAEK,
		SkipPolicy:  false,
		AuthSession: tc,
	})
	require.NoError(t, err)

	require.Equal(t, ekey, decryptedKey)

}

func TestECCEKPassword(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKB.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubB, err := pubEKB.OutPublic.Contents()
	require.NoError(t, err)

	ecDetail, err := outPubB.Parameters.ECCDetail()
	require.NoError(t, err)

	crv, err := ecDetail.CurveID.Curve()
	require.NoError(t, err)

	eccUnique, err := outPubB.Unique.ECC()
	require.NoError(t, err)

	epub := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	rB, err := x509.MarshalPKIXPublicKey(epub)
	require.NoError(t, err)
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	tempDirB := t.TempDir()
	filePathB := filepath.Join(tempDirB, "ekpub.pem")
	err = os.WriteFile(filePathB, pemdataB, 0644)
	require.NoError(t, err)

	ekey := []byte("somesecret")
	password := "somepassword"

	encrypted, err := Encrypt(ekey, &EncryptConfig{
		TPMConfig: TPMConfig{
			KeyPassword: []byte(password),
		},

		EncryptingPublicKey: epub,
		Parent:              ECCEK,
		SkipPolicy:          false,
	})

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: createEKB.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwrB)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(rwrB)

	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	tc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), primaryKey.Name, primaryKey.ObjectHandle)
	require.NoError(t, err)

	decryptedKey, err := Decrypt(encrypted, &DecryptConfig{
		TPMConfig: TPMConfig{
			//TPMPath:     *tpmPath, // <<< you need a tpm to decrypt, ofcourse
			TPMDevice: tpmDeviceB,
		},
		Parent:      ECCEK,
		SkipPolicy:  false,
		AuthSession: tc,
	})
	require.NoError(t, err)

	require.Equal(t, ekey, decryptedKey)

}

func TestRSASRKPassword(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKB.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubB, err := pubEKB.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetailB, err := outPubB.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUniqueB, err := outPubB.Unique.RSA()
	require.NoError(t, err)

	rsaPubB, err := tpm2.RSAPub(rsaDetailB, rsaUniqueB)
	require.NoError(t, err)

	rB, err := x509.MarshalPKIXPublicKey(rsaPubB)
	require.NoError(t, err)
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	tempDirB := t.TempDir()
	filePathB := filepath.Join(tempDirB, "ekpub.pem")
	err = os.WriteFile(filePathB, pemdataB, 0644)
	require.NoError(t, err)

	ekey := []byte("somesecret")
	password := "somepassword"

	encrypted, err := Encrypt(ekey, &EncryptConfig{
		TPMConfig: TPMConfig{
			KeyPassword: []byte(password),
		},

		EncryptingPublicKey: rsaPubB,
		Parent:              RSASRK,
		SkipPolicy:          false,
	})

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: createEKB.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwrB)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwrB)

	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	tc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), primaryKey.Name, primaryKey.ObjectHandle)
	require.NoError(t, err)

	decryptedKey, err := Decrypt(encrypted, &DecryptConfig{
		TPMConfig: TPMConfig{
			//TPMPath:     *tpmPath, // <<< you need a tpm to decrypt, ofcourse
			TPMDevice: tpmDeviceB,
		},
		Parent:      RSASRK,
		SkipPolicy:  false,
		AuthSession: tc,
	})
	require.NoError(t, err)

	require.Equal(t, ekey, decryptedKey)
}

func TestSkipPolicy(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKB.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubB, err := pubEKB.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetailB, err := outPubB.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUniqueB, err := outPubB.Unique.RSA()
	require.NoError(t, err)

	rsaPubB, err := tpm2.RSAPub(rsaDetailB, rsaUniqueB)
	require.NoError(t, err)

	rB, err := x509.MarshalPKIXPublicKey(rsaPubB)
	require.NoError(t, err)
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	tempDirB := t.TempDir()
	filePathB := filepath.Join(tempDirB, "ekpub.pem")
	err = os.WriteFile(filePathB, pemdataB, 0644)
	require.NoError(t, err)

	ekey := []byte("somesecret")

	encrypted, err := Encrypt(ekey, &EncryptConfig{
		TPMConfig: TPMConfig{},

		EncryptingPublicKey: rsaPubB,
		Parent:              RSAEK,
		SkipPolicy:          true,
	})

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: createEKB.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwrB)

	decryptedKey, err := Decrypt(encrypted, &DecryptConfig{
		TPMConfig: TPMConfig{
			//TPMPath:     *tpmPath, // <<< you need a tpm to decrypt, ofcourse
			TPMDevice: tpmDeviceB,
		},
		Parent:     RSAEK,
		SkipPolicy: true,
	})
	require.NoError(t, err)

	require.Equal(t, ekey, decryptedKey)

}

func TestH2Password(t *testing.T) {

	tpmDeviceB, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDeviceB.Close()

	rwrB := transport.FromReadWriter(tpmDeviceB)

	createEKB, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwrB)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKB.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	pubEKB, err := tpm2.ReadPublic{
		ObjectHandle: createEKB.ObjectHandle,
	}.Execute(rwrB)
	require.NoError(t, err)

	outPubB, err := pubEKB.OutPublic.Contents()
	require.NoError(t, err)

	ecDetail, err := outPubB.Parameters.ECCDetail()
	require.NoError(t, err)

	crv, err := ecDetail.CurveID.Curve()
	require.NoError(t, err)

	eccUnique, err := outPubB.Unique.ECC()
	require.NoError(t, err)

	epub := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	rB, err := x509.MarshalPKIXPublicKey(epub)
	require.NoError(t, err)
	pemdataB := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rB,
		},
	)

	tempDirB := t.TempDir()
	filePathB := filepath.Join(tempDirB, "ekpub.pem")
	err = os.WriteFile(filePathB, pemdataB, 0644)
	require.NoError(t, err)

	ekey := []byte("somesecret")
	password := "somepassword"

	encrypted, err := Encrypt(ekey, &EncryptConfig{
		TPMConfig: TPMConfig{
			KeyPassword: []byte(password),
		},

		EncryptingPublicKey: epub,
		Parent:              H2,
		SkipPolicy:          false,
	})

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: createEKB.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwrB)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwrB)

	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwrB)
	}()

	tc, err := NewPolicyAuthValueAndDuplicateSelectSession(rwrB, []byte(password), primaryKey.Name, primaryKey.ObjectHandle)
	require.NoError(t, err)

	decryptedKey, err := Decrypt(encrypted, &DecryptConfig{
		TPMConfig: TPMConfig{
			//TPMPath:     *tpmPath, // <<< you need a tpm to decrypt, ofcourse
			TPMDevice: tpmDeviceB,
		},
		Parent:      H2,
		SkipPolicy:  false,
		AuthSession: tc,
	})
	require.NoError(t, err)

	require.Equal(t, ekey, decryptedKey)

}
