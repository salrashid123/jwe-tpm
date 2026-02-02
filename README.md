## Json Web Encryption (JWE) using TPM backed keys

Allows clients to use TPM backed keys for `Json Web Encryption (JWE)`.

There are two modes of operation

- `A)`:  Seal/Unseal:

      Encrypt and Decrypt a JWE using a TPM backed key.  Use this if you are encryptin/decrypting on the same VM/system where the TPM exists. 

- `B)`: Remote Encryption (Duplicate/Import)

      This mode allows you to encrypt data remotely by using a target TPM's `Endorsement Public Key`, `Storage Root Key (SRK)` or with one based off of its `H2 Template`.  You can use the PEM formatted public key to encrypt data such that it can **only** get decrypted by the destination TPM

In both modes, you can specify certain policies around the TPM backed key to do the decryption.  Namely, you can stipulate that access to decrypt the data is gated on the user providing a passphrase or the system having certain `PCR` values

>> note this repo is not supported by google

---

* [Overview](#overview)
* [Options](#options)
* [References](#references)
* [JWE](#jwe)
  - [Seal/Unseal](#sealunseal)  
  - [Duplicate/Import](#duplicateimport)
* [Key Policies](#policies)
  - [SkipPolicy](#skippolicy)
  - [Password](#password)
  - [PCR](#pcr)
* [Key Parent](#key-parent)  
* [JWT](#jwt)
* [Session Encryption](#session-encryption)

---

## Overview

Essentially, you seal an AES encryption key into objects which can only get decrypted by a target system's TPM.

You use the AES key to encrypt the JWE.  In the end, the TPM sealed key encrypts the JWE so to decrypt it, you need access to the TPM.

To make all this work, you need to transmit the TPM encoded key as part of the JWT.   For this, we use a private header as described in [RFC 7516: JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516#page-15)

```
4.3.  Private Header Parameter Names

   A producer and consumer of a JWE may agree to use Header Parameter
   names that are Private Names: names that are not Registered Header
   Parameter names (Section 4.1) or Public Header Parameter names
   (Section 4.2).  Unlike Public Header Parameter names, Private Header
   Parameter names are subject to collision and should be used with
   caution.
```

in our case, the header is transmitted as `tpm_sealed_key` (for seal/unseal) and `tpm_import_key` (for duplicate/import).

---

## References

- [TPM Seal/Unseal with Policy](https://github.com/salrashid123/tpmseal)
- [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)
- [AEAD encryption using Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)
- [tpm2 key utility](https://github.com/salrashid123/tpm2genkey)
- [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)
- [TINK Go TPM extension](https://github.com/salrashid123/tink-go-tpm)

---

## JWE

The examples below cover the two modes.  The seal/unseal is easier since its directly on one machine.  The import/duplicate requires additional steps necessarily.

To use these samples locally, you can install [swtpm](https://github.com/stefanberger/swtpm).  If you want to use a real tpm, just set the path  to the device `-tpm-path="/dev/tpmrm0"`

For now, start a swtpm:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm &&
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert &&
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## in a new window
export TPM2TOOLS_TCTI="swtpm:port=2321"
```

### Seal/Unseal

To seal/unseal, we basically encode ae AES key into a TPM `keyedHash` object and unseal it using password or pcr policies.

![images/jwe_seal.png](images/jwe_seal.png)

Please note that the `seal/unseal` library is _not_ included in this repo but is imported from

* [](https://github.com/salrashid123/tpmsealhttps://github.com/salrashid123/tpmseal)

Anyway, the `example/` folder contains seal/unseal using a password policy as well as a 'skip policy' mode which just transfers the key without any constraints.

As golang, the flow is like this:

- `Encrypt`

```golang
	// the data we want to encrypt
	payload := []byte("Lorem Ipsum")

	// first crate a random aes256 key to encrypt the content
	//   this is the key we're going to place inside the TPM proctected import/duplicate data
	rootEncryptionKey := make([]byte, 32)
	rand.Read(rootEncryptionKey)
	fmt.Printf("root encryption key: %s\n", hex.EncodeToString((rootEncryptionKey)))

	// now seal it with the TPM based key
	tkey, err := tpmseal.Seal(&tpmseal.SealConfig{
		TPMConfig: tpmseal.TPMConfig{
			TPMPath: "/dev/tpmrm0",
		},
		Parent: tpmseal.H2,
		Key:    rootEncryptionKey,
	})

	// add the tpm based key and the parent we used as headers to the JWE
	h := jwe.NewHeaders()
	h.Set("tpm_sealed_key", tkey)
	h.Set("tpm_sealed_parent", "h2")

	// now read the root encryption key
	fromRawKey, err := jwk.Import(rootEncryptionKey)

	// and use that to encrypt as 'dir'
	// remember to add the headers
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), fromRawKey, jwe.WithPerRecipientHeaders(h)), jwe.WithContentEncryption(jwa.A256GCM()))
```

- `Decrypt`

```golang
// read the JWK
	jm, err := jwe.Parse(encrypted)

  // now iterate over the recipients (note: only one is supported currently)
	var sealed_key_byte []byte
	var parent_type tpmseal.ParentType
	for _, r := range jm.Recipients() {

		// read the headers and extract the sealed key and parent type
		h := r.Headers()
		var tkey string
		err := h.Get("tpm_sealed_key", &tkey)

    // decode the sealed key
		sealed_key_byte, err = base64.RawStdEncoding.DecodeString(tkey)

    // decode the paret type
		var pt string
		err = h.Get("tpm_sealed_parent", &pt)
    // you can switch based on the provided header type or just pick one (as shwon below)
		parent_type = tpmseal.H2
	}

	// unseal the data to reacquire the rootKey
	regeneratedRootEncryptionKey, err := tpmseal.Unseal(&tpmseal.UnSealConfig{
		TPMConfig: tpmseal.TPMConfig{
			TPMPath: "/dev/tpmrm0",
		},
		Parent: parent_type,
		Key:    sealed_key_byte,
	})

	fmt.Printf("decrypted root key: %s\n", hex.EncodeToString(regeneratedRootEncryptionKey))

  // register it
	rRawKey, err := jwk.Import(regeneratedRootEncryptionKey)

  // decrypt the payload
	d, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.DIRECT(), rRawKey))

	fmt.Printf("decrypted %s\n", string(d))
```

as an example:

```bash
cd example/seal

$ go run password/main.go --keyfile=/tmp/private.pem --password=bar -tpm-path="127.0.0.1:2321"

    root encryption key: ba4a95ae2f205699df60748fbe7620af01b1b68709f2e4a0918d01a6a5472d25
    {
      "ciphertext": "Yquu4DupCneny-s",
      "header": {
        "alg": "dir",
        "tpm_sealed_key": "LS0tLS1CRUdJTiBUU1MyIFBSSVZBVEUgS0VZLS0tLS0KTUlJQkF3WUdaNEVGQ2dFREFnUkFBQUFCQkZBQVRnQUlBQXNBQUFBU0FDQ1B6U0ZwcTVKcFRneGpQeHEzY29Rcgpna0c3d2dLSW1CL0hyQjdkd2YzYkRnQVFBQ0JRR3RLbTNhb2U5NUhiem9CdDNvTmNUSERSL2V5ZkNxYURvK2YxCjhWY0t3QVNCb0FDZUFDRGY1K0F3R1BXRnpkcmI0RHpIVkxaNnVEMjZ3aWNUMXE5VGNKWnRnckxUVEFBUU5YYTgKRlVHMTJFWXNqZEIreGMxeXlaSnRnVk5EREhTVHA3VXZNRFMrTlduLzc2WHVJN29ZYkpINHZGQVlDM05HMkVRbwphSmw2eFhUR3RCSEdhQmw5amNzU3ZpWkZrczdBTGJwbVhCY0ZuM0pyd00wUEFXelhKNC9yS0dZbDNoc2xYQ1ArCkxZQkxZSk1UVDJ0REN4VjZlYkJVNHJoeFc3RHZHdWM9Ci0tLS0tRU5EIFRTUzIgUFJJVkFURSBLRVktLS0tLQo",
        "tpm_sealed_parent": "h2"
      },
      "iv": "yRlpEw_V6U1gezyf",
      "protected": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidHBtX3NlYWxlZF9rZXkiOiJMUzB0TFMxQ1JVZEpUaUJVVTFNeUlGQlNTVlpCVkVVZ1MwVlpMUzB0TFMwS1RVbEpRa0YzV1VkYU5FVkdRMmRGUkVGblVrRkJRVUZDUWtaQlFWUm5RVWxCUVhOQlFVRkJVMEZEUTFCNlUwWndjVFZLY0ZSbmVHcFFlSEV6WTI5UmNncG5hMGMzZDJkTFNXMUNMMGh5UWpka2QyWXpZa1JuUVZGQlEwSlJSM1JMYlROaGIyVTVOVWhpZW05Q2RETnZUbU5VU0VSU0wyVjVaa054WVVSdksyWXhDamhXWTB0M1FWTkNiMEZEWlVGRFJHWTFLMEYzUjFCWFJucGtjbUkwUkhwSVZreGFOblZFTWpaM2FXTlVNWEU1VkdOS1duUm5ja3hVVkVGQlVVNVlZVGdLUmxWSE1USkZXWE5xWkVJcmVHTXhlWGxhU25SblZrNUVSRWhUVkhBM1ZYWk5SRk1yVGxkdUx6YzJXSFZKTjI5WllrcElOSFpHUVZsRE0wNUhNa1ZSYndwaFNtdzJlRmhVUjNSQ1NFZGhRbXc1YW1OelUzWnBXa1pyY3pkQlRHSndiVmhDWTBadU0wcHlkMDB3VUVGWGVsaEtOQzl5UzBkWmJETm9jMnhZUTFBckNreFpRa3haU2sxVVZESjBSRU40VmpabFlrSlZOSEpvZUZjM1JIWkhkV005Q2kwdExTMHRSVTVFSUZSVFV6SWdVRkpKVmtGVVJTQkxSVmt0TFMwdExRbyIsInRwbV9zZWFsZWRfcGFyZW50IjoiaDIifQ",
      "tag": "MlfbCOeyAbvukD3gkQ7PEA"
    }
    decrypted root key: ba4a95ae2f205699df60748fbe7620af01b1b68709f2e4a0918d01a6a5472d25
    decrypted Lorem Ipsum

```

in the output above

- `root encryption key`:  this is the random aes key
- `header.tpm_sealed_key`: this TPM sealed form of the root_encryption_key
- `ciphertext+iv+tag`: aes-gcm encrypted content using the root_encryption_key as the basis

If you base64 decode the `tpm_sealed_key`, you'll see the PEM formatted sealed TPM object

```
-----BEGIN TSS2 PRIVATE KEY-----
MIIBAwYGZ4EFCgEDAgRAAAABBFAATgAIAAsAAAASACCPzSFpq5JpTgxjPxq3coQr
gkG7wgKImB/HrB7dwf3bDgAQACBQGtKm3aoe95HbzoBt3oNcTHDR/eyfCqaDo+f1
8VcKwASBoACeACDf5+AwGPWFzdrb4DzHVLZ6uD26wicT1q9TcJZtgrLTTAAQNXa8
FUG12EYsjdB+xc1yyZJtgVNDDHSTp7UvMDS+NWn/76XuI7oYbJH4vFAYC3NG2EQo
aJl6xXTGtBHGaBl9jcsSviZFks7ALbpmXBcFn3JrwM0PAWzXJ4/rKGYl3hslXCP+
LYBLYJMTT2tDCxV6ebBU4rhxW7DvGuc=
-----END TSS2 PRIVATE KEY-----
```

---

### Duplicate/Import

In this mode, a remote TPM's Endorsement Public Key or SRK or H2 is used to seal the JWE encrytion key

At a high level, this utility basically performs [tpm2_duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md) and involves several steps:

If you want to transfer an external `RSA|ECC|AES|HMAC` key _from_  a `local` system  to `TPM-B`, you will need to

1. On `TPM-B`, extract the [Endorsement Public Key](https://trustedcomputinggroup.org/wp-content/uploads/EK-Credential-Profile-For-TPM-Family-2.0-Level-0-V2.5-R1.0_28March2022.pdf), the [H2 ECC SRK](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent) or the RSA|ECC Storage Root Key (`SRK`)
   Copy the public key to the system from which you want to transfer the secret key (eg, local)

2. On `local`, create the secret (the `AES` key)

3. On `local` use `TPM-B` public key to [duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md) the secret key such that it can only get loaded -inside- `TPM-B`
   The duplicate step will encrypt the external key such that only `TPM-B` can import it.
   The encrypted key is saved as a file which you will need to copy to `TPM-B`

4. On `TPM-B`  [import](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_import.1.md) the duplicated key you  copied from `local`
   The imported key is saved in TPM encoded PEM format for later use

5. On `TPM-B`, use the imported key to sign,encrypt,decrypt,hmac

It is critical to note the key that is transferred carries specific TPM policies which must be fulfilled upon use.  
These policies ensure the key cannot get duplicated beyond the target TPM. Specifically, the keys carry:

* PCR: `tpm2_policyor(tpm2_policypcr | tpm2_policyduplicateselect)`
* Password: `tpm2_policyor(tpm2_policyauthvalue | tpm2_policyduplicateselct)`.

![images/jwe_import.png](images/jwe_import.png)

As a demo, you can initialize any of the 'parent' keys on the system where the TPM exists

```bash
cd /tmp/

# using simulator
export TPM2TOOLS_TCTI="swtpm:port=2321"

### for RSAEK
tpm2_createek -c primaryB.ctx -G rsa -u ekB.pub -Q
tpm2_readpublic -c primaryB.ctx -o pub.pem -f PEM -Q
tpm2_flushcontext -t

### for RSASRK
# printf '\x00\x01' > ud.1
# dd if=/dev/zero bs=256 count=1 of=ud.2
# cat ud.1 ud.2 > unique.dat

# tpm2_createprimary -C o  -u unique.dat \
#    -G rsa2048  -g sha256  -c primary.ctx --attributes="fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -Q
# tpm2_readpublic -c primary.ctx -o pub.pem -f PEM
# tpm2_flushcontext -t

# for H2 Template
# printf '\x00\x00' > /tmp/unique.dat
# tpm2_createprimary -C o -G ecc  -g sha256 \
#      -c primary.ctx \
#      -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat
# tpm2_readpublic -c /tmp/primary.ctx -o /tmp/public.pem -f PEM -n /tmp/primary.name 
# tpm2_readpublic -c primary.ctx -o pub.pem -f PEM -Q
# tpm2 flushcontext -t
```

## Key Parent

For Duplicate/Import, the remote system can share a key based on a variety of "TPM Parents".

You can choose to use

* `Endorsement Key RSA or ECC`

  This is the easiest to use and the EK RSA or EK ECC public key is often found inside a signed x509 certificate.  See [Sign, Verify and decode using Google Cloud vTPM Attestation Key and Certificate](https://github.com/salrashid123/gcp-vtpm-ek-ak)

* `H2 Template`

  This is the default template used with openssl and the [ASN1 draft standard](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)

* `RSA|ECC Storage Root Key (SRK)`

  This RSA or ECC key is based on the Owner hierarchy 


## Policies

If you want to apply a PCR or password policy on the transfer and decryption, you can set the following.

The SkipPolicy setting below does not set any policy

#### SkipPolicy

If you want to skip the duplicate policy binding for all keys as described [here](https://github.com/salrashid123/tpmcopy/tree/main?tab=readme-ov-file#skippolicy), use the flag shown in the example below.

As an example of using the library

- `Encrypt`

```golang
	// first crate a random aes256 key to encrypt the content
	//   this is the key we're going to place inside the TPM proctected import/duplicate data
	rootEncryptionKey := make([]byte, 32)

	fmt.Printf("root encryption key: %s\n", hex.EncodeToString((rootEncryptionKey)))

	// read the public key of the target TPM
	encryptinPublicKey, err := os.ReadFile("/tmp/pub.pem")

	block, _ := pem.Decode(encryptinPublicKey)
	parsedEncryptingPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	pubKey, ok := parsedEncryptingPublicKey.(crypto.PublicKey)

  // assume we're using the "RSAEK" parent
  ptype := jwetpm.RSAEK

	// note: you don't need a TPM to encrypt
	encrypted, err := jwetpm.Encrypt(rootEncryptionKey, &jwetpm.EncryptConfig{
		TPMConfig: jwetpm.TPMConfig{},
		EncryptingPublicKey: pubKey,
		Parent:              ptype,
		SkipPolicy:          true,
	})

  // now set the TPM encrypted root key and the chosen parent type hint as the header
	h := jwe.NewHeaders()
	h.Set("tpm_import_key", encrypted)
	h.Set("tpm_import_parent", *parentKeyType)

  // now actaully encrypt the payload using the rootEncryptionKey
	fromRawKey, err := jwk.Import(rootEncryptionKey)
	jweencrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), fromRawKey, jwe.WithPerRecipientHeaders(h)), jwe.WithContentEncryption(jwa.A256GCM()))
```

- `Decrypt`

```golang
	jm, err := jwe.Parse(jweencrypted)

	// for each recipient in the payload
	//  (currently only one is supproted)
	var duplicated_key_byte []byte
	var parent_type jwetpm.ParentType
	for _, r := range jm.Recipients() {

		// read the headers and extract the sealed key and parent type
		h := r.Headers()
		var tkey string
		err := h.Get("tpm_import_key", &tkey)

		// decode
		duplicated_key_byte, err = base64.StdEncoding.DecodeString(tkey)

    // you can either switch based on the pt header or stipulate one
		var pt string
		err = h.Get("tpm_import_parent", &pt)
		parent_type = jwetpm.RSAEK
	}

	regeneratedRootEncryptionKey, err := jwetpm.Decrypt(duplicated_key_byte, &jwetpm.DecryptConfig{
		TPMConfig: jwetpm.TPMConfig{
			TPMPath:     "/dev/tpmrm0", // <<< you need a tpm to decrypt, ofcourse
		},
		SkipPolicy: true,
		Parent:     parent_type,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error parsing encrypting public key : %v", err)
		return 1
	}

	/// now decrypt the JWE

	fmt.Printf("decrypted root key: %s\n", hex.EncodeToString(regeneratedRootEncryptionKey))

	rRawKey, err := jwk.Import(regeneratedRootEncryptionKey)
	d, err := jwe.Decrypt(jweencrypted, jwe.WithKey(jwa.DIRECT(), rRawKey))

	fmt.Printf("decrypted %s\n", string(d))

```

as an end to end example, first acquire the `RSAEK` public key as `/tmp/pub.pem`

```bash
cd example/import/

go run skip_policy/main.go  --password=bar --parentKeyType=rsa_ek \
   --tpmPublicKeyFile=/tmp/pub.pem   --tpm-path="127.0.0.1:2321" 

root encryption key: 7cb2663d918c00a2fc7fe8141c08205119cce055b51553b1d2820ca7b7a38987
{
  "ciphertext": "Ka5jQUSM84hSbmQ",
  "encrypted_key": "gbhL0r08D7T9ObSQmtdZUB-6bfsMfX-u_ku7vjY9HBNU66y4RIqiow",
  "header": {
    "alg": "A128KW",
    "tpm_import_key": "eyJuYW1lIjoibXlrZXkiLCJ2ZXJzaW9uIjoxLCJ0eXBlIjoiS0VZRURIQVNIIiwicGFyZW50S2V5VHlwZSI6IkVuZG9yc2VtZW50UlNBIiwia2V5IjoiLS0tLS1CRUdJTiBUU1MyIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUJ2UVlHWjRFRkNnRUVvb0lCQmdTQ0FRSUJBTG5UY1F6N0k0dVc4L09jUTFvdkhWSjBwQ1ZNWDMvU09QcGVcbmh5aWlSRDg3cUtWd3IvMEJzdk0yc1hodHJTbFNBTGgrYzdWb2QxZzhaSzFkNWpVd0FHMFpxZEQ1YmthOWF4S3dcbm9wUEE1ZDh1aTBmZEdSeWJuaEc0bGsvazFRVlNWMlpLblRHaWNXYVdOWUhmOGcxS204aTRMZytUNW9HOGJBSDlcbkdnd0RNb3lmYUM5ZzNmMFNlaitFNW44OCtrYkF2T3NvdUpNYTE1ek5paDJPYnIydS9Gckx6MVBzYlF5SVd6eG5cbkw3WFVuU3hMK2pFTXN6TXI3SWhIWFQyZ24vUGlScnNaT0ZsbXFtVHBKOXY3dSswbmNsaVZneUZPWEVVSWNIYU5cbkhVd1ZCUGRCMnV1cEtDWTRTTGFuMGNlYnpVMzIrcW5jOGIxSDE0Um5ObHVNS3FVNldLb0NCRUFBQVVBRU1BQXVcbkFBZ0FDd0FBQUVBQUFBQVFBQ0NBM2x0VjBNNmQ0T1VEcnlNeUJPdmFhUEtjN2NqeUF5VVVDR0xjcGNwdllnUnhcbkFHOEFJSVp3ZGoxeElMNmVSMk5UMGlYcnVFTjhmcnkwcVAxdFZoNVg3WW9XUG4yaVc2UGlPcURyemhZZnkyL2JcbkR5SDBmbkExRUcwR0JBTjBQNUFOU3BXYXp3T3l2bXcxOGY4ekg3cmx3UDhTazNVOVBYdkczQzB1QVJTcHFuaE9cbmowUlFlank3SVppcXFWcHgyY0tBTUdjPVxuLS0tLS1FTkQgVFNTMiBQUklWQVRFIEtFWS0tLS0tXG4iLCJwYXJlbnROYW1lIjoiMDAwYjU5MDU1NGQ3ZTRjNGM3NTRhNGZlNDcwMWJhODNiMmEyOGNiMmY5MmEyYTcxZmExMTQyNjdiZjBhMzU3NjVjMzcifQ"
  },
  "iv": "sjxevIViaYbgzE5K",
  "protected": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwidHBtX2ltcG9ydF9rZXkiOiJleUp1WVcxbElqb2liWGxyWlhraUxDSjJaWEp6YVc5dUlqb3hMQ0owZVhCbElqb2lTMFZaUlVSSVFWTklJaXdpY0dGeVpXNTBTMlY1Vkhsd1pTSTZJa1Z1Wkc5eWMyVnRaVzUwVWxOQklpd2lhMlY1SWpvaUxTMHRMUzFDUlVkSlRpQlVVMU15SUZCU1NWWkJWRVVnUzBWWkxTMHRMUzFjYmsxSlNVSjJVVmxIV2pSRlJrTm5SVVZ2YjBsQ1FtZFRRMEZSU1VKQlRHNVVZMUY2TjBrMGRWYzRMMDlqVVRGdmRraFdTakJ3UTFaTldETXZVMDlRY0dWY2JtaDVhV2xTUkRnM2NVdFdkM0l2TUVKemRrMHljMWhvZEhKVGJGTkJUR2dyWXpkV2IyUXhaemhhU3pGa05XcFZkMEZITUZweFpFUTFZbXRoT1dGNFMzZGNibTl3VUVFMVpEaDFhVEJtWkVkU2VXSnVhRWMwYkdzdmF6RlJWbE5XTWxwTGJsUkhhV05YWVZkT1dVaG1PR2N4UzIwNGFUUk1aeXRVTlc5SE9HSkJTRGxjYmtkbmQwUk5iM2xtWVVNNVp6Tm1NRk5sYWl0Rk5XNDRPQ3RyWWtGMlQzTnZkVXBOWVRFMWVrNXBhREpQWW5JeWRTOUdja3g2TVZCellsRjVTVmQ2ZUc1Y2JrdzNXRlZ1VTNoTUsycEZUWE42VFhJM1NXaElXRlF5WjI0dlVHbFNjbk5hVDBac2JYRnRWSEJLT1hZM2RTc3dibU5zYVZabmVVWlBXRVZWU1dOSVlVNWNia2hWZDFaQ1VHUkNNblYxY0V0RFdUUlRUR0Z1TUdObFlucFZNeklyY1c1ak9HSXhTREUwVW01T2JIVk5TM0ZWTmxkTGIwTkNSVUZCUVZWQlJVMUJRWFZjYmtGQlowRkRkMEZCUVVWQlFVRkJRVkZCUTBOQk0yeDBWakJOTm1RMFQxVkVjbmxOZVVKUGRtRmhVRXRqTjJOcWVVRjVWVlZEUjB4amNHTndkbGxuVW5oY2JrRkhPRUZKU1ZwM1pHb3hlRWxNTm1WU01rNVVNR2xZY25WRlRqaG1jbmt3Y1ZBeGRGWm9OVmczV1c5WFVHNHlhVmMyVUdsUGNVUnllbWhaWm5reUwySmNia1I1U0RCbWJrRXhSVWN3UjBKQlRqQlFOVUZPVTNCWFlYcDNUM2wyYlhjeE9HWTRla2czY214M1VEaFRhek5WT1ZCWWRrY3pRekIxUVZKVGNIRnVhRTljYm1vd1VsRmxhbmszU1ZwcGNYRldjSGd5WTB0QlRVZGpQVnh1TFMwdExTMUZUa1FnVkZOVE1pQlFVa2xXUVZSRklFdEZXUzB0TFMwdFhHNGlMQ0p3WVhKbGJuUk9ZVzFsSWpvaU1EQXdZalU1TURVMU5HUTNaVFJqTkdNM05UUmhOR1psTkRjd01XSmhPRE5pTW1FeU9HTmlNbVk1TW1FeVlUY3habUV4TVRReU5qZGlaakJoTXpVM05qVmpNemNpZlEifQ",
  "tag": "PPBY6d3tql2tixsSEhgmgg"
}
decrypted root key: 7cb2663d918c00a2fc7fe8141c08205119cce055b51553b1d2820ca7b7a38987
decrypted Lorem Ipsum

```

in the output above

- `root encryption key`:  this is the random aes key
- `header.tpm_import_key`: this TPM encrypted form of the root_encryption_key
- `ciphertext+iv+tag`: aes-gcm encrypted content using the root_encryption_key

If you decode `tpm_import_key`, you'll see the actual TPM formatted key as PEM.  This is by decrypted by a target TPM and has policies to prevent _further_ duplication.  However, since upon the first decryption on the target TPM, the root encryption key is visible on the system already.

```json
{
  "name": "mykey",
  "version": 1,
  "type": "KEYEDHASH",
  "parentKeyType": "EndorsementRSA",
  "key": "-----BEGIN TSS2 PRIVATE KEY-----\nMIIBvQYGZ4EFCgEEooIBBgSCAQIBALnTcQz7I4uW8/OcQ1ovHVJ0pCVMX3/SOPpe\nhyiiRD87qKVwr/0BsvM2sXhtrSlSALh+c7Vod1g8ZK1d5jUwAG0ZqdD5bka9axKw\nopPA5d8ui0fdGRybnhG4lk/k1QVSV2ZKnTGicWaWNYHf8g1Km8i4Lg+T5oG8bAH9\nGgwDMoyfaC9g3f0Sej+E5n88+kbAvOsouJMa15zNih2Obr2u/FrLz1PsbQyIWzxn\nL7XUnSxL+jEMszMr7IhHXT2gn/PiRrsZOFlmqmTpJ9v7u+0ncliVgyFOXEUIcHaN\nHUwVBPdB2uupKCY4SLan0cebzU32+qnc8b1H14RnNluMKqU6WKoCBEAAAUAEMAAu\nAAgACwAAAEAAAAAQACCA3ltV0M6d4OUDryMyBOvaaPKc7cjyAyUUCGLcpcpvYgRx\nAG8AIIZwdj1xIL6eR2NT0iXruEN8fry0qP1tVh5X7YoWPn2iW6PiOqDrzhYfy2/b\nDyH0fnA1EG0GBAN0P5ANSpWazwOyvmw18f8zH7rlwP8Sk3U9PXvG3C0uARSpqnhO\nj0RQejy7IZiqqVpx2cKAMGc=\n-----END TSS2 PRIVATE KEY-----\n",
  "parentName": "000b590554d7e4c4c754a4fe4701ba83b2a28cb2f92a2a71fa114267bf0a35765c37"
}
```

#### Password

If you want the default duplication constraints

```bash
go run password/main.go --password=bar --parentKeyType=rsa_ek \
   --tpmPublicKeyFile=/tmp/pub.pem   --tpm-path="127.0.0.1:2321"

    root encryption key: 9be11fad11b45828097e6c8363724a47fda67fbe6d8d7d2901ebbd15c92b9ea0
    {
      "ciphertext": "hftXNjXrIo3DBn4",
      "encrypted_key": "9vrhBGz2xFEFOfDYk6xOukQPB2LAj_3yHEeVAHpERv_bcNaXOC1_wA",
      "header": {
        "alg": "A128KW",
        "tpm_import_key": "eyJuYW1lIjoiZm9vIiwgInZlcnNpb24iOjEsICJ0eXBlIjoiS0VZRURIQVNIIiwgInBhcmVudEtleVR5cGUiOiJFbmRvcnNlbWVudFJTQSIsICJrZXkiOiItLS0tLUJFR0lOIFRTUzIgUFJJVkFURSBLRVktLS0tLVxuTUlJQnVnWUdaNEVGQ2dFRW9vSUJCZ1NDQVFJQkFLb00vdlQwbzlreG1OL0pvS2pVQm9jSnNRMHk5TnJ5VXNsVFxuWkp1NGJNUkVsbkVMZFFHRG9iRUllZzR3YWJXTGhSMmIrcHFEOUtkN3Q4bFhUSFc5MWRmc1pJSmJHdXJ2aEkzdVxucWtkOEJwQ280MEhicTVKTmZMQjFjOVZZOHJTckNCbmMvTTQ3N2M2blZVTzRxS2ZuQ1dmbnNGbEg4WURGZExnaFxuOFpRaDFjYjdWTFpUV082U0tmbFlqbk96QTg0dEVEcjdEbmpuQVUxVUdXSVZsZS9aVmZkL0h4WDh0c1Z4MGsrRFxuU25iU0NXVTJzZ2xKS2c2QTNkQlpCRU9UUC9iczQvRHFXY1VhUWxZRmEyMTRpc0VjU3ltNmp1bStKWEk3NzVyVlxuTHlZZHJVWmYxNWh2WFJSV3g1a0FjSC8vbmh0WHVWeE1Dem8xZFhjMThHZysvcnQ0TkZvQ0JFQUFBVUFFTUFBdVxuQUFnQUN3QUFBRUFBQUFBUUFDQ2V3Um1pd0E0WHA2eWVTdlBXSnRZOHhoa0tqa2xlRlNqUjQ3Y1p1dkJsTFFSdVxuQUd3QUlIV1BEMVlWeUJobndEbE9KWXp1TmZ0dVJQM0lkaUdIV1ExeUt1Y2FqQTJRbDlqREdFaHRNSVI0VmtwY1xuUUxaK2pRSXpjUUU1MEZZcWtqZXpmQWdrV29UbGNzMUQ3WlkrVityQklldTlsUmk1SE13cDc3dEhWam5jcWU5NFxuemtGL3liK1lYREorRk9aZ0xGQT1cbi0tLS0tRU5EIFRTUzIgUFJJVkFURSBLRVktLS0tLVxuIiwgInBhcmVudE5hbWUiOiIwMDBiZGI3NTQ2NzdhZTc1Y2I5OWU2ZDFlZmRiM2QwOTcyNjhlNTY2YjE2MTQzMWIwNjE1ZDg2NmI2NTM4YzFiZWViMyJ9"
      },
      "iv": "2qKz3DFAKPyp-sr_",
      "protected": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwidHBtX2ltcG9ydF9rZXkiOiJleUp1WVcxbElqb2labTl2SWl3Z0luWmxjbk5wYjI0aU9qRXNJQ0owZVhCbElqb2lTMFZaUlVSSVFWTklJaXdnSW5CaGNtVnVkRXRsZVZSNWNHVWlPaUpGYm1SdmNuTmxiV1Z1ZEZKVFFTSXNJQ0pyWlhraU9pSXRMUzB0TFVKRlIwbE9JRlJUVXpJZ1VGSkpWa0ZVUlNCTFJWa3RMUzB0TFZ4dVRVbEpRblZuV1VkYU5FVkdRMmRGUlc5dlNVSkNaMU5EUVZGSlFrRkxiMDB2ZGxRd2J6bHJlRzFPTDBwdlMycFZRbTlqU25OUk1IazVUbko1VlhOc1ZGeHVXa3AxTkdKTlVrVnNia1ZNWkZGSFJHOWlSVWxsWnpSM1lXSlhUR2hTTW1JcmNIRkVPVXRrTjNRNGJGaFVTRmM1TVdSbWMxcEpTbUpIZFhKMmFFa3pkVnh1Y1d0a09FSndRMjgwTUVoaWNUVktUbVpNUWpGak9WWlpPSEpUY2tOQ2JtTXZUVFEzTjJNMmJsWlZUelJ4UzJadVExZG1ibk5HYkVnNFdVUkdaRXhuYUZ4dU9GcFJhREZqWWpkV1RGcFVWMDgyVTB0bWJGbHFiazk2UVRnMGRFVkVjamRFYm1wdVFWVXhWVWRYU1Zac1pTOWFWbVprTDBoNFdEaDBjMVo0TUdzclJGeHVVMjVpVTBOWFZUSnpaMnhLUzJjMlFUTmtRbHBDUlU5VVVDOWljelF2UkhGWFkxVmhVV3haUm1FeU1UUnBjMFZqVTNsdE5tcDFiU3RLV0VrM056VnlWbHh1VEhsWlpISlZXbVl4TldoMldGSlNWM2cxYTBGalNDOHZibWgwV0hWV2VFMURlbTh4WkZoak1UaEhaeXN2Y25RMFRrWnZRMEpGUVVGQlZVRkZUVUZCZFZ4dVFVRm5RVU4zUVVGQlJVRkJRVUZCVVVGRFEyVjNVbTFwZDBFMFdIQTJlV1ZUZGxCWFNuUlpPSGhvYTB0cWEyeGxSbE5xVWpRM1kxcDFka0pzVEZGU2RWeHVRVWQzUVVsSVYxQkVNVmxXZVVKb2JuZEViRTlLV1hwMVRtWjBkVkpRTTBsa2FVZElWMUV4ZVV0MVkyRnFRVEpSYkRscVJFZEZhSFJOU1ZJMFZtdHdZMXh1VVV4YUsycFJTWHBqVVVVMU1FWlpjV3RxWlhwbVFXZHJWMjlVYkdOek1VUTNXbGtyVml0eVFrbGxkVGxzVW1rMVNFMTNjRGMzZEVoV2FtNWpjV1U1TkZ4dWVtdEdMM2xpSzFsWVJFb3JSazlhWjB4R1FUMWNiaTB0TFMwdFJVNUVJRlJUVXpJZ1VGSkpWa0ZVUlNCTFJWa3RMUzB0TFZ4dUlpd2dJbkJoY21WdWRFNWhiV1VpT2lJd01EQmlaR0kzTlRRMk56ZGhaVGMxWTJJNU9XVTJaREZsWm1SaU0yUXdPVGN5TmpobE5UWTJZakUyTVRRek1XSXdOakUxWkRnMk5tSTJOVE00WXpGaVpXVmlNeUo5In0",
      "tag": "ON2j501NaULONw3tK5mK9A"
    }
    decrypted root key: 9be11fad11b45828097e6c8363724a47fda67fbe6d8d7d2901ebbd15c92b9ea0
    decrypted Lorem Ipsum
```

#### PCR

For PCR policy, you can bind the decoding of the JWE to a spcific PCR value

```bash
tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000

tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

go run pcr/main.go --parentKeyType=rsa_ek \
   --pcrValues=23:F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B  \
     --tpmPublicKeyFile=/tmp/pub.pem   --tpm-path="127.0.0.1:2321"  
```

---

## JWT

If all you want to do is issue a JWT, see

- [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)

Alternatively, the following allows you to use `github.com/lestrrat-go/jwx/v3/jwt` by specifying a `crypto.Signer` backed by a TPM like [tpmsigner](https://github.com/salrashid123/tpmsigner)

For details, see [Issue a TPM based JWT using `github.com/lestrrat-go/jwx/v3/jwt`](https://gist.github.com/salrashid123/edd32d03b12b3606cb240721d87715f7)

To set this mode up, first create a TPM based key to sign.  The following uses the H2 template and an rsa-ssa key:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm &&
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert &&
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## run any TPM command
export TPM2TOOLS_TCTI="swtpm:port=2321"
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
tpm2_flushcontext -l && tpm2_flushcontext -t

tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_flushcontext -l && tpm2_flushcontext -t

# tpm2_evictcontrol -C o -c key.ctx 0x81008001
    
tpm2_encodeobject -C primary.ctx -u key.pub -r  key.priv -o private.pem
tpm2_flushcontext -l && tpm2_flushcontext -t
```

From there, 

```bash
go run main.go --in /tmp/private.pem -tpm-path="127.0.0.1:2321"

  eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.fJEF72BsllMgLY-IQ6yHsXR84zi_xRgl8Z2T9iEz-jObxEIIzAj2SeKHwWwfmhDOMFsHJS5826nk9DsVTkhJiLLfk4mPFNdwVfyGdFKw2AlhJGT5EegnpIXF0tRolQkzmbnkoR0QOHSTZmYdA9CnHISG7_TpM27GRya_jHA5D-z0w01QC6Z_zy8mqvT7qCGwIcQn7ubuxN6lG-seNUMhfP__hy-p8Bp1NLDwkFRQ3tW5staUxQzQZZHQT654ky5kM17i3fmVgFKIBbYQKMhmfHBDtIhDwBiSibU46TIPKsJsTW89agtzQzpm07HrGD-jdS1Fbgii3LvKAO-kF7tDmw
```


Which you can also verify by using the public key

```bash
tpm2_readpublic -c key.ctx -f pem -o public.pem

$ cat public.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqSGmTL+UZP/j/H3KI3pm
bJAi7FwNGZgLGbRbDQuCAU3Yc3oWDsZxMGOzPiWeB87V34jr5a7F5L28AdQKG6ta
/Puq0xQOXx0ALtvXQ4If3vziK2a9J477PnMjmp3MRxMXerrBU1vfoR++diVOQ8Hm
ZjeFkdZCkZ2E3o5r2vfOiUto+TiWiL4OTdbJ8o8GxanC7vHSqWpR2PIkyt0aVBUM
vAWP1No94dvoOZR6xuiahMFRWnrndkSogs6ZejJ7Y3mceFhsFfGbQyAufA3HL9aI
HCYPhBPOQxrlqLtP/9Lou7YHuGKbjiT1GfIh4UeT6TKMO/gSuCZiUPE67wrsCUY7
awIDAQAB
-----END PUBLIC KEY-----
```


## Session Encryption

You can also enable [session encryption](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session) by specifying a trusted handle when initializing the TPMConfig