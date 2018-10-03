package ecies

// This file contains parameters for ECIES encryption, specifying the
// symmetric encryption and HMAC parameters.

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

//DefaultCurve for this package is the NIST P256 curve, which
// provides security equivalent to AES-128.
var DefaultCurve = elliptic.P256()

var (
	//ErrUnsupportedECDHAlgorithm is returned when ECDH is not supported
	ErrUnsupportedECDHAlgorithm = fmt.Errorf("ecies: unsupported ECDH algorithm")

	//ErrUnsupportedECIESParameters is returned when the ECIES parameters are not supportedf
	ErrUnsupportedECIESParameters = fmt.Errorf("ecies: unsupported ECIES parameters")
)

//Params describes ECIES parameters
type Params struct {
	Hash      func() hash.Hash // hash function
	hashAlgo  crypto.Hash
	Cipher    func([]byte) (cipher.Block, error) // symmetric cipher
	BlockSize int                                // block size of symmetric cipher
	KeyLen    int                                // length of symmetric key
}

// Standard ECIES parameters:
var (
	//EciesAes128Sha256 ECIES using AES128 and HMAC-SHA-256-16
	EciesAes128Sha256 = &Params{
		Hash:      sha256.New,
		hashAlgo:  crypto.SHA256,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    16,
	}

	//EciesAes256Sha256 ECIES using AES256 and HMAC-SHA-256-32
	EciesAes256Sha256 = &Params{
		Hash:      sha256.New,
		hashAlgo:  crypto.SHA256,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    32,
	}

	//EciesAes256Sha384 ECIES using AES256 and HMAC-SHA-384-48
	EciesAes256Sha384 = &Params{
		Hash:      sha512.New384,
		hashAlgo:  crypto.SHA384,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    32,
	}

	//EciesAes256Sha512 ECIES using AES256 and HMAC-SHA-512-64
	EciesAes256Sha512 = &Params{
		Hash:      sha512.New,
		hashAlgo:  crypto.SHA512,
		Cipher:    aes.NewCipher,
		BlockSize: aes.BlockSize,
		KeyLen:    32,
	}
)

var paramsFromCurve = map[elliptic.Curve]*Params{
	elliptic.P256(): EciesAes128Sha256,
	elliptic.P384(): EciesAes256Sha384,
	elliptic.P521(): EciesAes256Sha512,
}

//AddParamsForCurve add parameter to an elliptic curve
func AddParamsForCurve(curve elliptic.Curve, params *Params) {
	paramsFromCurve[curve] = params
}

// ParamsFromCurve selects parameters optimal for the selected elliptic curve.
// Only the curves P256, P384, and P512 are supported.
func ParamsFromCurve(curve elliptic.Curve) (params *Params) {
	return paramsFromCurve[curve]

	/*
		switch curve {
		case elliptic.P256():
			return EciesAes128Sha256
		case elliptic.P384():
			return EciesAes256Sha384
		case elliptic.P521():
			return EciesAes256Sha512
		default:
			return nil
		}
	*/
}

// ASN.1 encode the ECIES parameters relevant to the encryption operations.
func paramsToASNECIES(params *Params) (asnParams asnECIESParameters) {
	if nil == params {
		return
	}
	asnParams.KDF = asnNISTConcatenationKDF
	asnParams.MAC = hmacFull
	switch params.KeyLen {
	case 16:
		asnParams.Sym = aes128CTRinECIES
	case 24:
		asnParams.Sym = aes192CTRinECIES
	case 32:
		asnParams.Sym = aes256CTRinECIES
	}
	return
}

// ASN.1 encode the ECIES parameters relevant to ECDH.
func paramsToASNECDH(params *Params) (algo asnECDHAlgorithm) {
	switch params.hashAlgo {
	case crypto.SHA224:
		algo = dhSinglePassStdDhSha224kdf
	case crypto.SHA256:
		algo = dhSinglePassStdDhSha256kdf
	case crypto.SHA384:
		algo = dhSinglePassStdDhSha384kdf
	case crypto.SHA512:
		algo = dhSinglePassStdDhSha512kdf
	}
	return
}

// ASN.1 decode the ECIES parameters relevant to the encryption stage.
func asnECIEStoParams(asnParams asnECIESParameters, params *Params) {
	if !asnParams.KDF.Cmp(asnNISTConcatenationKDF) {
		params = nil
		return
	} else if !asnParams.MAC.Cmp(hmacFull) {
		params = nil
		return
	}

	switch {
	case asnParams.Sym.Cmp(aes128CTRinECIES):
		params.KeyLen = 16
		params.BlockSize = 16
		params.Cipher = aes.NewCipher
	case asnParams.Sym.Cmp(aes192CTRinECIES):
		params.KeyLen = 24
		params.BlockSize = 16
		params.Cipher = aes.NewCipher
	case asnParams.Sym.Cmp(aes256CTRinECIES):
		params.KeyLen = 32
		params.BlockSize = 16
		params.Cipher = aes.NewCipher
	default:
		params = nil
	}
}

// ASN.1 decode the ECIES parameters relevant to ECDH.
func asnECDHtoParams(asnParams asnECDHAlgorithm, params *Params) {
	if asnParams.Cmp(dhSinglePassStdDhSha224kdf) {
		params.hashAlgo = crypto.SHA224
		params.Hash = sha256.New224
	} else if asnParams.Cmp(dhSinglePassStdDhSha256kdf) {
		params.hashAlgo = crypto.SHA256
		params.Hash = sha256.New
	} else if asnParams.Cmp(dhSinglePassStdDhSha384kdf) {
		params.hashAlgo = crypto.SHA384
		params.Hash = sha512.New384
	} else if asnParams.Cmp(dhSinglePassStdDhSha512kdf) {
		params.hashAlgo = crypto.SHA512
		params.Hash = sha512.New
	} else {
		params = nil
	}
}
