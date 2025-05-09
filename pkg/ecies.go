package ecies

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"
)

var (
	big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

var (
	//ErrImport is returned when the key import failed
	ErrImport = fmt.Errorf("ecies: failed to import key")

	//ErrInvalidCurve is returned when the elliptic curve is invalid
	ErrInvalidCurve = fmt.Errorf("ecies: invalid elliptic curve")

	//ErrInvalidParams is returned when the ECIES parameter are invalid
	ErrInvalidParams = fmt.Errorf("ecies: invalid ECIES parameters")

	//ErrInvalidPublicKey is returned when the public key is invalid
	ErrInvalidPublicKey = fmt.Errorf("ecies: invalid public key")

	//ErrSharedKeyIsPointAtInfinity is returned when the shared key point to the infinity
	ErrSharedKeyIsPointAtInfinity = fmt.Errorf("ecies: shared key is point at infinity")

	//ErrSharedKeyTooBig is returned when the share key parameters are too big
	ErrSharedKeyTooBig = fmt.Errorf("ecies: shared key params are too big")

	//ErrKeyDataTooLong is returned when the data in the key are too long
	ErrKeyDataTooLong = fmt.Errorf("ecies: can't supply requested key data")

	//ErrSharedTooLong is returned when the shared secret is too long
	ErrSharedTooLong = fmt.Errorf("ecies: shared secret is too long")

	//ErrInvalidMessage is returned when the ECIES message is invalid
	ErrInvalidMessage = fmt.Errorf("ecies: invalid message")
)

// PublicKey is a representation of an elliptic curve public key.
type PublicKey struct {
	X *big.Int
	Y *big.Int
	elliptic.Curve
	Params *Params
}

//ExportECDSA converts an ECIES public key into an ECDSA public key.
func (pub *PublicKey) ExportECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
}

//ImportECDSAPublic converts an ECDSA public key into an ECIES public key.
func ImportECDSAPublic(pub *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{
		X:      pub.X,
		Y:      pub.Y,
		Curve:  pub.Curve,
		Params: ParamsFromCurve(pub.Curve),
	}
}

// PrivateKey is a representation of an elliptic curve private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

//ExportECDSA converts an ECIES private key into an ECDSA private key.
func (prv *PrivateKey) ExportECDSA() *ecdsa.PrivateKey {
	pub := &prv.PublicKey
	pubECDSA := pub.ExportECDSA()
	return &ecdsa.PrivateKey{
		PublicKey: *pubECDSA,
		D:         prv.D,
	}
}

//ImportECDSA converts an ECDSA private key into an ECIES private key.
func ImportECDSA(prv *ecdsa.PrivateKey) *PrivateKey {
	pub := ImportECDSAPublic(&prv.PublicKey)
	return &PrivateKey{*pub, prv.D}
}

//GenerateKey creates an elliptic curve public / private keypair. If params is nil,
// the recommended default paramters for the key will be chosen.
func GenerateKey(rand io.Reader, curve elliptic.Curve, params *Params) (prv *PrivateKey, err error) {
	pb, x, y, err := elliptic.GenerateKey(curve, rand)
	if err != nil {
		return
	}
	prv = new(PrivateKey)
	prv.PublicKey.X = x
	prv.PublicKey.Y = y
	prv.PublicKey.Curve = curve
	prv.D = new(big.Int).SetBytes(pb)
	if params == nil {
		params = ParamsFromCurve(curve)
	}
	prv.PublicKey.Params = params
	return
}

// MaxSharedKeyLength returns the maximum length of the shared key the
// public key can produce.
func MaxSharedKeyLength(pub *PublicKey) int {
	return (pub.Curve.Params().BitSize + 7) / 8
}

//GenerateShared creates an ECDH key agreement method used to establish secret keys for encryption.
func (prv *PrivateKey) GenerateShared(pub *PublicKey, skLen, macLen int) (sk []byte, err error) {
	if prv.PublicKey.Curve != pub.Curve {
		return nil, ErrInvalidCurve
	}
	if skLen+macLen > MaxSharedKeyLength(pub) {
		return nil, ErrSharedKeyTooBig
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil {
		return nil, ErrSharedKeyIsPointAtInfinity
	}

	sk = make([]byte, skLen+macLen)
	skBytes := x.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	} else if ctr[2]++; ctr[2] != 0 {
		return
	} else if ctr[1]++; ctr[1] != 0 {
		return
	} else if ctr[0]++; ctr[0] != 0 {
		return
	}
	return
}

// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) (k []byte, err error) {
	if s1 == nil {
		s1 = make([]byte, 0)
	}

	reps := ((kdLen + 7) * 8) / (hash.BlockSize() * 8)
	if big.NewInt(int64(reps)).Cmp(big2To32M1) > 0 {
		fmt.Println(big2To32M1)
		return nil, ErrKeyDataTooLong
	}

	counter := []byte{0, 0, 0, 1}
	k = make([]byte, 0)

	for i := 0; i <= reps; i++ {
		hash.Write(counter)
		hash.Write(z)
		hash.Write(s1)
		k = append(k, hash.Sum(nil)...)
		hash.Reset()
		incCounter(counter)
	}

	k = k[:kdLen]
	return
}

// messageTag computes the MAC of a message (called the tag) as per
// SEC 1, 3.5.
func messageTag(hash func() hash.Hash, km, msg, shared []byte) []byte {
	if shared == nil {
		shared = make([]byte, 0)
	}
	mac := hmac.New(hash, km)
	mac.Write(msg)
	tag := mac.Sum(nil)
	return tag
}

// Generate an initialisation vector for CTR mode.
func generateIV(params *Params, rand io.Reader) (iv []byte, err error) {
	iv = make([]byte, params.BlockSize)
	_, err = io.ReadFull(rand, iv)
	return
}

// symEncrypt carries out CTR encryption using the block cipher specified in the
// parameters.
func symEncrypt(rand io.Reader, params *Params, key, m []byte) (ct []byte, err error) {
	c, err := params.Cipher(key)
	if err != nil {
		return
	}

	iv, err := generateIV(params, rand)
	if err != nil {
		return
	}
	ctr := cipher.NewCTR(c, iv)

	ct = make([]byte, len(m)+params.BlockSize)
	copy(ct, iv)
	ctr.XORKeyStream(ct[params.BlockSize:], m)
	return
}

// symDecrypt carries out CTR decryption using the block cipher specified in
// the parameters
func symDecrypt(params *Params, key, ct []byte) (m []byte, err error) {
	c, err := params.Cipher(key)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(c, ct[:params.BlockSize])

	m = make([]byte, len(ct)-params.BlockSize)
	ctr.XORKeyStream(m, ct[params.BlockSize:])
	return
}

// Encrypt encrypts a message using ECIES as specified in SEC 1, 5.1. If
// the shared information parameters aren't being used, they should be
// nil.
func Encrypt(rand io.Reader, pub *PublicKey, m, s1, s2 []byte) (ct []byte, err error) {
	params := pub.Params
	if params == nil {
		if params = ParamsFromCurve(pub.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}
	R, err := GenerateKey(rand, pub.Curve, params)
	if err != nil {
		return
	}

	hash := params.Hash()
	z, err := R.GenerateShared(pub, params.KeyLen, params.KeyLen)
	if err != nil {
		return
	}
	K, err := concatKDF(hash, z, s1, params.KeyLen+params.KeyLen)
	if err != nil {
		return
	}
	Ke := K[:params.KeyLen]
	Km := K[params.KeyLen:]
	hash.Write(Km)
	Km = hash.Sum(nil)
	hash.Reset()

	em, err := symEncrypt(rand, params, Ke, m)
	if err != nil || len(em) <= params.BlockSize {
		return
	}

	d := messageTag(params.Hash, Km, em, s2)

	Rb := elliptic.Marshal(pub.Curve, R.PublicKey.X, R.PublicKey.Y)
	ct = make([]byte, len(Rb)+len(em)+len(d))
	copy(ct, Rb)
	copy(ct[len(Rb):], em)
	copy(ct[len(Rb)+len(em):], d)
	return
}

// Decrypt decrypts an ECIES ciphertext.
func (prv *PrivateKey) Decrypt(c, s1, s2 []byte) (m []byte, err error) {
	if c == nil || len(c) == 0 {
		err = ErrInvalidMessage
		return
	}
	params := prv.PublicKey.Params
	if params == nil {
		if params = ParamsFromCurve(prv.PublicKey.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}
	hash := params.Hash()

	var (
		rLen   int
		hLen   = hash.Size()
		mStart int
		mEnd   int
	)

	switch c[0] {
	case 2, 3, 4:
		rLen = ((prv.PublicKey.Curve.Params().BitSize + 7) / 4)
		if len(c) < (rLen + hLen + 1) {
			err = ErrInvalidMessage
			return
		}
	default:
		err = ErrInvalidPublicKey
		return
	}

	mStart = rLen
	mEnd = len(c) - hLen

	R := new(PublicKey)
	R.Curve = prv.PublicKey.Curve
	R.X, R.Y = elliptic.Unmarshal(R.Curve, c[:rLen])
	if R.X == nil {
		err = ErrInvalidPublicKey
		return
	}

	z, err := prv.GenerateShared(R, params.KeyLen, params.KeyLen)
	if err != nil {
		return
	}

	K, err := concatKDF(hash, z, s1, params.KeyLen+params.KeyLen)
	if err != nil {
		return
	}

	Ke := K[:params.KeyLen]
	Km := K[params.KeyLen:]
	hash.Write(Km)
	Km = hash.Sum(nil)
	hash.Reset()

	d := messageTag(params.Hash, Km, c[mStart:mEnd], s2)
	if subtle.ConstantTimeCompare(c[mEnd:], d) != 1 {
		err = ErrInvalidMessage
		return
	}

	m, err = symDecrypt(params, Ke, c[mStart:mEnd])
	return
}
