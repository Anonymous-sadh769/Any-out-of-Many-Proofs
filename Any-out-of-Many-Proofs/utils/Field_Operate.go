package utils

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

//map the number into Zp field
func Mod_Zp(num *big.Int, curve *secp256k1.KoblitzCurve) *big.Int {
	temp := big.NewInt(0)
	return num.Mod(num, temp.Sub(curve.P, big.NewInt(1)))
}

// Determine whether a number is in Zp, if it is greater than p-1, return 1; less than 0, return -1; in Zp, return 0
func Is_In_Zp(num *big.Int, curve *secp256k1.KoblitzCurve) int {
	if num.Cmp(curve.P) >= 0 {
		return 1
	}
	if num.Cmp(big.NewInt(0)) < 0 {
		return -1
	}
	return 0
}

// Add operation in Zp field
func Add_In_P(a *big.Int, b *big.Int) *big.Int {
	var m, n secp256k1.ModNScalar
	c := big.NewInt(0)

	m.SetByteSlice(a.Bytes())
	n.SetByteSlice(b.Bytes())

	m.Add(&n)
	mbyte := m.Bytes()
	c.SetBytes(mbyte[0:32])
	return c
}

// Multiple operation in Zp field
func Mul_In_P(a *big.Int, b *big.Int) *big.Int {
	var m, n secp256k1.ModNScalar
	c := big.NewInt(0)

	m.SetByteSlice(a.Bytes())
	n.SetByteSlice(b.Bytes())

	m.Mul(&n)
	mbyte := m.Bytes()
	c.SetBytes(mbyte[0:32])
	return c
}

// Inverse operation in Zp field
func Inverse_Zp(a *big.Int) *big.Int {
	var m secp256k1.ModNScalar
	b := big.NewInt(0)
	m.SetByteSlice(a.Bytes())
	m.InverseNonConst()
	mbyte := m.Bytes()
	b.SetBytes(mbyte[0:32])
	return b
}

// Inverse operation of bytes
func Neg_Byte(a byte) *big.Int {
	var m secp256k1.ModNScalar
	b := big.NewInt(0)
	m.SetInt(uint32(a))
	m.Negate()
	mbyte := m.Bytes()
	b.SetBytes(mbyte[0:32])
	return b
}

// Negate operation in Zp
func Neg_Zp(a *big.Int) *big.Int {
	var m secp256k1.ModNScalar
	b := big.NewInt(0)
	m.SetByteSlice(a.Bytes())
	m.Negate()
	mbyte := m.Bytes()
	b.SetBytes(mbyte[0:32])
	return b

}

// Multiple operation in Zp field
func Sub_In_P(a *big.Int, b *big.Int) *big.Int {
	var m, n secp256k1.ModNScalar
	c := big.NewInt(0)
	nb := Neg_Zp(b)

	m.SetByteSlice(a.Bytes())
	n.SetByteSlice(nb.Bytes())

	m.Add(&n)
	mbyte := m.Bytes()
	c.SetBytes(mbyte[0:32])
	return c
}
