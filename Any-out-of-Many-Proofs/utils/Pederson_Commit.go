package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

// Generate Commitment: Com(m) = m*G
func Commit(G Point, secret *big.Int, curve *secp256k1.KoblitzCurve) Point {
	var com Point
	com.X, com.Y = curve.ScalarMult(G.X, G.Y, secret.Bytes())
	return com
}

// Generate Perdersen Commitment: Com(m,r) = m*G + r*H
func Pedersen_Commit(G Point, H Point, secret *big.Int, random *big.Int, curve *secp256k1.KoblitzCurve) Point {
	var com Point
	com1 := Commit(G, secret, curve)
	com2 := Commit(H, random, curve)
	com.X, com.Y = curve.Add(com1.X, com1.Y, com2.X, com2.Y)
	return com
}

// Generate Perdersen Vector Commitment
func Commit_Vector(G_vector []Point, secret []*big.Int, curve *secp256k1.KoblitzCurve) Point {
	com := Commit(G_vector[0], secret[0], curve)
	for i := 1; i < len(G_vector); i++ {
		commitArray := Commit(G_vector[i], secret[i], curve)
		com.X, com.Y = curve.Add(com.X, com.Y, commitArray.X, commitArray.Y)
	}
	return com
}

// Generate Perdersen Vector Commitment
func Pedersen_Commit_Vector(G_vector []Point, H_vector []Point, secret []*big.Int, random []*big.Int, curve *secp256k1.KoblitzCurve) Point {
	com := Pedersen_Commit(G_vector[0], H_vector[0], secret[0], random[0], curve)
	for i := 1; i < len(G_vector); i++ {
		commitArray := Pedersen_Commit(G_vector[i], H_vector[i], secret[i], random[i], curve)
		com.X, com.Y = curve.Add(com.X, com.Y, commitArray.X, commitArray.Y)
	}
	return com
}

//Check the equality of two commitments
func Commit_Is_Equal(com0 Point, com1 Point) bool {
	if com0.X.Cmp(com1.X) == 0 && com0.Y.Cmp(com1.Y) == 0 {
		return true
	}
	return false
}

//Generate random Zp element
func Generate_Random_Zp() *big.Int {
	//Max random value, a 130-bits integer, i.e 2^130 - 1
	max := big.NewInt(0)
	var R *big.Int
	max.Exp(big.NewInt(2), big.NewInt(130), nil)
	max.Sub(max, big.NewInt(1))
	//Generate cryptographically strong pseudo-random between 0 - max
	R, err := rand.Int(rand.Reader, max)
	if err != nil {
		fmt.Println("Failed to generate random Zp.")
		return nil
	}
	return R
}

//Generate random vector big.Int
func Generate_Random_Zp_Vector(n int) []*big.Int {
	var rand_vector []*big.Int
	for i := 0; i < n; i++ {
		rand_vector = append(rand_vector, Generate_Random_Zp())
	}
	return rand_vector
}
