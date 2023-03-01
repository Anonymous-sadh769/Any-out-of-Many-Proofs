package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Generate Commitment: Com(m) = m*G
func Commit(G Point, secret *big.Int) Point {
	var com Point
	com.X, com.Y = Curve.ScalarMult(G.X, G.Y, secret.Bytes())
	return com
}

// Generate Perdersen Commitment: Com(m,r) = m*G + r*H
func Pedersen_Commit(G Point, H Point, secret *big.Int, random *big.Int) Point {
	var com Point
	com1 := Commit(G, secret)
	com2 := Commit(H, random)
	com.X, com.Y = Curve.Add(com1.X, com1.Y, com2.X, com2.Y)
	return com
}

// Generate Perdersen Vector Commitment
func Commit_Vector(G_vector []Point, secret []*big.Int) Point {
	com := Commit(G_vector[0], secret[0])
	for i := 1; i < len(G_vector); i++ {
		commitArray := Commit(G_vector[i], secret[i])
		com.X, com.Y = Curve.Add(com.X, com.Y, commitArray.X, commitArray.Y)
	}
	return com
}

// Generate Perdersen Vector Commitment
func Pedersen_Commit_Vector(G_vector []Point, H_vector []Point, secret []*big.Int, random []*big.Int) Point {
	com := Pedersen_Commit(G_vector[0], H_vector[0], secret[0], random[0])
	if len(G_vector) == 1 {
		return com
	} else {
		for i := 1; i < len(G_vector); i++ {
			commitArray := Pedersen_Commit(G_vector[i], H_vector[i], secret[i], random[i])
			com.X, com.Y = Curve.Add(com.X, com.Y, commitArray.X, commitArray.Y)
		}
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
func Generate_Random_Zp(d int) *big.Int {
	//Max random value, a 130-bits integer, i.e 2^130 - 1
	max := big.NewInt(0)
	var R *big.Int
	max.Exp(big.NewInt(2), big.NewInt(int64(d)), nil)
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
func Generate_Random_Zp_Vector(n int, d int) []*big.Int {
	var rand_vector []*big.Int
	for i := 0; i < n; i++ {
		rand_vector = append(rand_vector, Generate_Random_Zp(d))
	}
	return rand_vector
}

func Generate_Point_Vector_with_y(vec []Point, yN []*big.Int) []Point {
	var res []Point
	for i := 0; i < len(yN); i++ {
		res = append(res, Commit(vec[i], yN[i]))
	}
	return res
}
