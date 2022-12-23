package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/egoistzty/Code-Any-out-of-Many.git/utils"
)

func prove(a []*big.Int, b []*big.Int) ([]*big.Int, []*big.Int, *big.Int, []*big.Int, []*big.Int) {
	fmt.Println("Start Prove Algorithm...")
	//Parameters
	var L []*big.Int // store all L values in each round
	var R []*big.Int // store all R values in each round
	// Generate initial challenge value
	temp := big.NewInt(114514)
	var x32 [32]byte
	var x []byte
	l := len(a)
	x32 = sha256.Sum256(temp.Bytes())
	// Compute the inner product t of original vectors <a,b>=t
	t, _ := utils.Cal_IP_Vec(a, b)
	counter := 0
	// Recursive Reduction Algorithm
	for l > 1 {
		counter++
		if l != len(b) {
			fmt.Println("Error: vectors in different size!")
		} else if l > 2 {
			// Write a_L, a_R, b_L, b_R
			a_L := a[0 : l/2]
			a_R := a[l/2 : l]
			b_L := b[0 : l/2]
			b_R := b[l/2 : l]
			// Calculate L, R
			temp, _ = utils.Cal_IP_Vec(a_L, b_R)
			L = append(L, temp)
			temp, _ = utils.Cal_IP_Vec(a_R, b_L)
			R = append(R, temp)
			// Calculate reduced vectors a', b'
			x = x32[:]
			a, _ = utils.Cal_Add_Vec(utils.Cal_Sca_Vec(a_L, big.NewInt(0).SetBytes(x)), a_R)
			b, _ = utils.Cal_Add_Vec(utils.Cal_Sca_Vec(b_R, big.NewInt(0).SetBytes(x)), b_L)
			// Update challege x with Fiat-Shamir
			temp = utils.Mul_In_P(L[len(L)-1], R[len(R)-1])
			x32 = sha256.Sum256(temp.Bytes())
			fmt.Println("Round", counter, "Completes!")
		} else {
			// The final round reducing vector to size 1
			a_L := a[0 : l/2]
			a_R := a[l/2 : l]
			b_L := b[0 : l/2]
			b_R := b[l/2 : l]
			temp, _ = utils.Cal_IP_Vec(a_L, b_R)
			L = append(L, temp)
			temp, _ = utils.Cal_IP_Vec(a_R, b_L)
			R = append(R, temp)
			a, _ = utils.Cal_Add_Vec(utils.Cal_Sca_Vec(a_L, big.NewInt(0).SetBytes(x)), a_R)
			b, _ = utils.Cal_Add_Vec(utils.Cal_Sca_Vec(b_R, big.NewInt(0).SetBytes(x)), b_L)
			fmt.Println("Round", counter, "Completes!")
			fmt.Println("Algorithm Completes!")
		}
		// update length l after each round
		l = len(a)
	}
	// return transcript to verify algorithm
	return L, R, t, a, b
}

func verify(L []*big.Int, R []*big.Int, t *big.Int, a []*big.Int, b []*big.Int) {
	fmt.Println("Start Verify Algorithm...")
	//Parameters
	res, _ := utils.Cal_IP_Vec(a, b) //inner product of compressed vectors
	l := len(R)
	// Generate initial challenge value
	temp := big.NewInt(114514)
	x32 := sha256.Sum256(temp.Bytes())
	x := x32[:]
	counter := 0
	var t1, t2, t12 *big.Int
	// Recursive Verification Algorithm
	for i := 0; i < l; i++ {
		counter++
		fmt.Println("Round", counter, "Completes!")
		// Compute t' = x^2 L + x t + R
		x2 := utils.Mul_In_P(big.NewInt(0).SetBytes(x), big.NewInt(0).SetBytes(x))
		t1 = utils.Mul_In_P(x2, L[i])
		t2 = utils.Mul_In_P(t, big.NewInt(0).SetBytes(x))
		t12 = utils.Add_In_P(t1, t2)
		t = utils.Add_In_P(t12, R[i])
		// Update challege x with Fiat-Shamir
		if i < l-1 {
			temp = utils.Mul_In_P(L[i], R[i])
			x32 = sha256.Sum256(temp.Bytes())
			x = x32[:]
		}
	}
	// Print the result of verification
	if res.Cmp(t) == 0 {
		fmt.Println("Verfication Passes!")
	} else {
		fmt.Println("Verfication Fails!")
	}
}
