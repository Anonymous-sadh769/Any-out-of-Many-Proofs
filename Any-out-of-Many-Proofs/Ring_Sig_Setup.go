package main

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/egoistzty/Code-Any-out-of-Many.git/utils"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

//Generete vector b_0 for partial knowledge proofs

func Generate_b_0(k int, N int) ([]*big.Int, error) {

	var b_0 []*big.Int

	//Ensure k<=N
	if k > N {
		return nil, errors.New("the secret number should not be bigger than ring set")
	}

	//generate a zero vector
	for j := 0; j < N; j++ {
		b_0 = append(b_0, big.NewInt(0))
	}

	//Generate N-length binary vector with k "1"
	for i := 0; i < k; i++ {
		temp := utils.Generate_Random_Zp()
		var rand big.Int
		rand.Mod(temp, big.NewInt(int64(N)))
		index := rand.Int64()
		if b_0[index].Cmp(big.NewInt(0)) == 0 {
			b_0[index] = big.NewInt(1)
		} else {
			i = i - 1
		}
	}
	fmt.Println("Generate N-length b_0 with k bits of 1 as:", b_0)
	return b_0, nil
}

//Generete vector b_1 according to b_0
func Generate_b_1(b_0 []*big.Int) (b_1 []*big.Int) {
	for i := 0; i < len(b_0); i++ {
		b_1 = append(b_1, utils.Sub_In_P(big.NewInt(1), b_0[i]))
	}
	return b_1
}

//Generete exponential scalar vector y^n = (y^1,...,y^n)
func Generate_Exp_Scalar_Vector(y *big.Int, n int) []*big.Int {
	var Scalar_Vector []*big.Int
	Scalar_Vector = append(Scalar_Vector, big.NewInt(1))
	for i := 1; i < n; i++ {
		Scalar_Vector = append(Scalar_Vector, utils.Mul_In_P(Scalar_Vector[i-1], y))
	}
	return Scalar_Vector
}

//Generete scalar vector z*1^n = (z,...,z)
func Generate_Scalar_Vector(z *big.Int, n int) []*big.Int {
	var Scalar_Vector []*big.Int
	for i := n; i > 0; i-- {
		Scalar_Vector = append(Scalar_Vector, z)
	}
	return Scalar_Vector
}

// //Generate random value (byte)
// func Generate_Random_Byte(r int) []byte {
// 	max := big.NewInt(255)
// 	//Generate cryptographically strong pseudo-random between 0 - max
// 	R, err := rand.Int(rand.Reader, max)
// 	if err != nil {
// 		fmt.Println("Failed to generate random Zp.")
// 		return nil
// 	}
// 	return R.Bytes()
// }

func Generate_Inverse_H(H []utils.Point, y *big.Int, n int, curve *secp256k1.KoblitzCurve) []utils.Point {
	yn := Generate_Scalar_Vector(y, n)
	var h1 []utils.Point
	for key, value := range H {
		var point utils.Point
		point.X, point.Y = curve.ScalarMult(value.X, value.Y, utils.Inverse_Zp(yn[key]).Bytes())
		h1 = append(h1, point)
	}
	return h1
}

//Generate the negative vector of Z
func Generate_neg_z_Vector(z byte, n int) []*big.Int {
	var zn []*big.Int
	for i := n; i > 0; i-- {
		zn = append(zn, utils.Neg_Byte(z))
	}
	return zn
}

func Generate_Multi_Public_Key(k, N int, bit []*big.Int, curve *secp256k1.KoblitzCurve) []utils.Point {
	var public_key []utils.Point
	var num1, num2 int
	fake_secret_key := utils.Generate_Random_Zp_Vector(int(N - k))
	for i := 0; i < int(N); i++ {
		if bit[i].Cmp(big.NewInt(0)) == 0 {
			secret_key := fake_secret_key[num1]
			num1++
			public_key = append(public_key, utils.Commit(prover.Public_ck, secret_key, curve))
		}
		if bit[i].Cmp(big.NewInt(1)) == 0 {
			secret_key := prover.sec_Vec_Key[num2]
			num2++
			public_key = append(public_key, utils.Commit(prover.Public_ck, secret_key, curve))
		}
	}
	return public_key
}
