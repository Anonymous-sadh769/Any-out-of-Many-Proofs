package omniring

import (
	"crypto/sha256"
	"math/big"

	"anyOutOfMany/utils"
)

const q = 256

type Transcript struct {
	A         utils.Point
	B         utils.Point
	T1        utils.Point
	T2        utils.Point
	Tau_x     *big.Int
	Mu        *big.Int
	Eta, Zeta []*big.Int
	Ip        *big.Int
	L, R      []utils.Point
	W         *big.Int
	X         *big.Int
	Y         *big.Int
	Z         *big.Int
}

//Generete vector b_0 for partial knowledge proofs

func Generate_b_0(k int, N int) ([]*big.Int, error) {

	var b_0 []*big.Int

	//generate a zero vector
	for j := 0; j < N; j++ {
		b_0 = append(b_0, big.NewInt(0))
	}

	n := N / k
	counter := 0
	//Generate N-length binary vector with one "1" in each n-length subvector
	for i := 0; i < k; i++ {
		temp := utils.Generate_Random_Zp(q)
		var rand big.Int
		rand.Mod(temp, big.NewInt(int64(n)))
		index := rand.Int64()
		b_0[index+int64(counter*n)] = big.NewInt(1)
		counter++
	}
	return b_0, nil
}

//Generete vector b_1 according to b_0
func Generate_b_1(b_0 []*big.Int) (b_1 []*big.Int) {
	for i := 0; i < len(b_0); i++ {
		b_1 = append(b_1, utils.Sub_In_P(big.NewInt(1), b_0[i]))
	}
	return b_1
}

//Generete constant vector
func Generate_cons_vec(n int, c *big.Int) []*big.Int {
	var zero []*big.Int
	for i := 0; i < n; i++ {
		zero = append(zero, c)
	}
	return zero
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

func Generate_Inverse_H(H []utils.Point, y *big.Int, n int) []utils.Point {
	yn := Generate_Scalar_Vector(y, n)
	var h1 []utils.Point
	for key, value := range H {
		var point utils.Point
		point.X, point.Y = utils.Curve.ScalarMult(value.X, value.Y, utils.Inverse_Zp(yn[key]).Bytes())
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

func (prover *Prover) Generate_Multi_Public_Key(k, N int, bit []*big.Int) []utils.Point {
	var public_key []utils.Point
	var num1, num2 int
	n := N / k
	fake_secret_key := utils.Generate_Random_Zp_Vector(int(N-k), q)
	for i := 0; i < int(n); i++ {
		if bit[i].Cmp(big.NewInt(0)) == 0 {
			secret_key := fake_secret_key[num1]
			num1++
			public_key = append(public_key, utils.Commit(prover.Gen_H, secret_key))
		}
		if bit[i].Cmp(big.NewInt(1)) == 0 {
			secret_key := prover.sec_Vec_Key[num2]
			num2++
			public_key = append(public_key, utils.Commit(prover.Gen_H, secret_key))
		}
	}
	return public_key
}

func (prover *Prover) Generate_Multi_Public_Coin(k, N int, bit []*big.Int) []utils.Point {
	var public_coin []utils.Point
	num1, num2 := 0, 0
	fake_secret_value := utils.Generate_Random_Zp_Vector(int(N-k), q)
	fake_secret_random := utils.Generate_Random_Zp_Vector(int(N-k), q)
	for i := 0; i < int(N); i++ {
		if bit[i].Cmp(big.NewInt(0)) == 0 {
			secret_key := fake_secret_value[num1]
			secret_random := fake_secret_random[num1]
			public_coin = append(public_coin, utils.Pedersen_Commit(prover.Gen_G, prover.Gen_H, secret_key, secret_random))
			num1++
		}
		if bit[i].Cmp(big.NewInt(1)) == 0 {
			secret_key := prover.sec_Vec_Key[num2]
			secret_random := prover.sec_Vec_Random[num2]
			public_coin = append(public_coin, utils.Pedersen_Commit(prover.Gen_G, prover.Gen_H, secret_key, secret_random))
			num2++
		}
	}
	return public_coin
}

// Generate challenge
func Generate_YZ(A utils.Point, B utils.Point) (*big.Int, *big.Int) {
	AB1 := utils.Cal_Point_Add(A, utils.Cal_Point_Sca(B, big.NewInt(1)))
	AB2 := utils.Cal_Point_Add(A, utils.Cal_Point_Sca(B, big.NewInt(2)))
	y32 := sha256.Sum256(AB1.Point2Bytes())
	y := big.NewInt(0).SetBytes(y32[:])
	z32 := sha256.Sum256(AB2.Point2Bytes())
	z := big.NewInt(0).SetBytes(z32[:])
	return y, z
}

func Generate_X(T1 utils.Point, T2 utils.Point) *big.Int {
	T1T2 := utils.Cal_Point_Add(T1, T2)
	x32 := sha256.Sum256(T1T2.Point2Bytes())
	x := big.NewInt(0).SetBytes(x32[:])
	return x
}

func Generate_W(A utils.Point) *big.Int {
	x32 := sha256.Sum256(A.Point2Bytes())
	x := big.NewInt(0).SetBytes(x32[:])
	return x
}
