package range_proofs

import (
	"crypto/sha256"
	"math/big"
	"math/rand"
	"time"

	"anyOutOfMany/utils"
)

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
	X         *big.Int
	Y         *big.Int
	Z         *big.Int
}

//Generete vector b_0 for partial knowledge proofs

func Generate_b_0(d int) []*big.Int {

	var b_0 []*big.Int

	for j := 0; j < d; j++ {
		rand.Seed(time.Now().Unix() + int64(j)) // unix 时间戳，秒
		data := rand.Int63n(2)
		b_0 = append(b_0, big.NewInt(data))
	}

	return b_0
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

func Generate_Public_Coin(g utils.Point, h utils.Point, d int, bit []*big.Int, gamma *big.Int) utils.Point {
	var public_coin utils.Point
	weight := big.NewInt(1)
	value := big.NewInt(0)
	for i := 0; i < len(bit); i++ {
		value = utils.Add_In_P(value, utils.Mul_In_P(bit[i], weight))
		weight = utils.Mul_In_P(weight, big.NewInt(2))
	}
	public_coin = utils.Pedersen_Commit(g, h, value, gamma)
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
