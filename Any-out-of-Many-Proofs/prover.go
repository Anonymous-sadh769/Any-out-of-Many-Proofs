package main

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

type Prover struct {
	//public pb_1ameters:
	//generator G,U,V
	//generator vector P_Vector, H_Vector
	//ring set size N

	Public_g, G, U, V  Point
	P_Vector, H_Vector []Point
	N                  int64
	curve              *secp256k1.KoblitzCurve

	//k is number of secrets
	//D_Vector is the commitment of r_s
	k        int64
	s_vector []byte //private vector
	D_Vector []Point
	r_alpha  byte

	//pb_1ameters relative to Commitment A,B,C
	b_0        []*big.Int
	b_1        []*big.Int
	s_0        []*big.Int
	s_1        []*big.Int
	r_s        []*big.Int
	A, B, C, D Point
	alpha      byte
	beta       byte
	gama       byte

	//pb_1ameters relative to Commitment T_1, T_2
	y, z, d  byte
	c        byte
	tau1     byte
	tau2     byte
	t_1, t_2 *big.Int
	T_1, T_2 Point

	//零知识证明阶段的相关参数/////////////////////////////////////////////
	x         int
	rho       byte
	eta, zeta []*big.Int
	tx        *big.Int
	taux      *big.Int
	mju       *big.Int
}

type ProverZKP struct {
	taux      *big.Int
	mju       *big.Int
	eta, zeta []*big.Int
	tx        *big.Int
}

func (prover *Prover) New(Public_g Point, G Point, U Point, V Point, H_Vector []Point, k int64, N int64, curve secp256k1.KoblitzCurve) error {

	prover.Public_g = Public_g
	prover.G = G
	prover.U = U
	prover.V = V
	prover.H_Vector = H_Vector[:N]
	prover.k = k
	prover.N = N
	prover.curve = &curve
	//Generate secrets of prover
	prover.s_vector = GenerateRandomVector(int(k))
	fmt.Println("secret vector:", prover.s_vector)
	return nil
}

//Get Commitment A,B,C,D
func (prover *Prover) GetCom() (Point, Point, Point, Point) {
	prover.generateKey()
	prover.generateCom()
	return prover.A, prover.B, prover.C, prover.D
}

//generate key
func (prover *Prover) generateKey() {
	err := errors.New("")

	//生成b_0,b_1两个矢量
	prover.b_0, err = Generate_b_0(prover.k, prover.N)
	if err != nil {
		fmt.Println(err)
		return
	}
	prover.b_1 = Generate_b_1(prover.b_0)
	prover.P_Vector = GenerateMultiPublicKey(prover.k, prover.N, prover.b_0) //generate public key vector Y
}

//Generate random b_0,b_1,s_0,s_1 and corresponding Commitment A,B,C,D
func (prover *Prover) generateCom() {

	//Generate commitment A
	prover.alpha = GenerateRandom(0)
	commit_A := CommitSingleVector(prover.P_Vector, prover.b_0)
	commit_Alpha := CommitSingle(prover.U, []byte{prover.alpha})
	prover.A.x, prover.A.y = curve.Add(commit_A.x, commit_A.y, commit_Alpha.x, commit_Alpha.y)

	//Generate commitment B
	prover.beta = GenerateRandom(0)
	commit_B := CommitSingleVector(prover.P_Vector, prover.b_1)
	commit_Beta := CommitSingle(prover.U, []byte{prover.beta})
	prover.B.x, prover.B.y = curve.Add(commit_B.x, commit_B.y, commit_Beta.x, commit_Beta.y)

	//Generate commitment C
	prover.gama = GenerateRandom(0)
	prover.s_0 = GenerateS(prover.N, 1)
	prover.s_1 = GenerateS(prover.N, 2)
	commit_C := CommitVectors(prover.P_Vector, prover.H_Vector, prover.s_0, prover.s_1)
	commit_Gama := CommitSingle(prover.U, []byte{prover.gama})
	prover.C.x, prover.C.y = curve.Add(commit_C.x, commit_C.y, commit_Gama.x, commit_Gama.y)

	//Generate commitment D
	prover.r_alpha = GenerateRandom(0)
	prover.r_s = GenerateS(prover.N, 0)
	var Public_g_vector []Point
	for i := 0; i < int(prover.N); i++ {
		Public_g_vector = append(Public_g_vector, prover.Public_g)
	}
	commit_D := CommitSingleVector(Public_g_vector, prover.r_s)
	commit_r_alpha := CommitSingle(prover.U, []byte{prover.r_alpha})
	prover.D.x, prover.D.y = curve.Add(commit_D.x, commit_D.y, commit_r_alpha.x, commit_r_alpha.y)
}

//Compute T_1, T_2
func (prover *Prover) calculateT() {
	Vector_y_N := Generate_Scalar_Vector(prover.y, prover.N) //y的N维向量：y^1,y^2,...,y^N
	Vector_1_N := Generate_Scalar_Vector(1, prover.N)
	s1_YN := Cal_Hadamard_Vector_Big(prover.s_1, Vector_y_N)

	//Compute t2
	//prover.t2 = PutInP(Inner_ProofBig(prover.sL, srYn),prover.curve)
	prover.t_2 = Inner_Product_Big(prover.s_0, s1_YN)
	//生成tau2
	prover.tau2 = GenerateRandom(0)

	//计算t1
	sum := big.NewInt(0)

	//t1的第一项
	s0_yN := Inner_Product_Big(prover.s_0, Vector_y_N)
	t11 := mulInP(big.NewInt(int64(prover.z)), s0_yN)

	//t1的第二项
	s0_yN_b1 := Inner_Product_Big(prover.s_0, Cal_Hadamard_Vector_Big(Vector_y_N, prover.b_1))
	t12 := mulInP(big.NewInt(int64(prover.d)), s0_yN_b1)

	//t1的第三项
	s1_yN := Cal_Hadamard_Vector_Big(Vector_y_N, prover.s_1)
	t13 := Inner_Product_Big(prover.b_0, s1_yN)

	//t1的第四项
	s1_yN_1N := Inner_Product_Big(Vector_1_N, s1_yN)
	t14 := mulInP(big.NewInt(int64(prover.z)), s1_yN_1N)

	sum = addInP(addInP(t11, t12), addInP(t13, t14))
	//prover.t1 = PutInP(sum,prover.curve)
	prover.t_1 = sum
	//生成tau1
	prover.tau1 = GenerateRandom(0)
}

//用于获取承诺T1,T2
func (prover *Prover) GetT() (Point, Point) {
	prover.generateT()
	return prover.T_1, prover.T_2
}

//生成T1,T2两个承诺
func (prover *Prover) generateT() {
	prover.calculateT()
	prover.T_2 = Commit(prover.U, prover.V, prover.t_2.Bytes(), big.NewInt(int64(prover.tau2)).Bytes())
	prover.T_1 = Commit(prover.U, prover.V, prover.t_1.Bytes(), big.NewInt(int64(prover.tau1)).Bytes())
}

//Compute l(x) zeta
func (prover *Prover) calculateLx() {
	var lx []*big.Int
	lx = CalVectorAdd(CalVectorSubByte(prover.b_0, GenerateZ(prover.z, prover.N)), CalVectorTimes(prover.s_0, int64(prover.x)))
	prover.eta = lx
}

//Compute r(x) eta
func (prover *Prover) calculateRx() {
	var rx []*big.Int
	yn := Generate_Scalar_Vector(prover.y, prover.N)
	y2n := Generate_Scalar_Vector(2, prover.N)

	rx = CalVectorAdd(Cal_Hadamard_Vector_Big(yn, CalVectorAdd(prover.b_1, CalVectorAddByte(CalVectorTimes(prover.s_1, int64(prover.x)), GenerateZ(prover.z, prover.N)))), CalVectorTimes(y2n, int64(prover.z)*int64(prover.z)))
	prover.zeta = rx
}

//计算t(x)的值，即<l(x),r(x)>
func (prover *Prover) calculateTx() {
	//prover.tx = PutInP(Inner_ProofBig(prover.lx, prover.rx),prover.curve)
	prover.tx = Inner_Product_Big(prover.eta, prover.zeta)
}

//计算taux的值
func (prover *Prover) calculateTaux() {
	taux := big.NewInt(0)
	x2 := big.NewInt(0)
	taux = addInP(mulInP(big.NewInt(int64(prover.tau2)), x2.Mul(big.NewInt(int64(prover.x)), big.NewInt(int64(prover.x)))), mulInP(big.NewInt(int64(prover.tau1)), big.NewInt(int64(prover.x))))
	prover.rho = GenerateRandom(0)
	taux = addInP(taux, mulInP(big.NewInt(int64(prover.z)*int64(prover.z)), big.NewInt(int64(prover.rho))))
	prover.taux = taux
	//prover.taux = big.NewInt(1)
}

//计算mju值
func (prover *Prover) calculateMju() {
	//prover.mju = PutInP(big.NewInt(int64(prover.alpha) + int64(prover.rho)*int64(prover.x)),prover.curve)
	prover.mju = addInP(big.NewInt(int64(prover.alpha)), mulInP(big.NewInt(int64(prover.rho)), big.NewInt(int64(prover.x))))
}

func (prover *Prover) GetProverZKP() ProverZKP {
	prover.calculateMju()
	prover.calculateTaux()
	prover.calculateLx()
	prover.calculateRx()
	prover.calculateTx()

	proverZKP := ProverZKP{
		taux: prover.taux,
		mju:  prover.mju,
		tx:   prover.tx,
		eta:  prover.eta,
		zeta: prover.zeta,
	}
	return proverZKP
}
