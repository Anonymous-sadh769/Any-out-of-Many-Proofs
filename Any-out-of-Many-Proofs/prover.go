package main

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"

	"github.com/egoistzty/Code-Any-out-of-Many.git/utils"
)

type Prover struct {
	///////////////////////////////public parameters:
	Public_ck            utils.Point   // generator as commitment key for public keys
	Gen_u, Gen_v         utils.Point   // generators u,v
	Gen_Vec_G, Gen_Vec_H []utils.Point // generator vector g h
	Pub_Vec_Key          []utils.Point // public key vector i.e., ring set

	A, B      utils.Point // commitments A, B
	T1, T2, E utils.Point // commitments T1, T2, E

	N     int                     // ring size N
	curve *secp256k1.KoblitzCurve // elliptic curve

	/////////////////////////////////private parameters:
	k           int        // secret number
	sec_Vec_Key []*big.Int // secrets

	//binary vector and corresponding randomness
	b_0 []*big.Int
	b_1 []*big.Int
	s_0 []*big.Int
	s_1 []*big.Int

	// masking value
	r_s   *big.Int
	alpha *big.Int
	beta  *big.Int

	// intemediate values zeta, eta, t1, t2 and corresponding randomness
	t_1, t_2 *big.Int
	tau_1    *big.Int
	tau_2    *big.Int

	// challenge values
	y, z *big.Int
	x    *big.Int

	// parameters for response
	eta, zeta []*big.Int
	ip        *big.Int
	tau_x     *big.Int
	mu        *big.Int
	f_s       *big.Int

	// constant parameters
	yN  []*big.Int // vector y^N = (y^1,...,y^N)
	z1N []*big.Int // vector z \cdot 1^N = (z^1,...,z^N)
}

type ProverZKP struct {
	tau_x     *big.Int
	mu        *big.Int
	eta, zeta []*big.Int
	ip        *big.Int
	f_s       *big.Int
}

// Initialization function
func (prover *Prover) New(Public_ck utils.Point, G utils.Point, U utils.Point, V utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, k int, N int, curve secp256k1.KoblitzCurve) {
	prover.Public_ck = Public_ck
	prover.Gen_u = U
	prover.Gen_v = V
	prover.Gen_Vec_G = G_Vector[:N]
	prover.Gen_Vec_H = H_Vector[:N]
	prover.k = k
	prover.N = N
	prover.curve = &curve
	//Generate secrets of prover
	prover.sec_Vec_Key = utils.Generate_Random_Zp_Vector(k)
	fmt.Println("secret vector:", prover.sec_Vec_Key)
}

////////////////////////Public interfaces

//Get Commitments A,B
func (prover *Prover) GetAB() (utils.Point, utils.Point) {
	prover.generateKey()
	prover.generateCom()
	return prover.A, prover.B
}

//Get Commitments T1,T2
func (prover *Prover) GetT() (utils.Point, utils.Point, utils.Point) {
	prover.calculateT()
	prover.calculateE()
	return prover.T1, prover.T2, prover.E
}

//Get response zeta, eta, t, tau_x, mu, f_s
func (prover *Prover) GetRsp() ([]utils.Point, ProverZKP) {
	prover.calculateLx()
	prover.calculateRx()
	prover.calculateIP()
	prover.calculateMu()
	prover.calculateTaux()
	prover.calculateFs()
	//prover.TestCorrect()
	proverZKP := ProverZKP{
		tau_x: prover.tau_x,
		mu:    prover.mu,
		ip:    prover.ip,
		eta:   prover.eta,
		zeta:  prover.zeta,
		f_s:   prover.f_s,
	}
	return prover.Pub_Vec_Key, proverZKP
}

////////////////////////Private functions
//Generate b_0,b_1,s_0,s_1 and public keys
func (prover *Prover) generateKey() {
	//Generate binary vector b_0 b_1
	prover.b_0, _ = Generate_b_0(prover.k, prover.N)
	prover.b_1 = Generate_b_1(prover.b_0)
	b_0_b_1, _ := utils.Cal_Add_Vec(prover.b_0, prover.b_1)
	i1N := Generate_Scalar_Vector(big.NewInt(1), prover.N)
	b_0_b_1_1N, _ := utils.Cal_Sub_Vec(b_0_b_1, i1N)
	fmt.Println("b_0+1^N-b_1:", b_0_b_1_1N)
	prover.s_0 = utils.Generate_Random_Zp_Vector(prover.N)
	prover.s_1 = utils.Generate_Random_Zp_Vector(prover.N)
	//generate key
	prover.Pub_Vec_Key = Generate_Multi_Public_Key(prover.k, prover.N, prover.b_0, prover.curve) //generate public key vector Y
}

//Generate Commitments A,B,C,D
func (prover *Prover) generateCom() {

	//Generate commitment A
	prover.alpha = utils.Generate_Random_Zp()
	g_b0_h_b1 := utils.Pedersen_Commit_Vector(prover.Gen_Vec_G, prover.Gen_Vec_H, prover.b_0, prover.b_1, prover.curve)
	u_alpha := utils.Commit(prover.Gen_u, prover.alpha, prover.curve)
	prover.A.X, prover.A.Y = prover.curve.Add(g_b0_h_b1.X, g_b0_h_b1.Y, u_alpha.X, u_alpha.Y)

	//Generate commitment B
	prover.beta = utils.Generate_Random_Zp()
	g_s0_h_s1 := utils.Pedersen_Commit_Vector(prover.Gen_Vec_G, prover.Gen_Vec_H, prover.s_0, prover.s_1, prover.curve)
	u_beta := utils.Commit(prover.Gen_u, prover.beta, prover.curve)
	prover.B.X, prover.B.Y = prover.curve.Add(g_s0_h_s1.X, g_s0_h_s1.Y, u_beta.X, u_beta.Y)
}

//Compute T_1, T_2
func (prover *Prover) calculateT() {
	// Compute the vectors of challenge
	prover.yN = Generate_Exp_Scalar_Vector(prover.y, prover.N)
	prover.z1N = Generate_Scalar_Vector(prover.z, prover.N)

	s0_yN, _ := utils.Cal_HP_Vec(prover.s_0, prover.yN)

	// t1 = <s_0 \circ y^N, z \cdot 1^N + b_1> + <b_0 - z \cdot 1^N, s_1 \circ y^N>
	z_1N_b1, _ := utils.Cal_Add_Vec(prover.z1N, prover.b_1)
	b0_z_1N, _ := utils.Cal_Add_Vec(prover.b_0, prover.z1N)
	s1_yN, _ := utils.Cal_HP_Vec(prover.s_1, prover.yN)

	s0_yN_z_1N_b1, _ := utils.Cal_IP_Vec(s0_yN, z_1N_b1)
	b0_z_1N_s1_yN, _ := utils.Cal_IP_Vec(b0_z_1N, s1_yN)

	prover.t_1 = utils.Add_In_P(s0_yN_z_1N_b1, b0_z_1N_s1_yN)

	//Generate tau2
	prover.tau_1 = utils.Generate_Random_Zp()

	//Compute T1
	prover.T1 = utils.Pedersen_Commit(prover.Gen_v, prover.Gen_u, prover.t_1, prover.tau_1, prover.curve)

	//Compute t2 = <s_0 \circ y^N, s_1>
	prover.t_2, _ = utils.Cal_IP_Vec(s0_yN, prover.s_1)

	//Generate tau2
	prover.tau_2 = utils.Generate_Random_Zp()

	//Compute T2
	prover.T2 = utils.Pedersen_Commit(prover.Gen_v, prover.Gen_u, prover.t_2, prover.tau_2, prover.curve)
}

//Compute commitment E
func (prover *Prover) calculateE() {
	prover.r_s = utils.Generate_Random_Zp()
	yN_s0, _ := utils.Cal_HP_Vec(prover.yN, prover.s_0)
	P_yN_s0 := utils.Commit_Vector(prover.Pub_Vec_Key, yN_s0, prover.curve)
	com_rs := utils.Commit(prover.Public_ck, utils.Neg_Zp(prover.r_s), prover.curve)
	prover.E.X, prover.E.Y = prover.curve.Add(P_yN_s0.X, P_yN_s0.Y, com_rs.X, com_rs.Y)
}

//Compute l(x) i.e., zeta = (b0 + z1^N + s0x) \circ y^N
func (prover *Prover) calculateLx() {
	var lx []*big.Int
	b0_yN, _ := utils.Cal_HP_Vec(prover.b_0, prover.yN)
	z_1N_yN, _ := utils.Cal_HP_Vec(prover.z1N, prover.yN)
	s0_x_yN, _ := utils.Cal_HP_Vec(utils.Cal_Sca_Vec(prover.s_0, prover.x), prover.yN)
	b0_yN_z_1N_yN, _ := utils.Cal_Add_Vec(b0_yN, z_1N_yN)

	lx, _ = utils.Cal_Add_Vec(b0_yN_z_1N_yN, s0_x_yN)
	prover.zeta = lx
}

//Compute r(x) i.e., eta = z1^N + b1 + s1x
func (prover *Prover) calculateRx() {
	var rx []*big.Int
	z_1N := Generate_Scalar_Vector(prover.z, prover.N)
	z_1N_b1, _ := utils.Cal_Add_Vec(z_1N, prover.b_1)
	s1_x := utils.Cal_Sca_Vec(prover.s_1, prover.x)

	rx, _ = utils.Cal_Add_Vec(z_1N_b1, s1_x)
	prover.eta = rx
}

//Compute t = <l(x), r(x)>
func (prover *Prover) calculateIP() {
	//prover.tx = Mod_Zp(Inner_ProofBig(prover.lx, prover.rx),prover.curve)
	prover.ip, _ = utils.Cal_IP_Vec(prover.eta, prover.zeta)
}

//Compute tau_x = tau_1 x + tau_2 x^2
func (prover *Prover) calculateTaux() {
	tau1_x := utils.Mul_In_P(prover.tau_1, prover.x)
	tau2_x2 := utils.Mul_In_P(prover.tau_2, utils.Mul_In_P(prover.x, prover.x))
	prover.tau_x = utils.Add_In_P(tau1_x, tau2_x2)
}

//Compute mu = alpha + beta x
func (prover *Prover) calculateMu() {
	beta_x := utils.Mul_In_P(prover.beta, prover.x)
	prover.mu = utils.Add_In_P(prover.alpha, beta_x)
}

//Compute f_s = \sum y^i s_i
func (prover *Prover) calculateFs() {
	prover.f_s = utils.Mul_In_P(prover.r_s, prover.x)
	yi := big.NewInt(1)
	index := 0
	var yi_si *big.Int
	for i := 0; i < prover.N; i++ {
		if prover.b_0[i].Cmp(big.NewInt(1)) == 0 {
			yi_si = utils.Mul_In_P(yi, prover.sec_Vec_Key[index])
			index = index + 1
		} else {
			yi_si = big.NewInt(0)
		}
		prover.f_s = utils.Add_In_P(prover.f_s, yi_si)
		yi = utils.Mul_In_P(yi, prover.y)
	}
	beta_x := utils.Mul_In_P(prover.beta, prover.x)
	prover.mu = utils.Add_In_P(prover.alpha, beta_x)
}

// func (prover *Prover) TestCorrect() {
// 	// Test CalculateFs
// 	f_ss := utils.Add_In_P(prover.f_s, utils.Neg_Zp(utils.Mul_In_P(prover.r_s, prover.x)))
// 	b_0_yN, _ := utils.Cal_HP_Vec(prover.b_0, prover.yN)
// 	LHS1 := utils.Commit_Vector(prover.Pub_Vec_Key, b_0_yN, prover.curve)
// 	RHS1 := utils.Commit(prover.Public_ck, f_ss, prover.curve)
// 	if utils.Commit_Is_Equal(LHS1, RHS1) {
// 		fmt.Println("Test CalculateFs Succeeds!")
// 	} else {
// 		fmt.Println("Test CalculateFs Fails!")
// 	}

// 	T_1_temp := utils.Commit(prover.Gen_v, prover.t_1, prover.curve)
// 	T_2_temp := utils.Commit(prover.Gen_v, prover.t_2, prover.curve)
// 	var delta *big.Int
// 	z_1N_yN, _ := utils.Cal_HP_Vec(prover.z1N, prover.yN)
// 	n_z_1N_yN := utils.Cal_Neg_Vec(z_1N_yN)
// 	delta, _ = utils.Cal_IP_Vec(n_z_1N_yN, prover.z1N)
// 	LHS2 := utils.Commit(prover.Gen_v, prover.ip, prover.curve)
// 	x2 := utils.Mul_In_P(prover.x, prover.x)
// 	v_delta := utils.Commit(prover.Gen_v, delta, prover.curve)
// 	T1_T2 := utils.Pedersen_Commit(T_1_temp, T_2_temp, prover.x, x2, prover.curve)
// 	var RHS2 utils.Point
// 	RHS2.X, RHS2.Y = prover.curve.Add(v_delta.X, v_delta.Y, T1_T2.X, T1_T2.Y)
// 	if utils.Commit_Is_Equal(LHS2, RHS2) {
// 		fmt.Println("Test CalculateT Succeeds!")
// 	} else {
// 		fmt.Println("Test CalculateT Fails!")
// 	}
// }
