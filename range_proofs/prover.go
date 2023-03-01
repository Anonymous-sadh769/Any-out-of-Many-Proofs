package range_proofs

import (
	"math/big"

	"anyOutOfMany/utils"
)

const q = 256

type Prover struct {
	///////////////////////////////public parameters:
	Gen_g, Gen_h         utils.Point   // generators u,v
	Gen_Vec_G, Gen_Vec_H []utils.Point // generator vector g h
	Pub_Coin             utils.Point   // public key vector i.e., ring set

	A, B   utils.Point   // commitments A, B
	T1, T2 utils.Point   // commitments T, T1, T2, E
	L, R   []utils.Point // auxiliary commitments L,R

	D int // value width d
	/////////////////////////////////private parameters:
	sec_value *big.Int // secrets

	//binary vector and corresponding randomness
	b_0 []*big.Int
	b_1 []*big.Int
	s_0 []*big.Int
	s_1 []*big.Int

	// masking value
	alpha *big.Int
	beta  *big.Int
	gamma *big.Int

	// intemediate values zeta, eta, t1, t2 and corresponding randomness
	t_1, t_2 *big.Int
	tau_1    *big.Int
	tau_2    *big.Int

	// challenge values
	y, z *big.Int
	x    *big.Int

	// parameters for response
	zeta, eta, c_zeta, c_eta []*big.Int
	tau_x                    *big.Int
	mu                       *big.Int
	ip                       *big.Int

	// constant parameters
	yN     []*big.Int // vector y^N = (y^1,...,y^N)
	z1N    []*big.Int // vector z \cdot 1^N = (z^1,...,z^N)
	vec_2N []*big.Int
}

// Initialization function
func (prover *Prover) New(G utils.Point, H utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, d int) {
	prover.Gen_g = G
	prover.Gen_h = H
	prover.Gen_Vec_G = G_Vector
	prover.Gen_Vec_H = H_Vector
	prover.D = d
	//Generate secrets of prover
	prover.sec_value = utils.Generate_Random_Zp(d)
	prover.generateCoin()
}

////////////////////////Public interfaces

//Get response zeta, eta, t, tau_x, mu, f_s
func (prover *Prover) GenerateRsp() (utils.Point, Transcript) {

	//prover computes Commitments A, B
	prover.calculateAB()

	//prover generates challenges y,z
	prover.y, prover.z = Generate_YZ(prover.A, prover.B)

	//prover compute Commitments T1, T2
	prover.calculateT()

	//verifier get T1, T2, E and transmit x to prover
	prover.x = Generate_X(prover.T1, prover.T2)

	prover.calculateLx()
	prover.calculateRx()
	prover.calculateIP()
	prover.calculateMu()
	prover.calculateTaux()

	//prover.TestCorrect()
	transcript := Transcript{
		A:     prover.A,
		B:     prover.B,
		T1:    prover.T1,
		T2:    prover.T2,
		Tau_x: prover.tau_x,
		Mu:    prover.mu,
		Ip:    prover.ip,
		Zeta:  prover.zeta,
		Eta:   prover.eta,
		L:     prover.L,
		R:     prover.R,
		X:     prover.x,
		Y:     prover.y,
		Z:     prover.z,
	}
	return prover.Pub_Coin, transcript
}

////////////////////////Private functions

//Generate b_0,b_1,s_0,s_1 and public keys
func (prover *Prover) generateCoin() {
	//Generate binary vector b_0 b_1
	prover.b_0 = Generate_b_0(prover.D)
	prover.b_1 = Generate_b_1(prover.b_0)
	prover.s_0 = utils.Generate_Random_Zp_Vector(prover.D, q)
	prover.s_1 = utils.Generate_Random_Zp_Vector(prover.D, q)
	//generate key
	prover.gamma = utils.Generate_Random_Zp(q)
	prover.Pub_Coin = Generate_Public_Coin(prover.Gen_g, prover.Gen_h, prover.D, prover.b_0, prover.gamma) //generate public key vector Y
}

//Generate Commitments A,B,C,D
func (prover *Prover) calculateAB() {
	//Generate commitment A
	prover.alpha = utils.Generate_Random_Zp(q)
	g_b0_h_b1 := utils.Pedersen_Commit_Vector(prover.Gen_Vec_G, prover.Gen_Vec_H, prover.b_0, prover.b_1)
	h_alpha := utils.Commit(prover.Gen_h, prover.alpha)
	prover.A.X, prover.A.Y = utils.Curve.Add(g_b0_h_b1.X, g_b0_h_b1.Y, h_alpha.X, h_alpha.Y)

	//Generate commitment B
	prover.beta = utils.Generate_Random_Zp(q)
	g_s0_h_s1 := utils.Pedersen_Commit_Vector(prover.Gen_Vec_G, prover.Gen_Vec_H, prover.s_0, prover.s_1)
	h_beta := utils.Commit(prover.Gen_h, prover.beta)
	prover.B.X, prover.B.Y = utils.Curve.Add(g_s0_h_s1.X, g_s0_h_s1.Y, h_beta.X, h_beta.Y)
}

//Compute T_1, T_2
func (prover *Prover) calculateT() {
	// Compute the vectors of challenge
	prover.yN = Generate_Exp_Scalar_Vector(prover.y, prover.D)
	prover.vec_2N = Generate_Exp_Scalar_Vector(big.NewInt(2), prover.D)
	prover.z1N = Generate_Scalar_Vector(prover.z, prover.D)
	z2 := utils.Mul_In_P(prover.z, prover.z)
	// t1 = <s_0 \circ y^N, z \cdot 1^N + b_1> + <b_0 - z \cdot 1^N, s_1 \circ y^N>
	s0_yN := utils.Cal_HP_Vec(prover.s_0, prover.yN)
	b_1_z1N := utils.Cal_Add_Vec(prover.b_1, prover.z1N)
	t11 := utils.Cal_IP_Vec(s0_yN, b_1_z1N)

	z2_2N := utils.Cal_Sca_Vec(prover.vec_2N, z2)
	t12 := utils.Cal_IP_Vec(prover.s_0, z2_2N)

	b0_z_1N := utils.Cal_Add_Vec(prover.b_0, prover.z1N)
	s1_yN := utils.Cal_HP_Vec(prover.s_1, prover.yN)

	t13 := utils.Cal_IP_Vec(b0_z_1N, s1_yN)

	prover.t_1 = utils.Add_In_P(t11, t12)
	prover.t_1 = utils.Add_In_P(prover.t_1, t13)

	//Generate tau1
	prover.tau_1 = utils.Generate_Random_Zp(q)

	//Compute T1
	prover.T1 = utils.Pedersen_Commit(prover.Gen_g, prover.Gen_h, prover.t_1, prover.tau_1)

	//Compute t2 = <s_0 \circ y^N, s_1>
	prover.t_2 = utils.Cal_IP_Vec(s0_yN, prover.s_1)

	//Generate tau2
	prover.tau_2 = utils.Generate_Random_Zp(q)

	//Compute T2
	prover.T2 = utils.Pedersen_Commit(prover.Gen_g, prover.Gen_h, prover.t_2, prover.tau_2)
}

//Compute l(x) i.e., zeta = b0 - z1^N + s0x
func (prover *Prover) calculateLx() {
	var lx []*big.Int
	z_1N := Generate_Scalar_Vector(prover.z, prover.D)
	b0_z_1N := utils.Cal_Sub_Vec(prover.b_0, z_1N)
	s0_x := utils.Cal_Sca_Vec(prover.s_0, prover.x)

	lx = utils.Cal_Add_Vec(b0_z_1N, s0_x)
	prover.zeta = lx
}

//Compute r(x) i.e., eta = (b1 + z1^N + s1x) \circ y^N + z2\cdot 2^N
func (prover *Prover) calculateRx() {
	var rx []*big.Int
	b1_yN := utils.Cal_HP_Vec(prover.b_1, prover.yN)
	z_1N_yN := utils.Cal_HP_Vec(prover.z1N, prover.yN)
	s1_x_yN := utils.Cal_HP_Vec(utils.Cal_Sca_Vec(prover.s_1, prover.x), prover.yN)
	b1_yN_z_1N_yN := utils.Cal_Add_Vec(b1_yN, z_1N_yN)
	b1_yN_z_1N_yN_s1_x_yN := utils.Cal_Add_Vec(b1_yN_z_1N_yN, s1_x_yN)
	z2 := utils.Mul_In_P(prover.z, prover.z)
	z2_2N := utils.Cal_Sca_Vec(prover.vec_2N, z2)
	rx = utils.Cal_Add_Vec(b1_yN_z_1N_yN_s1_x_yN, z2_2N)
	prover.eta = rx
}

//Compute t = <l(x), r(x)>
func (prover *Prover) calculateIP() {
	//prover.tx = Mod_Zp(Inner_ProofBig(prover.lx, prover.rx),prover.curve)
	prover.ip = utils.Cal_IP_Vec(prover.zeta, prover.eta)
}

//Compute tau_x = tau_1 x + tau_2 x^2
func (prover *Prover) calculateTaux() {
	z2_gamma := utils.Mul_In_P(prover.z, utils.Mul_In_P(prover.z, prover.gamma))
	tau1_x := utils.Mul_In_P(prover.tau_1, prover.x)
	tau2_x2 := utils.Mul_In_P(prover.tau_2, utils.Mul_In_P(prover.x, prover.x))
	prover.tau_x = utils.Add_In_P(tau1_x, tau2_x2)
	prover.tau_x = utils.Add_In_P(prover.tau_x, z2_gamma)
}

//Compute mu = alpha + beta x
func (prover *Prover) calculateMu() {
	beta_x := utils.Mul_In_P(prover.beta, prover.x)
	prover.mu = utils.Add_In_P(prover.alpha, beta_x)
}
