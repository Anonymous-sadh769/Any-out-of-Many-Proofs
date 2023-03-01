package any_proofs

import (
	"math/big"

	"anyOutOfMany/utils"
)

const q = 256

type Prover struct {
	///////////////////////////////public parameters:
	Public_ck            utils.Point   // generator as commitment key for public keys
	Gen_u, Gen_v         utils.Point   // generators u,v
	Gen_Vec_G, Gen_Vec_H []utils.Point // generator vector g h
	Pub_Vec_Key          []utils.Point // public key vector i.e., ring set

	A, B      utils.Point   // commitments A, B
	T1, T2, E utils.Point   // commitments T, T1, T2, E
	L, R      []utils.Point // auxiliary commitments L,R

	N int // ring size N
	d int // value width
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
	zeta, eta, C_zeta, C_eta []*big.Int
	tau_x                    *big.Int
	mu                       *big.Int
	f_s                      *big.Int
	ip                       *big.Int

	// constant parameters
	YN  []*big.Int // vector y^N = (y^1,...,y^N)
	Z1N []*big.Int // vector z \cdot 1^N = (z^1,...,z^N)
}

// Initialization function
func (prover *Prover) New(Public_ck utils.Point, G utils.Point, U utils.Point, V utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, k int, N int) {
	prover.Public_ck = Public_ck
	prover.Gen_u = U
	prover.Gen_v = V
	prover.Gen_Vec_G = G_Vector
	prover.Gen_Vec_H = H_Vector
	prover.k = k
	prover.N = N
	//Generate secrets of prover
	prover.sec_Vec_Key = utils.Generate_Random_Zp_Vector(prover.k, q)
	prover.generateKey()
}

////////////////////////Public interfaces

//Get response zeta, eta, t, tau_x, mu, f_s
func (prover *Prover) GenerateRsp() ([]utils.Point, Transcript) {

	//prover computes Commitments A, B
	prover.calculateAB()

	//prover generates challenges y,z
	prover.y, prover.z = Generate_YZ(prover.A, prover.B)

	//prover compute Commitments T1, T2
	prover.calculateT()
	prover.calculateE()

	//verifier get T1, T2, E and transmit x to prover
	prover.x = Generate_X(prover.T1, prover.T2, prover.E)

	prover.calculateLx()
	prover.calculateRx()
	prover.calculateIP()
	prover.calculateMu()
	prover.calculateTaux()
	prover.calculateFs()

	//prover.TestCorrect()
	transcript := Transcript{
		A:     prover.A,
		B:     prover.B,
		T1:    prover.T1,
		T2:    prover.T2,
		E:     prover.E,
		Tau_x: prover.tau_x,
		Mu:    prover.mu,
		Ip:    prover.ip,
		Zeta:  prover.zeta,
		Eta:   prover.eta,
		F_s:   prover.f_s,
		X:     prover.x,
		Y:     prover.y,
		Z:     prover.z,
	}
	return prover.Pub_Vec_Key, transcript
}

////////////////////////Private functions

//Generate b_0,b_1,s_0,s_1 and public keys
func (prover *Prover) generateKey() {
	//Generate binary vector b_0 b_1
	prover.b_0, _ = prover.Generate_b_0(prover.k, prover.N)
	prover.b_1 = Generate_b_1(prover.b_0)
	prover.s_0 = utils.Generate_Random_Zp_Vector(prover.N, q)
	prover.s_1 = utils.Generate_Random_Zp_Vector(prover.N, q)
	//generate key
	prover.Pub_Vec_Key = prover.Generate_Multi_Public_Key(prover.Public_ck, prover.k, prover.N, prover.b_0) //generate public key vector Y
}

//Generate Commitments A,B,C,D
func (prover *Prover) calculateAB() {
	//Generate commitment A
	prover.alpha = utils.Generate_Random_Zp(q)
	g_b0_h_b1 := utils.Pedersen_Commit_Vector(prover.Gen_Vec_G, prover.Gen_Vec_H, prover.b_0, prover.b_1)
	u_alpha := utils.Commit(prover.Gen_u, prover.alpha)
	prover.A.X, prover.A.Y = utils.Curve.Add(g_b0_h_b1.X, g_b0_h_b1.Y, u_alpha.X, u_alpha.Y)

	//Generate commitment B
	prover.beta = utils.Generate_Random_Zp(q)
	g_s0_h_s1 := utils.Pedersen_Commit_Vector(prover.Gen_Vec_G, prover.Gen_Vec_H, prover.s_0, prover.s_1)
	u_beta := utils.Commit(prover.Gen_u, prover.beta)
	prover.B.X, prover.B.Y = utils.Curve.Add(g_s0_h_s1.X, g_s0_h_s1.Y, u_beta.X, u_beta.Y)
}

//Compute T_1, T_2
func (prover *Prover) calculateT() {
	// Compute the vectors of challenge
	prover.YN = Generate_Exp_Scalar_Vector(prover.y, prover.N)
	prover.Z1N = Generate_Scalar_Vector(prover.z, prover.N)

	s0_yN := utils.Cal_HP_Vec(prover.s_0, prover.YN)

	// t1 = <s_0 \circ y^N, z \cdot 1^N + b_1> + <b_0 - z \cdot 1^N, s_1 \circ y^N>
	z_1N_b1 := utils.Cal_Add_Vec(prover.Z1N, prover.b_1)
	b0_z_1N := utils.Cal_Add_Vec(prover.b_0, prover.Z1N)
	s1_yN := utils.Cal_HP_Vec(prover.s_1, prover.YN)

	s0_yN_z_1N_b1 := utils.Cal_IP_Vec(s0_yN, z_1N_b1)
	b0_z_1N_s1_yN := utils.Cal_IP_Vec(b0_z_1N, s1_yN)

	prover.t_1 = utils.Add_In_P(s0_yN_z_1N_b1, b0_z_1N_s1_yN)

	//Generate tau2
	prover.tau_1 = utils.Generate_Random_Zp(q)

	//Compute T1
	prover.T1 = utils.Pedersen_Commit(prover.Gen_v, prover.Gen_u, prover.t_1, prover.tau_1)

	//Compute t2 = <s_0 \circ y^N, s_1>
	prover.t_2 = utils.Cal_IP_Vec(s0_yN, prover.s_1)

	//Generate tau2
	prover.tau_2 = utils.Generate_Random_Zp(q)

	//Compute T2
	prover.T2 = utils.Pedersen_Commit(prover.Gen_v, prover.Gen_u, prover.t_2, prover.tau_2)
}

//Compute commitment E
func (prover *Prover) calculateE() {
	prover.r_s = utils.Generate_Random_Zp(q)
	yN_s0 := utils.Cal_HP_Vec(prover.YN, prover.s_0)
	P_yN_s0 := utils.Commit_Vector(prover.Pub_Vec_Key, yN_s0)
	com_rs := utils.Commit(prover.Public_ck, utils.Neg_Zp(prover.r_s))
	prover.E.X, prover.E.Y = utils.Curve.Add(P_yN_s0.X, P_yN_s0.Y, com_rs.X, com_rs.Y)
}

//Compute r(x) i.e., zeta = z1^N + b0 + s0x
func (prover *Prover) calculateRx() {
	var lx []*big.Int
	z_1N := Generate_Scalar_Vector(prover.z, prover.N)
	z_1N_b0 := utils.Cal_Add_Vec(z_1N, prover.b_0)
	s0_x := utils.Cal_Sca_Vec(prover.s_0, prover.x)

	lx = utils.Cal_Add_Vec(z_1N_b0, s0_x)
	prover.zeta = lx
}

//Compute r(x) i.e., eta = (z1^N + b1 + s1x) \circ y^N
func (prover *Prover) calculateLx() {
	var rx []*big.Int
	b1_yN := utils.Cal_HP_Vec(prover.b_1, prover.YN)
	z_1N_yN := utils.Cal_HP_Vec(prover.Z1N, prover.YN)
	s1_x_yN := utils.Cal_HP_Vec(utils.Cal_Sca_Vec(prover.s_1, prover.x), prover.YN)
	b1_yN_z_1N_yN := utils.Cal_Add_Vec(b1_yN, z_1N_yN)

	rx = utils.Cal_Add_Vec(b1_yN_z_1N_yN, s1_x_yN)
	prover.eta = rx
}

//Compute t = <l(x), r(x)>
func (prover *Prover) calculateIP() {
	//prover.tx = Mod_Zp(Inner_ProofBig(prover.lx, prover.rx),prover.curve)
	prover.ip = utils.Cal_IP_Vec(prover.eta, prover.zeta)
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
