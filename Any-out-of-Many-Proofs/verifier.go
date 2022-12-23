package main

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/egoistzty/Code-Any-out-of-Many.git/utils"
)

type Verifier struct {
	//公开的参数，包括G,H和G,H的矢量，要承诺的范围n,以及相同的椭圆曲线
	Public_ck            utils.Point
	Gen_u, Gen_v         utils.Point
	Gen_Vec_G, Gen_Vec_H []utils.Point
	Pub_Vec_Key          []utils.Point // public key vector i.e., ring set

	A, B      utils.Point // commitments A, B
	T1, T2, E utils.Point // commitments T1, T2, E

	N     int                     // ring size N
	curve *secp256k1.KoblitzCurve // elliptic curve

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
	y2N []*big.Int // vector y^N = (y^1,...,y^N)
	z1N []*big.Int // vector z \cdot 1^N = (z^1,...,z^1)
	V1N []*big.Int // vector z \cdot 1^N = (z^1,...,z^1)

	//Zero Knowledge Proof generated by prover
	proverZKP ProverZKP
}

func (verifier *Verifier) New(Public_ck utils.Point, G utils.Point, U utils.Point, V utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, k int, N int, curve secp256k1.KoblitzCurve) {
	verifier.Public_ck = Public_ck
	verifier.Gen_u = U
	verifier.Gen_v = V
	verifier.Gen_Vec_H = H_Vector[:N]
	verifier.Gen_Vec_G = G_Vector[:N]
	verifier.N = N
	verifier.curve = &curve
}

// Public interfaces
// func (verifier *Verifier) GetAB() {
// 	verifier.A, verifier.B = prover.GetAB()
// }

// func (verifier *Verifier) GetT() {
// 	verifier.T1, verifier.T2, verifier.E = prover.GetT()
// }

// func (verifier *Verifier) Get() {
// 	verifier.proverZKP = prover.GetRsp()
// }

// Generate challenge
func (verifier *Verifier) GetYZ() (*big.Int, *big.Int) {
	verifier.y = utils.Generate_Random_Zp()
	verifier.z = utils.Generate_Random_Zp()
	verifier.yN = Generate_Exp_Scalar_Vector(verifier.y, verifier.N)
	verifier.y2N = Generate_Exp_Scalar_Vector(big.NewInt(2), verifier.N)
	verifier.z1N = Generate_Scalar_Vector(verifier.z, verifier.N)
	verifier.V1N = Generate_Scalar_Vector(big.NewInt(1), verifier.N)
	return verifier.y, verifier.z
}

func (verifier *Verifier) GetX() *big.Int {
	verifier.x = utils.Generate_Random_Zp()
	return verifier.x
}

func (verifier *Verifier) ParseZKP() {
	verifier.tau_x = verifier.proverZKP.tau_x
	verifier.mu = verifier.proverZKP.mu
	verifier.eta = verifier.proverZKP.eta
	verifier.zeta = verifier.proverZKP.zeta
	verifier.ip = verifier.proverZKP.ip
	verifier.f_s = verifier.proverZKP.f_s
	bit_1 := verifier.checkT()
	bit_2 := verifier.checkAB()
	bit_3 := verifier.checkSk()
	bit_4 := verifier.checkIP()
	bit := bit_1 && bit_2 && bit_3 && bit_4
	if bit {
		fmt.Println("ZKP Succeeds!")
	} else {
		fmt.Println("ZKP Fails!")
	}
}

// Private functions
func (verifier *Verifier) checkT() bool {
	// Compute delta = <z \cdot 1^N \circ y^N, (z+1) \cdot 1^N>
	var delta *big.Int
	z1N_1N, _ := utils.Cal_Add_Vec(verifier.z1N, verifier.V1N)
	z1N_yN, _ := utils.Cal_HP_Vec(verifier.z1N, verifier.yN)
	delta, _ = utils.Cal_IP_Vec(z1N_yN, z1N_1N)

	// Left hand side
	LHS := utils.Pedersen_Commit(verifier.Gen_v, verifier.Gen_u, verifier.ip, verifier.tau_x, verifier.curve)

	// Right hand side
	x2 := utils.Mul_In_P(verifier.x, verifier.x)
	v_delta := utils.Commit(verifier.Gen_v, delta, verifier.curve)
	T1_T2 := utils.Pedersen_Commit(verifier.T1, verifier.T2, verifier.x, x2, verifier.curve)
	var RHS utils.Point
	RHS.X, RHS.Y = verifier.curve.Add(v_delta.X, v_delta.Y, T1_T2.X, T1_T2.Y)

	// Check the equation
	if utils.Commit_Is_Equal(LHS, RHS) {
		fmt.Println("checkT Succeeds!")
	} else {
		fmt.Println("checkT Fails!")
	}
	return utils.Commit_Is_Equal(LHS, RHS)
}

func (verifier *Verifier) checkAB() bool {
	// Left hand side
	Inv_yn := utils.Cal_Inv_Vec(verifier.yN)
	zeta_no_y, _ := utils.Cal_HP_Vec(verifier.zeta, Inv_yn)

	g_zeta_h_eta := utils.Pedersen_Commit_Vector(verifier.Gen_Vec_G, verifier.Gen_Vec_H, zeta_no_y, verifier.eta, verifier.curve)
	u_mu := utils.Commit(verifier.Gen_u, verifier.mu, verifier.curve)

	var LHS utils.Point
	LHS.X, LHS.Y = verifier.curve.Add(g_zeta_h_eta.X, g_zeta_h_eta.Y, u_mu.X, u_mu.Y)

	// Right hand side
	A_Bx := utils.Pedersen_Commit(verifier.A, verifier.B, big.NewInt(1), verifier.x, verifier.curve)
	g_z_1N_h_z_1N := utils.Pedersen_Commit_Vector(verifier.Gen_Vec_G, verifier.Gen_Vec_H, verifier.z1N, verifier.z1N, verifier.curve)

	var RHS utils.Point
	RHS.X, RHS.Y = verifier.curve.Add(A_Bx.X, A_Bx.Y, g_z_1N_h_z_1N.X, g_z_1N_h_z_1N.Y)

	// Check the equation
	bo := utils.Commit_Is_Equal(LHS, RHS)
	if bo {
		fmt.Println("checkAB Succeeds!")
	} else {
		fmt.Println("checkAB Fails!")
	}
	return bo
}

func (verifier *Verifier) checkSk() bool {
	// Left hand side
	//zeta_yN, _ := utils.Cal_HP_Vec(verifier.zeta, verifier.yN)
	LHS := utils.Commit_Vector(verifier.Pub_Vec_Key, verifier.zeta, verifier.curve)

	// Right hand side
	Com_sk := utils.Pedersen_Commit(verifier.Public_ck, verifier.E, verifier.f_s, verifier.x, verifier.curve)
	z_yN := utils.Cal_Sca_Vec(verifier.yN, verifier.z)
	P_z_yN := utils.Commit_Vector(verifier.Pub_Vec_Key, z_yN, verifier.curve)

	var RHS utils.Point
	RHS.X, RHS.Y = verifier.curve.Add(Com_sk.X, Com_sk.Y, P_z_yN.X, P_z_yN.Y)

	// Check the equation
	if utils.Commit_Is_Equal(LHS, RHS) {
		fmt.Println("checkSk Succeeds!")
	} else {
		fmt.Println("checkSk Fails!")
	}
	return utils.Commit_Is_Equal(LHS, RHS)
}

func (verifier *Verifier) checkIP() bool {
	// Right hand side
	res, _ := utils.Cal_IP_Vec(verifier.zeta, verifier.eta)
	// Check the equation
	if verifier.ip.Cmp(res) == 0 {
		fmt.Println("checkIP Succeeds!")
		return true
	} else {
		fmt.Println("checkIP Fails!")
		return false
	}
}
