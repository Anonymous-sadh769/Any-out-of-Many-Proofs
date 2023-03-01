package range_proofs

import (
	"math/big"

	"anyOutOfMany/utils"
)

type Verifier struct {
	///////////////////////////////public parameters:
	Gen_g, Gen_h         utils.Point   // generators u,v
	Gen_Vec_G, Gen_Vec_H []utils.Point // generator vector g h
	Pub_Coin             utils.Point   // public key vector i.e., ring set

	A, B   utils.Point   // commitments A, B
	T1, T2 utils.Point   // commitments T, T1, T2, E
	L, R   []utils.Point // auxiliary commitments L,R

	d int // value width d

	// challenge values
	y, z *big.Int
	x    *big.Int

	// parameters for response
	C_zeta, C_eta []*big.Int
	tau_x         *big.Int
	mu            *big.Int
	ip            *big.Int

	// constant parameters
	yN     []*big.Int // vector y^N = (y^1,...,y^N)
	z1N    []*big.Int // vector z \cdot 1^N = (z^1,...,z^N)
	vec_2N []*big.Int

	//Zero Knowledge Proof generated by prover
	Trans Transcript
}

func (verifier *Verifier) New(G utils.Point, H utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, d int) {
	verifier.Gen_g = G
	verifier.Gen_h = H
	verifier.Gen_Vec_G = G_Vector
	verifier.Gen_Vec_H = H_Vector
	verifier.d = d
}

func (verifier *Verifier) ParseZKP() utils.Point {
	verifier.A = verifier.Trans.A
	verifier.B = verifier.Trans.B
	verifier.T1 = verifier.Trans.T1
	verifier.T2 = verifier.Trans.T2
	verifier.tau_x = verifier.Trans.Tau_x
	verifier.mu = verifier.Trans.Mu
	verifier.ip = verifier.Trans.Ip
	verifier.x = verifier.Trans.X
	verifier.y = verifier.Trans.Y
	verifier.z = verifier.Trans.Z

	// Check the challenges
	verifier.yN = Generate_Exp_Scalar_Vector(verifier.y, verifier.d)
	verifier.vec_2N = Generate_Exp_Scalar_Vector(big.NewInt(2), verifier.d)
	verifier.z1N = Generate_Scalar_Vector(verifier.z, verifier.d)

	RHS := verifier.Validate()
	return RHS
}

func (verifier *Verifier) Validate() utils.Point {

	// Compute Right hand side
	var RHS utils.Point
	// Compute the part in Step (1)
	// Compute delta = <z \cdot 1^N \circ y^N, (z+1) \cdot 1^N>
	z2 := utils.Mul_In_P(verifier.z, verifier.z)
	Gen_V_z2 := utils.Commit(verifier.Pub_Coin, z2)

	v1N := Generate_Scalar_Vector(big.NewInt(1), verifier.d)
	verifier.yN = Generate_Scalar_Vector(verifier.y, verifier.d)

	z_z2 := utils.Sub_In_P(verifier.z, z2)
	v1N_yN := utils.Cal_IP_Vec(v1N, verifier.yN)
	delta_1 := utils.Mul_In_P(z_z2, v1N_yN)

	z3 := utils.Mul_In_P(verifier.z, z2)
	v1N_2N := utils.Cal_IP_Vec(v1N, verifier.vec_2N)
	delta_2 := utils.Mul_In_P(z3, v1N_2N)

	delta := utils.Sub_In_P(delta_1, delta_2)
	Gen_g_delta := utils.Commit(verifier.Gen_g, delta)

	x2 := utils.Mul_In_P(verifier.x, verifier.x)
	T1_T2 := utils.Pedersen_Commit(verifier.T1, verifier.T2, verifier.x, x2)

	RHS = utils.Cal_Point_Add(Gen_V_z2, Gen_g_delta)
	RHS = utils.Cal_Point_Add(RHS, T1_T2)

	neg_taux := utils.Neg_Zp(verifier.tau_x)
	Gen_h_taux := utils.Commit(verifier.Gen_h, neg_taux)

	RHS = utils.Cal_Point_Add(RHS, Gen_h_taux)

	// Compute the part in Step (2)
	Inv_yN := Generate_Exp_Scalar_Vector(utils.Inverse_Zp(verifier.y), verifier.d)
	Inv_Vec_H := utils.Generate_Point_Vector_with_y(verifier.Gen_Vec_H, Inv_yN)

	A_Bx := utils.Pedersen_Commit(verifier.A, verifier.B, big.NewInt(1), verifier.x)
	neg_z1N := Generate_Scalar_Vector(utils.Neg_Zp(verifier.z), verifier.d)
	g_neg_z1N := utils.Commit_Vector(verifier.Gen_Vec_G, neg_z1N)

	z_yN := utils.Cal_Sca_Vec(verifier.yN, verifier.z)
	z2_2N := utils.Cal_Sca_Vec(verifier.vec_2N, z2)
	z_yN_z2_2N := utils.Cal_Add_Vec(z_yN, z2_2N)

	Gen_h_zy := utils.Commit_Vector(Inv_Vec_H, z_yN_z2_2N)

	RHS = utils.Cal_Point_Add(RHS, A_Bx)
	RHS = utils.Cal_Point_Add(RHS, g_neg_z1N)
	RHS = utils.Cal_Point_Add(RHS, Gen_h_zy)

	Com_mu := utils.Commit(verifier.Gen_h, verifier.mu)
	RHS = utils.Cal_Point_Add(RHS, Com_mu)

	return RHS
}