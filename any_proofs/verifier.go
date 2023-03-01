package any_proofs

import (
	"math/big"

	"anyOutOfMany/utils"
)

type Verifier struct {
	//Public parameters including generators, commitments, system parameter N and elliptic curve
	Public_ck               utils.Point
	Gen_u, Gen_v            utils.Point
	Gen_Vec_G, Gen_Vec_H    []utils.Point
	Pub_Vec_Key, Pub_Key_yN []utils.Point // public key vector i.e., ring set

	A, B      utils.Point // commitments A, B
	T1, T2, E utils.Point // commitments T1, T2, E
	L, R      []utils.Point

	N int // ring size N

	// challenge values
	y, z *big.Int
	x    *big.Int

	// parameters for response
	C_zeta, C_eta []*big.Int
	ip            *big.Int
	tau_x         *big.Int
	mu            *big.Int
	f_s           *big.Int

	// constant parameters
	YN  []*big.Int // vector y^N = (y^1,...,y^N)
	y2N []*big.Int // vector y^N = (y^1,...,y^N)
	z1N []*big.Int // vector z \cdot 1^N = (z^1,...,z^1)
	V1N []*big.Int // vector z \cdot 1^N = (z^1,...,z^1)

	//Zero Knowledge Proof generated by prover
	Trans Transcript
}

func (verifier *Verifier) New(Public_ck utils.Point, G utils.Point, U utils.Point, V utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, k int, N int) {
	verifier.Public_ck = Public_ck
	verifier.Gen_u = U
	verifier.Gen_v = V
	verifier.Gen_Vec_H = H_Vector
	verifier.Gen_Vec_G = G_Vector
	verifier.N = N
}

func (verifier *Verifier) ParseZKP() utils.Point {
	verifier.A = verifier.Trans.A
	verifier.B = verifier.Trans.B
	verifier.T1 = verifier.Trans.T1
	verifier.T2 = verifier.Trans.T2
	verifier.E = verifier.Trans.E
	verifier.tau_x = verifier.Trans.Tau_x
	verifier.mu = verifier.Trans.Mu
	verifier.ip = verifier.Trans.Ip
	verifier.f_s = verifier.Trans.F_s
	verifier.x = verifier.Trans.X
	verifier.y = verifier.Trans.Y
	verifier.z = verifier.Trans.Z

	// Check the challenges

	verifier.YN = Generate_Exp_Scalar_Vector(verifier.y, verifier.N)
	verifier.z1N = Generate_Scalar_Vector(verifier.z, verifier.N)
	verifier.y2N = Generate_Exp_Scalar_Vector(big.NewInt(2), verifier.N)
	verifier.V1N = Generate_Scalar_Vector(big.NewInt(1), verifier.N)

	RHS := verifier.Validate()
	return RHS

}

func (verifier *Verifier) Validate() utils.Point {
	// Parameters for Left hand side
	verifier.Pub_Key_yN = utils.Generate_Point_Vector_with_y(verifier.Pub_Vec_Key, verifier.YN)

	// Compute Right hand side
	var RHS utils.Point
	// Compute the part in Step (1)
	// Compute delta = <z \cdot 1^N \circ y^N, (z+1) \cdot 1^N>
	z1N_1N := utils.Cal_Add_Vec(verifier.z1N, verifier.V1N)
	z1N_yN := utils.Cal_HP_Vec(verifier.z1N, verifier.YN)
	delta := utils.Cal_IP_Vec(z1N_yN, z1N_1N)

	x2 := utils.Mul_In_P(verifier.x, verifier.x)
	v_delta := utils.Commit(verifier.Gen_v, delta)
	T1_T2 := utils.Pedersen_Commit(verifier.T1, verifier.T2, verifier.x, x2)
	RHS = utils.Cal_Point_Add(v_delta, T1_T2)

	// Compute the part in Step (2)
	A_Bx := utils.Pedersen_Commit(verifier.A, verifier.B, big.NewInt(1), verifier.x)
	var Sum_gh utils.Point
	Sum_gh.X = big.NewInt(0)
	Sum_gh.Y = big.NewInt(0)
	for i := 0; i < len(verifier.Gen_Vec_G); i++ {
		Sum_gh = utils.Cal_Point_Add(Sum_gh, verifier.Gen_Vec_G[i])
		Sum_gh = utils.Cal_Point_Add(Sum_gh, verifier.Gen_Vec_H[i])
	}
	g_z_1N_h_z_1N := utils.Commit(Sum_gh, verifier.z)

	Com_mu := utils.Commit(verifier.Gen_u, utils.Neg_Zp(verifier.mu))

	RHS = utils.Cal_Point_Add(RHS, A_Bx)
	RHS = utils.Cal_Point_Add(RHS, g_z_1N_h_z_1N)
	RHS = utils.Cal_Point_Add(RHS, Com_mu)

	// Compute the part in Step (3)
	Com_sk := utils.Pedersen_Commit(verifier.Public_ck, verifier.E, verifier.f_s, verifier.x)
	var Sun_Pub_Key_yN utils.Point
	Sun_Pub_Key_yN.X = big.NewInt(0)
	Sun_Pub_Key_yN.Y = big.NewInt(0)
	for i := 0; i < len(verifier.Pub_Key_yN); i++ {
		Sun_Pub_Key_yN = utils.Cal_Point_Add(Sun_Pub_Key_yN, verifier.Pub_Key_yN[i])
	}
	Pub_Key_zyN := utils.Commit(Sun_Pub_Key_yN, verifier.z)
	RHS = utils.Cal_Point_Add(RHS, Com_sk)
	RHS = utils.Cal_Point_Add(RHS, Pub_Key_zyN)

	// Compute the part in Step (4)
	Com_taux := utils.Commit(verifier.Gen_u, utils.Neg_Zp(verifier.tau_x))
	RHS = utils.Cal_Point_Add(RHS, Com_taux)

	return RHS
}

// func (verifier *Verifier) checkSk() bool {
// 	// Left hand side
// 	//zeta_yN, _ := utils.Cal_HP_Vec(verifier.zeta, verifier.yN)
// 	LHS := utils.Commit_Vector(verifier.Pub_Vec_Key, verifier.c_zeta, verifier.curve)

// 	// Right hand side
// 	Com_sk := utils.Pedersen_Commit(verifier.Public_ck, verifier.E, verifier.f_s, verifier.x, verifier.curve)
// 	z_yN := utils.Cal_Sca_Vec(verifier.yN, verifier.z)
// 	P_z_yN := utils.Commit_Vector(verifier.Pub_Vec_Key, z_yN, verifier.curve)

// 	var RHS utils.Point
// 	RHS.X, RHS.Y = verifier.curve.Add(Com_sk.X, Com_sk.Y, P_z_yN.X, P_z_yN.Y)

// 	// Check the equation
// 	if utils.Commit_Is_Equal(LHS, RHS) {
// 		fmt.Println("Secret keys are valid!")
// 	} else {
// 		fmt.Println("Secret keys are invalid!")
// 	}
// 	return utils.Commit_Is_Equal(LHS, RHS)
// }

// func (verifier *Verifier) checkIP() bool {
// 	// Right hand side
// 	res, _ := utils.Cal_IP_Vec(verifier.c_zeta, verifier.c_eta)
// 	// Check the equation
// 	if verifier.ip.Cmp(res) == 0 {
// 		fmt.Println("Inner product is valid!")
// 		return true
// 	} else {
// 		fmt.Println("Inner product is invalid!")
// 		return false
// 	}
// }
