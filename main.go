package main

import (
	"fmt"
	"math"
	"math/big"
	"time"

	//"math/big"
	"anyOutOfMany/any_proofs"
	"anyOutOfMany/omniring"
	"anyOutOfMany/range_proofs"
	"anyOutOfMany/utils"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

const k = 1
const N = 8
const d = 64
const m = 1

func main() {
	OurRingCT()
	Omniring()
}

func OurRingCT() {

	var ap_prover any_proofs.Prover
	var ap_verifier any_proofs.Verifier
	var rp_prover [m]range_proofs.Prover
	var rp_verifier [m]range_proofs.Verifier

	p_start := time.Now()
	fmt.Println("Initialize Any-out-of-Many Proofs")
	anyProofsSetup(k, N, d, &ap_prover, &ap_verifier) // k for secret number N for ring size
	fmt.Println("Generate Any-out-of-Many Proofs")
	zeta_p, eta_p, Vec_g_p, Vec_h_p := anyProofsProve(&ap_prover, &ap_verifier)
	g_v := ap_prover.Gen_v
	fmt.Println("Initialize and Generate Range Proofs")
	for i := 0; i < m; i++ {
		var temp_rp_prover range_proofs.Prover
		var temp_rp_verifier range_proofs.Verifier
		rangeProofsSetup(k, N, d, &temp_rp_prover, &temp_rp_verifier)
		rp_prover[i] = temp_rp_prover
		rp_verifier[i] = temp_rp_verifier

		temp_zeta, temp_eta, temp_Vec_h := rangeProofsProve(&rp_prover[i], &rp_verifier[i])
		zeta_p = append(zeta_p, temp_zeta...)
		eta_p = append(eta_p, temp_eta...)
		Vec_g_p = append(Vec_g_p, rp_prover[i].Gen_Vec_G...)
		Vec_h_p = append(Vec_h_p, temp_Vec_h...)
		g_v = utils.Cal_Point_Add(g_v, rp_prover[i].Gen_g)
	}

	// Padding the vectors to 2^n length
	deg := math.Ceil(math.Log2(float64(len(zeta_p))))
	pad := math.Pow(2, deg) - float64(len(zeta_p))
	zero_vec := Generate_cons_vec(int(pad), big.NewInt(0))
	var one_vec []utils.Point
	for i := 0; i < len(zero_vec); i++ {
		one_vec = append(one_vec, utils.Commit(ap_prover.Gen_u, big.NewInt(0)))
	}
	zeta_p = append(zeta_p, zero_vec...)
	eta_p = append(eta_p, zero_vec...)
	Vec_g_p = append(Vec_g_p, one_vec...)
	Vec_h_p = append(Vec_h_p, one_vec...)

	fmt.Println("Execute Optimization")
	L, R, C_zeta, C_eta := opt_prove(zeta_p, eta_p, Vec_g_p, Vec_h_p, g_v)
	p_elapsed := time.Since(p_start)

	RHS, Vec_g_v := anyProofsVerify(&ap_verifier)
	Vec_h_v := ap_verifier.Gen_Vec_H

	for i := 0; i < m; i++ {
		temp_RHS := rangeProofsVerify(&rp_verifier[i])
		RHS = utils.Cal_Point_Add(RHS, temp_RHS)
		Vec_g_v = append(Vec_g_v, rp_verifier[i].Gen_Vec_G...)
		Vec_h_v = append(Vec_h_v, rp_verifier[i].Gen_Vec_H...)
	}

	// Padding the vectors to 2^n length
	Vec_g_v = append(Vec_g_v, one_vec...)
	Vec_h_v = append(Vec_h_v, one_vec...)

	v_start := time.Now()
	fmt.Println("Verify Aggregated Proofs")
	opt_verify(L, R, RHS, Vec_g_v, Vec_h_v, g_v, C_zeta, C_eta)

	v_elapsed := time.Since(v_start)
	fmt.Println("Prover Running Time:", p_elapsed)
	fmt.Println("Verify Running Time:", v_elapsed)

}

func Omniring() {

	var or_prover omniring.Prover
	var or_verifier omniring.Verifier
	var rp_prover [m]range_proofs.Prover
	var rp_verifier [m]range_proofs.Verifier

	p_start := time.Now()
	fmt.Println("Initialize Ring Signature Proofs")
	omniringSetup(k, N, d, &or_prover, &or_verifier) // k for secret number N for ring size
	fmt.Println("Generate Ring Signature Proofs")
	zeta_p, eta_p, Vec_g_p, Vec_h_p := omniringProve(&or_prover, &or_verifier)
	g_v := or_prover.Gen_G

	fmt.Println("Initialize and Generate Range Proofs")
	for i := 0; i < m; i++ {
		var temp_rp_prover range_proofs.Prover
		var temp_rp_verifier range_proofs.Verifier
		rangeProofsSetup(k, N, d, &temp_rp_prover, &temp_rp_verifier)
		rp_prover[i] = temp_rp_prover
		rp_verifier[i] = temp_rp_verifier

		temp_zeta, temp_eta, temp_Vec_h := rangeProofsProve(&rp_prover[i], &rp_verifier[i])
		zeta_p = append(zeta_p, temp_zeta...)
		eta_p = append(eta_p, temp_eta...)
		Vec_g_p = append(Vec_g_p, rp_prover[i].Gen_Vec_G...)
		Vec_h_p = append(Vec_h_p, temp_Vec_h...)
		g_v = utils.Cal_Point_Add(g_v, rp_prover[i].Gen_g)
	}

	// Padding the vectors to 2^n length
	deg := math.Ceil(math.Log2(float64(len(zeta_p))))
	pad := math.Pow(2, deg) - float64(len(zeta_p))
	zero_vec := Generate_cons_vec(int(pad), big.NewInt(0))
	var one_vec []utils.Point
	for i := 0; i < len(zero_vec); i++ {
		one_vec = append(one_vec, utils.Commit(or_prover.Gen_F, big.NewInt(0)))
	}
	zeta_p = append(zeta_p, zero_vec...)
	eta_p = append(eta_p, zero_vec...)
	Vec_g_p = append(Vec_g_p, one_vec...)
	Vec_h_p = append(Vec_h_p, one_vec...)

	fmt.Println("Execute Optimization")
	L, R, C_zeta, C_eta := opt_prove(zeta_p, eta_p, Vec_g_p, Vec_h_p, g_v)
	p_elapsed := time.Since(p_start)

	RHS, Vec_g_v, Vec_h_v := omniringVerify(&or_verifier)

	for i := 0; i < m; i++ {
		temp_RHS := rangeProofsVerify(&rp_verifier[i])
		RHS = utils.Cal_Point_Add(RHS, temp_RHS)
		Vec_g_v = append(Vec_g_v, rp_verifier[i].Gen_Vec_G...)
		Vec_h_v = append(Vec_h_v, rp_verifier[i].Gen_Vec_H...)
	}

	// Padding the vectors to 2^n length
	Vec_g_v = append(Vec_g_v, one_vec...)
	Vec_h_v = append(Vec_h_v, one_vec...)

	v_start := time.Now()
	fmt.Println("Verify Aggregated Proofs")
	opt_verify(L, R, RHS, Vec_g_v, Vec_h_v, g_v, C_zeta, C_eta)

	v_elapsed := time.Since(v_start)
	fmt.Println("Prover Running Time:", p_elapsed)
	fmt.Println("Verify Running Time:", v_elapsed)

}

func anyProofsSetup(k int, N int, d int, prover *any_proofs.Prover, verifier *any_proofs.Verifier) {

	utils.Curve = secp256k1.S256() //Choose an elliptic curve

	u := utils.GeneratePoint()
	g := utils.GeneratePoint()
	h := utils.GeneratePoint()
	Public_g := utils.GeneratePoint()

	g_Vector := utils.GenerateMultiPoint(N)
	h_Vector := utils.GenerateMultiPoint(N)

	//construct any-out-of-many proofs
	prover.New(Public_g, u, g, h, g_Vector, h_Vector, k, N)
	verifier.New(Public_g, u, g, h, g_Vector, h_Vector, k, N)

}

func anyProofsProve(prover *any_proofs.Prover, verifier *any_proofs.Verifier) ([]*big.Int, []*big.Int, []utils.Point, []utils.Point) {

	//verifier get response
	pub_Vec_Key, trans := prover.GenerateRsp()
	verifier.Pub_Vec_Key = pub_Vec_Key
	verifier.Trans = trans

	// Compress the openings
	Inv_yN := Generate_Exp_Scalar_Vector(utils.Inverse_Zp(trans.Y), prover.N)
	Inv_Vec_H := utils.Generate_Point_Vector_with_y(prover.Gen_Vec_H, Inv_yN)
	Pub_Key_yN := utils.Generate_Point_Vector_with_y(pub_Vec_Key, prover.YN)
	Vec_G_P := utils.Cal_Point_Add_Vec(prover.Gen_Vec_G, Pub_Key_yN)

	return trans.Zeta, trans.Eta, Vec_G_P, Inv_Vec_H
	// ap_verifier.L, ap_verifier.R, ap_verifier.C_zeta, ap_verifier.C_eta = opt_prove(trans.Zeta, trans.Eta, Vec_G_P, Inv_Vec_H, ap_prover.Gen_v)
	// fmt.Println("ZKProofs Generated...")
}

func anyProofsVerify(verifier *any_proofs.Verifier) (utils.Point, []utils.Point) {
	RHS := verifier.ParseZKP()

	Pub_Key_yN := utils.Generate_Point_Vector_with_y(verifier.Pub_Vec_Key, verifier.YN)
	Vec_G_P := utils.Cal_Point_Add_Vec(verifier.Gen_Vec_G, Pub_Key_yN)

	return RHS, Vec_G_P
	// opt_verify(ap_verifier.L, ap_verifier.R, RHS, Vec_G_P, ap_verifier.Gen_Vec_H, ap_verifier.Gen_v, ap_verifier.C_zeta, ap_verifier.C_eta, ap_verifier.Trans.Y)
}

func rangeProofsSetup(k int, N int, d int, prover *range_proofs.Prover, verifier *range_proofs.Verifier) {

	utils.Curve = secp256k1.S256() //Choose an elliptic curve

	g := utils.GeneratePoint()
	h := utils.GeneratePoint()

	g_Vector := utils.GenerateMultiPoint(d)
	h_Vector := utils.GenerateMultiPoint(d)

	//construct an object prover
	prover.New(g, h, g_Vector, h_Vector, d)
	verifier.New(g, h, g_Vector, h_Vector, d)
}

func rangeProofsProve(prover *range_proofs.Prover, verifier *range_proofs.Verifier) ([]*big.Int, []*big.Int, []utils.Point) {

	//verifier get response
	Pub_Coin, trans := prover.GenerateRsp()
	verifier.Pub_Coin = Pub_Coin
	verifier.Trans = trans

	// Compress the openings
	Inv_yN := Generate_Exp_Scalar_Vector(utils.Inverse_Zp(trans.Y), prover.D)
	Inv_Vec_H := utils.Generate_Point_Vector_with_y(prover.Gen_Vec_H, Inv_yN)
	// rp_verifier.L, rp_verifier.R, rp_verifier.C_zeta, rp_verifier.C_eta = opt_prove(trans.Zeta, trans.Eta, rp_prover.Gen_Vec_G, Inv_Vec_H, rp_prover.Gen_g)
	// fmt.Println("ZKProofs Generated...")
	return trans.Zeta, trans.Eta, Inv_Vec_H
}

func rangeProofsVerify(verifier *range_proofs.Verifier) utils.Point {
	RHS := verifier.ParseZKP()
	// opt_verify(rp_verifier.L, rp_verifier.R, RHS, rp_verifier.Gen_Vec_G, rp_verifier.Gen_Vec_H, rp_verifier.Gen_g, rp_verifier.C_zeta, rp_verifier.C_eta, rp_verifier.Trans.Y)
	return RHS
}

func omniringSetup(k int, N int, d int, prover *omniring.Prover, verifier *omniring.Verifier) {

	utils.Curve = secp256k1.S256() //Choose an elliptic curve

	n := N / k
	u := utils.Generate_Random_Zp(d)
	v := utils.Generate_Random_Zp(d)
	Gen_F := utils.GeneratePoint()
	Gen_G := utils.GeneratePoint()
	Gen_H := utils.GeneratePoint()
	P_vector := utils.GenerateMultiPoint(2 + N)
	G_Vector := utils.GenerateMultiPoint(3*k + N)
	H_Vector := utils.GenerateMultiPoint(2 + n + 3*k + N)

	//construct any-out-of-many proofs
	prover.New(u, v, Gen_F, Gen_G, Gen_H, P_vector, G_Vector, H_Vector, k, N, d)
	verifier.New(u, v, Gen_F, Gen_G, Gen_H, P_vector, G_Vector, H_Vector, k, N, d)

}

func omniringProve(prover *omniring.Prover, verifier *omniring.Verifier) ([]*big.Int, []*big.Int, []utils.Point, []utils.Point) {

	//verifier get response
	pub_Vec_Key, pub_Inp_Coin, pub_Out_Coin, trans, Gen_Vec_G, Gen_Vec_H := prover.GenerateRsp()
	verifier.Pub_Vec_Key = pub_Vec_Key
	verifier.Trans = trans
	verifier.Inp_Vec_Coin = pub_Inp_Coin
	verifier.Out_Vec_Coin = pub_Out_Coin
	fmt.Println(len(pub_Out_Coin))
	// Compress the openings
	verifier.L, verifier.R, verifier.C_zeta, verifier.C_zeta = opt_prove(trans.Zeta, trans.Eta, Gen_Vec_G, Gen_Vec_H, prover.Gen_G)

	return trans.Zeta, trans.Eta, Gen_Vec_G, Gen_Vec_H
	// ap_verifier.L, ap_verifier.R, ap_verifier.C_zeta, ap_verifier.C_eta = opt_prove(trans.Zeta, trans.Eta, Vec_G_P, Inv_Vec_H, ap_prover.Gen_v)
	// fmt.Println("ZKProofs Generated...")
}

func omniringVerify(verifier *omniring.Verifier) (utils.Point, []utils.Point, []utils.Point) {
	RHS, Gen_Vec_G, Gen_Vec_H := verifier.ParseZKP()

	return RHS, Gen_Vec_G, Gen_Vec_H
	// opt_verify(ap_verifier.L, ap_verifier.R, RHS, Vec_G_P, ap_verifier.Gen_Vec_H, ap_verifier.Gen_v, ap_verifier.C_zeta, ap_verifier.C_eta, ap_verifier.Trans.Y)
}

//Generete constant vector
func Generate_cons_vec(n int, c *big.Int) []*big.Int {
	var zero []*big.Int
	for i := 0; i < n; i++ {
		zero = append(zero, c)
	}
	return zero
}
