package main

import (
	"crypto/sha256"
	"math/big"

	"anyOutOfMany/utils"
)

func opt_prove(a []*big.Int, b []*big.Int, G_Vector []utils.Point, H_Vector []utils.Point, G_v utils.Point) ([]utils.Point, []utils.Point, []*big.Int, []*big.Int) {
	//Parameters
	var L []utils.Point // store L values in each round
	var R []utils.Point // store R values in each round

	// Generate initial challenge value
	var G_temp utils.Point
	l := len(a)
	var x32 [32]byte
	var temp, x, inv_x *big.Int
	counter := 0 // Recursive Reduction Algorithm

	for l > 1 {
		// Write a_L, a_R, b_L, b_R
		a_L := a[0 : l/2]
		a_R := a[l/2 : l]
		b_L := b[0 : l/2]
		b_R := b[l/2 : l]

		// Write G_L, G_R, H_L, H_R
		G_L := G_Vector[0 : l/2]
		G_R := G_Vector[l/2 : l]
		H_L := H_Vector[0 : l/2]
		H_R := H_Vector[l/2 : l]

		var G_H, V_ip utils.Point
		// Calculate L power x
		temp = utils.Cal_IP_Vec(a_L, b_R)
		G_H = utils.Pedersen_Commit_Vector(G_R, H_L, a_L, b_R)
		V_ip = utils.Commit(G_v, temp)
		L = append(L, utils.Cal_Point_Add(G_H, V_ip))

		// Calculate R power x^-1
		temp = utils.Cal_IP_Vec(a_R, b_L)
		G_H = utils.Pedersen_Commit_Vector(G_L, H_R, a_R, b_L)
		V_ip = utils.Commit(G_v, temp)
		R = append(R, utils.Cal_Point_Add(G_H, V_ip))

		// Update challenge x with Fiat-Shamir
		G_temp = utils.Cal_Point_Add(L[counter], R[counter])
		x32 = sha256.Sum256(G_temp.Point2Bytes())
		x = big.NewInt(0).SetBytes(x32[:])
		inv_x = utils.Inverse_Zp(x)
		counter++

		// Calculate compressed vectors a', b'
		a = utils.Cal_Add_Vec(utils.Cal_Sca_Vec(a_L, x), a_R)
		b = utils.Cal_Add_Vec(utils.Cal_Sca_Vec(b_L, inv_x), b_R)

		// Calculate compressed vectors g', h'
		G_Vector = utils.Cal_Point_Add_Vec(utils.Cal_Point_Sca_Vec(G_L, inv_x), G_R)
		H_Vector = utils.Cal_Point_Add_Vec(utils.Cal_Point_Sca_Vec(H_L, x), H_R)

		// update length l after each round
		l = len(a)
	}

	//return transcript to verify algorithm
	return L, R, a, b
}

func opt_verify(L []utils.Point, R []utils.Point, T utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, G_v utils.Point, a []*big.Int, b []*big.Int) {
	// Generate initial challenge value
	var G_temp, LHS utils.Point
	var L_x, L_x_T, R_inv_x utils.Point

	var x32 [32]byte
	var x, inv_x *big.Int
	var temp []*big.Int
	l := len(L)
	counter := 0
	N := len(G_Vector)
	ax := Generate_Scalar_Vector(a[0], N)
	bx := Generate_Scalar_Vector(b[0], N)

	// Recursive Verification Algorithm
	for counter < l {
		// Update challenge x with Fiat-Shamir
		G_temp = utils.Cal_Point_Add(L[counter], R[counter])
		x32 = sha256.Sum256(G_temp.Point2Bytes())
		x = big.NewInt(0).SetBytes(x32[:])
		inv_x = utils.Inverse_Zp(x)

		vec_x := Generate_Scalar_Vector(x, N/2)
		vec_inv_x := Generate_Scalar_Vector(inv_x, N/2)
		vec_one := Generate_Scalar_Vector(big.NewInt(1), N/2)
		temp = nil
		for i := 0; i < len(G_Vector)/N; i++ {
			temp = append(temp, vec_inv_x...)
			temp = append(temp, vec_one...)
		}
		ax = utils.Cal_HP_Vec(ax, temp)

		temp = nil
		for i := 0; i <= len(G_Vector)/N; i++ {
			temp = append(temp, vec_x...)
			temp = append(temp, vec_one...)
		}
		bx = utils.Cal_HP_Vec(bx, temp)

		// Compute T = L^(x) T R^(x^-1)
		L_x = utils.Cal_Point_Sca(L[counter], x)
		L_x_T = utils.Cal_Point_Add(L_x, T)
		R_inv_x = utils.Cal_Point_Sca(R[counter], inv_x)
		T = utils.Cal_Point_Add(L_x_T, R_inv_x)

		counter++
		N = N / 2
	}

	//Compute the commitment to compressed zeta and eta in Step (2) and (3)
	Com_1 := utils.Pedersen_Commit_Vector(G_Vector, H_Vector, ax, bx)

	//Compute the commitment to inner product tilde t in Step (4)
	ip := utils.Cal_IP_Vec(a, b)
	Com_2 := utils.Commit(G_v, ip)

	LHS = utils.Cal_Point_Add(Com_1, Com_2)
	_ = LHS
	// Print the result of verification
	// return utils.Is_Equal_Point(LHS, T)
}

//Generete scalar vector z*1^n = (z,...,z)
func Generate_Scalar_Vector(z *big.Int, n int) []*big.Int {
	var Scalar_Vector []*big.Int
	for i := n; i > 0; i-- {
		Scalar_Vector = append(Scalar_Vector, z)
	}
	return Scalar_Vector
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
