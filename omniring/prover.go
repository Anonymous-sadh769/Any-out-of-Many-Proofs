package omniring

import (
	"math"
	"math/big"

	"anyOutOfMany/utils"
)

type Prover struct {
	///////////////////////////////public parameters:
	u, v                            *big.Int      // generator as commitment key for public keys
	Gen_F, Gen_G, Gen_H             utils.Point   // generators u,v
	Gen_Vec_G, Gen_Vec_H, Gen_Vec_P []utils.Point // generator vector g h
	Gen_Vec_Gw                      []utils.Point
	Pub_Vec_Key                     []utils.Point // public key vector i.e., ring set
	Out_Vec_Coin, Inp_Vec_Coin      []utils.Point
	A, B                            utils.Point   // commitments A, B
	T1, T2                          utils.Point   // commitments T, T1, T2, E
	L, R                            []utils.Point // auxiliary commitments L,R

	N int // total number of source accounts N
	k int // secret number
	n int // ring size
	d int // maximum width of value

	// challenge values
	w    *big.Int
	y, z *big.Int
	x    *big.Int

	/////////////////////////////////private parameters:
	sec_Vec_Key, sec_Vec_Value, sec_Vec_Random []*big.Int // secrets
	out_Vec_Value, out_Vec_Random              []*big.Int
	vec_inv_theta                              []*big.Int

	//binary vector and corresponding randomness
	b_0 []*big.Int
	b_1 []*big.Int
	s_L []*big.Int
	s_R []*big.Int
	c_L []*big.Int
	c_R []*big.Int

	// masking value
	r_A, r_B *big.Int
	alpha    *big.Int
	beta     *big.Int

	// intemediate values zeta, eta, t1, t2 and corresponding randomness
	tau_1 *big.Int
	tau_2 *big.Int

	// parameters for response
	zeta, eta, c_zeta, c_eta []*big.Int
	tau_x                    *big.Int
	mu                       *big.Int
	ip                       *big.Int
}

// Initialization function
func (prover *Prover) New(u *big.Int, v *big.Int, F utils.Point, G utils.Point, H utils.Point, P_Vector []utils.Point, G_Vector []utils.Point, H_Vector []utils.Point, k int, N int, d int) {
	prover.u = u
	prover.v = v
	prover.Gen_F = F
	prover.Gen_G = G
	prover.Gen_H = H
	prover.Gen_Vec_P = P_Vector
	prover.Gen_Vec_G = G_Vector
	prover.Gen_Vec_H = H_Vector
	prover.k = k
	prover.N = N
	prover.n = N / k
	prover.d = d

	//Generate secrets of prover
	prover.sec_Vec_Key = utils.Generate_Random_Zp_Vector(k, prover.d)
	prover.generateKey()
	prover.sec_Vec_Value = utils.Generate_Random_Zp_Vector(k, prover.d)
	prover.sec_Vec_Random = utils.Generate_Random_Zp_Vector(k, prover.d)
	if len(prover.sec_Vec_Value) > 1 {
		prover.out_Vec_Value = utils.Cal_Add_Vec(prover.sec_Vec_Value[:len(prover.sec_Vec_Value)/2], prover.sec_Vec_Value[len(prover.sec_Vec_Value)/2:]) //Simulate the transaction between input and output
		prover.out_Vec_Random = utils.Generate_Random_Zp_Vector(k/2, prover.d)
		prover.generateCoin()
	} else {
		prover.out_Vec_Value = prover.sec_Vec_Value
		prover.out_Vec_Random = utils.Generate_Random_Zp_Vector(1, prover.d)
		prover.generateCoin()
	}
}

////////////////////////Public interfaces

//Get response zeta, eta, t, tau_x, mu, f_s
func (prover *Prover) GenerateRsp() ([]utils.Point, []utils.Point, []utils.Point, Transcript, []utils.Point, []utils.Point) {

	//prover computes Commitments A, B
	prover.calculateRound1()

	//prover compute Commitments T1, T2

	prover.calculateRound2()

	theta_eta := utils.Cal_HP_Vec(prover.vec_inv_theta, prover.eta)

	// Padding the vectors to 2^n length
	deg := math.Ceil(math.Log2(float64(len(prover.c_L))))
	pad := math.Pow(2, deg) - float64(len(prover.c_L))
	zero_vec := Generate_cons_vec(int(pad), big.NewInt(0))
	var one_vec []utils.Point
	for i := 0; i < len(zero_vec); i++ {
		one_vec = append(one_vec, utils.Commit(prover.Gen_F, big.NewInt(0)))
	}
	prover.zeta = append(prover.zeta, zero_vec...)
	theta_eta = append(theta_eta, zero_vec...)
	prover.Gen_Vec_Gw = append(prover.Gen_Vec_Gw, one_vec...)
	prover.Gen_Vec_H = append(prover.Gen_Vec_H, one_vec...)

	// Compress the openings
	// prover.L, prover.R, prover.c_zeta, prover.c_eta = opt_prove(prover.zeta, theta_eta, prover.Gen_Vec_Gw, prover.Gen_Vec_H, prover.Gen_G)

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
		Eta:   theta_eta,
		W:     prover.w,
		X:     prover.x,
		Y:     prover.y,
		Z:     prover.z,
	}
	return prover.Pub_Vec_Key, prover.Inp_Vec_Coin, prover.Out_Vec_Coin, transcript, prover.Gen_Vec_Gw, prover.Gen_Vec_H
}

////////////////////////Private functions

//Generate b_0,b_1,s_0,s_1 and public keys
func (prover *Prover) generateKey() {
	//Generate binary vector b_0 b_1
	prover.b_0, _ = Generate_b_0(prover.k, prover.N)
	prover.b_1 = Generate_b_1(prover.b_0)
	//generate key
	prover.Pub_Vec_Key = prover.Generate_Multi_Public_Key(prover.k, prover.N, prover.b_0) //generate public key vector Y
}

func (prover *Prover) generateCoin() {
	//generate Input Coin
	prover.Inp_Vec_Coin = prover.Generate_Multi_Public_Coin(prover.k, prover.N, prover.b_0) //generate public key vector Y
	//generate Output Coin
	for i := 0; i < len(prover.out_Vec_Value); i++ {
		secret_key := prover.out_Vec_Value[i]
		secret_random := prover.out_Vec_Random[i]
		prover.Out_Vec_Coin = append(prover.Out_Vec_Coin, utils.Pedersen_Commit(prover.Gen_G, prover.Gen_H, secret_key, secret_random))
	}
}

//Generate Commitments A
func (prover *Prover) calculateRound1() {
	// Generate commitment Y
	Coin_u := utils.Cal_Point_Sca_Vec(prover.Inp_Vec_Coin, prover.u) // Coin^u
	Gen_Vec_Y := utils.Cal_Point_Add_Vec(prover.Pub_Vec_Key, Coin_u) // Y = Pk \circ Coin^u

	// Generate G_0, i.e., G_w with w=0
	G0 := utils.Commit(prover.Gen_G, big.NewInt(0))
	H0 := utils.Commit(prover.Gen_G, big.NewInt(0))
	zero_vec := Generate_cons_vec(prover.n, big.NewInt(0))
	var Gen_Vec_Y0 []utils.Point
	for i := 0; i < len(zero_vec); i++ {
		Gen_Vec_Y0 = append(Gen_Vec_Y0, utils.Commit(Gen_Vec_Y[i], zero_vec[i]))
	}

	var temp []utils.Point
	temp = append(temp, G0)
	temp = append(temp, H0)
	temp = append(temp, Gen_Vec_Y0...)
	temp = utils.Cal_Point_Add_Vec(temp, prover.Gen_Vec_P)
	Gen_Vec_G0 := append(temp, prover.Gen_Vec_G...)

	//////////////////////////////////////////////Generate commitment A
	prover.r_A = utils.Generate_Random_Zp(prover.d)

	//Generate c_L
	v_k := Generate_Exp_Scalar_Vector(prover.v, prover.k)
	u_a := utils.Cal_Sca_Vec(prover.sec_Vec_Value, prover.u)
	c_L_1 := utils.Cal_IP_Vec(u_a, v_k) // zeta
	u_r := utils.Cal_Sca_Vec(prover.sec_Vec_Random, prover.u)
	u_r_x := utils.Cal_Add_Vec(u_r, prover.sec_Vec_Key)
	c_L_2 := utils.Cal_IP_Vec(u_r_x, v_k) //eta

	vk_E := Generate_cons_vec(prover.n, big.NewInt(0))
	counter := 0
	var res []*big.Int
	for i := 0; i < prover.k; i++ {
		res = utils.Cal_Sca_Vec(prover.b_0[(0+counter*prover.n):((counter+1)*prover.n)], v_k[i])
		vk_E = utils.Cal_Add_Vec(vk_E, res)
		counter++
	}

	prover.c_L = append(prover.c_L, c_L_1)
	prover.c_L = append(prover.c_L, c_L_2)
	prover.c_L = append(prover.c_L, vk_E...)
	prover.c_L = append(prover.c_L, prover.b_0...)
	prover.c_L = append(prover.c_L, prover.sec_Vec_Value...)
	prover.c_L = append(prover.c_L, prover.sec_Vec_Random...)
	prover.c_L = append(prover.c_L, prover.sec_Vec_Key...)

	//Generate c_R
	vec_zero := Generate_cons_vec(2+prover.n, big.NewInt(0))
	vec_one := Generate_cons_vec(prover.N, big.NewInt(1))
	b_0_1 := utils.Cal_Sub_Vec(prover.b_0, vec_one)
	vec_zero_2 := Generate_cons_vec(2*prover.k, big.NewInt(0))
	inv_sec_key := utils.Cal_Inv_Vec(prover.sec_Vec_Key)

	prover.c_R = append(prover.c_R, vec_zero...)
	prover.c_R = append(prover.c_R, b_0_1...)
	prover.c_R = append(prover.c_R, vec_zero_2...)
	prover.c_R = append(prover.c_R, inv_sec_key...)

	F_rA := utils.Commit(prover.Gen_F, prover.r_A)
	G_L_H_R := utils.Pedersen_Commit_Vector(Gen_Vec_G0, prover.Gen_Vec_H, prover.c_L, prover.c_R)
	prover.A.X, prover.A.Y = utils.Curve.Add(F_rA.X, F_rA.Y, G_L_H_R.X, G_L_H_R.Y)

	//Generate challenge w
	prover.w = Generate_W(prover.A)

	//////////////////////////////////////////////Generate commitment B
	prover.s_L = utils.Generate_Random_Zp_Vector(2+prover.n+prover.N+3*prover.k, prover.d)
	prover.s_R = utils.Generate_Random_Zp_Vector(2+prover.n+prover.N+3*prover.k, prover.d)
	prover.r_B = utils.Generate_Random_Zp(prover.d)

	// Generate G_w
	Gw := utils.Commit(prover.Gen_G, prover.w)
	Hw := utils.Commit(prover.Gen_G, prover.w)
	w_vec := Generate_cons_vec(prover.n, prover.w)
	var Gen_Vec_Yw []utils.Point
	for i := 0; i < len(w_vec); i++ {
		Gen_Vec_Yw = append(Gen_Vec_Yw, utils.Commit(Gen_Vec_Y[i], w_vec[i]))
	}
	temp = nil
	temp = append(temp, Gw)
	temp = append(temp, Hw)
	temp = append(temp, Gen_Vec_Yw...)
	temp = utils.Cal_Point_Add_Vec(temp, prover.Gen_Vec_P)
	prover.Gen_Vec_Gw = append(temp, prover.Gen_Vec_G...)

	F_rB := utils.Commit(prover.Gen_F, prover.r_B)
	G_L_H_R = utils.Pedersen_Commit_Vector(prover.Gen_Vec_Gw, prover.Gen_Vec_H, prover.s_L, prover.s_R)
	prover.B.X, prover.B.Y = utils.Curve.Add(F_rB.X, F_rB.Y, G_L_H_R.X, G_L_H_R.Y)

	//Compute challenges y,z
	prover.y, prover.z = Generate_YZ(prover.A, prover.B)
}

func (prover *Prover) calculateRound2() {
	n := prover.n
	k := prover.k
	N := prover.N
	zero_vec := Generate_cons_vec(2+n+N+3*k, big.NewInt(0))
	var vec_v [9][]*big.Int
	for i := 0; i < 9; i++ {
		vec_v[i] = zero_vec
	}
	vec_u4 := zero_vec

	////////////////////////////////////////////// Compute constraint vectors
	vec_yN := Generate_Exp_Scalar_Vector(prover.y, N)
	copy(vec_v[0][2+n:2+n+N-1], vec_yN)
	vec_yk := Generate_Exp_Scalar_Vector(prover.y, k)
	copy(vec_v[1][2+n+N+2*k:2+n+N+3*k-1], vec_yk)
	// no vec_v2
	var vec_yk_1n []*big.Int
	for i := 0; i < k; i++ {
		vec_yk_1n = append(vec_yk_1n, Generate_cons_vec(n, vec_yk[i])...)
	}
	copy(vec_v[3][2+n:2+n+N-1], vec_yk_1n)

	vec_vk := Generate_Exp_Scalar_Vector(prover.v, prover.k)
	vec_uvk := utils.Cal_Sca_Vec(vec_vk, prover.u)
	vec_v[4][0] = big.NewInt(1)
	copy(vec_v[4][2+n+N:2+n+N+k-1], vec_uvk)

	vec_v[5][1] = big.NewInt(1)
	copy(vec_v[5][2+n+N+k:2+n+N+2*k-1], vec_uvk)
	copy(vec_v[5][2+n+N+2*k:2+n+N+3*k-1], vec_vk)

	vec_yn := Generate_Exp_Scalar_Vector(prover.y, n)
	neg_vec_yn := utils.Cal_Neg_Vec(vec_yn)
	var vec_vk_yn []*big.Int
	for i := 0; i < k; i++ {
		vec_vk_yn = append(vec_vk_yn, utils.Cal_Sca_Vec(vec_yn, vec_vk[i])...)
	}
	copy(vec_v[6][2:2+n-1], neg_vec_yn)
	copy(vec_v[6][2+n:2+n+N], vec_vk_yn)

	neg_vec_1k := Generate_cons_vec(k, big.NewInt(-1))
	copy(vec_v[7][2+n+N:2+n+N+k-1], neg_vec_1k)

	copy(vec_v[8], vec_v[0])

	u2 := utils.Mul_In_P(prover.u, prover.u)
	vec_u2vk := utils.Cal_Sca_Vec(vec_vk, u2)
	copy(vec_u4, vec_u2vk)

	vec_theta := zero_vec
	temp := big.NewInt(1)
	for i := 0; i < 2; i++ {
		vec_theta = utils.Cal_Add_Vec(vec_theta, utils.Cal_Sca_Vec(vec_v[i], temp))
		temp = utils.Mul_In_P(temp, prover.z)
	}

	vec_ksi := zero_vec
	temp = utils.Mul_In_P(prover.z, prover.z)
	for i := 2; i < 8; i++ {
		vec_ksi = utils.Cal_Add_Vec(vec_ksi, utils.Cal_Sca_Vec(vec_v[i], temp))
		temp = utils.Mul_In_P(temp, prover.z)
	}

	vec_mu := zero_vec
	temp = utils.Mul_In_P(prover.z, prover.z)
	for i := 2; i < 9; i++ {
		vec_mu = utils.Cal_Add_Vec(vec_mu, utils.Cal_Sca_Vec(vec_v[i], temp))
		temp = utils.Mul_In_P(temp, prover.z)
	}

	temp = big.NewInt(1) // z^8
	for i := 0; i < 8; i++ {
		temp = utils.Mul_In_P(temp, prover.z)
	}
	vec_vv := utils.Cal_Sca_Vec(vec_v[8], temp)

	temp = big.NewInt(1) // z^4
	for i := 0; i < 4; i++ {
		temp = utils.Mul_In_P(temp, prover.z)
	}
	vec_ww := utils.Cal_Sca_Vec(vec_u4, temp)

	prover.vec_inv_theta = utils.Cal_Inv_Vec(vec_theta)
	vec_ww_vv := utils.Cal_Sub_Vec(vec_ww, vec_vv)
	vec_alpha := utils.Cal_HP_Vec(prover.vec_inv_theta, vec_ww_vv)
	// TODO
	// vec_beta, _ := utils.Cal_HP_Vec(vec_inv_theta, vec_mu) // Calculated by the verifier, as well as theta and mu

	// Compute T_1, T_2
	// Compute t_1
	vec_cL_alpha := utils.Cal_Add_Vec(prover.c_L, vec_alpha)
	vec_theta_sR := utils.Cal_HP_Vec(vec_theta, prover.s_R)
	t1L := utils.Cal_IP_Vec(vec_cL_alpha, vec_theta_sR)
	vec_theta_cR := utils.Cal_HP_Vec(vec_theta, prover.c_R)
	vec_theta_cR_mu := utils.Cal_Add_Vec(vec_theta_cR, vec_mu)
	t1R := utils.Cal_IP_Vec(prover.s_L, vec_theta_cR_mu)
	t_1 := utils.Add_In_P(t1L, t1R)

	//Generate tau2
	prover.tau_1 = utils.Generate_Random_Zp(prover.d)

	//Compute T1
	prover.T1 = utils.Pedersen_Commit(prover.Gen_G, prover.Gen_F, t_1, prover.tau_1)

	//Compute t_2
	vec_theta_s_R := utils.Cal_HP_Vec(vec_theta, prover.s_R)
	t_2 := utils.Cal_IP_Vec(prover.s_L, vec_theta_s_R)

	//Generate tau2
	prover.tau_2 = utils.Generate_Random_Zp(prover.d)

	//Compute T2
	prover.T2 = utils.Pedersen_Commit(prover.Gen_G, prover.Gen_F, t_2, prover.tau_2)

	//prover compute Commitments T1, T2
	// Compute x
	prover.x = Generate_X(prover.T1, prover.T2)
	////////////////////////////////////////////// Calculate rx, i.e., zeta
	vec_sL_x := utils.Cal_Sca_Vec(prover.s_L, prover.x)
	prover.zeta = utils.Cal_Add_Vec(vec_cL_alpha, vec_sL_x)

	////////////////////////////////////////////// Calculate lx, i.e., eta
	vec_sR_x := utils.Cal_Sca_Vec(prover.s_R, prover.x)
	vec_cR_sRx := utils.Cal_Add_Vec(prover.c_R, vec_sR_x)
	vec_theta_cR_sRx := utils.Cal_HP_Vec(vec_theta, vec_cR_sRx)
	prover.eta = utils.Cal_Add_Vec(vec_theta_cR_sRx, vec_mu)

	//Compute t = <l(x), r(x)>
	prover.ip = utils.Cal_IP_Vec(prover.eta, prover.zeta)

	//Compute tau_x = tau_1 x + tau_2 x^2
	z2 := utils.Mul_In_P(prover.z, prover.z)
	vec_yk2 := Generate_Exp_Scalar_Vector(prover.y, len(prover.out_Vec_Value))
	tau0 := utils.Mul_In_P(z2, utils.Cal_IP_Vec(prover.out_Vec_Random, vec_yk2))

	tau1_x := utils.Mul_In_P(prover.tau_1, prover.x)
	tau2_x2 := utils.Mul_In_P(prover.tau_2, utils.Mul_In_P(prover.x, prover.x))
	prover.tau_x = utils.Add_In_P(tau0, tau1_x)
	prover.tau_x = utils.Add_In_P(prover.tau_x, tau2_x2)

	//Compute mu
	prover.mu = utils.Add_In_P(prover.r_A, utils.Mul_In_P(prover.r_B, prover.x))
}
