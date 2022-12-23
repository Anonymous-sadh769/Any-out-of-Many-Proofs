package main

import (
	"fmt"
	"time"

	//"math/big"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"

	"github.com/egoistzty/Code-Any-out-of-Many.git/utils"
)

var prover Prover
var verifier Verifier

func main() {

	setup(64, 256) // k for secret number N for ring size
	p_start := time.Now()
	fmt.Println("p_start:", p_start)
	zkpConstruct()
	p_elapsed := time.Since(p_start)
	fmt.Println("Prover Running Time:", p_elapsed)

	v_start := time.Now()
	fmt.Println("v_start:", v_start)
	zkpVerify()
	v_elapsed := time.Since(v_start)
	fmt.Println("Verify Running Time:", v_elapsed)

}

func setup(k int, N int) {

	var curve = secp256k1.S256() //Choose an elliptic curve

	g := utils.GeneratePoint()
	u := utils.GeneratePoint()
	v := utils.GeneratePoint()
	fmt.Println("Generate g,u,v...")
	Public_g := utils.GeneratePoint()

	g_Vector := utils.GenerateMultiPoint(N)
	h_Vector := utils.GenerateMultiPoint(N)
	fmt.Println("Generate vectors g_vector, h_vector...")

	//construct an object prover
	prover.New(Public_g, g, u, v, g_Vector, h_Vector, k, N, *curve)

	//construct an object verifier
	verifier.New(Public_g, g, u, v, g_Vector, h_Vector, k, N, *curve)
}

func zkpConstruct() {
	fmt.Println("Genreate ZKP transcripts...")
	//Prover compute Commitments A, B and transmit to verifier
	verifier.A, verifier.B = prover.GetAB()
	//verifier.GetCom(A, S)

	//verifier get A, B and transmit y, z to prover
	prover.y, prover.z = verifier.GetYZ()

	//Prover compute Commitments T1, T2 and transmit to verifier
	verifier.T1, verifier.T2, verifier.E = prover.GetT()

	//verifier get T1, T2, E and transmit x to prover
	prover.x = verifier.GetX()

	verifier.Pub_Vec_Key, verifier.proverZKP = prover.GetRsp()
	fmt.Println("ZKProofs", verifier.proverZKP)
}

func zkpVerify() {
	fmt.Println("-----------------------------------------------")
	fmt.Println("Received ZKP transcripts and start verifying...")
	verifier.ParseZKP()
}
