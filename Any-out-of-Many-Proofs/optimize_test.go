package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/egoistzty/Code-Any-out-of-Many.git/utils"
)

func Test_optimization(t *testing.T) {
	test_vec_1 := utils.Generate_Random_Zp_Vector(4096)
	test_vec_2 := utils.Generate_Random_Zp_Vector(4096)
	start := time.Now()
	L, R, ip, a, b := prove(test_vec_1, test_vec_2)
	elapsed := time.Since(start)
	fmt.Println("Prove Running Time:", elapsed)
	start = time.Now()
	verify(L, R, ip, a, b)
	elapsed = time.Since(start)
	fmt.Println("Verify Running Time:", elapsed)
}
