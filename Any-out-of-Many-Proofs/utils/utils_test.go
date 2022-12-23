package utils

import (
	"fmt"
	"math/big"
	"testing"
)

func Test_Mul_In_P(t *testing.T) {
	var a, b *big.Int
	test_vector := Mul_In_P(a, b)
	fmt.Println(test_vector)
}
