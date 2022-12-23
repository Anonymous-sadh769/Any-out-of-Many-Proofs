package utils

import (
	"errors"
	"fmt"
	"math/big"
)

//Calculate the inner product of two big.Int vectors
func Cal_IP_Vec(vec_a []*big.Int, vec_b []*big.Int) (*big.Int, error) {
	defer func() {
		err := recover() //catch the error
		if err != nil {
			fmt.Println("Error catched:")
		}
	}()
	// Ensure two vectors have same length
	if len(vec_a) != len(vec_b) {
		return nil, errors.New("different length of two vectors")
	}
	// Create new big int variable: result
	var result = big.NewInt(0)
	// Calculate the inner product
	for key := range vec_a {
		result = Add_In_P(result, Mul_In_P(vec_a[key], vec_b[key]))
	}
	return result, nil
}

//Calculate the Hadamard product of two big.Int vectors
func Cal_HP_Vec(vec_a []*big.Int, vec_b []*big.Int) ([]*big.Int, error) {
	defer func() {
		err := recover() //catch the error
		if err != nil {
			fmt.Println("Error catched:")
		}
	}()
	// Ensure two vectors have same length
	if len(vec_a) != len(vec_b) {
		return nil, errors.New("different length of two vectors")
	}
	// Create new big int variable: result
	var result []*big.Int
	// Calculate the Hadamard product
	for i := range vec_a {
		result = append(result, Mul_In_P(vec_a[i], vec_b[i]))
	}
	return result, nil
}

//Calculate the scalar product of two big.Int vectors
func Cal_Sca_Vec(vec_a []*big.Int, sca_b *big.Int) []*big.Int {
	// Create new big int variable: result
	var result []*big.Int
	// Calculate the scalar product
	for i := range vec_a {
		result = append(result, Mul_In_P(vec_a[i], sca_b))
	}
	return result
}

//Calculate the addition of two big.Int vectors
func Cal_Add_Vec(vec_a []*big.Int, vec_b []*big.Int) ([]*big.Int, error) {
	defer func() {
		err := recover() //catch the error
		if err != nil {
			fmt.Println("Error catched:")
		}
	}()
	// Ensure two vectors have same length
	if len(vec_a) != len(vec_b) {
		return nil, errors.New("different length of two vectors")
	}
	// Create new big int variable: result
	var result []*big.Int
	// Calculate the addition vector
	for i := range vec_a {
		result = append(result, Add_In_P(vec_a[i], vec_b[i]))
	}
	return result, nil
}

//Calculate the substract of two big.Int vectors
func Cal_Sub_Vec(vec_a []*big.Int, vec_b []*big.Int) ([]*big.Int, error) {
	defer func() {
		err := recover() //catch the error
		if err != nil {
			fmt.Println("Error catched:")
		}
	}()
	// Ensure two vectors have same length
	if len(vec_a) != len(vec_b) {
		return nil, errors.New("different length of two vectors")
	}
	// Create new big int variable: result
	var result []*big.Int
	// Calculate the addition vector
	for i := range vec_a {
		result = append(result, Add_In_P(vec_a[i], Neg_Zp(vec_b[i])))
	}
	return result, nil
}

//Calculate the negation of two big.Int vectors
func Cal_Neg_Vec(vec_a []*big.Int) []*big.Int {
	// Create new big int variable: result
	var result []*big.Int
	// Calculate the addition vector
	for i := range vec_a {
		result = append(result, Neg_Zp(vec_a[i]))
	}
	return result
}

//Calculate the inverse of two big.Int vectors
func Cal_Inv_Vec(vec_a []*big.Int) []*big.Int {
	// Create new big int variable: result
	var result []*big.Int
	// Calculate the addition vector
	for i := range vec_a {
		result = append(result, Inverse_Zp(vec_a[i]))
	}
	return result
}
