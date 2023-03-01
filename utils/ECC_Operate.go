package utils

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

var Curve *secp256k1.KoblitzCurve

type Point struct {
	X *big.Int
	Y *big.Int
}

// Create a method for converting Point type to byte
func (recv Point) Point2Bytes() []byte {
	var result []byte
	result = append(result, recv.X.Bytes()...)
	result = append(result, recv.Y.Bytes()...)
	return result
}

// Generate single point on Elliptic Curve
func GeneratePoint() Point {
	private, _ := secp256k1.GeneratePrivateKey()
	pub := private.PubKey()
	var point Point
	point.X = pub.X()
	point.Y = pub.Y()
	return point
}

// Generate multiple points on Elliptic Curve
func GenerateMultiPoint(N int) []Point {
	var points []Point
	for i := N; i > 0; i-- {
		points = append(points, GeneratePoint())
	}
	return points
}

//Calculate the scalar multiplication of a point vector
func Cal_Point_Sca(vec Point, value *big.Int) Point {
	// Create new big int variable: result
	var result Point
	result.X, result.Y = Curve.ScalarMult(vec.X, vec.Y, value.Bytes())
	return result
}

//Calculate the scalar multiplication of a point vector
func Cal_Point_Sca_Vec(vec []Point, value *big.Int) []Point {
	// Create new big int variable: result
	var result []Point
	// Calculate the addition vector
	for i := range vec {
		var temp Point
		temp.X, temp.Y = Curve.ScalarMult(vec[i].X, vec[i].Y, value.Bytes())
		result = append(result, temp)
	}
	return result
}

//Calculate the addition of two point vectors
func Cal_Point_Add(vec_a Point, vec_b Point) Point {
	// Create new big int variable: result
	var result Point
	// Calculate the addition vector
	result.X, result.Y = Curve.Add(vec_a.X, vec_a.Y, vec_b.X, vec_b.Y)
	return result
}

//Calculate the addition of two point vectors
func Cal_Point_Add_Vec(vec_a []Point, vec_b []Point) []Point {
	// Create new big int variable: result
	var result []Point
	// Calculate the addition vector
	for i := range vec_a {
		var temp Point
		temp.X, temp.Y = Curve.Add(vec_a[i].X, vec_a[i].Y, vec_b[i].X, vec_b[i].Y)
		result = append(result, temp)
	}
	return result
}

func Is_Equal_Point(a Point, b Point) bool {
	if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
		return true
	} else {
		return false
	}
}
