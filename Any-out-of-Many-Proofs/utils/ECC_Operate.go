package utils

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

type Point struct {
	X *big.Int
	Y *big.Int
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
