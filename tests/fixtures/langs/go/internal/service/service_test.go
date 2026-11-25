package service

import "testing"

func TestPlace(t *testing.T) {
	s := &OrderService{}
	s.Place("a")
}
