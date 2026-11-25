package service

import "example.com/shop/internal/repo"

type OrderService struct {
	repo *repo.OrderRepo
}

func (s *OrderService) Place(item string) error {
	return s.repo.Save(item)
}
