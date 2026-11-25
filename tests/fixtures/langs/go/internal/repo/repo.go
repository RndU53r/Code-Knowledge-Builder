package repo

import (
	"database/sql"
	"fmt"
	"net/http"
)

type BaseRepo struct{}

func (b *BaseRepo) Save(item string) error {
	return nil
}

type OrderRepo struct {
	BaseRepo
	db *sql.DB
}

func (o *OrderRepo) Save(item string) error {
	http.Get("http://billing/charge")
	o.db.Query(fmt.Sprintf("SELECT * FROM orders WHERE id = %s", item))
	return o.BaseRepo.Save(item)
}
