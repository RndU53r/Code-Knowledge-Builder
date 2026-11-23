package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"

	"example.com/fulfillment/internal/queue"
)

func main() {
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	shippingURL := os.Getenv("SHIPPING_API_URL")
	apiKey := os.Getenv("SHIPPING_API_KEY")
	client := &http.Client{Timeout: 10 * time.Second}

	err = queue.Consume(os.Getenv("RABBITMQ_URL"), func(evt queue.OrderCreated) error {
		payload, _ := json.Marshal(map[string]any{"order_id": evt.OrderID, "address": evt.ShippingAddress})
		req, _ := http.NewRequest("POST", shippingURL+"/shipments", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := client.Do(req)
		status := "shipped"
		if err != nil || resp.StatusCode >= 300 {
			status = "failed"
		}
		_, dbErr := db.Exec("UPDATE orders SET status = $1 WHERE id = $2", status, evt.OrderID)
		return dbErr
	})
	if err != nil {
		log.Fatal(err)
	}
}
