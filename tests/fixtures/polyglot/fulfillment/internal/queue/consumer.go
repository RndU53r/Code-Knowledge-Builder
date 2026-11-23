package queue

import (
	"encoding/json"
	"log"

	amqp "github.com/rabbitmq/amqp091-go"
)

type OrderCreated struct {
	OrderID         string `json:"order_id"`
	CustomerID      string `json:"customer_id"`
	TotalCents      int    `json:"total_cents"`
	ShippingAddress string `json:"shipping_address"`
}

func Consume(url string, handle func(OrderCreated) error) error {
	conn, err := amqp.Dial(url)
	if err != nil {
		return err
	}
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	q, err := ch.QueueDeclare("fulfillment.order-created", true, false, false, false, nil)
	if err != nil {
		return err
	}
	if err := ch.QueueBind(q.Name, "order.created", "orders", false, nil); err != nil {
		return err
	}
	msgs, err := ch.Consume(q.Name, "fulfillment", false, false, false, false, nil)
	if err != nil {
		return err
	}
	for m := range msgs {
		var evt OrderCreated
		if err := json.Unmarshal(m.Body, &evt); err != nil {
			log.Printf("bad message: %v", err)
			m.Nack(false, false)
			continue
		}
		if err := handle(evt); err != nil {
			log.Printf("handle failed for %s: %v", evt.OrderID, err)
			m.Nack(false, true)
			continue
		}
		m.Ack(false)
	}
	return nil
}
