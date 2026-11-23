package main

import (
	"encoding/json"
	"flag"
	"os"
)

type item struct {
	SKU string `json:"sku"`
	Qty int    `json:"qty"`
}

func main() {
	_ = flag.Bool("json", true, "json io")
	flag.Parse()
	var items []item
	if err := json.NewDecoder(os.Stdin).Decode(&items); err != nil {
		os.Exit(2)
	}
	total := 0
	for _, it := range items {
		total += it.Qty * 999
	}
	json.NewEncoder(os.Stdout).Encode(map[string]int{"total_cents": total})
}
