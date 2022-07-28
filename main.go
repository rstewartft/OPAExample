package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

func main() {
	ctx := context.Background()
	fmt.Println()

	// Raw input data that will be used in evaluation.
	raw1 := `{
  "user": "bob",
  "action": "read",
  "object": "billing_methods",
  "org_id": 1
}`
	fmt.Printf("Bob should not be able to see billing methods for Org 1 since he is only a driver. Policy evaluation result: %t \n", evaluatePolicy(ctx, raw1))

	raw2 := `{
  "user": "bob",
  "action": "read",
  "object": "billing_methods",
  "org_id": 2
}`
	fmt.Printf("Bob should be able to see billing methods for Org 2 since he is an owner. Policy evaluation result: %t \n", evaluatePolicy(ctx, raw2))

	raw3 := `{
  		"user": "bob",
  		"action": "read",
  		"object": "driver_assignments",
  		"org_id": 2
	}`
	fmt.Printf("Bob is a driver for Org 1 so can only see driver assignments. Policy evaluation result: %t \n", evaluatePolicy(ctx, raw3))

	raw4 := `{
  		"user": "alice",
  		"action": "write",
  		"object": "billing_methods",
  		"org_id": 1
	}`
	fmt.Printf("Alice is an owner and admin for Org 1 only. She can update billing methods. Policy evaluation result: %t \n", evaluatePolicy(ctx, raw4))

	raw5 := `{
  		"user": "alice",
  		"action": "read",
  		"object": "driver_assignments",
  		"org_id": 2
	}`
	fmt.Printf("Alice is an owner and admin for Org 1 only. She cannot do anything in Org 2. Policy evaluation result: %t \n", evaluatePolicy(ctx, raw5))

	raw6 := `{
  		"user": "larry",
  		"action": "write",
  		"object": "vehicle_issues",
  		"org_id": 1
	}`
	fmt.Printf("Larr is a laborer for Org 1 only. He can create vehicle issues for this org. Policy evaluation result: %t \n", evaluatePolicy(ctx, raw6))
}

func evaluatePolicy(ctx context.Context, raw string) bool {
	d := json.NewDecoder(bytes.NewBufferString(raw))

	// Numeric values must be represented using json.Number.
	d.UseNumber()

	var input interface{}

	if err := d.Decode(&input); err != nil {
		panic(err)
	}

	// Create a simple query over the input.
	query := rego.New(
		rego.Query("data.rbac.authz.allow"),
		rego.Load([]string{"./authorization.rego"}, nil),
		rego.Input(input))

	rs, err := query.Eval(ctx)

	if err != nil {
		// Handle error.
	}

	return rs.Allowed()
}
