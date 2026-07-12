package main

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestCircuitScenarios(t *testing.T) {
	scenarios := []string{
		"contributor_payments",
		"defi_swaps",
		"supply_lending",
		"amount_limits",
		"function_level_controls",
		"interact_dapps",
		"advanced_signer_policies",
	}

	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			assignment, err := getExampleAssignment(scenario)
			if err != nil {
				t.Fatalf("build assignment: %v", err)
			}

			var circuit ZKGuardCircuit
			if err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("circuit constraints are not satisfied: %v", err)
			}
		})
	}
}
