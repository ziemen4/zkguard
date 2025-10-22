// gnark/bench_test.go
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

// --example flag to filter benchmarks. Usage: go test -bench . -example <name>
var exampleFlag = flag.String("example", "all", "Run benchmark for a specific example, or 'all'.")
var timeFlag = flag.Bool("time", false, "Run a single timing run and print results in seconds, skipping standard benchmarks.")

// getExampleAssignment is a helper that sets up the data for a specific example
// and returns the witness assignment struct. This centralizes test case data.
func getExampleAssignment(exampleName string) (ZKGuardCircuit, error) {
	// --- Common Setup for all Scenarios ---
	primaryKey, _ := eth_crypto.HexToECDSA("1ab2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2")
	daoSafeAddress := eth_crypto.PubkeyToAddress(primaryKey.PublicKey)

	govKey1, _ := eth_crypto.HexToECDSA("d2b651f6682d36d83a15039a831e5a619b48f9a3f25603f7e346f3be8f45c713")
	govKey2, _ := eth_crypto.HexToECDSA("2286b7bf48a97957770a5d2f8e1329128f83c07a0d4b851b238116541f714930")
	govKey3, _ := eth_crypto.HexToECDSA("a853651333333333333333333333333333333333333333333333333333333333")
	govAddr1 := eth_crypto.PubkeyToAddress(govKey1.PublicKey)
	govAddr2 := eth_crypto.PubkeyToAddress(govKey2.PublicKey)
	govAddr3 := eth_crypto.PubkeyToAddress(govKey3.PublicKey)
	governanceSigners := []*ecdsa.PrivateKey{govKey1, govKey2, govKey3}

	teamWallet1, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	teamWallet2, _ := hex.DecodeString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	stablecoin, _ := hex.DecodeString("dAC17F958D2ee523a2206206994597C13D831ec7")
	dex, _ := hex.DecodeString("7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
	lendingPool, _ := hex.DecodeString("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9")
	weth, _ := hex.DecodeString("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")

	teamWalletsSet := newAddressSet(teamWallet1, teamWallet2)
	governanceSignersSet := newAddressSet(eth_crypto.PubkeyToAddress(govKey1.PublicKey).Bytes(), eth_crypto.PubkeyToAddress(govKey2.PublicKey).Bytes(), eth_crypto.PubkeyToAddress(govKey3.PublicKey).Bytes())

	// Create group and allowlist hashes.
	var groupSetSizes [MAX_GROUPS]byte
	groupSetSizes[0] = 2 // teamWallet group
	groupSetSizes[1] = 3 // governance group

	var groupAddressSet [MAX_GROUPS][MAX_ADDRS_PER_SET]big.Int
	groupAddressSet[0] = newAddressSetBigInt(teamWallet1, teamWallet2)
	groupAddressSet[1] = newAddressSetBigInt(govAddr1.Bytes(), govAddr2.Bytes(), govAddr3.Bytes())

	emptySet := newAddressSetBigInt()
	for i := 2; i < MAX_GROUPS; i++ {
		groupAddressSet[i] = emptySet
	}

	var groupHash = AddressSetHash(groupSetSizes, groupAddressSet)

	// Implement obtention of allowlist hash as a byte array.
	var allowSetSizes [MAX_ALLOWLISTS]byte
	allowSetSizes[0] = 1 // approvedDEXs
	allowSetSizes[1] = 1 // approvedLendingProtocols

	var allowAddressSet [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]big.Int
	allowAddressSet[0] = newAddressSetBigInt(dex)
	allowAddressSet[1] = newAddressSetBigInt(lendingPool)

	for i := 2; i < MAX_ALLOWLISTS; i++ {
		allowAddressSet[i] = emptySet
	}

	var allowHash = AddressSetHash(allowSetSizes, allowAddressSet)

	// Frontend parsing of Groups and AllowLists.
	var groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	groups[0] = teamWalletsSet
	groups[1] = governanceSignersSet
	for i := 2; i < MAX_GROUPS; i++ {
		groups[i] = newAddressSet()
	}
	var groupSizes [MAX_GROUPS]frontend.Variable
	groupSizes[0] = 2
	groupSizes[1] = 3
	for i := 2; i < MAX_GROUPS; i++ {
		groupSizes[i] = 0
	}
	var allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	allowLists[0] = newAddressSet(dex)
	allowLists[1] = newAddressSet(lendingPool)
	for i := 2; i < MAX_ALLOWLISTS; i++ {
		allowLists[i] = newAddressSet()
	}
	var allowSizes [MAX_ALLOWLISTS]frontend.Variable
	allowSizes[0] = 1
	allowSizes[1] = 1
	for i := 2; i < MAX_ALLOWLISTS; i++ {
		allowSizes[i] = 0
	}

	var policyLines []PolicyLine
	var to *big.Int
	var value *big.Int
	var calldata []byte
	var signers []*ecdsa.PrivateKey

	switch exampleName {
	case "contributor_payments":
		policyLines = []PolicyLine{{ID: 1, TxType: TT_TRANSFER, DestinationTag: DP_GROUP, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoSafeAddress.Bytes()), AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(stablecoin), AmountMax: new(big.Int), Action: ACT_ALLOW}}
		to = new(big.Int).SetBytes(stablecoin)
		value = new(big.Int)
		amount := new(big.Int).SetUint64(5000 * 1e6)
		amountBytes := make([]byte, 32)
		amount.FillBytes(amountBytes)
		var buf bytes.Buffer
		buf.Write(transferSelector)
		buf.Write(bytes.Repeat([]byte{0}, 12))
		buf.Write(teamWallet1)
		buf.Write(amountBytes)
		calldata = buf.Bytes()
		signers = []*ecdsa.PrivateKey{primaryKey}
	case "defi_swaps":
		policyLines = []PolicyLine{{ID: 2, TxType: TT_CONTRACTCALL, DestinationTag: DP_ALLOWLIST, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoSafeAddress.Bytes()), AssetTag: AP_ANY, AmountMax: new(big.Int), Action: ACT_ALLOW}}
		to = new(big.Int).SetBytes(dex)
		value = new(big.Int).SetUint64(1e18)
		calldata = []byte{}
		signers = []*ecdsa.PrivateKey{primaryKey}
	case "supply_lending":
		policyLines = []PolicyLine{{ID: 3, TxType: TT_TRANSFER, DestinationTag: DP_ALLOWLIST, DestinationIdx: 1, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoSafeAddress.Bytes()), AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(weth), AmountMax: new(big.Int), Action: ACT_ALLOW}}
		to = new(big.Int).SetBytes(weth)
		value = new(big.Int)
		amount := new(big.Int).SetUint64(1e18)
		amountBytes := make([]byte, 32)
		amount.FillBytes(amountBytes)
		var buf bytes.Buffer
		buf.Write(transferSelector)
		buf.Write(bytes.Repeat([]byte{0}, 12))
		buf.Write(lendingPool)
		buf.Write(amountBytes)
		calldata = buf.Bytes()
		signers = []*ecdsa.PrivateKey{primaryKey}
	case "amount_limits":
		policyLines = []PolicyLine{{ID: 4, TxType: TT_TRANSFER, DestinationTag: DP_GROUP, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoSafeAddress.Bytes()), AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(stablecoin), AmountMax: new(big.Int).SetUint64(10000 * 1e6), Action: ACT_ALLOW}}
		to = new(big.Int).SetBytes(stablecoin)
		value = new(big.Int)
		amount := new(big.Int).SetUint64(9000 * 1e6)
		amountBytes := make([]byte, 32)
		amount.FillBytes(amountBytes)
		var buf bytes.Buffer
		buf.Write(transferSelector)
		buf.Write(bytes.Repeat([]byte{0}, 12))
		buf.Write(teamWallet1)
		buf.Write(amountBytes)
		calldata = buf.Bytes()
		signers = []*ecdsa.PrivateKey{primaryKey}
	case "function_level_controls":
		swapSelector, _ := hex.DecodeString("7ff36ab5")
		policyLines = []PolicyLine{{ID: 5, TxType: TT_CONTRACTCALL, DestinationTag: DP_ALLOWLIST, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoSafeAddress.Bytes()), AssetTag: AP_ANY, AmountMax: new(big.Int), FunctionSelector: swapSelector, Action: ACT_ALLOW}}
		to = new(big.Int).SetBytes(dex)
		value = new(big.Int).SetUint64(1e18)
		calldata = swapSelector
		signers = []*ecdsa.PrivateKey{primaryKey}
	case "interact_dapps":
		policyLines = []PolicyLine{{ID: 6, TxType: TT_CONTRACTCALL, DestinationTag: DP_ALLOWLIST, DestinationIdx: 1, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoSafeAddress.Bytes()), AssetTag: AP_ANY, AmountMax: new(big.Int), Action: ACT_ALLOW}}
		to = new(big.Int).SetBytes(lendingPool)
		value = new(big.Int)
		calldata = []byte{0x12, 0x34, 0x56, 0x78}
		signers = []*ecdsa.PrivateKey{primaryKey}
	case "advanced_signer_policies":
		policyLines = []PolicyLine{{ID: 7, TxType: TT_CONTRACTCALL, DestinationTag: DP_ALLOWLIST, DestinationIdx: 0, SignerTag: SP_THRESHOLD, SignerGroupIdx: 1, Threshold: 2, AssetTag: AP_ANY, AmountMax: new(big.Int), Action: ACT_ALLOW}}
		to = new(big.Int).SetBytes(dex)
		value = new(big.Int).SetUint64(10e18)
		calldata = []byte{0xaa, 0xbb, 0xcc, 0xdd}
		signers = []*ecdsa.PrivateKey{governanceSigners[0], governanceSigners[1]}
	default:
		return ZKGuardCircuit{}, fmt.Errorf("unknown example name: %s", exampleName)
	}

	return buildWitness(policyLines, 0, to, value, calldata, signers, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash), nil
}

func BenchmarkZKGuard(b *testing.B) {
	// --- 1. BENCHMARK ONE-TIME COSTS EFFICIENTLY ---
	var circuit ZKGuardCircuit
	var cs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	// Manually run and report the benchmark for compilation. This runs it once
	// and gives us the resulting R1CS for the next step.
	b.Run("CircuitCompilation", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		start := time.Now()
		var err error
		cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			b.Fatalf("compilation failed: %v", err)
		}
		b.StopTimer()
		totalTime := time.Since(start)
		avgTime := totalTime / time.Duration(b.N)
		b.Logf("-> Avg. time per op: %s (ran %d iterations in %s)", avgTime.Round(time.Millisecond), b.N, totalTime.Round(time.Millisecond))
	})

	// Manually run and report the benchmark for setup. This runs it once
	// and gives us the proving/verifying keys for the next steps.
	b.Run("Groth16_Setup", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		start := time.Now()
		var err error
		pk, vk, err = groth16.Setup(cs)
		if err != nil {
			b.Fatalf("setup failed: %v", err)
		}
		b.StopTimer()
		totalTime := time.Since(start)
		avgTime := totalTime / time.Duration(b.N)
		b.Logf("-> Avg. time per op: %s (ran %d iterations in %s)", avgTime.Round(time.Millisecond), b.N, totalTime.Round(time.Millisecond))
	})

	loc, _ := time.LoadLocation("UTC")
	b.Logf("Setup complete on %s. Starting per-proof benchmarks...", time.Now().In(loc).Format(time.RFC1123))

	// --- 2. PREPARE ALL EXAMPLE ASSIGNMENTS ---
	// We generate all assignments once to avoid re-generating them in each benchmark phase.
	examples := []string{
		"contributor_payments", "defi_swaps", "supply_lending",
		"amount_limits", "function_level_controls", "interact_dapps",
		"advanced_signer_policies",
	}
	assignments := make(map[string]ZKGuardCircuit)
	for _, name := range examples {
		assignment, err := getExampleAssignment(name)
		if err != nil {
			b.Fatalf("failed to create assignment for %s: %v", name, err)
		}
		assignments[name] = assignment
	}

	// --- 3. BENCHMARK PER-PROOF COSTS, GROUPED BY PHASE ---

	b.Run("WitnessCreation", func(b *testing.B) {
		for _, name := range examples {
			if *exampleFlag != "all" && *exampleFlag != name {
				continue
			}

			assignment := assignments[name]
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				start := time.Now()
				for i := 0; i < b.N; i++ {
					_, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
					if err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				totalTime := time.Since(start)
				avgTime := totalTime / time.Duration(b.N)
				b.Logf("-> Avg. time per op: %s (ran %d iterations in %s)", avgTime.Round(time.Millisecond), b.N, totalTime.Round(time.Millisecond))
			})
		}
	})

	b.Run("Prove", func(b *testing.B) {
		for _, name := range examples {
			if *exampleFlag != "all" && *exampleFlag != name {
				continue
			}

			assignment := assignments[name]
			fullWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
			if err != nil {
				b.Fatal(err)
			}

			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				start := time.Now()
				for i := 0; i < b.N; i++ {
					_, err := groth16.Prove(cs, pk, fullWitness)
					if err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				totalTime := time.Since(start)
				avgTime := totalTime / time.Duration(b.N)
				b.Logf("-> Avg. time per op: %s (ran %d iterations in %s)", avgTime.Round(time.Millisecond), b.N, totalTime.Round(time.Millisecond))
			})
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for _, name := range examples {
			if *exampleFlag != "all" && *exampleFlag != name {
				continue
			}

			assignment := assignments[name]
			fullWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			publicWitness, err := fullWitness.Public()
			if err != nil {
				b.Fatal(err)
			}
			proof, err := groth16.Prove(cs, pk, fullWitness)
			if err != nil {
				b.Fatal(err)
			}

			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				start := time.Now()
				for i := 0; i < b.N; i++ {
					err := groth16.Verify(proof, vk, publicWitness)
					if err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				totalTime := time.Since(start)
				avgTime := totalTime / time.Duration(b.N)
				b.Logf("-> Avg. time per op: %s (ran %d iterations in %s)", avgTime.Round(time.Millisecond), b.N, totalTime.Round(time.Millisecond))
			})
		}
	})
}
