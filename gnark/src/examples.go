// gnark/examples.go
// Contains the logic for running all DAO example scenarios for ZKGuard.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// execute runs a given assignment in one of two modes:
// 1. Fast logic check (prove=false)
// 2. Full proof generation and verification (prove=true)
func execute(assignment ZKGuardCircuit, prove bool) {
	if !prove {
		// Fast mode: just check if the circuit constraints are satisfied.
		checkCircuitLogic(assignment)
		return
	}

	// Full proof mode: Compile, Setup, Prove, and Verify.
	fmt.Println("  ▶ Mode: Full Proof Generation")
	var circuit ZKGuardCircuit

	fmt.Println("    1. Compiling circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Sprintf("circuit compilation failed: %v", err))
	}

	fmt.Println("    2. Performing trusted setup (Groth16)...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(fmt.Sprintf("trusted setup failed: %v", err))
	}

	fmt.Println("    3. Creating witness...")
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(fmt.Sprintf("witness creation failed: %v", err))
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(fmt.Sprintf("public witness creation failed: %v", err))
	}

	fmt.Println("    4. Generating proof...")
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(fmt.Sprintf("proof generation failed: %v", err))
	}

	fmt.Println("    5. Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("  → ❌ VERIFICATION FAILED: %v\n\n", err)
	} else {
		fmt.Println("  → ✅ VERIFICATION SUCCESSFUL!")
	}
}

// checkCircuitLogic is the fast-mode checker.
func checkCircuitLogic(assignment ZKGuardCircuit) {
	fmt.Println("  ▶ Mode: Circuit Logic Check")
	var circuit ZKGuardCircuit
	err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("  → ❌ FAILED: %v\n\n", err)
	} else {
		fmt.Println("  → ✅ PASSED")
	}
}

// RunAllExamples executes all scenarios sequentially.
func RunAllExamples(sk *ecdsa.PrivateKey, governanceSigners []*ecdsa.PrivateKey, daoAddr [20]byte, stablecoin, teamWallet1, dex, lendingPool, weth []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("--- Running All ZKGuard DAO Policy Examples ---")
	runContributorPayments(sk, daoAddr, stablecoin, teamWallet1, groups, groupSizes, allowLists, allowSizes, prove)
	runDeFiSwaps(sk, daoAddr, dex, groups, groupSizes, allowLists, allowSizes, prove)
	runSupplyLending(sk, daoAddr, weth, lendingPool, groups, groupSizes, allowLists, allowSizes, prove)
	runAmountLimits(sk, daoAddr, stablecoin, teamWallet1, groups, groupSizes, allowLists, allowSizes, prove)
	runFunctionLevelControls(sk, daoAddr, dex, groups, groupSizes, allowLists, allowSizes, prove)
	runInteractDapps(sk, daoAddr, lendingPool, groups, groupSizes, allowLists, allowSizes, prove)
	runAdvancedSignerPolicies(governanceSigners, daoAddr, dex, groups, groupSizes, allowLists, allowSizes, prove)
}

// --- Individual Scenario Functions (updated to call execute) ---

func runContributorPayments(sk *ecdsa.PrivateKey, daoAddr [20]byte, stablecoin, teamWallet1 []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("\n▶ Running Example: Contributor Payments")
	policyLines := []PolicyLine{{ID: 1, TxType: TT_TRANSFER, DestinationTag: DP_GROUP, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoAddr[:]), AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(stablecoin), AmountMax: new(big.Int), Action: ACT_ALLOW}}
	amount := new(big.Int).SetUint64(5000 * 1e6)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)
	var calldataBuf bytes.Buffer
	calldataBuf.Write(transferSelector)
	calldataBuf.Write(bytes.Repeat([]byte{0}, 12))
	calldataBuf.Write(teamWallet1)
	calldataBuf.Write(amountBytes)
	assignment := buildWitness(policyLines, 0, new(big.Int).SetBytes(stablecoin), new(big.Int), calldataBuf.Bytes(), []*ecdsa.PrivateKey{sk}, groups, groupSizes, allowLists, allowSizes)
	execute(assignment, prove)
}

func runDeFiSwaps(sk *ecdsa.PrivateKey, daoAddr [20]byte, dex []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("\n▶ Running Example: DeFi Swaps")
	policyLines := []PolicyLine{{ID: 2, TxType: TT_CONTRACTCALL, DestinationTag: DP_ALLOWLIST, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoAddr[:]), AssetTag: AP_ANY, AmountMax: new(big.Int), Action: ACT_ALLOW}}
	assignment := buildWitness(policyLines, 0, new(big.Int).SetBytes(dex), new(big.Int).SetUint64(1e18), []byte{}, []*ecdsa.PrivateKey{sk}, groups, groupSizes, allowLists, allowSizes)
	execute(assignment, prove)
}

func runSupplyLending(sk *ecdsa.PrivateKey, daoAddr [20]byte, weth, lendingPool []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("\n▶ Running Example: Supply Lending")
	policyLines := []PolicyLine{{ID: 3, TxType: TT_TRANSFER, DestinationTag: DP_ALLOWLIST, DestinationIdx: 1, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoAddr[:]), AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(weth), AmountMax: new(big.Int), Action: ACT_ALLOW}}
	amount := new(big.Int).SetUint64(1e18)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)
	var calldataBuf bytes.Buffer
	calldataBuf.Write(transferSelector)
	calldataBuf.Write(bytes.Repeat([]byte{0}, 12))
	calldataBuf.Write(lendingPool)
	calldataBuf.Write(amountBytes)
	assignment := buildWitness(policyLines, 0, new(big.Int).SetBytes(weth), new(big.Int), calldataBuf.Bytes(), []*ecdsa.PrivateKey{sk}, groups, groupSizes, allowLists, allowSizes)
	execute(assignment, prove)
}

func runAmountLimits(sk *ecdsa.PrivateKey, daoAddr [20]byte, stablecoin, teamWallet1 []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("\n▶ Running Example: Amount Limits (Valid)")
	policyLines := []PolicyLine{{ID: 4, TxType: TT_TRANSFER, DestinationTag: DP_GROUP, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoAddr[:]), AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(stablecoin), AmountMax: new(big.Int).SetUint64(10000 * 1e6), Action: ACT_ALLOW}}
	amount := new(big.Int).SetUint64(9000 * 1e6)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)
	var calldataBuf bytes.Buffer
	calldataBuf.Write(transferSelector)
	calldataBuf.Write(bytes.Repeat([]byte{0}, 12))
	calldataBuf.Write(teamWallet1)
	calldataBuf.Write(amountBytes)
	assignment := buildWitness(policyLines, 0, new(big.Int).SetBytes(stablecoin), new(big.Int), calldataBuf.Bytes(), []*ecdsa.PrivateKey{sk}, groups, groupSizes, allowLists, allowSizes)
	execute(assignment, prove)
}

func runFunctionLevelControls(sk *ecdsa.PrivateKey, daoAddr [20]byte, dex []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("\n▶ Running Example: Function-Level Controls (Valid)")
	swapSelector, _ := hex.DecodeString("7ff36ab5")
	policyLines := []PolicyLine{{ID: 5, TxType: TT_CONTRACTCALL, DestinationTag: DP_ALLOWLIST, DestinationIdx: 0, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoAddr[:]), AssetTag: AP_ANY, AmountMax: new(big.Int), FunctionSelector: swapSelector, Action: ACT_ALLOW}}
	assignment := buildWitness(policyLines, 0, new(big.Int).SetBytes(dex), new(big.Int).SetUint64(1e18), swapSelector, []*ecdsa.PrivateKey{sk}, groups, groupSizes, allowLists, allowSizes)
	execute(assignment, prove)
}

func runInteractDapps(sk *ecdsa.PrivateKey, daoAddr [20]byte, lendingPool []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("\n▶ Running Example: Interact with dApps")
	policyLines := []PolicyLine{{ID: 6, TxType: TT_CONTRACTCALL, DestinationTag: DP_ALLOWLIST, DestinationIdx: 1, SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(daoAddr[:]), AssetTag: AP_ANY, AmountMax: new(big.Int), FunctionSelector: nil, Action: ACT_ALLOW}}
	to := new(big.Int).SetBytes(lendingPool)
	value := new(big.Int) // value: 0
	calldata := []byte{0x12, 0x34, 0x56, 0x78}
	assignment := buildWitness(policyLines, 0, to, value, calldata, []*ecdsa.PrivateKey{sk}, groups, groupSizes, allowLists, allowSizes)
	execute(assignment, prove)
}

func runAdvancedSignerPolicies(governanceSigners []*ecdsa.PrivateKey, daoAddr [20]byte, dex []byte, groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable, groupSizes [MAX_GROUPS]frontend.Variable, allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable, allowSizes [MAX_ALLOWLISTS]frontend.Variable, prove bool) {
	fmt.Println("\n▶ Running Example: Advanced Signer Policies (2-of-3)")
	policyLines := []PolicyLine{
		{
			ID:             7,
			TxType:         TT_CONTRACTCALL,
			DestinationTag: DP_ALLOWLIST,
			DestinationIdx: 0, // ApprovedDEXs
			SignerTag:      SP_THRESHOLD,
			SignerGroupIdx: 1, // GovernanceSigners
			Threshold:      2, // 2-of-3 required
			AssetTag:       AP_ANY,
			AmountMax:      new(big.Int),
			Action:         ACT_ALLOW,
		},
	}

	// We'll use the first two governance keys to sign.
	signers := []*ecdsa.PrivateKey{governanceSigners[0], governanceSigners[1]}

	// A sample high-value transaction
	to := new(big.Int).SetBytes(dex)
	value := new(big.Int).SetUint64(10e18) // 10 ETH
	calldata := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	assignment := buildWitness(policyLines, 0, to, value, calldata, signers, groups, groupSizes, allowLists, allowSizes)
	execute(assignment, prove)
}
