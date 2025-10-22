// gnark/main.go
// Main entrypoint for the ZKGuard application.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/consensys/gnark/frontend"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

// AddressSetHash computes the hash by padding each big.Int to 20 bytes.
func AddressSetHash(
	sizes [MAX_GROUPS]byte,
	addressSet [MAX_GROUPS][MAX_ADDRS_PER_SET]big.Int,
) (out [32]byte) {

	hGroups := sha256.New()

	// Create a reusable buffer to hold the 20-byte representation
	byteBuffer := make([]byte, 20) // Use 20 bytes

	for i := 0; i < MAX_GROUPS; i++ {
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			// Use FillBytes to get the 20-byte, big-endian
			// representation of the address.
			addressSet[i][j].FillBytes(byteBuffer)

			// Write the full 20-byte buffer
			hGroups.Write(byteBuffer)
		}

		// Write the size for this group (1 byte)
		hGroups.Write([]byte{sizes[i]})
	}

	copy(out[:], hGroups.Sum(nil))
	return out
}

// newAddressSet is a helper function to create a fully initialized address set.
// It fills unused slots with 0 to prevent "missing assignment" errors in gnark.
func newAddressSet(addrs ...[]byte) [MAX_ADDRS_PER_SET]frontend.Variable {
	var set [MAX_ADDRS_PER_SET]frontend.Variable
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		if i < len(addrs) {
			set[i] = new(big.Int).SetBytes(addrs[i])
		} else {
			set[i] = 0 // Explicitly initialize unused slots
		}
	}
	return set
}

// newAddressSetBigInt is a helper function to create a fully initialized address set from big.Ints.
// It fills unused slots with 0 to prevent "missing assignment" errors in gnark.
func newAddressSetBigInt(addrs ...[]byte) [MAX_ADDRS_PER_SET]big.Int {
	var set [MAX_ADDRS_PER_SET]big.Int
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		if i < len(addrs) {
			set[i].SetBytes(addrs[i])
		} else {
			set[i].SetInt64(0) // Explicitly initialize unused slots
		}
	}
	return set
}

func main() {
	// --- CLI Flag Definition ---
	exampleName := flag.String("example", "", "Run a specific DAO policy example. Use 'all' to run all examples.")
	proveCmd := flag.Bool("prove", false, "Generate and verify a full zk-SNARK proof for the selected example.")
	flag.Parse()

	loc, _ := time.LoadLocation("UTC")
	fmt.Printf("--- ZKGuard CLI starting on %s ---\n", time.Now().In(loc).Format(time.RFC1123))

	if *exampleName == "" {
		fmt.Println("\nPlease specify an example to run with the -example flag.")
		fmt.Println("\nUsage: go run . -example <name> [--prove]")
		fmt.Println("\nAvailable examples: contributor_payments, defi_swaps, supply_lending, amount_limits, function_level_controls, interact_dapps, all")
		return
	}

	// --- Common Setup for all Scenarios ---
	sk, err := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	daoSafeAddress := eth_crypto.PubkeyToAddress(sk.PublicKey)

	// Define variables
	teamWallet1, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	teamWallet2, _ := hex.DecodeString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	stablecoin, _ := hex.DecodeString("dAC17F958D2ee523a2206206994597C13D831ec7")  // USDT
	dex, _ := hex.DecodeString("7a250d5630B4cF539739dF2C5dAcb4c659F2488D")         // Uniswap v2 Router
	lendingPool, _ := hex.DecodeString("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9") // Aave Pool
	weth, _ := hex.DecodeString("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")

	govKey1, _ := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
	govKey2, _ := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
	govKey3, _ := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
	govAddr1 := eth_crypto.PubkeyToAddress(govKey1.PublicKey)
	govAddr2 := eth_crypto.PubkeyToAddress(govKey2.PublicKey)
	govAddr3 := eth_crypto.PubkeyToAddress(govKey3.PublicKey)
	governanceSigners := []*ecdsa.PrivateKey{govKey1, govKey2, govKey3}

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
	teamWalletsSet := newAddressSet(teamWallet1, teamWallet2)
	governanceSignersSet := newAddressSet(govAddr1.Bytes(), govAddr2.Bytes(), govAddr3.Bytes())
	approvedDEXs := newAddressSet(dex)
	approvedLendingProtocols := newAddressSet(lendingPool)

	// Initialize Groups and AllowLists with actual data and padding.
	var groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	groups[0] = teamWalletsSet
	groups[1] = governanceSignersSet
	for i := 2; i < MAX_GROUPS; i++ {
		groups[i] = newAddressSet()
	}

	var allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	allowLists[0] = approvedDEXs
	allowLists[1] = approvedLendingProtocols
	for i := 2; i < MAX_ALLOWLISTS; i++ {
		allowLists[i] = newAddressSet()
	}

	var groupSizes [MAX_GROUPS]frontend.Variable
	groupSizes[0] = 2
	groupSizes[1] = 3
	for i := 2; i < MAX_GROUPS; i++ {
		groupSizes[i] = 0
	}

	var allowSizes [MAX_ALLOWLISTS]frontend.Variable
	allowSizes[0] = 1
	allowSizes[1] = 1
	for i := 2; i < MAX_ALLOWLISTS; i++ {
		allowSizes[i] = 0
	}

	// --- Dispatch to the correct example function, passing the --prove flag ---
	switch strings.ToLower(*exampleName) {
	case "contributor_payments":
		runContributorPayments(sk, daoSafeAddress, stablecoin, teamWallet1, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	case "defi_swaps":
		runDeFiSwaps(sk, daoSafeAddress, dex, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	case "supply_lending":
		runSupplyLending(sk, daoSafeAddress, weth, lendingPool, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	case "amount_limits":
		runAmountLimits(sk, daoSafeAddress, stablecoin, teamWallet1, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	case "function_level_controls":
		runFunctionLevelControls(sk, daoSafeAddress, dex, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	case "interact_dapps":
		runInteractDapps(sk, daoSafeAddress, lendingPool, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	case "advanced_signer_policies":
		runAdvancedSignerPolicies(governanceSigners, daoSafeAddress, dex, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	case "all":
		RunAllExamples(sk, governanceSigners, daoSafeAddress, stablecoin, teamWallet1, dex, lendingPool, weth, groups, groupSizes, groupHash, allowLists, allowSizes, allowHash, *proveCmd)
	default:
		fmt.Printf("Error: Unknown example '%s'\n", *exampleName)
		fmt.Println("Available examples: contributor_payments, defi_swaps, supply_lending, amount_limits, function_level_controls, interact_dapps, all")
	}
}
