// gnark/main.go
// Main entrypoint for the ZKGuard application.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark/frontend"
)

// AddressSetHash computes the hash by padding each big.Int to 20 bytes.
func AddressSetHash(
	sizes [MAX_GROUPS]byte,
	addressSet [MAX_GROUPS][MAX_ADDRS_PER_SET]big.Int,
) (out [32]byte) {
	hGroups := sha256.New()
	byteBuffer := make([]byte, 20)

	for i := 0; i < MAX_GROUPS; i++ {
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			addressSet[i][j].FillBytes(byteBuffer)
			hGroups.Write(byteBuffer)
		}
		hGroups.Write([]byte{sizes[i]})
	}

	copy(out[:], hGroups.Sum(nil))
	return out
}

// newAddressSet creates a fully initialized frontend address set.
func newAddressSet(addrs ...[]byte) [MAX_ADDRS_PER_SET]frontend.Variable {
	var set [MAX_ADDRS_PER_SET]frontend.Variable
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		if i < len(addrs) {
			set[i] = new(big.Int).SetBytes(addrs[i])
		} else {
			set[i] = 0
		}
	}
	return set
}

// newAddressSetBigInt creates a fully initialized big.Int address set.
func newAddressSetBigInt(addrs ...[]byte) [MAX_ADDRS_PER_SET]big.Int {
	var set [MAX_ADDRS_PER_SET]big.Int
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		if i < len(addrs) {
			set[i].SetBytes(addrs[i])
		} else {
			set[i].SetInt64(0)
		}
	}
	return set
}

func main() {
	exampleName := flag.String("example", "", "Run a scenario from shared examples. Use 'all' to run all scenarios.")
	proveCmd := flag.Bool("prove", false, "Generate and verify a full zk-SNARK proof for the selected scenario.")
	policyFile := flag.String("policy-file", "../shared/config/policy.json", "Path to shared policy JSON.")
	groupsFile := flag.String("groups-file", "../shared/config/groups.json", "Path to shared groups JSON.")
	allowlistsFile := flag.String("allowlists-file", "../shared/config/allowlists.json", "Path to shared allowlists JSON.")
	scenariosFile := flag.String("scenarios-file", "../shared/examples/scenarios.json", "Path to shared scenarios JSON.")
	flag.Parse()

	loc, _ := time.LoadLocation("UTC")
	fmt.Printf("--- ZKGuard CLI starting on %s ---\n", time.Now().In(loc).Format(time.RFC1123))

	if *exampleName == "" {
		fmt.Println("\nPlease specify a scenario with the -example flag.")
		fmt.Println("\nUsage: go run ./src/... -example <scenario|all> [--prove] [--policy-file ...] [--groups-file ...] [--allowlists-file ...] [--scenarios-file ...]")
		os.Exit(1)
	}

	if err := runSharedScenarioCLI(
		*exampleName,
		*proveCmd,
		*policyFile,
		*groupsFile,
		*allowlistsFile,
		*scenariosFile,
	); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
