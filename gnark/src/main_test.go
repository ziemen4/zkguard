// main_test.go
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

func BenchmarkZKGuard(b *testing.B) {
	// ---------------------------------------------------------------------------------
	// 1. Setup Phase: Copy the exact data generation from main.go
	// This ensures the data for the witness is identical to the working code.
	// ---------------------------------------------------------------------------------
	sk, _ := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
	fromAddressBytes := eth_crypto.PubkeyToAddress(sk.PublicKey).Bytes()
	toAddrBytes, _ := hex.DecodeString("12f3a2b4cC21881f203818aA1F78851Df974Bcc2")
	erc20AddrBytes, _ := hex.DecodeString("dAC17F958D2ee523a2206206994597C13D831ec7")

	amount := new(big.Int).SetUint64(1_000_000)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes)

	var calldata bytes.Buffer
	calldata.Write(transferSelector)
	calldata.Write(bytes.Repeat([]byte{0}, 12))
	calldata.Write(toAddrBytes)
	calldata.Write(amountBytes)

	paddedCalldata := make([]byte, MAX_DATA_BYTES)
	copy(paddedCalldata, calldata.Bytes())
	finalCallHash := sha256.Sum256(paddedCalldata)
	finalGroupsHash := sha256.Sum256([]byte{})
	finalAllowHash := sha256.Sum256([]byte{})

	toForSigning := new(big.Int).SetBytes(erc20AddrBytes).Bytes()
	toPadded := make([]byte, 20)
	copy(toPadded[20-len(toForSigning):], toForSigning)
	valueForSigning := make([]byte, 16)
	messageBytes := bytes.Join([][]byte{toPadded, valueForSigning, paddedCalldata}, nil)
	messageToSign := eth_crypto.Keccak256(messageBytes)

	sigBytes, _ := eth_crypto.Sign(messageToSign, sk)
	sigR := new(big.Int).SetBytes(sigBytes[:32])
	sigS := new(big.Int).SetBytes(sigBytes[32:64])
	sigV := int64(sigBytes[64])

	sigRBytes := make([]byte, 32)
	sigR.FillBytes(sigRBytes)
	sigSBytes := make([]byte, 32)
	sigS.FillBytes(sigSBytes)
	sigRHi := new(big.Int).SetBytes(sigRBytes[:16])
	sigRLo := new(big.Int).SetBytes(sigRBytes[16:])
	sigSHi := new(big.Int).SetBytes(sigSBytes[:16])
	sigSLo := new(big.Int).SetBytes(sigSBytes[16:])

	policyLines := []PolicyLine{
		{
			ID: 1, TxType: TT_TRANSFER, DestinationTag: DP_ANY, DestinationIdx: 0,
			SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(fromAddressBytes), SignerGroupIdx: 0,
			AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(erc20AddrBytes), Action: ACT_ALLOW,
		},
	}
	for i := 2; i <= 32; i++ {
		policyLines = append(policyLines, PolicyLine{ID: i, SignerAddr: new(big.Int), AssetAddr: new(big.Int)})
	}

	serializedPolicy := make([][]byte, 32)
	for i, p := range policyLines {
		serializedPolicy[i] = serializePolicyLineForHash(p)
	}
	tree, _ := NewMerkleTree(serializedPolicy)
	merkleRoot := tree.Root
	siblings, pathBits := tree.GetProof(0)

	paddedSiblings := [MERKLE_TREE_DEPTH][32]frontend.Variable{}
	paddedPath := [MERKLE_TREE_DEPTH]frontend.Variable{}
	for i := 0; i < MERKLE_TREE_DEPTH; i++ {
		if i < len(siblings) {
			for j, b := range siblings[i] {
				paddedSiblings[i][j] = b
			}
			paddedPath[i] = pathBits[i]
		}
	}

	// Compile the circuit once before benchmarking
	var circuit ZKGuardCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		b.Fatalf("failed to compile: %v", err)
	}

	// Create the witness assignment struct
	var groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	var groupSizes [MAX_GROUPS]frontend.Variable
	var allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	var allowSizes [MAX_ALLOWLISTS]frontend.Variable

	for i := 0; i < MAX_GROUPS; i++ {
		groupSizes[i] = 0
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			groups[i][j] = 0
		}
	}
	for i := 0; i < MAX_ALLOWLISTS; i++ {
		allowSizes[i] = 0
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			allowLists[i][j] = 0
		}
	}

	activePolicyLine := policyLines[0]
	assignment := ZKGuardCircuit{
		// Public inputs
		CallHash:         to32FrontendVariable(finalCallHash[:]),
		PolicyMerkleRoot: to32FrontendVariable(merkleRoot),
		GroupsHash:       to32FrontendVariable(finalGroupsHash[:]),
		AllowHash:        to32FrontendVariable(finalAllowHash[:]),
		// User action witness
		To:      new(big.Int).SetBytes(erc20AddrBytes),
		Value:   0,
		Data:    toDataArray(calldata.Bytes()),
		DataLen: calldata.Len(),
		Signer:  new(big.Int).SetBytes(fromAddressBytes),
		SigRHi:  sigRHi,
		SigRLo:  sigRLo,
		SigSHi:  sigSHi,
		SigSLo:  sigSLo,
		SigV:    sigV,
		// Policy line witness
		PolicyLine: PolicyLineWitness{
			ID:             activePolicyLine.ID,
			TxType:         activePolicyLine.TxType,
			DestinationTag: activePolicyLine.DestinationTag,
			DestinationIdx: activePolicyLine.DestinationIdx,
			SignerTag:      activePolicyLine.SignerTag,
			SignerAddr:     activePolicyLine.SignerAddr,
			SignerGroupIdx: activePolicyLine.SignerGroupIdx,
			AssetTag:       activePolicyLine.AssetTag,
			AssetAddr:      activePolicyLine.AssetAddr,
			Action:         activePolicyLine.Action,
		},
		// Merkle proof witness
		MerkleProofSiblings: paddedSiblings,
		MerkleProofPath:     paddedPath,
		Groups:              groups,
		GroupSizes:          groupSizes,
		AllowLists:          allowLists,
		AllowSizes:          allowSizes,
	}

	// ---------------------------------------------------------------------------------
	// 2. Run and measure each part of the process
	// ---------------------------------------------------------------------------------
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	b.Run("Groth16/Setup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pk, vk, _ = groth16.Setup(cs)
		}
	})

	// Generate the full witness once
	var fullWitness witness.Witness
	b.Run("WitnessCreation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fullWitness, err = frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
			if err != nil {
				b.Fatalf("failed to create witness: %v", err)
			}
		}
	})

	publicWitness, err := fullWitness.Public()
	if err != nil {
		b.Fatalf("failed to get public witness: %v", err)
	}

	// Reset timer to not include the one-time setup in the Prove benchmark
	b.ResetTimer()

	var proof groth16.Proof
	b.Run("Groth16/Prove", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			proof, err = groth16.Prove(cs, pk, fullWitness)
			if err != nil {
				b.Fatalf("failed to prove: %v", err)
			}
		}
	})

	b.Run("Groth16/Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				b.Fatalf("failed to verify: %v", err)
			}
		}
	})
}
