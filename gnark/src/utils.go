// gnark/utils.go
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time" // Added for timestamp

	"github.com/consensys/gnark/frontend"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

type MerkleTree struct {
	Levels [][][]byte
	Root   []byte
}

func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot construct Merkle tree with no data")
	}
	leaves := make([][]byte, len(data))
	copy(leaves, data)
	nextPoT := nextPowerOfTwo(len(leaves))
	if len(leaves) < nextPoT {
		last := leaves[len(leaves)-1]
		for i := len(leaves); i < nextPoT; i++ {
			leaves = append(leaves, last)
		}
	}
	tree := &MerkleTree{}
	tree.Levels = append(tree.Levels, leaves)
	currentLevel := leaves
	for len(currentLevel) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			h := sha256.New()
			h.Write(currentLevel[i])
			h.Write(currentLevel[i+1])
			nextLevel = append(nextLevel, h.Sum(nil))
		}
		tree.Levels = append(tree.Levels, nextLevel)
		currentLevel = nextLevel
	}
	tree.Root = tree.Levels[len(tree.Levels)-1][0]
	return tree, nil
}

func (t *MerkleTree) GetProof(index int) ([][]byte, []int) {
	var proof [][]byte
	var pathBits []int
	for level := 0; level < len(t.Levels)-1; level++ {
		var siblingIndex int
		if index%2 == 0 {
			siblingIndex = index + 1
			pathBits = append(pathBits, 0)
		} else {
			siblingIndex = index - 1
			pathBits = append(pathBits, 1)
		}
		proof = append(proof, t.Levels[level][siblingIndex])
		index /= 2
	}
	return proof, pathBits
}

func nextPowerOfTwo(n int) int {
	if n > 0 && (n&(n-1)) == 0 {
		return n
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func serializePolicyLineForHash(p PolicyLine) []byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(p.ID))
	buf.WriteByte(byte(p.TxType))
	buf.WriteByte(byte(p.DestinationTag))
	buf.WriteByte(byte(p.DestinationIdx))
	var destAddrBytes, signerAddrBytes, assetAddrBytes, amountMaxBytes []byte
	if p.DestinationAddr != nil {
		destAddrBytes = p.DestinationAddr.Bytes()
	}
	buf.Write(padTo32Bytes(destAddrBytes))
	buf.WriteByte(byte(p.SignerTag))
	if p.SignerAddr != nil {
		signerAddrBytes = p.SignerAddr.Bytes()
	}
	if p.AssetAddr != nil {
		assetAddrBytes = p.AssetAddr.Bytes()
	}
	if p.AmountMax != nil {
		amountMaxBytes = p.AmountMax.Bytes()
	}
	buf.Write(padTo32Bytes(signerAddrBytes))
	buf.WriteByte(byte(p.SignerGroupIdx))
	buf.WriteByte(byte(p.AssetTag))
	buf.Write(padTo32Bytes(assetAddrBytes))
	buf.Write(padTo32Bytes(amountMaxBytes))
	selector := make([]byte, 4)
	copy(selector, p.FunctionSelector)
	buf.Write(selector)
	buf.WriteByte(byte(p.Action))
	buf.WriteByte(byte(p.Threshold)) // New field added to hash
	return buf.Bytes()
}

func padTo32Bytes(b []byte) []byte {
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func to32FrontendVariable(b []byte) [32]frontend.Variable {
	var arr [32]frontend.Variable
	for i := 0; i < 32; i++ {
		arr[i] = 0
		if i < len(b) {
			arr[i] = b[i]
		}
	}
	return arr
}

func toDataArray(calldata []byte) [MAX_DATA_BYTES]frontend.Variable {
	var arr [MAX_DATA_BYTES]frontend.Variable
	for i := 0; i < MAX_DATA_BYTES; i++ {
		arr[i] = 0
		if i < len(calldata) {
			arr[i] = calldata[i]
		}
	}
	return arr
}

func padSelector(selector []byte) [4]frontend.Variable {
	var padded [4]frontend.Variable
	for i := 0; i < 4; i++ {
		if i < len(selector) {
			padded[i] = selector[i]
		} else {
			padded[i] = 0
		}
	}
	return padded
}

// buildWitness constructs the full circuit witness for a given scenario.
func buildWitness(policyLines []PolicyLine,
	activePolicyIndex int,
	from *big.Int,
	to *big.Int,
	value *big.Int,
	calldata []byte,
	signerKeys []*ecdsa.PrivateKey,
	groups [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable,
	groupSizes [MAX_GROUPS]frontend.Variable,
	groupHash [32]byte,
	allowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable,
	allowSizes [MAX_ALLOWLISTS]frontend.Variable,
	allowHash [32]byte,
) ZKGuardCircuit {
	paddedCalldata := make([]byte, MAX_DATA_BYTES)
	copy(paddedCalldata, calldata)

	fromForSigning := from.Bytes()
	fromPadded := make([]byte, 20)
	copy(fromPadded[20-len(fromForSigning):], fromForSigning)

	toForSigning := to.Bytes()
	toPadded := make([]byte, 20)
	copy(toPadded[20-len(toForSigning):], toForSigning)
	valueForSigning := make([]byte, 16)
	value.FillBytes(valueForSigning)
	messageBytes := bytes.Join([][]byte{fromPadded, toPadded, valueForSigning, paddedCalldata}, nil)
	messageToSign := eth_crypto.Keccak256(messageBytes)

	// The final call hash is what gets verified in the circuit.
	finalCallHash := eth_crypto.Keccak256(messageBytes)

	// --- Multi-Signature Processing ---
	if len(signerKeys) > MAX_SIGNATURES {
		panic(fmt.Sprintf("too many signers provided: got %d, max %d", len(signerKeys), MAX_SIGNATURES))
	}

	// Get secp256k1 curve parameters for low-S normalization.
	secp256k1N := eth_crypto.S256().Params().N
	secp256k1HalfN := new(big.Int).Div(secp256k1N, big.NewInt(2))

	var signatures [MAX_SIGNATURES]SignatureWitness
	for i := 0; i < MAX_SIGNATURES; i++ {
		if i < len(signerKeys) {
			sigBytes, _ := eth_crypto.Sign(messageToSign, signerKeys[i])
			r := new(big.Int).SetBytes(sigBytes[:32])
			s := new(big.Int).SetBytes(sigBytes[32:64])
			v := sigBytes[64] // This is 0 or 1.

			// Enforce low S value. This is required by the ecrecover precompile.
			if s.Cmp(secp256k1HalfN) > 0 {
				s.Sub(secp256k1N, s)
				v = 1 - v // Flip recovery ID
			}

			sigRBytes := make([]byte, 32)
			r.FillBytes(sigRBytes)
			sigSBytes := make([]byte, 32)
			s.FillBytes(sigSBytes)
			signatures[i] = SignatureWitness{
				R_Hi: new(big.Int).SetBytes(sigRBytes[:16]),
				R_Lo: new(big.Int).SetBytes(sigRBytes[16:]),
				S_Hi: new(big.Int).SetBytes(sigSBytes[:16]),
				S_Lo: new(big.Int).SetBytes(sigSBytes[16:]),
				V:    int64(v),
			}
		} else {
			// Pad unused signature slots with zeros
			signatures[i] = SignatureWitness{R_Hi: 0, R_Lo: 0, S_Hi: 0, S_Lo: 0, V: 0}
		}
	}
	// --- End Multi-Signature Processing ---

	for len(policyLines) < 1<<MERKLE_TREE_DEPTH {
		policyLines = append(policyLines, PolicyLine{ID: 0, SignerAddr: new(big.Int), AssetAddr: new(big.Int), AmountMax: new(big.Int)})
	}

	hashedLeaves := make([][]byte, len(policyLines))
	for i, p := range policyLines {
		serializedData := serializePolicyLineForHash(p)
		leafHash := sha256.Sum256(serializedData)
		hashedLeaves[i] = leafHash[:]
	}

	tree, _ := NewMerkleTree(hashedLeaves)
	merkleRoot := tree.Root
	siblings, pathBits := tree.GetProof(activePolicyIndex)

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
	activePolicyLine := policyLines[activePolicyIndex]
	activePolicySelector := padSelector(activePolicyLine.FunctionSelector)

	var destAddr, signerAddr, assetAddr, amountMax frontend.Variable
	if activePolicyLine.DestinationAddr != nil {
		destAddr = activePolicyLine.DestinationAddr
	} else {
		destAddr = 0
	}
	if activePolicyLine.SignerAddr != nil {
		signerAddr = activePolicyLine.SignerAddr
	} else {
		signerAddr = 0
	}
	if activePolicyLine.AssetAddr != nil {
		assetAddr = activePolicyLine.AssetAddr
	} else {
		assetAddr = 0
	}
	if activePolicyLine.AmountMax != nil {
		amountMax = activePolicyLine.AmountMax
	} else {
		amountMax = 0
	}

	return ZKGuardCircuit{
		CallHash:         to32FrontendVariable(finalCallHash[:]),
		PolicyMerkleRoot: to32FrontendVariable(merkleRoot),
		GroupsHash:       to32FrontendVariable(groupHash[:]),
		AllowHash:        to32FrontendVariable(allowHash[:]),
		From:             from,
		To:               to,
		Value:            value,
		Data:             toDataArray(calldata),
		DataLen:          len(calldata),
		Signatures:       signatures,
		NumSigs:          len(signerKeys),
		PolicyLine: PolicyLineWitness{
			ID:               activePolicyLine.ID,
			TxType:           activePolicyLine.TxType,
			DestinationTag:   activePolicyLine.DestinationTag,
			DestinationIdx:   activePolicyLine.DestinationIdx,
			DestinationAddr:  destAddr,
			SignerTag:        activePolicyLine.SignerTag,
			SignerAddr:       signerAddr,
			SignerGroupIdx:   activePolicyLine.SignerGroupIdx,
			AssetTag:         activePolicyLine.AssetTag,
			AssetAddr:        assetAddr,
			AmountMax:        amountMax,
			FunctionSelector: activePolicySelector,
			Action:           activePolicyLine.Action,
			Threshold:        activePolicyLine.Threshold,
		},
		MerkleProofSiblings: paddedSiblings,
		MerkleProofPath:     paddedPath,
		Groups:              groups,
		GroupSizes:          groupSizes,
		AllowLists:          allowLists,
		AllowSizes:          allowSizes,
	}
}

// getTimeStamp returns a formatted string for the current time UTC.
func getTimeStamp() string {
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		return ""
	}
	return time.Now().In(loc).Format("January 2, 2006 at 3:04:05 PM MST")
}
