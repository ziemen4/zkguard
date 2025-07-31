// main.go
// zkguard circuit
// -----------------------------------------------------------------------------
// A gnark implementation of the ZKGuard “policy‑engine” originally written for
// Risc‑0. This refactored version aligns with the updated architecture where
// the circuit verifies a user action against a *single policy line* and a
// Merkle proof that confirms the line belongs to a committed policy root.
//
// The circuit proves two main things:
// 1. The provided policy line is a valid member of the policy (via Merkle proof).
// 2. The policy line ALLOWS the given user action.
//
// This approach ensures the in-circuit work remains constant, regardless of the
// overall policy size, which is defined by the Merkle tree's depth.
// -----------------------------------------------------------------------------
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"encoding/hex"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/hash/sha2"

	keccak "github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

// -----------------------------------------------------------------------------
//
//	Static Parameters
//
// -----------------------------------------------------------------------------
const (
	// === core limits ==========================================================
	MERKLE_TREE_DEPTH = 5 // Max depth of the policy Merkle tree (for 2^5=32 rules)
	MAX_GROUPS        = 8 // distinct signer / destination groups
	MAX_ALLOWLISTS    = 8
	MAX_ADDRS_PER_SET = 32 // per group *or* per allow‑list
	MAX_DATA_BYTES    = 128
)

// Helper: selector for ERC‑20 transfer(address,uint256)
var transferSelector = []byte{0xa9, 0x05, 0x9c, 0xbb}

// -----------------------------------------------------------------------------
//
//	Auxiliary Structures
//
// -----------------------------------------------------------------------------
const (
	// TxType
	TT_TRANSFER     = 0
	TT_CONTRACTCALL = 1

	// DestinationPattern
	DP_ANY       = 0
	DP_GROUP     = 1
	DP_ALLOWLIST = 2

	// SignerPattern
	SP_ANY   = 0
	SP_EXACT = 1
	SP_GROUP = 2

	// AssetPattern
	AP_ANY   = 0
	AP_EXACT = 1

	// ActionType
	ACT_ALLOW = 1
)

// PolicyLineWitness is the fixed‑layout encoding of one rule.
type PolicyLineWitness struct {
	ID             frontend.Variable
	TxType         frontend.Variable
	DestinationTag frontend.Variable
	DestinationIdx frontend.Variable
	SignerTag      frontend.Variable
	SignerAddr     frontend.Variable
	SignerGroupIdx frontend.Variable
	AssetTag       frontend.Variable
	AssetAddr      frontend.Variable
	Action         frontend.Variable
}

type PolicyLine struct {
	ID             int
	TxType         int
	DestinationTag int
	DestinationIdx int
	SignerTag      int
	SignerAddr     *big.Int
	SignerGroupIdx int
	AssetTag       int
	AssetAddr      *big.Int
	Action         int
}

// ZKGuardCircuit bundles *everything* the prover needs.
type ZKGuardCircuit struct {
	// Public commitments
	CallHash         [32]frontend.Variable `gnark:",public"`
	PolicyMerkleRoot [32]frontend.Variable `gnark:",public"`
	GroupsHash       [32]frontend.Variable `gnark:",public"`
	AllowHash        [32]frontend.Variable `gnark:",public"`

	// UserAction witness
	To      frontend.Variable
	Value   frontend.Variable
	Data    [MAX_DATA_BYTES]frontend.Variable
	DataLen frontend.Variable
	Signer  frontend.Variable
	SigRHi  frontend.Variable
	SigRLo  frontend.Variable
	SigSHi  frontend.Variable
	SigSLo  frontend.Variable
	SigV    frontend.Variable // recovery id (0 or 1)

	// Single Policy Line & Proof
	PolicyLine          PolicyLineWitness
	MerkleProofSiblings [MERKLE_TREE_DEPTH][32]frontend.Variable
	MerkleProofPath     [MERKLE_TREE_DEPTH]frontend.Variable // 0 for left, 1 for right

	// Canonicalised Groups/Allowlists
	Groups     [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	GroupSizes [MAX_GROUPS]frontend.Variable
	AllowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	AllowSizes [MAX_ALLOWLISTS]frontend.Variable
}

// -----------------------------------------------------------------------------
//
//	Helper Primitives
//
// -----------------------------------------------------------------------------
func isZero(api frontend.API, v frontend.Variable) frontend.Variable {
	return api.IsZero(v)
}

func eq(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return isZero(api, api.Sub(a, b))
}

func orBitwise(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Sub(api.Add(a, b), api.Mul(a, b))
}

func inSet(api frontend.API, addr frontend.Variable, set [MAX_ADDRS_PER_SET]frontend.Variable, n frontend.Variable) frontend.Variable {
	found := frontend.Variable(0)
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		isMember := eq(api, addr, set[i])
		isActive := cmp.IsLess(api, i, n)
		found = orBitwise(api, found, api.And(isMember, isActive))
	}
	return found
}

func bytesEq4(api frontend.API, data [MAX_DATA_BYTES]frontend.Variable, length frontend.Variable) frontend.Variable {
	isLongEnough := cmp.IsLessOrEqual(api, 4, length)
	ok := frontend.Variable(1)
	for i := 0; i < 4; i++ {
		ok = api.And(ok, eq(api, data[i], int(transferSelector[i])))
	}
	return api.And(ok, isLongEnough)
}

// variablesToBytes converts a slice of frontend.Variable to a slice of uints.U8.
func variablesToBytes(api frontend.API, vars ...frontend.Variable) []uints.U8 {
	uapi, _ := uints.New[uints.U32](api)
	bytes := make([]uints.U8, len(vars))
	for i, v := range vars {
		bytes[i] = uapi.ByteValueOf(v)
	}
	return bytes
}

func classifyTx(api frontend.API, ua *ZKGuardCircuit) (frontend.Variable, frontend.Variable, frontend.Variable) {
	isEthTransfer := api.And(isZero(api, ua.DataLen), api.Sub(1, isZero(api, ua.Value)))
	isErc20 := bytesEq4(api, ua.Data, ua.DataLen)

	txTransfer := orBitwise(api, isEthTransfer, isErc20)
	txType := api.Select(txTransfer, TT_TRANSFER, TT_CONTRACTCALL)

	destAddr := ua.To
	assetAddr := ua.To

	assetAddr = api.Select(isEthTransfer, 0, assetAddr)

	var erc20To frontend.Variable = 0
	for i := 0; i < 20; i++ {
		erc20To = api.Add(api.Mul(erc20To, 256), ua.Data[4+12+i])
	}
	destAddr = api.Select(isErc20, erc20To, destAddr)

	return txType, destAddr, assetAddr
}

// -----------------------------------------------------------------------------
//
//	Main Circuit Logic
//
// -----------------------------------------------------------------------------
func (c *ZKGuardCircuit) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U32](api)

	// --- 1. Merkle Proof Verification ---
	leafHasher, _ := sha2.New(api)
	write1Byte := func(v frontend.Variable) { leafHasher.Write([]uints.U8{uapi.ByteValueOf(v)}) }
	write32Bytes := func(v frontend.Variable) {
		bits := api.ToBinary(v, 256)
		bytes := make([]uints.U8, 32)
		for i := 0; i < 32; i++ {
			bytes[i] = uapi.ByteValueOf(api.FromBinary(bits[(31-i)*8 : (32-i)*8]...))
		}
		leafHasher.Write(bytes)
	}
	write1Byte(c.PolicyLine.ID)
	write1Byte(c.PolicyLine.TxType)
	write1Byte(c.PolicyLine.DestinationTag)
	write1Byte(c.PolicyLine.DestinationIdx)
	write1Byte(c.PolicyLine.SignerTag)
	write32Bytes(c.PolicyLine.SignerAddr)
	write1Byte(c.PolicyLine.SignerGroupIdx)
	write1Byte(c.PolicyLine.AssetTag)
	write32Bytes(c.PolicyLine.AssetAddr)
	write1Byte(c.PolicyLine.Action)
	computedHashBytes := leafHasher.Sum()

	// (Merkle path reconstruction logic)
	for i := 0; i < MERKLE_TREE_DEPTH; i++ {
		pathBit := c.MerkleProofPath[i]
		siblingBytes := c.MerkleProofSiblings[i]
		hasher, _ := sha2.New(api)
		left := make([]uints.U8, 32)
		right := make([]uints.U8, 32)
		for j := 0; j < 32; j++ {
			left[j] = uapi.ByteValueOf(api.Select(pathBit, siblingBytes[j], computedHashBytes[j].Val))
			right[j] = uapi.ByteValueOf(api.Select(pathBit, computedHashBytes[j].Val, siblingBytes[j]))
		}
		hasher.Write(left)
		hasher.Write(right)
		computedHashBytes = hasher.Sum()
	}

	// ✨ DEBUG: Print computed vs. provided Merkle Root
	api.Println("--- Merkle Root Verification ---")
	for i := 0; i < 32; i++ {
		api.Println("Computed Merkle Root Byte", i, ":", computedHashBytes[i].Val)
		api.Println("Provided Merkle Root Byte", i, ":", c.PolicyMerkleRoot[i])
	}
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedHashBytes[i].Val, c.PolicyMerkleRoot[i])
	}

	// --- 2. CallData Hash Verification --
	h, _ := sha2.New(api) // Use sha2 as requested

	// The witness c.Data is already zero-padded to MAX_DATA_BYTES.
	// We hash this entire fixed-size array.
	dataBytes := make([]uints.U8, MAX_DATA_BYTES)
	for i := 0; i < MAX_DATA_BYTES; i++ {
		dataBytes[i] = uapi.ByteValueOf(c.Data[i])
	}
	h.Write(dataBytes)
	computedSha2Hash := h.Sum()

	// ✨ DEBUG: Print computed vs. provided SHA2 hash
	api.Println("--- Calldata SHA2 Hash Verification ---")
	for i := 0; i < 32; i++ {
		api.Println("Computed SHA2 Hash Byte", i, ":", computedSha2Hash[i].Val)
		api.Println("Provided SHA2 Hash Byte", i, ":", c.CallHash[i])
	}

	// Expose the computed hash as a public output by constraining
	// it to be equal to the public CalldataSha2Hash input.
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(c.CallHash[i], computedSha2Hash[i].Val)
	}

	// The circuit hashes the fixed-size PADDED data array.
	hMsg, _ := keccak.NewLegacyKeccak256(api)

	// We build a single slice containing To || Value || Data
	msgForHashBytes := make([]uints.U8, 20+16+MAX_DATA_BYTES)

	// Part 1: Convert 'To' to Big-Endian bytes
	toBytes := api.ToBinary(c.To, 160)
	for i := 0; i < 20; i++ {
		byteVal := api.FromBinary(toBytes[(19-i)*8 : (20-i)*8]...)
		msgForHashBytes[i] = uapi.ByteValueOf(byteVal)
	}

	// Part 2: Convert 'Value' to Big-Endian bytes
	valueBytes := api.ToBinary(c.Value, 128)
	for i := 0; i < 16; i++ {
		byteVal := api.FromBinary(valueBytes[(15-i)*8 : (16-i)*8]...)
		msgForHashBytes[20+i] = uapi.ByteValueOf(byteVal)
	}

	// Part 3: Copy the full PADDED 'Data' array
	// `dataBytes` is already available from the CallHash verification step.
	for i := 0; i < MAX_DATA_BYTES; i++ {
		msgForHashBytes[20+16+i] = uapi.ByteValueOf(c.Data[i])
	}

	// Write the single, fixed-size slice to the hasher
	hMsg.Write(msgForHashBytes)
	msgHash := hMsg.Sum()

	api.Println("--- Ecrecover Message Hash ---")
	for i := 0; i < 32; i++ {
		api.Println("MsgHash Byte", i, ":", msgHash[i].Val)
	}

	// --- 4. ecrecover & Address Verification ---
	// (ecrecover logic is complex and likely correct, let's check its output)
	frField, _ := emulated.NewField[emulated.Secp256k1Fr](api)
	fpField, _ := emulated.NewField[emulated.Secp256k1Fp](api)
	digestBits := make([]frontend.Variable, 256)
	for i := 0; i < 32; i++ {
		bits := api.ToBinary(msgHash[31-i].Val, 8)
		copy(digestBits[i*8:], bits)
	}
	msgEmu := frField.FromBits(digestBits...)
	rLimbs := make([]frontend.Variable, 4)
	rLimbs[2], rLimbs[3] = bitslice.Partition(api, c.SigRHi, 64, bitslice.WithNbDigits(128))
	rLimbs[0], rLimbs[1] = bitslice.Partition(api, c.SigRLo, 64, bitslice.WithNbDigits(128))
	rEmu := frField.NewElement(rLimbs)
	sLimbs := make([]frontend.Variable, 4)
	sLimbs[2], sLimbs[3] = bitslice.Partition(api, c.SigSHi, 64, bitslice.WithNbDigits(128))
	sLimbs[0], sLimbs[1] = bitslice.Partition(api, c.SigSLo, 64, bitslice.WithNbDigits(128))
	sEmu := frField.NewElement(sLimbs)
	vPlus27 := api.Add(c.SigV, 27)
	recoveredPk := evmprecompiles.ECRecover(api, *msgEmu, vPlus27, *rEmu, *sEmu, 1, 0)
	pxBits := fpField.ToBits(&recoveredPk.X)
	pyBits := fpField.ToBits(&recoveredPk.Y)
	pkBytes := make([]uints.U8, 64)
	// Correctly convert Px and Py to BIG-ENDIAN bytes before hashing
	for i := 0; i < 32; i++ {
		// Convert Px (first 32 bytes)
		pxByte := api.FromBinary(pxBits[(31-i)*8 : (32-i)*8]...)
		pkBytes[i] = uapi.ByteValueOf(pxByte)

		// Convert Py (next 32 bytes)
		pyByte := api.FromBinary(pyBits[(31-i)*8 : (32-i)*8]...)
		pkBytes[32+i] = uapi.ByteValueOf(pyByte)
	}
	pkHasher, _ := keccak.NewLegacyKeccak256(api)
	pkHasher.Write(pkBytes)
	pkHash := pkHasher.Sum()
	var recoveredAddress frontend.Variable = 0
	for i := 0; i < 20; i++ {
		recoveredAddress = api.Add(api.Mul(recoveredAddress, 256), pkHash[12+i].Val)
	}

	// ✨ DEBUG: Print recovered vs. provided signer address
	api.Println("--- Address Verification ---")
	api.Println("Recovered Signer Address:", recoveredAddress)
	api.Println("Provided Signer Address:", c.Signer)
	api.AssertIsEqual(recoveredAddress, c.Signer)

	// --- 5. Policy Evaluation ---
	txType, destAddr, assetAddr := classifyTx(api, c)

	// ✨ DEBUG: Print transaction classification results
	api.Println("--- Transaction Classification ---")
	api.Println("Classified TxType:", txType)
	api.Println("Classified Dest Addr:", destAddr)
	api.Println("Classified Asset Addr:", assetAddr)

	line := c.PolicyLine

	// 1. Transaction Type Check: Does the action's type (transfer/call) match the policy?
	mTx := eq(api, line.TxType, txType)

	// 2. Destination Check: Does the action's destination address match the policy?
	// The policy can specify ANY destination, a GROUP of addresses, or an ALLOWLIST of addresses.
	mDestAny := eq(api, line.DestinationTag, DP_ANY)
	mDestGrpTag := eq(api, line.DestinationTag, DP_GROUP)
	mDestListTag := eq(api, line.DestinationTag, DP_ALLOWLIST)

	// Select the correct destination group from the witness based on the policy's index.
	var selectedGroup [MAX_ADDRS_PER_SET]frontend.Variable
	for i := range selectedGroup {
		selectedGroup[i] = 0
	}
	var selectedGroupSize frontend.Variable = 0
	for k := 0; k < MAX_GROUPS; k++ {
		isCorrectIndex := eq(api, line.DestinationIdx, k)
		selectedGroupSize = api.Select(isCorrectIndex, c.GroupSizes[k], selectedGroupSize)
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			selectedGroup[j] = api.Select(isCorrectIndex, c.Groups[k][j], selectedGroup[j])
		}
	}
	// Check if the destination address is in the selected group.
	destInGrp := inSet(api, destAddr, selectedGroup, selectedGroupSize)
	mDestGrp := api.And(mDestGrpTag, destInGrp)

	// Select the correct destination allowlist from the witness based on the policy's index.
	var selectedAllowList [MAX_ADDRS_PER_SET]frontend.Variable
	for i := range selectedAllowList {
		selectedAllowList[i] = 0
	}
	var selectedAllowListSize frontend.Variable = 0
	for k := 0; k < MAX_ALLOWLISTS; k++ {
		isCorrectIndex := eq(api, line.DestinationIdx, k)
		selectedAllowListSize = api.Select(isCorrectIndex, c.AllowSizes[k], selectedAllowListSize)
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			selectedAllowList[j] = api.Select(isCorrectIndex, c.AllowLists[k][j], selectedAllowList[j])
		}
	}
	// Check if the destination address is in the selected allowlist.
	destInList := inSet(api, destAddr, selectedAllowList, selectedAllowListSize)
	mDestList := api.And(mDestListTag, destInList)

	// The destination check passes if the policy is ANY, or if the GROUP/ALLOWLIST conditions are met.
	mDest := orBitwise(api, mDestAny, orBitwise(api, mDestGrp, mDestList))

	// 3. Signer Check: Does the action's signer match the policy?
	// The policy can specify ANY signer, an EXACT address, or a GROUP of valid signers.
	mSignerAny := eq(api, line.SignerTag, SP_ANY)
	mSignerExact := api.And(eq(api, line.SignerTag, SP_EXACT), eq(api, c.Signer, line.SignerAddr))
	mSignerGrpTag := eq(api, line.SignerTag, SP_GROUP)

	// Select the correct signer group from the witness based on the policy's index.
	var selectedSignerGroup [MAX_ADDRS_PER_SET]frontend.Variable
	for i := range selectedSignerGroup {
		selectedSignerGroup[i] = 0
	}
	var selectedSignerGroupSize frontend.Variable = 0
	for k := 0; k < MAX_GROUPS; k++ {
		isCorrectIndex := eq(api, line.SignerGroupIdx, k)
		selectedSignerGroupSize = api.Select(isCorrectIndex, c.GroupSizes[k], selectedSignerGroupSize)
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			selectedSignerGroup[j] = api.Select(isCorrectIndex, c.Groups[k][j], selectedSignerGroup[j])
		}
	}
	// Check if the action's signer is in the selected group.
	signerInGrp := inSet(api, c.Signer, selectedSignerGroup, selectedSignerGroupSize)
	mSignerGrp := api.And(mSignerGrpTag, signerInGrp)

	// The signer check passes if the policy is ANY, or if the EXACT/GROUP conditions are met.
	mSigner := orBitwise(api, mSignerAny, orBitwise(api, mSignerExact, mSignerGrp))

	// 4. Asset Check: Does the action's asset (e.g., token contract) match the policy?
	// The policy can specify ANY asset or an EXACT asset address.
	mAssetAny := eq(api, line.AssetTag, AP_ANY)
	mAssetExact := api.And(eq(api, line.AssetTag, AP_EXACT), eq(api, assetAddr, line.AssetAddr))

	// The asset check passes if the policy is ANY or if the EXACT condition is met.
	mAsset := orBitwise(api, mAssetAny, mAssetExact)

	// 5. Special Case for Contract Calls:
	// A generic contract call cannot specify an exact asset, as the asset is unknown.
	// This check ensures that if the action is a contract call, the asset policy must be ANY.
	isCall := eq(api, txType, TT_CONTRACTCALL)
	callAssetOK := orBitwise(api, api.Sub(1, isCall), mAssetAny)

	// Final Result: The rule matches only if all individual checks (Tx, Dest, Signer, Asset) pass.
	ruleMatches := api.And(mTx, api.And(mDest, api.And(mSigner, api.And(mAsset, callAssetOK))))

	// ✨ DEBUG: Print final policy evaluation results
	api.Println("--- Policy Evaluation ---")
	api.Println("Tx Match (mTx):", mTx)
	api.Println("Destination Match (mDest):", mDest)
	api.Println("Signer Match (mSigner):", mSigner)
	api.Println("Asset Match (mAsset):", mAsset)
	api.Println("Action is Allow:", eq(api, line.Action, ACT_ALLOW))
	api.Println("Final Rule Match Result:", ruleMatches)

	api.AssertIsEqual(ruleMatches, 1)
	api.AssertIsEqual(line.Action, ACT_ALLOW)

	return nil
}

// ---------------------------------------------------------------------------------
// Helper functions for the main test function
// ---------------------------------------------------------------------------------
type MerkleTree struct {
	Leaves [][]byte
	Layers [][][]byte
	Root   []byte
}

func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data provided")
	}
	numLeaves := len(data)
	if numLeaves&(numLeaves-1) != 0 {
		return nil, fmt.Errorf("number of leaves must be a power of 2")
	}

	var leaves [][]byte
	for _, d := range data {
		hash := sha256.Sum256(d)
		leaves = append(leaves, hash[:])
	}

	tree := &MerkleTree{Leaves: leaves}
	tree.Layers = append(tree.Layers, leaves)
	level := leaves
	for len(level) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(level); i += 2 {
			combined := append(level[i], level[i+1]...)
			hash := sha256.Sum256(combined)
			nextLevel = append(nextLevel, hash[:])
		}
		tree.Layers = append(tree.Layers, nextLevel)
		level = nextLevel
	}
	tree.Root = level[0]
	return tree, nil
}
func (t *MerkleTree) GetProof(leafIndex int) (siblings [][]byte, pathBits []int) {
	currentIndex := leafIndex
	for _, layer := range t.Layers[:len(t.Layers)-1] {
		var siblingIndex int
		if currentIndex%2 == 0 {
			pathBits = append(pathBits, 0)
			siblingIndex = currentIndex + 1
		} else {
			pathBits = append(pathBits, 1)
			siblingIndex = currentIndex - 1
		}
		siblings = append(siblings, layer[siblingIndex])
		currentIndex /= 2
	}
	return
}

func serializePolicyLineForHash(line PolicyLine) []byte {
	// 10 fields: 8 are 1-byte, 2 are 32-bytes (addresses) = 8 + 64 = 72 bytes total
	buf := make([]byte, 72)

	buf[0] = byte(line.ID)
	buf[1] = byte(line.TxType)
	buf[2] = byte(line.DestinationTag)
	buf[3] = byte(line.DestinationIdx)
	buf[4] = byte(line.SignerTag)

	// Use FillBytes to write the address into a fixed 32-byte slice
	line.SignerAddr.FillBytes(buf[5:37])

	buf[37] = byte(line.SignerGroupIdx)
	buf[38] = byte(line.AssetTag)

	// Use FillBytes for the second address
	line.AssetAddr.FillBytes(buf[39:71])

	buf[71] = byte(line.Action)

	return buf
}
func to32FrontendVariable(data []byte) [32]frontend.Variable {
	var arr [32]frontend.Variable
	for i := 0; i < 32; i++ {
		if i < len(data) {
			arr[i] = int(data[i])
		} else {
			arr[i] = 0
		}
	}
	return arr
}
func toDataArray(data []byte) [MAX_DATA_BYTES]frontend.Variable {
	var arr [MAX_DATA_BYTES]frontend.Variable
	for i := 0; i < MAX_DATA_BYTES; i++ {
		if i < len(data) {
			arr[i] = int(data[i])
		} else {
			arr[i] = 0
		}
	}
	return arr
}

func main() {
	fmt.Println("▶ Part 0: Generating test data...")
	// This part remains unchanged
	sk, _ := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
	fromAddressBytes := eth_crypto.PubkeyToAddress(sk.PublicKey).Bytes()
	toAddrBytes, _ := hex.DecodeString("12f3a2b4cC21881f203818aA1F78851Df974Bcc2")
	erc20AddrBytes, _ := hex.DecodeString("dAC17F958D2ee523a2206206994597C13D831ec7")

	// --- Correctly ABI-encode the calldata ---
	// The 'amount' for an ERC20 transfer must be a uint256 (32 bytes).
	amount := new(big.Int).SetUint64(1_000_000)
	amountBytes := make([]byte, 32)
	amount.FillBytes(amountBytes) // big.Int.FillBytes pads to the slice length.

	// Now construct the calldata with the correctly-sized amount.
	var calldata bytes.Buffer
	calldata.Write(transferSelector)            // 4 bytes for the function selector
	calldata.Write(bytes.Repeat([]byte{0}, 12)) // Left-pad the 'to' address to 32 bytes
	calldata.Write(toAddrBytes)                 // 20 bytes for the 'to' address
	calldata.Write(amountBytes)                 // 32 bytes for the 'amount'

	// --- Corrected Off-Chain Hashing ---
	// 1. Create the padded data that will be used for hashes AND the witness.
	// This ensures consistency.
	paddedCalldata := make([]byte, MAX_DATA_BYTES)
	copy(paddedCalldata, calldata.Bytes())

	// 2. Hash the padded data to create the public input.
	finalCallHash := sha256.Sum256(paddedCalldata)
	finalGroupsHash := sha256.Sum256([]byte{})
	finalAllowHash := sha256.Sum256([]byte{})

	// --- Final Off-Chain Hashing (using PADDED data) ---
	// To be consistent with the ZK circuit, we MUST hash a fixed-size message.
	// The spec must be updated to hash the PADDED data.

	// 1. Get the 'To' bytes (20 bytes)
	toForSigning := new(big.Int).SetBytes(erc20AddrBytes).Bytes()
	toPadded := make([]byte, 20)
	copy(toPadded[20-len(toForSigning):], toForSigning)

	// 2. Get the 'Value' bytes (16 bytes, which is 0)
	valueForSigning := make([]byte, 16)

	// 3. Get the PADDED 'Data' bytes (128 bytes)
	// We use `paddedCalldata` which was created for the CallHash public input.
	dataForSigning := paddedCalldata

	// 4. Concatenate To || Value || PaddedData and hash
	messageBytes := bytes.Join([][]byte{
		toPadded,
		valueForSigning,
		dataForSigning,
	}, nil)

	messageToSign := eth_crypto.Keccak256(messageBytes)

	fmt.Println("\n--- Off-Chain Ecrecover Message Hash ---")
	for i, b := range messageToSign {
		fmt.Printf("Off-chain MsgHash Byte %d : %d\n", i, b)
	}

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

	// Padding for a 32-leaf tree (depth 5) requires 32 total leaves.
	// We only have 2 policy lines, so we add 30 empty ones.
	policyLines := []PolicyLine{
		{
			ID: 1, TxType: TT_TRANSFER, DestinationTag: DP_ANY, DestinationIdx: 0,
			SignerTag: SP_EXACT, SignerAddr: new(big.Int).SetBytes(fromAddressBytes), SignerGroupIdx: 0,
			AssetTag: AP_EXACT, AssetAddr: new(big.Int).SetBytes(erc20AddrBytes), Action: ACT_ALLOW,
		},
		// The rest are padding to make the tree complete
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
	// We are proving the first policy line at index 0
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

	fmt.Println("\n▶ Part 1: Compiling circuit...")
	var circuit ZKGuardCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Sprintf("failed to compile: %v", err))
	}

	fmt.Println("\n▶ Part 2: Performing trusted setup...")
	pk, vk, _ := groth16.Setup(cs)

	fmt.Println("\n▶ Part 3: Creating witness...")

	// ✨ FIX: Initialize the unused arrays to avoid nil pointer errors ✨
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

	// Use the first policy line for the witness
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

		// ✨ FIX: Assign the initialized (but empty) group/allowlist data ✨
		Groups:     groups,
		GroupSizes: groupSizes,
		AllowLists: allowLists,
		AllowSizes: allowSizes,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(fmt.Sprintf("failed to create witness: %v", err))
	}
	publicWitness, _ := witness.Public()

	fmt.Println("\n▶ Part 4: Generating proof...")
	// Add error handling here
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		// This will now print the useful "constraint not satisfied" error and exit
		panic(fmt.Sprintf("failed to generate proof: %v", err))
	}

	fmt.Println("\n▶ Part 5: Verifying proof...")
	// This part will now only run if the proof was generated successfully
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Println("  → ✅ Proof verified successfully!")
}
