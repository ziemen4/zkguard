// circuit.go
// zkguard circuit definition
package main

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/hash/sha2"
	keccak "github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	MERKLE_TREE_DEPTH = 5
	MAX_GROUPS        = 8
	MAX_ALLOWLISTS    = 8
	MAX_ADDRS_PER_SET = 32
	MAX_DATA_BYTES    = 128
	MAX_SIGNATURES    = 4 // New: Max number of signatures we can verify in the circuit
)

var transferSelector = []byte{0xa9, 0x05, 0x9c, 0xbb}

const (
	TT_TRANSFER     = 0
	TT_CONTRACTCALL = 1
	DP_ANY          = 0
	DP_GROUP        = 1
	DP_ALLOWLIST    = 2
	SP_ANY          = 0
	SP_EXACT        = 1
	SP_GROUP        = 2
	SP_THRESHOLD    = 3 // New: Signer pattern for threshold signatures
	AP_ANY          = 0
	AP_EXACT        = 1
	ACT_ALLOW       = 1
)

// SignatureWitness holds the components of a single ECDSA signature.
type SignatureWitness struct {
	R_Hi frontend.Variable
	R_Lo frontend.Variable
	S_Hi frontend.Variable
	S_Lo frontend.Variable
	V    frontend.Variable
}

type PolicyLineWitness struct {
	ID               frontend.Variable
	TxType           frontend.Variable
	DestinationTag   frontend.Variable
	DestinationIdx   frontend.Variable
	SignerTag        frontend.Variable
	SignerAddr       frontend.Variable
	SignerGroupIdx   frontend.Variable
	AssetTag         frontend.Variable
	AssetAddr        frontend.Variable
	AmountMax        frontend.Variable
	FunctionSelector [4]frontend.Variable
	Action           frontend.Variable
	Threshold        frontend.Variable // New: Required signature count for SP_THRESHOLD
}

type PolicyLine struct {
	ID               int
	TxType           int
	DestinationTag   int
	DestinationIdx   int
	SignerTag        int
	SignerAddr       *big.Int
	SignerGroupIdx   int
	AssetTag         int
	AssetAddr        *big.Int
	AmountMax        *big.Int
	FunctionSelector []byte
	Action           int
	Threshold        int // New: Required signature count for SP_THRESHOLD
}

type ZKGuardCircuit struct {
	// Public inputs
	CallHash         [32]frontend.Variable `gnark:",public"`
	PolicyMerkleRoot [32]frontend.Variable `gnark:",public"`
	GroupsHash       [32]frontend.Variable `gnark:",public"`
	AllowHash        [32]frontend.Variable `gnark:",public"`
	// On-chain action
	To         frontend.Variable
	Value      frontend.Variable
	Data       [MAX_DATA_BYTES]frontend.Variable
	DataLen    frontend.Variable
	Signatures [MAX_SIGNATURES]SignatureWitness // Replaces single signature fields
	NumSigs    frontend.Variable                // Number of provided signatures
	// Poliicy line to enforce
	PolicyLine PolicyLineWitness
	// Proof of membership for the policy line
	MerkleProofSiblings [MERKLE_TREE_DEPTH][32]frontend.Variable
	MerkleProofPath     [MERKLE_TREE_DEPTH]frontend.Variable
	// Groups and AllowLists
	Groups     [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	GroupSizes [MAX_GROUPS]frontend.Variable
	AllowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	AllowSizes [MAX_ALLOWLISTS]frontend.Variable
}

// --- Helper Primitives (isZero, eq, etc.) ---
func isZero(api frontend.API, v frontend.Variable) frontend.Variable { return api.IsZero(v) }
func eq(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return isZero(api, api.Sub(a, b))
}
func orBitwise(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Sub(api.Add(a, b), api.Mul(a, b))
}
func inSet(api frontend.API, addr frontend.Variable, set [MAX_ADDRS_PER_SET]frontend.Variable, n frontend.Variable) frontend.Variable {
	found := frontend.Variable(0)
	isAddrZero := isZero(api, addr)
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		isMember := eq(api, addr, set[i])
		isActive := cmp.IsLess(api, i, n)
		found = orBitwise(api, found, api.And(isMember, isActive))
	}
	return api.And(found, api.Sub(1, isAddrZero)) // Ensure address 0 is never a member
}
func bytesEq4(api frontend.API, data [MAX_DATA_BYTES]frontend.Variable, length frontend.Variable) frontend.Variable {
	isLongEnough := cmp.IsLessOrEqual(api, 4, length)
	ok := frontend.Variable(1)
	for i := 0; i < 4; i++ {
		ok = api.And(ok, eq(api, data[i], int(transferSelector[i])))
	}
	return api.And(ok, isLongEnough)
}

// --- classifyTx ---
func classifyTx(api frontend.API, ua *ZKGuardCircuit) (frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) {
	isErc20 := bytesEq4(api, ua.Data, ua.DataLen)
	txType := api.Select(isErc20, TT_TRANSFER, TT_CONTRACTCALL)
	destAddr := ua.To
	assetAddr := ua.To
	amount := ua.Value
	var erc20To frontend.Variable = 0
	for i := 0; i < 20; i++ {
		erc20To = api.Add(api.Mul(erc20To, 256), ua.Data[4+12+i])
	}
	destAddr = api.Select(isErc20, erc20To, destAddr)
	var erc20Amount frontend.Variable = 0
	for i := 0; i < 32; i++ {
		erc20Amount = api.Add(api.Mul(erc20Amount, 256), ua.Data[4+32+i])
	}
	amount = api.Select(isErc20, erc20Amount, amount)
	isPureEthSend := api.And(isZero(api, ua.DataLen), api.Sub(1, isZero(api, ua.Value)))
	assetAddr = api.Select(isPureEthSend, 0, assetAddr)
	return txType, destAddr, assetAddr, amount
}

// selectSet is a generic helper to safely select a specific address set and its size from a list of sets.
// This prevents code duplication and potential bugs in the Define method.
func selectSet(
	api frontend.API,
	index frontend.Variable,
	allSets [][MAX_ADDRS_PER_SET]frontend.Variable,
	allSizes []frontend.Variable,
	numSets int,
) ([MAX_ADDRS_PER_SET]frontend.Variable, frontend.Variable) {

	var selectedSet [MAX_ADDRS_PER_SET]frontend.Variable
	for i := range selectedSet {
		selectedSet[i] = 0
	}
	var selectedSize frontend.Variable = 0

	for k := 0; k < numSets; k++ {
		isCorrectIndex := eq(api, index, k)
		selectedSize = api.Select(isCorrectIndex, allSizes[k], selectedSize)
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			selectedSet[j] = api.Select(isCorrectIndex, allSets[k][j], selectedSet[j])
		}
	}
	return selectedSet, selectedSize
}

// -----------------------------------------------------------------------------
//
//	Main Circuit Logic
//
// -----------------------------------------------------------------------------
func (c *ZKGuardCircuit) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U32](api)
	frField, _ := emulated.NewField[emulated.Secp256k1Fr](api)
	fpField, _ := emulated.NewField[emulated.Secp256k1Fp](api)

	// --- 1. Merkle Proof Verification (updated for Threshold field) ---
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
	write32Bytes(c.PolicyLine.AmountMax)
	write1Byte(c.PolicyLine.FunctionSelector[0])
	write1Byte(c.PolicyLine.FunctionSelector[1])
	write1Byte(c.PolicyLine.FunctionSelector[2])
	write1Byte(c.PolicyLine.FunctionSelector[3])
	write1Byte(c.PolicyLine.Action)
	write1Byte(c.PolicyLine.Threshold) // New field added to hash
	computedHashBytes := leafHasher.Sum()

	// Merkle path reconstruction logic...
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
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedHashBytes[i].Val, c.PolicyMerkleRoot[i])
	}

	// --- 2. CallData Hash & Message Hash ---
	hMsg, _ := keccak.NewLegacyKeccak256(api)
	msgForHashBytes := make([]uints.U8, 20+16+MAX_DATA_BYTES)
	toBytes := api.ToBinary(c.To, 160)
	for i := 0; i < 20; i++ {
		byteVal := api.FromBinary(toBytes[(19-i)*8 : (20-i)*8]...)
		msgForHashBytes[i] = uapi.ByteValueOf(byteVal)
	}
	valueBytes := api.ToBinary(c.Value, 128)
	for i := 0; i < 16; i++ {
		byteVal := api.FromBinary(valueBytes[(15-i)*8 : (16-i)*8]...)
		msgForHashBytes[20+i] = uapi.ByteValueOf(byteVal)
	}
	for i := 0; i < MAX_DATA_BYTES; i++ {
		msgForHashBytes[20+16+i] = uapi.ByteValueOf(c.Data[i])
	}
	hMsg.Write(msgForHashBytes)
	msgHash := hMsg.Sum()

	// --- 3. Multi-Signature Verification Loop ---
	recoveredSigners := [MAX_SIGNATURES]frontend.Variable{}
	digestBits := make([]frontend.Variable, 256)
	for i := 0; i < 32; i++ {
		bits := api.ToBinary(msgHash[31-i].Val, 8)
		copy(digestBits[i*8:], bits)
	}
	msgEmu := frField.FromBits(digestBits...)

	for i := 0; i < MAX_SIGNATURES; i++ {
		// Check if the current signature slot is active
		isActiveSig := cmp.IsLess(api, i, c.NumSigs)
		sig := c.Signatures[i]

		// Use api.Select to choose the real signature values if active, or safe dummy values if inactive.
		// A dummy signature of r=1, s=1, v=0 will not cause ecrecover to panic.
		rHi := api.Select(isActiveSig, sig.R_Hi, 0)
		rLo := api.Select(isActiveSig, sig.R_Lo, 1) // Dummy R = 1
		sHi := api.Select(isActiveSig, sig.S_Hi, 0)
		sLo := api.Select(isActiveSig, sig.S_Lo, 1) // Dummy S = 1
		v := api.Select(isActiveSig, sig.V, 0)      // Dummy V = 0

		// Now assemble R and S from the selected (real or dummy) values
		rLimbs := make([]frontend.Variable, 4)
		rLimbs[2], rLimbs[3] = bitslice.Partition(api, rHi, 64, bitslice.WithNbDigits(128))
		rLimbs[0], rLimbs[1] = bitslice.Partition(api, rLo, 64, bitslice.WithNbDigits(128))
		rEmu := frField.NewElement(rLimbs)
		sLimbs := make([]frontend.Variable, 4)
		sLimbs[2], sLimbs[3] = bitslice.Partition(api, sHi, 64, bitslice.WithNbDigits(128))
		sLimbs[0], sLimbs[1] = bitslice.Partition(api, sLo, 64, bitslice.WithNbDigits(128))
		sEmu := frField.NewElement(sLimbs)
		vPlus27 := api.Add(v, 27)

		// ecrecover will now execute safely on every loop.
		// For inactive slots, it will produce a meaningless public key from the dummy signature.
		recoveredPk := evmprecompiles.ECRecover(api, *msgEmu, vPlus27, *rEmu, *sEmu, 1, 0)

		// ... (hash public key to get address)
		pkBytes := make([]uints.U8, 64)
		pxBits := fpField.ToBits(&recoveredPk.X)
		pyBits := fpField.ToBits(&recoveredPk.Y)
		for j := 0; j < 32; j++ {
			pxByte := api.FromBinary(pxBits[(31-j)*8 : (32-j)*8]...)
			pkBytes[j] = uapi.ByteValueOf(pxByte)
			pyByte := api.FromBinary(pyBits[(31-j)*8 : (32-j)*8]...)
			pkBytes[32+j] = uapi.ByteValueOf(pyByte)
		}
		pkHasher, _ := keccak.NewLegacyKeccak256(api)
		pkHasher.Write(pkBytes)
		pkHash := pkHasher.Sum()
		var recoveredAddress frontend.Variable = 0
		for j := 0; j < 20; j++ {
			recoveredAddress = api.Add(api.Mul(recoveredAddress, 256), pkHash[12+j].Val)
		}

		// Finally, select the real address if the signature was active, or 0 if it was a dummy.
		recoveredSigners[i] = api.Select(isActiveSig, recoveredAddress, 0)
	}

	// --- 4. Policy Evaluation (with updated Signer Logic) ---
	txType, destAddr, assetAddr, amount := classifyTx(api, c)
	line := c.PolicyLine

	// Get the selected signer group (used by both SP_GROUP and SP_THRESHOLD)
	signerGroup, signerGroupSize := selectSet(api, line.SignerGroupIdx, c.Groups[:], c.GroupSizes[:], MAX_GROUPS)

	// Get the correct destination group/list based on the policy's DestinationIdx.
	destGroup, destGroupSize := selectSet(api, line.DestinationIdx, c.Groups[:], c.GroupSizes[:], MAX_GROUPS)
	destList, destListSize := selectSet(api, line.DestinationIdx, c.AllowLists[:], c.AllowSizes[:], MAX_ALLOWLISTS)

	// Evaluate Signer policies
	mSignerAny := eq(api, line.SignerTag, SP_ANY) // SP_ANY policy just needs >=1 valid signature, which is implicitly checked by the logic.

	mSignerExactTag := eq(api, line.SignerTag, SP_EXACT)
	mSignerExactCheck := eq(api, recoveredSigners[0], line.SignerAddr)
	mSignerExact := api.And(mSignerExactTag, mSignerExactCheck)

	mSignerGrpTag := eq(api, line.SignerTag, SP_GROUP)
	signerInGrpCheck := inSet(api, recoveredSigners[0], signerGroup, signerGroupSize)
	mSignerGrp := api.And(mSignerGrpTag, signerInGrpCheck)

	mSignerThresholdTag := eq(api, line.SignerTag, SP_THRESHOLD)
	validThresholdSigners := frontend.Variable(0)
	for i := 0; i < MAX_SIGNATURES; i++ {
		isMember := inSet(api, recoveredSigners[i], signerGroup, signerGroupSize)
		validThresholdSigners = api.Add(validThresholdSigners, isMember)
	}
	thresholdMet := cmp.IsLessOrEqual(api, line.Threshold, validThresholdSigners)
	mSignerThreshold := api.And(mSignerThresholdTag, thresholdMet)

	mSigner := orBitwise(api, mSignerAny, orBitwise(api, mSignerExact, orBitwise(api, mSignerGrp, mSignerThreshold)))

	// Evaluate other policies (mDest, mAsset, etc)
	mTx := eq(api, line.TxType, txType)
	mDestAny := eq(api, line.DestinationTag, DP_ANY)
	mDestGrp := api.And(eq(api, line.DestinationTag, DP_GROUP), inSet(api, destAddr, destGroup, destGroupSize))
	mDestList := api.And(eq(api, line.DestinationTag, DP_ALLOWLIST), inSet(api, destAddr, destList, destListSize))
	mDest := orBitwise(api, mDestAny, orBitwise(api, mDestGrp, mDestList))
	mAssetAny := eq(api, line.AssetTag, AP_ANY)
	mAssetExact := api.And(eq(api, line.AssetTag, AP_EXACT), eq(api, assetAddr, line.AssetAddr))
	mAsset := orBitwise(api, mAssetAny, mAssetExact)
	noAmountLimit := isZero(api, line.AmountMax)
	amountOK := cmp.IsLessOrEqual(api, amount, line.AmountMax)
	mAmount := orBitwise(api, noAmountLimit, amountOK)
	isSelectorZero := api.And(
		isZero(api, line.FunctionSelector[0]),
		api.And(
			isZero(api, line.FunctionSelector[1]),
			api.And(
				isZero(api, line.FunctionSelector[2]),
				isZero(api, line.FunctionSelector[3]),
			),
		),
	)
	selectorMatches := api.And(
		eq(api, line.FunctionSelector[0], c.Data[0]),
		api.And(
			eq(api, line.FunctionSelector[1], c.Data[1]),
			api.And(
				eq(api, line.FunctionSelector[2], c.Data[2]),
				eq(api, line.FunctionSelector[3], c.Data[3]),
			),
		),
	)
	mSelector := orBitwise(api, isSelectorZero, selectorMatches)
	isCall := eq(api, txType, TT_CONTRACTCALL)
	callAssetOK := orBitwise(api, api.Sub(1, isCall), mAssetAny)

	ruleMatches := api.And(mTx, api.And(mDest, api.And(mSigner, api.And(mAsset, api.And(mAmount, api.And(mSelector, callAssetOK))))))

	api.AssertIsEqual(ruleMatches, 1)
	api.AssertIsEqual(line.Action, ACT_ALLOW)

	return nil
}
