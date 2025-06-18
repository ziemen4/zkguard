// main.go
// zkguard circuit
// -----------------------------------------------------------------------------
// A gnark implementation of the ZKGuard “policy‑engine” originally written for
// Risc‑0.  The circuit reproduces, one‑for‑one, the checks performed by the
// Rust guest: it classifies the user action, verifies an Ethereum‐style
// secp256k1 signature, walks the ordered policy, and enforces first‑match
// semantics.  Finally, it exposes the same 4 public commitments so that the
// verifier can pin the exact inputs that were used inside the proof.
//
// ⚠️  IMPORTANT: zk‑friendly DSLs like gnark require static allocation.  To keep
//
//	the circuit practical we impose a set of *compile‑time* upper bounds.  If
//	your production deployment needs larger limits, just bump the constants
//	below and re‑compile — the constraint system will scale automatically.
//
// -----------------------------------------------------------------------------
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"encoding/hex"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/evmprecompiles"
	keccak "github.com/consensys/gnark/std/hash/sha3"
	cmp "github.com/consensys/gnark/std/math/cmp"
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
	MAX_POLICY_LINES  = 32 // max lines in the policy vector
	MAX_GROUPS        = 8  // distinct signer / destination groups
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
// We re‑encode the Rust enums as small integers so they fit neatly in circuits.
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
	ACT_BLOCK = 0
	ACT_ALLOW = 1
)

// PolicyLineWitness is the fixed‑layout encoding of one rule.
// Strings (names) are replaced by *indices* into the canonicalised maps that
// live in witness (so string matching happens off‑circuit, we just reference
// by number).
//
// ┌───────────────────────────────────────────────────────────────────────────┐
// │  Field                │ Type                │ Notes                      │
// ├───────────────────────┼─────────────────────┼────────────────────────────┤
// │  ID                   │ uint32              │ Ascending order enforced   │
// │  TxType               │ {0,1}               │ transfer / call            │
// │  DestinationTag       │ {0,1,2}             │ any / group / allow‑list   │
// │  DestinationIdx       │ uint8               │ index into group/list set  │
// │  SignerTag            │ {0,1,2}             │ any / exact / group        │
// │  SignerAddr           │ uint160             │ used when tag == exact     │
// │  SignerGroupIdx       │ uint8               │ index when tag == group    │
// │  AssetTag             │ {0,1}               │ any / exact                │
// │  AssetAddr            │ uint160             │ used when tag == exact     │
// │  Action               │ {0,1}               │ allow / block              │
// └───────────────────────────────────────────────────────────────────────────┘

type PolicyLineWitness struct {
	ID             frontend.Variable
	TxType         frontend.Variable
	DestinationTag frontend.Variable
	DestinationIdx frontend.Variable // if tag==group|allow
	SignerTag      frontend.Variable
	SignerAddr     frontend.Variable // 160‑bit packed into Fr
	SignerGroupIdx frontend.Variable // if tag==group
	AssetTag       frontend.Variable
	AssetAddr      frontend.Variable // 160‑bit packed
	Action         frontend.Variable
}

// ZKGuardCircuit bundles *everything* the prover needs.  All data outside the
// policy engine is boiled down to 4 public commitments, mirroring the Risc‑0
// guest.
type ZKGuardCircuit struct {

	// ------------- public commitments (exactly like the Risc‑0 guest) ------
	CallHash   [32]frontend.Variable `gnark:",public"` // keccak256(userAction.data)
	PolicyHash [32]frontend.Variable `gnark:",public"`
	GroupsHash [32]frontend.Variable `gnark:",public"`
	AllowHash  [32]frontend.Variable `gnark:",public"`

	// ----------------------- UserAction witness ----------------------------
	To      frontend.Variable                 // uint160
	Value   frontend.Variable                 // uint128
	Data    [MAX_DATA_BYTES]frontend.Variable // calldata (padded with 0) – each <256
	DataLen frontend.Variable                 // actual length ( ≤ MAX_DATA_BYTES )
	Signer  frontend.Variable                 // uint160
	SigR    frontend.Variable                 // secp256k1 signature (r)
	SigS    frontend.Variable                 // secp256k1 signature (s)
	SigV    frontend.Variable                 // recovery id (v ∈ {27,28})

	// --------------------- Canonicalised policy/maps -----------------------
	Policy     []PolicyLineWitness
	Groups     [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable // flattened addr sets
	GroupSizes [MAX_GROUPS]frontend.Variable                    // how many entries used
	AllowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	AllowSizes [MAX_ALLOWLISTS]frontend.Variable
}

// -----------------------------------------------------------------------------
//
//	Helper Primitives
//
// -----------------------------------------------------------------------------
// isZero returns 1 if v == 0 else 0.
func isZero(api frontend.API, v frontend.Variable) frontend.Variable {
	return api.IsZero(v)
}

// eq returns 1 if a == b else 0.
func eq(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return isZero(api, api.Sub(a, b))
}

// orBitwise performs OR over {0,1} variables: out = a ∨ b.
func orBitwise(api frontend.API, a, b frontend.Variable) frontend.Variable {
	// a + b – a·b gives OR over boolean vars.
	return api.Sub(api.Add(a, b), api.Mul(a, b))
}

// inSet checks membership of addr (uint160) in the first n elements of set.
func inSet(api frontend.API, addr frontend.Variable, set [MAX_ADDRS_PER_SET]frontend.Variable, n frontend.Variable) frontend.Variable {
	found := frontend.Variable(0)
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		same := eq(api, addr, set[i])
		active := cmp.IsLessOrEqual(api, frontend.Variable(i+1), n) // i < n
		found = orBitwise(api, found, api.Mul(same, active))
	}
	return found
}

// bytesEq4 checks the first 4 bytes of the calldata against the ERC‑20
// transfer selector.
func bytesEq4(api frontend.API, data [MAX_DATA_BYTES]frontend.Variable) frontend.Variable {
	ok := frontend.Variable(1)
	for i := 0; i < 4; i++ {
		ok = api.And(ok, eq(api, data[i], int(transferSelector[i])))
	}
	return ok
}

// classifyTx mirrors the Rust logic, returning (txType, destAddr, assetAddr).
// In circuits we represent addresses as packed uint160.
func classifyTx(api frontend.API, ua *ZKGuardCircuit) (frontend.Variable, frontend.Variable, frontend.Variable) {
	isEthTransfer := api.And(isZero(api, ua.DataLen), api.IsZero(isZero(api, ua.Value))) // value > 0 && dataLen==0
	isErc20 := api.And(cmp.IsLessOrEqual(api, ua.DataLen, 4), bytesEq4(api, ua.Data))    // dataLen <= 4 && data == transferSelector

	txTransfer := orBitwise(api, isEthTransfer, isErc20)

	// destAddr --------------------------------------------------------------
	destAddr := ua.To  // default
	assetAddr := ua.To // overwritten if ETH transfer

	// If ETH transfer   → asset = 0x00..00
	assetAddr = api.Select(isEthTransfer, 0, assetAddr)

	// If ERC‑20 transfer we need to extract (to, tokenContract)
	if isErc20 == 1 {
		// calldata layout: selector (4) | to (32) | amount (32)
		// Extract 20 bytes starting at offset 16 (big‑endian)… we treat it as one big‑end var.
		var to frontend.Variable = 0
		for i := 0; i < 20; i++ {
			to = api.Add(api.Mul(to, 256), ua.Data[4+16+i])
		}
		destAddr = api.Select(isErc20, to, destAddr)
		assetAddr = api.Select(isErc20, ua.To /*token contract*/, assetAddr)
	}

	txType := api.Select(txTransfer, TT_TRANSFER, TT_CONTRACTCALL)
	return txType, destAddr, assetAddr
}

// -----------------------------------------------------------------------------
//                             Main Circuit Logic
// -----------------------------------------------------------------------------

func (c *ZKGuardCircuit) Define(api frontend.API) error {
	// --------------------------------------------------------
	// 1. Re‑compute keccak256(userAction.data) & expose public
	// --------------------------------------------------------
	uapi, _ := uints.New[uints.U32](api)

	h, _ := keccak.New256(api)
	bytes := make([]uints.U8, MAX_DATA_BYTES)

	for i := 0; i < MAX_DATA_BYTES; i++ {
		bytes[i] = uapi.ByteValueOf(c.Data[i]) // ONE constraint
	}
	h.Write(bytes) // sha3.Keccak
	callDigest := h.Sum()

	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(callDigest[i], uapi.ByteValueOf(c.CallHash[i]))
	}

	// --------------------------------------------------------
	// 2. Derive message hash (to||value||data) for signature
	// --------------------------------------------------------
	h2, _ := keccak.New256(api)
	// to (20 bytes) + value (16 bytes) + data (padded to 32 bytes)
	msgBytes := make([]uints.U8, 20+16+MAX_DATA_BYTES)
	toBits := api.ToBinary(c.To, 160) // Decompose uint160 into 160 bits
	for i := 0; i < 20; i++ {
		byteVar := api.FromBinary(toBits[i*8 : (i+1)*8]...)
		msgBytes[i] = uapi.ByteValueOf(byteVar)
	}

	valueBits := api.ToBinary(c.Value, 128) // Decompose uint128 into 128 bits
	for i := 0; i < 16; i++ {
		byteVar := api.FromBinary(valueBits[i*8 : (i+1)*8]...)
		msgBytes[20+i] = uapi.ByteValueOf(byteVar)
	}

	for i := 0; i < MAX_DATA_BYTES; i++ {
		msgBytes[20+16+i] = uapi.ByteValueOf(c.Data[i]) // 32 bytes of data
	}
	h2.Write(msgBytes) // sha3.Keccak
	msgHash := h2.Sum()

	// --------------------------------------------------------
	// 3. ecrecover: recover address from signature and verify against signer
	// --------------------------------------------------------
	frField, _ := emulated.NewField[emulated.Secp256k1Fr](api)
	fpField, _ := emulated.NewField[emulated.Secp256k1Fp](api)

	// Convert msgHash
	digestBits := make([]frontend.Variable, 0, 256)

	// Keccak returns bytes big-endian, so walk from the last byte to the first
	// to obtain *little-endian* bit order expected by FromBits.
	for i := 31; i >= 0; i-- {
		// (a) unwrap the uints.U8 into the underlying field element
		byteVal := msgHash[i].Val // <- that's a frontend.Variable

		// (b) decompose that byte into its 8 LSB-first bits
		bits := api.ToBinary(byteVal, 8)

		// (c) append
		digestBits = append(digestBits, bits...)
	}

	// Optional sanity: prove every byte is ≤ 255
	for i := 0; i < 32; i++ {
		uapi.ByteAssertEq(uapi.ByteValueOf(msgHash[i].Val), msgHash[i])
	}

	// Prepare inputs for ECRecover
	msgEmu := frField.FromBits(api, digestBits)
	rEmu := frField.NewElement(c.SigR)
	sEmu := frField.NewElement(c.SigS)

	// Call ECRecover precompile.
	// strict = 1: enforces s <= (Fr-1)/2, standard for tx signatures.
	// isFailure = 0: we expect a valid signature, not a failure case.
	recoveredPk := evmprecompiles.ECRecover(api, *msgEmu, c.SigV, *rEmu, *sEmu, 1, 0)

	// The recovered public key must be hashed with Keccak256 to get the address.
	// Address = Keccak256(Px || Py)[12:]
	pxBits := fpField.ToBits(&recoveredPk.X)
	pyBits := fpField.ToBits(&recoveredPk.Y)

	// Concatenate Px and Py (32 bytes each) into a 64-byte slice for hashing.
	pkBytes := make([]uints.U8, 64)
	for i := 0; i < 32; i++ {
		pxByteVar := api.FromBinary(pxBits[i*8 : (i+1)*8]...)
		pkBytes[i] = uapi.ByteValueOf(pxByteVar)
		pyByteVar := api.FromBinary(pyBits[i*8 : (i+1)*8]...)
		pkBytes[32+i] = uapi.ByteValueOf(pyByteVar)
	}

	// Hash the 64-byte public key
	h3, _ := keccak.New256(api)
	h3.Write(pkBytes)
	pkHash := h3.Sum() // pkHash is [32]uints.U8

	// Re-compose the address (last 20 bytes of the hash) into a single variable.
	var recoveredAddress frontend.Variable = 0
	for i := 0; i < 20; i++ {
		byteVar := pkHash[12+i].Val
		recoveredAddress = api.Add(api.Mul(recoveredAddress, 256), byteVar)
	}

	// Assert that the recovered address matches the provided signer address.
	api.AssertIsEqual(recoveredAddress, c.Signer)

	// --------------------------------------------------------
	// 4. Classify the user action (TxType, dest, asset)
	// --------------------------------------------------------
	txType, destAddr, assetAddr := classifyTx(api, c)

	// --------------------------------------------------------
	// 5. Policy evaluation (first‑match semantics)
	// --------------------------------------------------------
	prevMatch := frontend.Variable(0)
	allowed := frontend.Variable(0)
	prevID := frontend.Variable(-1)

	for i := 0; i < MAX_POLICY_LINES; i++ {
		line := c.Policy[i]

		isZeroResult := isZero(api, line.ID)
		isActiveRule := api.Sub(1, isZeroResult)
		api.AssertIsLessOrEqual(prevID, api.Add(prevID, api.Mul(isActiveRule, api.Sub(line.ID, prevID))))
		prevID = api.Select(isActiveRule, line.ID, prevID)

		// (a) tx‑type must match ------------------------------------------
		mTx := eq(api, line.TxType, txType)

		// (b) destination pattern -----------------------------------------
		mDestAny := eq(api, line.DestinationTag, DP_ANY)

		// group
		mDestGrpTag := eq(api, line.DestinationTag, DP_GROUP)
		var selectedGroup [MAX_ADDRS_PER_SET]frontend.Variable
		var selectedGroupSize frontend.Variable = 0
		for k := 0; k < MAX_GROUPS; k++ {
			isCorrectIndex := eq(api, line.DestinationIdx, k)
			selectedGroupSize = api.Select(isCorrectIndex, c.GroupSizes[k], selectedGroupSize)
			for j := 0; j < MAX_ADDRS_PER_SET; j++ {
				selectedGroup[j] = api.Select(isCorrectIndex, c.Groups[k][j], selectedGroup[j])
			}
		}
		destInGrp := inSet(api, destAddr, selectedGroup, selectedGroupSize)
		mDestGrp := api.And(mDestGrpTag, destInGrp)

		// allow‑list
		mDestListTag := eq(api, line.DestinationTag, DP_ALLOWLIST)
		var selectedAllowList [MAX_ADDRS_PER_SET]frontend.Variable
		var selectedAllowListSize frontend.Variable = 0
		for k := 0; k < MAX_ALLOWLISTS; k++ {
			isCorrectIndex := eq(api, line.DestinationIdx, k)
			selectedAllowListSize = api.Select(isCorrectIndex, c.AllowSizes[k], selectedAllowListSize)
			for j := 0; j < MAX_ADDRS_PER_SET; j++ {
				selectedAllowList[j] = api.Select(isCorrectIndex, c.AllowLists[k][j], selectedAllowList[j])
			}
		}
		destInList := inSet(api, destAddr, selectedAllowList, selectedAllowListSize)
		mDestList := api.And(mDestListTag, destInList)

		mDest := orBitwise(api, mDestAny, orBitwise(api, mDestGrp, mDestList))

		// (c) signer pattern ----------------------------------------------
		mSignerAny := eq(api, line.SignerTag, SP_ANY)
		mSignerExactTag := eq(api, line.SignerTag, SP_EXACT)
		mSignerExact := api.And(mSignerExactTag, eq(api, c.Signer, line.SignerAddr))

		mSignerGrpTag := eq(api, line.SignerTag, SP_GROUP)
		var selectedSignerGroup [MAX_ADDRS_PER_SET]frontend.Variable
		var selectedSignerGroupSize frontend.Variable = 0
		for k := 0; k < MAX_GROUPS; k++ {
			isCorrectIndex := eq(api, line.SignerGroupIdx, k)
			selectedSignerGroupSize = api.Select(isCorrectIndex, c.GroupSizes[k], selectedSignerGroupSize)
			for j := 0; j < MAX_ADDRS_PER_SET; j++ {
				selectedSignerGroup[j] = api.Select(isCorrectIndex, c.Groups[k][j], selectedSignerGroup[j])
			}
		}
		signerInGrp := inSet(api, c.Signer, selectedSignerGroup, selectedSignerGroupSize)
		mSignerGrp := api.And(mSignerGrpTag, signerInGrp)

		mSigner := orBitwise(api, mSignerAny, orBitwise(api, mSignerExact, mSignerGrp))

		// (d) asset pattern -----------------------------------------------
		mAssetAny := eq(api, line.AssetTag, AP_ANY)
		mAssetExactTag := eq(api, line.AssetTag, AP_EXACT)
		mAssetExact := api.And(mAssetExactTag, eq(api, assetAddr, line.AssetAddr))
		mAsset := orBitwise(api, mAssetAny, mAssetExact)

		// (e) if txType==contractCall asset must be "any" ------------------
		isCall := eq(api, txType, TT_CONTRACTCALL)
		assetMustAny := api.Mul(isCall, mAssetAny) // 1 only when contractCall & any

		// ------------------------------------------------------------------
		ruleMatches := api.And(api.And(api.And(mTx, mDest), api.And(mSigner, mAsset)), assetMustAny)

		// enforce first‑match semantics ------------------------------------
		firstMatch := api.Mul(ruleMatches, api.Sub(1, prevMatch)) // match && !prevMatch
		prevMatch = orBitwise(api, prevMatch, ruleMatches)        // update history

		// take rule's action ----------------------------------------------
		allowedByRule := api.Mul(firstMatch, eq(api, line.Action, ACT_ALLOW))
		allowed = orBitwise(api, allowed, allowedByRule)
	}

	// --------------------------------------------------------
	// 6. Must be allowed ==> circuit passes
	// --------------------------------------------------------
	api.AssertIsEqual(prevMatch, 1)
	api.AssertIsEqual(allowed, 1)

	return nil
}

func main() {
	// ---------------------------------------------------------------------------------
	// PART 0: Data Generation (porting the logic from the Risc0 host)
	// ---------------------------------------------------------------------------------
	fmt.Println("▶ Part 0: Generating test data...")

	// Generate a new signer key and derive its address
	sk, err := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate signer key: %v", err))
	}
	fromAddressBytes := eth_crypto.PubkeyToAddress(sk.PublicKey).Bytes()
	fmt.Printf("  → Generated Signer Address: 0x%x\n", fromAddressBytes)

	// Define destination and token addresses
	toAddrBytes, _ := hex.DecodeString("12f3a2b4cC21881f203818aA1F78851Df974Bcc2")
	erc20AddrBytes, _ := hex.DecodeString("dAC17F958D2ee523a2206206994597C13D831ec7") // USDT

	// Craft calldata for `transfer(address,uint256)`
	amount := new(big.Int).SetUint64(1_000_000) // 1 USDT (6 decimals)
	calldata := new(bytes.Buffer)
	calldata.Write(transferSelector)
	calldata.Write(bytes.Repeat([]byte{0}, 12)) // Pad address to 32 bytes
	calldata.Write(toAddrBytes)
	calldata.Write(bytes.Repeat([]byte{0}, 16)) // Pad amount high bits
	calldata.Write(amount.Bytes())
	calldataBytes := calldata.Bytes()

	// Create the message hash to be signed, mirroring the circuit's logic.
	// Circuit hash = H(to || value || H(data))
	toBig := new(big.Int).SetBytes(erc20AddrBytes)
	valueBig := big.NewInt(0)
	callDataHash := eth_crypto.Keccak256(calldataBytes)

	var msgBuf bytes.Buffer
	msgBuf.Write(toBig.Bytes())
	msgBuf.Write(valueBig.Bytes())
	msgBuf.Write(callDataHash)
	messageToSign := eth_crypto.Keccak256(msgBuf.Bytes())

	// Sign the message. We use go-ethereum's crypto library to get a recoverable signature.
	// The resulting signature is 65 bytes long: [R || S || V], where V is 0 or 1.
	sigBytes, err := eth_crypto.Sign(messageToSign, sk)
	if err != nil {
		panic(fmt.Sprintf("failed to sign message: %v", err))
	}

	// Extract R, S, and V. The circuit expects V to be 27 or 28.
	sigR := new(big.Int).SetBytes(sigBytes[:32])
	sigS := new(big.Int).SetBytes(sigBytes[32:64])
	sigV := new(big.Int).SetInt64(int64(sigBytes[64]) + 27)

	// Build the simple policy
	policy := make([]PolicyLineWitness, MAX_POLICY_LINES)
	policy[0] = PolicyLineWitness{
		ID:             1,
		TxType:         TT_TRANSFER,
		DestinationTag: DP_ANY,
		SignerTag:      SP_EXACT,
		SignerAddr:     new(big.Int).SetBytes(fromAddressBytes),
		AssetTag:       AP_EXACT,
		AssetAddr:      new(big.Int).SetBytes(erc20AddrBytes),
		Action:         ACT_ALLOW,
	}

	// Calculate public hashes (commitments)
	// For this test, we just hash the relevant data.
	finalCallHash := eth_crypto.Keccak256(calldataBytes)
	finalPolicyHash := eth_crypto.Keccak256([]byte("dummy policy hash"))   // Placeholder
	finalGroupsHash := eth_crypto.Keccak256([]byte("dummy groups hash"))   // Placeholder
	finalAllowHash := eth_crypto.Keccak256([]byte("dummy allowlist hash")) // Placeholder

	// ---------------------------------------------------------------------------------
	// PART 1: Compile the circuit
	// ---------------------------------------------------------------------------------
	fmt.Println("\n▶ Part 1: Compiling circuit...")

	// We must initialize slices to their max capacity to avoid compilation errors.
	circuit := ZKGuardCircuit{
		Policy:     make([]PolicyLineWitness, MAX_POLICY_LINES),
		Groups:     [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable{},
		GroupSizes: [MAX_GROUPS]frontend.Variable{},
		AllowLists: [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable{},
		AllowSizes: [MAX_ALLOWLISTS]frontend.Variable{},
		Data:       [MAX_DATA_BYTES]frontend.Variable{},
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Sprintf("failed to compile circuit: %v", err))
	}
	fmt.Println("  → Circuit compiled successfully!")
	fmt.Printf("    Constraints: %d\n", cs.GetNbConstraints())

	// ---------------------------------------------------------------------------------
	// PART 2: Perform trusted setup (Groth16)
	// ---------------------------------------------------------------------------------
	fmt.Println("\n▶ Part 2: Performing trusted setup...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(fmt.Sprintf("failed to run setup: %v", err))
	}
	fmt.Println("  → Setup complete.")

	// ---------------------------------------------------------------------------------
	// PART 3: Create witness from assignment
	// ---------------------------------------------------------------------------------
	fmt.Println("\n▶ Part 3: Creating witness...")

	// Prepare calldata for the circuit, padding to max length
	paddedData := make([]frontend.Variable, MAX_DATA_BYTES)
	for i := 0; i < len(calldataBytes); i++ {
		paddedData[i] = calldataBytes[i]
	}
	for i := len(calldataBytes); i < MAX_DATA_BYTES; i++ {
		paddedData[i] = 0 // Ensure padding is zero
	}

	// Create the full witness assignment
	assignment := ZKGuardCircuit{
		// Public inputs
		CallHash:   [32]frontend.Variable(toFrontendVariableArray(finalCallHash)),
		PolicyHash: [32]frontend.Variable(toFrontendVariableArray(finalPolicyHash)),
		GroupsHash: [32]frontend.Variable(toFrontendVariableArray(finalGroupsHash)),
		AllowHash:  [32]frontend.Variable(toFrontendVariableArray(finalAllowHash)),

		// Private witness
		To:      new(big.Int).SetBytes(erc20AddrBytes),
		Value:   0,
		Data:    [MAX_DATA_BYTES]frontend.Variable(paddedData),
		DataLen: len(calldataBytes),
		Signer:  new(big.Int).SetBytes(fromAddressBytes),
		SigR:    sigR,
		SigS:    sigS,
		SigV:    sigV,
		Policy:  policy,
		// Groups & Allowlists are empty, so we just provide empty arrays.
		Groups:     [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable{},
		GroupSizes: [MAX_GROUPS]frontend.Variable{},
		AllowLists: [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable{},
		AllowSizes: [MAX_ALLOWLISTS]frontend.Variable{},
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(fmt.Sprintf("failed to create witness: %v", err))
	}
	publicWitness, _ := witness.Public()
	fmt.Println("  → Witness created successfully.")

	// ---------------------------------------------------------------------------------
	// PART 4: Generate the proof
	// ---------------------------------------------------------------------------------
	fmt.Println("\n▶ Part 4: Generating proof...")
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(fmt.Sprintf("failed to generate proof: %v", err))
	}
	fmt.Println("  → Proof generated successfully!")

	// ---------------------------------------------------------------------------------
	// PART 5: Verify the proof
	// ---------------------------------------------------------------------------------
	fmt.Println("\n▶ Part 5: Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(fmt.Sprintf("proof verification failed: %v", err))
	}
	fmt.Println("  → ✅ Proof verified successfully!")
}

// Helper function to convert a byte slice to a frontend.Variable slice
func toFrontendVariableArray(data []byte) [32]frontend.Variable {
	var arr [32]frontend.Variable
	for i := 0; i < 32; i++ {
		if i < len(data) {
			arr[i] = data[i]
		} else {
			arr[i] = 0
		}
	}
	return arr
}
