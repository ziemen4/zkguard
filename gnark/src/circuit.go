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

// --- Circuit Constants ---
// These constants define the fixed-size parameters of the circuit.
// They determine the capacity of the circuit for things like policy complexity and data sizes.
const (
	// MERKLE_TREE_DEPTH defines the depth of the policy Merkle tree.
	// The total number of policies supported is 2^MERKLE_TREE_DEPTH. (e.g., 5 -> 32 policies)
	MERKLE_TREE_DEPTH = 5
	// MAX_GROUPS is the maximum number of address groups (e.g., for dev team, multisig members) the circuit can handle.
	MAX_GROUPS = 8
	// MAX_ALLOWLISTS is the maximum number of address allowlists (e.g., for approved contract destinations) the circuit can handle
	MAX_ALLOWLISTS = 8
	// MAX_ADDRS_PER_SET is the maximum number of addresses that can be stored in a single group or allowlist.
	MAX_ADDRS_PER_SET = 32
	// MAX_DATA_BYTES defines the maximum size of the transaction `calldata` byte array.
	MAX_DATA_BYTES = 256
	// MAX_SIGNATURES is the maximum number of ECDSA signatures the circuit can verify for a single action.
	// This is essential for implementing threshold signature policies.
	MAX_SIGNATURES = 5
)

// transferSelector is the first 4 bytes of the keccak256 hash of the function signature "transfer(address,uint256)".
// This is the standard function selector for an ERC20 token transfer.
var transferSelector = []byte{0xa9, 0x05, 0x9c, 0xbb}

// --- Policy Tag Constants ---
// These integer constants are used within policy lines to define behavior patterns.
// They act as enums to make the policy logic clear and structured.
const (
	// TxType Tags: Define the type of transaction being evaluated.
	// A transfer of a native asset (e.g., ETH) or an ERC20 token.
	TT_TRANSFER = 0
	// A general contract call (not an ERC20 transfer).
	TT_CONTRACTCALL = 1

	// DestinationPolicy Tags: Define how the transaction's destination is checked.
	// Any destination address is allowed.
	DP_ANY = 0
	// Destination must be a member of a specified group.
	DP_GROUP = 1
	// Destination must be on a specified allowlist.
	DP_ALLOWLIST = 2
	// The destination must be a specific address.
	DP_EXACT = 3

	// SignerPolicy Tags: Define how the transaction's signer(s) are authenticated.
	// Any valid signature is allowed.
	SP_ANY = 0
	// The signature must come from a single, specific address.
	SP_EXACT = 1
	// The signer must be a member of a specified group.
	SP_GROUP = 2
	// A minimum number of signatures from a specified group must be provided.
	SP_THRESHOLD = 3

	// AssetPolicy Tags: Define how the asset being transferred or interacted with is checked.
	// Any asset is allowed.
	AP_ANY = 0
	// The asset must be a specific contract address (e.g., a specific ERC20 token).
	AP_EXACT = 1
	// If the policy matches, the action is allowed. (Future: ACT_DENY, etc.)
	ACT_ALLOW = 1
)

// SignatureWitness holds the components of a single ECDSA signature.
// These are provided as private inputs to the circuit for each signature to be verified.
type SignatureWitness struct {
	// R is the first 256-bit component of an ECDSA signature. Since a single field element
	// We split it into two 128-bit limbs (High and Low).
	R_Hi frontend.Variable
	R_Lo frontend.Variable
	// S is the second 256-bit component of an ECDSA signature, also split into two 128-bit limbs.
	S_Hi frontend.Variable
	S_Lo frontend.Variable
	// V is the recovery ID (typically 0 or 1, or 27/28 in Ethereum legacy txs).
	// It's used to recover the correct public key from the signature.
	V frontend.Variable
}

// PolicyLineWitness is the in-circuit representation of a single policy rule.
// All fields are of type `frontend.Variable` as they are part of the circuit's private witness.
type PolicyLineWitness struct {
	// A unique identifier for the policy line.
	ID frontend.Variable
	// The transaction type this rule applies to (e.g., TT_TRANSFER).
	TxType frontend.Variable
	// The destination check type (e.g., DP_GROUP).
	DestinationTag frontend.Variable
	// The index of the group/allowlist to use for the destination check.
	DestinationIdx frontend.Variable
	// The specific address for DP_EXACT checks.
	DestinationAddr frontend.Variable
	// The signer authentication type (e.g., SP_THRESHOLD).
	SignerTag frontend.Variable
	// The specific address for SP_EXACT checks.
	SignerAddr frontend.Variable
	// The index of the group to use for SP_GROUP or SP_THRESHOLD checks.
	SignerGroupIdx frontend.Variable
	// The asset check type (e.g., AP_EXACT).
	AssetTag frontend.Variable
	// The specific asset address (e.g., token contract) for AP_EXACT checks.
	AssetAddr frontend.Variable
	// The maximum value for transfers. 0 means no limit.
	AmountMax frontend.Variable
	// The 4-byte function selector for contract call restrictions. 0 means no restriction.
	FunctionSelector [4]frontend.Variable
	// The action to take on match (e.g., ACT_ALLOW).
	Action frontend.Variable
	// For SP_THRESHOLD, the required number of valid signatures.
	Threshold frontend.Variable
}

// PolicyLine is the native Go struct used to define policies outside the circuit.
// This struct is used to prepare the witness data that is then fed into the `PolicyLineWitness`.
type PolicyLine struct {
	ID               int
	TxType           int
	DestinationTag   int
	DestinationIdx   int
	DestinationAddr  *big.Int
	SignerTag        int
	SignerAddr       *big.Int
	SignerGroupIdx   int
	AssetTag         int
	AssetAddr        *big.Int
	AmountMax        *big.Int
	FunctionSelector []byte
	Action           int
	Threshold        int
}

type ZKGuardCircuit struct {
	// ------------------ PUBLIC INPUTS ------------------
	// Public inputs are known by both the prover and the verifier. They are the public "statement"
	// that the proof is about. In our case, they are commitments to the state and the action.

	// CallHash is a placeholder commitment to the transaction data. Not used within this circuit's logic
	// but can be part of the public statement for external consistency.
	CallHash [32]frontend.Variable `gnark:",public"`

	// PolicyMerkleRoot is the root hash of the Merkle tree containing all policy rules.
	// This commits to the entire policy set, allowing the circuit to verify one rule at a time
	// while being sure it belongs to the committed set.
	PolicyMerkleRoot [32]frontend.Variable `gnark:",public"`

	// GroupsHash is a placeholder commitment to the address groups.
	GroupsHash [32]frontend.Variable `gnark:",public"`

	// AllowHash is a placeholder commitment to the address allow-lists.
	AllowHash [32]frontend.Variable `gnark:",public"`

	// ------------------ PRIVATE WITNESS (Prover Inputs) ------------------
	// The private witness is known only to the prover. It contains the evidence needed to satisfy
	// the circuit's constraints.

	// --- On-chain action details ---
	// The sender address (`from`) of the transaction.
	From frontend.Variable
	// The destination address (`to`) of the transaction.
	To frontend.Variable
	// The amount of native currency (`value`) sent.
	Value frontend.Variable
	// The calldata (`data`) of the transaction.
	Data [MAX_DATA_BYTES]frontend.Variable
	// The actual length of the calldata.
	DataLen frontend.Variable
	// An array of signatures to be verified. For a simple transaction, only one might be used.
	// For a threshold policy, multiple slots will be filled.
	Signatures [MAX_SIGNATURES]SignatureWitness
	// The number of signatures provided in the `Signatures` array. This is used to control
	// the verification loop.
	NumSigs frontend.Variable

	// --- Policy line and its proof ---
	// The specific policy rule that the prover claims allows this action.
	PolicyLine PolicyLineWitness
	// The sibling nodes in the Merkle tree required to reconstruct the path from the policy line leaf to the root.
	MerkleProofSiblings [MERKLE_TREE_DEPTH][32]frontend.Variable
	// The path bits (0 for left, 1 for right) indicating the position of the leaf at each level of the tree.
	MerkleProofPath [MERKLE_TREE_DEPTH]frontend.Variable

	// --- Full data sets for policy evaluation ---
	// These are the complete sets of addresses for all groups and allowlists. The circuit needs these
	// to perform membership checks required by the policy line.
	Groups     [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	GroupSizes [MAX_GROUPS]frontend.Variable
	AllowLists [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	AllowSizes [MAX_ALLOWLISTS]frontend.Variable
}

// --- Helper Primitives ---
// These are basic logic gates and functions used throughout the circuit.

// isZero checks if a variable is zero. Returns 1 if v is 0, else 0.
func isZero(api frontend.API, v frontend.Variable) frontend.Variable { return api.IsZero(v) }

// eq checks if two variables are equal. Returns 1 if a == b, else 0.
func eq(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return isZero(api, api.Sub(a, b))
}

// orBitwise performs a boolean OR operation on two variables that are constrained to be 0 or 1.
// It uses the formula: a OR b = a + b - a*b.
func orBitwise(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Sub(api.Add(a, b), api.Mul(a, b))
}

// inSet checks if a given address `addr` is present in a `set` of `n` elements.
// This is a core function for checking membership in groups and allowlists.
func inSet(api frontend.API, addr frontend.Variable, set [MAX_ADDRS_PER_SET]frontend.Variable, n frontend.Variable) frontend.Variable {
	found := frontend.Variable(0)
	isAddrZero := isZero(api, addr)
	// Iterate through the entire fixed-size set.
	for i := 0; i < MAX_ADDRS_PER_SET; i++ {
		isMember := eq(api, addr, set[i])
		// Check if the current slot is active (i.e., within the actual size `n` of the set).
		isActive := cmp.IsLess(api, i, n)
		// The address is found if it matches `set[i]` and the slot is active.
		found = orBitwise(api, found, api.And(isMember, isActive))
	}
	// An address of 0 should never be considered a valid member.
	return api.And(found, api.Sub(1, isAddrZero)) // Ensure address 0 is never a member
}

// bytesEq4 checks if the first 4 bytes of `data` match the ERC20 transfer selector.
func bytesEq4(api frontend.API, data [MAX_DATA_BYTES]frontend.Variable, length frontend.Variable) frontend.Variable {
	// Ensure data is long enough to contain a 4-byte selector.
	isLongEnough := cmp.IsLessOrEqual(api, 4, length)
	ok := frontend.Variable(1)
	// Check each of the first 4 bytes.
	for i := 0; i < 4; i++ {
		ok = api.And(ok, eq(api, data[i], int(transferSelector[i])))
	}
	return api.And(ok, isLongEnough)
}

// --- classifyTx ---
// This function parses the raw transaction details (`To`, `Value`, `Data`) and classifies the transaction.
// It extracts the semantically correct destination, asset, and amount, regardless of whether it's a
// native ETH transfer, an ERC20 transfer, or a general contract call.
func classifyTx(api frontend.API, ua *ZKGuardCircuit) (frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) {
	// An ERC20 transfer is identified by its 4-byte function selector.
	isErc20 := bytesEq4(api, ua.Data, ua.DataLen)
	// If it's an ERC20 transfer, classify as TT_TRANSFER, otherwise as TT_CONTRACTCALL.
	txType := api.Select(isErc20, TT_TRANSFER, TT_CONTRACTCALL)
	// Set default values for a native transfer or contract call.
	destAddr := ua.To
	assetAddr := ua.To
	amount := ua.Value
	// If it's an ERC20 transfer, we need to parse the destination and amount from the calldata.
	// ERC20 transfer calldata format: selector(4B) + to(32B padded) + value(32B).
	var erc20To frontend.Variable = 0
	for i := 0; i < 20; i++ {
		// Extract address (last 20 bytes of the first 32-byte argument)
		erc20To = api.Add(api.Mul(erc20To, 256), ua.Data[4+12+i])
	}
	// Use the parsed ERC20 recipient if `isErc20` is true.
	destAddr = api.Select(isErc20, erc20To, destAddr)
	var erc20Amount frontend.Variable = 0
	for i := 0; i < 32; i++ {
		// Extract amount (second 32-byte argument)
		erc20Amount = api.Add(api.Mul(erc20Amount, 256), ua.Data[4+32+i])
	}
	// Use the parsed ERC20 amount if `isErc20` is true.
	amount = api.Select(isErc20, erc20Amount, amount)
	// A pure ETH send is a transaction with a non-zero value and no calldata.
	isPureEthSend := api.And(isZero(api, ua.DataLen), api.Sub(1, isZero(api, ua.Value)))
	// For pure ETH sends, the "asset" is ETH, which we represent with address 0.
	assetAddr = api.Select(isPureEthSend, 0, assetAddr)
	return txType, destAddr, assetAddr, amount
}

// selectSet is a generic helper to safely select a specific address set (and its size) from a list of sets.
// In gnark, we cannot use a circuit variable to index an array directly. This function implements a multiplexer:
// it iterates through all sets and uses `api.Select` to pick the values from the correct set based on `index`.
func selectSet(
	api frontend.API,
	index frontend.Variable,
	allSets [][MAX_ADDRS_PER_SET]frontend.Variable,
	allSizes []frontend.Variable,
	numSets int,
) ([MAX_ADDRS_PER_SET]frontend.Variable, frontend.Variable) {

	var selectedSet [MAX_ADDRS_PER_SET]frontend.Variable
	for i := range selectedSet {
		// Initialize to 0
		selectedSet[i] = 0
	}
	var selectedSize frontend.Variable = 0

	// Loop through all possible sets.
	for k := 0; k < numSets; k++ {
		isCorrectIndex := eq(api, index, k)
		// If this is the correct index, select the size and addresses from this set.
		// Otherwise, keep the previously selected values.
		selectedSize = api.Select(isCorrectIndex, allSizes[k], selectedSize)
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			selectedSet[j] = api.Select(isCorrectIndex, allSets[k][j], selectedSet[j])
		}
	}
	return selectedSet, selectedSize
}

// isEqualHash checks if two 32-byte hashes are equal. Raises an assertion failure if not equal.
func isEqualHash(api frontend.API, hashA []uints.U8, hashB [32]frontend.Variable) {
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(hashA[i].Val, hashB[i])
	}
}

// -----------------------------------------------------------------------------
//
//	Main Circuit Logic
//
// -----------------------------------------------------------------------------
func (c *ZKGuardCircuit) Define(api frontend.API) error {
	// Initialize helper APIs for uints and emulated fields for secp256k1 operations.
	uapi, _ := uints.New[uints.U32](api)
	// Field for signature values (r, s)
	frField, _ := emulated.NewField[emulated.Secp256k1Fr](api)
	// Field for curve point coordinates (x, y)
	fpField, _ := emulated.NewField[emulated.Secp256k1Fp](api)

	// --- 1. Merkle Proof Verification ---
	// This section proves that the provided `PolicyLine` is a legitimate member of the policy set
	// committed to in the public input `PolicyMerkleRoot`.

	// Create a SHA256 hasher within the circuit.
	leafHasher, _ := sha2.New(api)
	// Helper functions to write data to the hasher in the correct format.
	write1Byte := func(v frontend.Variable) { leafHasher.Write([]uints.U8{uapi.ByteValueOf(v)}) }
	write32Bytes := func(v frontend.Variable) {
		bits := api.ToBinary(v, 256)
		bytes := make([]uints.U8, 32)
		for i := 0; i < 32; i++ {
			// Convert 256 bits into 32 bytes (big-endian).
			bytes[i] = uapi.ByteValueOf(api.FromBinary(bits[(31-i)*8 : (32-i)*8]...))
		}
		leafHasher.Write(bytes)
	}

	// Sequentially hash all fields of the policy line to compute the leaf hash.
	// The order must be identical to the off-circuit hashing implementation.
	write1Byte(c.PolicyLine.ID)
	write1Byte(c.PolicyLine.TxType)
	write1Byte(c.PolicyLine.DestinationTag)
	write1Byte(c.PolicyLine.DestinationIdx)
	write32Bytes(c.PolicyLine.DestinationAddr)
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
	write1Byte(c.PolicyLine.Threshold)
	computedHashBytes := leafHasher.Sum()

	// Reconstruct the Merkle root using the computed leaf hash, the proof siblings, and the path.
	for i := 0; i < MERKLE_TREE_DEPTH; i++ {
		// 0 means current hash is on the left, 1 on the right.
		pathBit := c.MerkleProofPath[i]
		siblingBytes := c.MerkleProofSiblings[i]
		hasher, _ := sha2.New(api)
		left := make([]uints.U8, 32)
		right := make([]uints.U8, 32)
		// Arrange the current hash and the sibling hash in the correct order (left/right) based on pathBit.
		for j := 0; j < 32; j++ {
			left[j] = uapi.ByteValueOf(api.Select(pathBit, siblingBytes[j], computedHashBytes[j].Val))
			right[j] = uapi.ByteValueOf(api.Select(pathBit, computedHashBytes[j].Val, siblingBytes[j]))
		}
		hasher.Write(left)
		hasher.Write(right)
		// The new `computedHashBytes` is the hash of the next level up the tree.
		computedHashBytes = hasher.Sum()
	}

	// After iterating up the tree, the computed hash must equal the public Merkle root.
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedHashBytes[i].Val, c.PolicyMerkleRoot[i])
	}

	// --- 2. Hash Verifications ---
	// This section computes the message hash that the user(s) must have signed.
	// For Ethereum compatibility, this must use Keccak256.
	hMsg, _ := keccak.NewLegacyKeccak256(api)
	// Serialize the transaction data (From, To, Value, Data) into a byte array for hashing.
	msgForHashBytes := make([]uints.U8, 20+20+16+MAX_DATA_BYTES)
	fromBytes := api.ToBinary(c.From, 160)
	for i := 0; i < 20; i++ {
		byteVal := api.FromBinary(fromBytes[(19-i)*8 : (20-i)*8]...)
		msgForHashBytes[i] = uapi.ByteValueOf(byteVal)
	}
	toBytes := api.ToBinary(c.To, 160)
	for i := 0; i < 20; i++ {
		byteVal := api.FromBinary(toBytes[(19-i)*8 : (20-i)*8]...)
		msgForHashBytes[20+i] = uapi.ByteValueOf(byteVal)
	}
	valueBytes := api.ToBinary(c.Value, 128)
	for i := 0; i < 16; i++ {
		byteVal := api.FromBinary(valueBytes[(15-i)*8 : (16-i)*8]...)
		msgForHashBytes[20+20+i] = uapi.ByteValueOf(byteVal)
	}
	for i := 0; i < MAX_DATA_BYTES; i++ {
		msgForHashBytes[20+20+16+i] = uapi.ByteValueOf(c.Data[i])
	}
	hMsg.Write(msgForHashBytes)
	// This is the 32-byte hash that was signed.
	msgHash := hMsg.Sum()

	// Check that msgHash is equal to c.CallHash
	isEqualHash(api, msgHash, c.CallHash)

	// Hash the Groups and AllowLists to verify their commitments.
	// This can use Sha256 as we don't require Ethereum compatibility here.
	hGroups, _ := sha2.New(api)
	for i := 0; i < MAX_GROUPS; i++ {
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			// Create a slice to hold the 20 bytes for this address
			addressBytes := make([]uints.U8, 20)

			// 1. Get 160 bits (LSB-first)
			bits := api.ToBinary(c.Groups[i][j], 160)

			// 2. Loop 20 times (for 20 bytes)
			for k := 0; k < 20; k++ {
				// 3. Get bits for the k-th byte in Big-Endian order.
				//    k=0  -> bits[152:160] (MSB)
				//    k=19 -> bits[0:8] (LSB)
				byteBits := bits[(19-k)*8 : (20-k)*8]

				// 4. Pack bits into a frontend.Variable (byte)
				byteVal := api.FromBinary(byteBits...)

				// 5. Convert to U8 and store in big-endian order
				addressBytes[k] = uapi.ByteValueOf(byteVal)
			}

			// 6. Write the 20 big-endian bytes for this address
			hGroups.Write(addressBytes)
		}
		hGroups.Write([]uints.U8{uapi.ByteValueOf(c.GroupSizes[i])})
	}
	groupsHashBytes := hGroups.Sum()
	isEqualHash(api, groupsHashBytes, c.GroupsHash)

	hAllow, _ := sha2.New(api)
	for i := 0; i < MAX_ALLOWLISTS; i++ {
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			// Create a slice to hold the 20 bytes for this address
			addressBytes := make([]uints.U8, 20)

			// 1. Get 160 bits (LSB-first)
			bits := api.ToBinary(c.AllowLists[i][j], 160)

			// 2. Loop 20 times (for 20 bytes)
			for k := 0; k < 20; k++ {
				// 3. Get bits for the k-th byte in Big-Endian order.
				//    k=0  -> bits[152:160] (MSB)
				//    k=19 -> bits[0:8] (LSB)
				byteBits := bits[(19-k)*8 : (20-k)*8]

				// 4. Pack bits into a frontend.Variable (byte)
				byteVal := api.FromBinary(byteBits...)

				// 5. Convert to U8 and store in big-endian order
				addressBytes[k] = uapi.ByteValueOf(byteVal)
			}

			// 6. Write the 20 big-endian bytes for this address
			hAllow.Write(addressBytes)
		}
		hAllow.Write([]uints.U8{uapi.ByteValueOf(c.AllowSizes[i])})
	}
	allowHashBytes := hAllow.Sum()
	isEqualHash(api, allowHashBytes, c.AllowHash)

	// --- 3. Multi-Signature Verification Loop ---
	// This section verifies all provided signatures against the message hash and recovers the signer addresses.
	recoveredSigners := [MAX_SIGNATURES]frontend.Variable{}
	// Convert the message hash into the emulated field format required by the ECRecover precompile.
	digestBits := make([]frontend.Variable, 256)
	for i := 0; i < 32; i++ {
		bits := api.ToBinary(msgHash[31-i].Val, 8)
		copy(digestBits[i*8:], bits)
	}
	msgEmu := frField.FromBits(digestBits...)
	// Loop through all possible signature slots. The loop runs a fixed number of times.
	for i := 0; i < MAX_SIGNATURES; i++ {
		// Check if this signature slot is active (i.e., if i < NumSigs).
		isActiveSig := cmp.IsLess(api, i, c.NumSigs)
		sig := c.Signatures[i]

		// Use `api.Select` to use real signature values if active, or safe dummy values if inactive.
		// This ensures the circuit structure is fixed and avoids panics in `ECRecover` with zero values.
		// A dummy signature of r=1, s=1, v=0 is safe.
		rHi := api.Select(isActiveSig, sig.R_Hi, 0)
		rLo := api.Select(isActiveSig, sig.R_Lo, 1) // Dummy R = 1
		sHi := api.Select(isActiveSig, sig.S_Hi, 0)
		sLo := api.Select(isActiveSig, sig.S_Lo, 1) // Dummy S = 1
		v := api.Select(isActiveSig, sig.V, 0)      // Dummy V = 0

		// Recompose R and S from their high and low 128-bit limbs into emulated field elements.
		rLimbs := make([]frontend.Variable, 4)
		rLimbs[2], rLimbs[3] = bitslice.Partition(api, rHi, 64, bitslice.WithNbDigits(128))
		rLimbs[0], rLimbs[1] = bitslice.Partition(api, rLo, 64, bitslice.WithNbDigits(128))
		rEmu := frField.NewElement(rLimbs)
		sLimbs := make([]frontend.Variable, 4)
		sLimbs[2], sLimbs[3] = bitslice.Partition(api, sHi, 64, bitslice.WithNbDigits(128))
		sLimbs[0], sLimbs[1] = bitslice.Partition(api, sLo, 64, bitslice.WithNbDigits(128))
		sEmu := frField.NewElement(sLimbs)
		// ECRecover gadget expects V to be 27 or 28.
		vPlus27 := api.Add(v, 27)

		// Call the ECRecover precompile gadget. For inactive slots, it runs on dummy data and produces a meaningless result.
		recoveredPk := evmprecompiles.ECRecover(api, *msgEmu, vPlus27, *rEmu, *sEmu, 1, 0)

		// Convert the recovered public key (X, Y coordinates) into an Ethereum address.
		// This involves hashing the 64-byte public key with Keccak256 and taking the last 20 bytes.
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
			// Reconstruct address from the last 20 bytes of the hash.
			recoveredAddress = api.Add(api.Mul(recoveredAddress, 256), pkHash[12+j].Val)
		}

		// Store the result. If the signature was active, store the recovered address. If not, store 0.
		recoveredSigners[i] = api.Select(isActiveSig, recoveredAddress, 0)
	}

	// --- 4. Policy Evaluation ---
	// This section checks if the classified transaction and recovered signers satisfy the constraints of the policy line.
	txType, destAddr, assetAddr, amount := classifyTx(api, c)
	line := c.PolicyLine

	// Fetch the correct address sets (groups/allowlists) based on the indices in the policy line.
	// We use the `selectSet` helper to do this safely.
	signerGroup, signerGroupSize := selectSet(api, line.SignerGroupIdx, c.Groups[:], c.GroupSizes[:], MAX_GROUPS)

	// Get the correct destination garoup/list based on the policy's DestinationIdx.
	destGroup, destGroupSize := selectSet(api, line.DestinationIdx, c.Groups[:], c.GroupSizes[:], MAX_GROUPS)
	destList, destListSize := selectSet(api, line.DestinationIdx, c.AllowLists[:], c.AllowSizes[:], MAX_ALLOWLISTS)

	// --- Evaluate Signer Policy ---
	// `mSigner` will be 1 if the signer constraints are met, 0 otherwise.
	// SP_ANY: Always true, as the signature recovery loop already ensures at least one valid signature if NumSigs > 0.
	mSignerAny := eq(api, line.SignerTag, SP_ANY)

	// SP_EXACT: The first recovered signer's address must match the address specified in the policy.
	mSignerExactTag := eq(api, line.SignerTag, SP_EXACT)
	mSignerExactCheck := eq(api, recoveredSigners[0], line.SignerAddr)
	mSignerExact := api.And(mSignerExactTag, mSignerExactCheck)

	// SP_GROUP: The first recovered signer must be a member of the specified signer group.
	mSignerGrpTag := eq(api, line.SignerTag, SP_GROUP)
	signerInGrpCheck := inSet(api, recoveredSigners[0], signerGroup, signerGroupSize)
	mSignerGrp := api.And(mSignerGrpTag, signerInGrpCheck)

	// SP_THRESHOLD: Count how many of the recovered signers are members of the specified group.
	mSignerThresholdTag := eq(api, line.SignerTag, SP_THRESHOLD)
	validThresholdSigners := frontend.Variable(0)
	// Loop through all recovered signers to count valid members of the signer group.
	for i := 0; i < MAX_SIGNATURES; i++ {
		// 1. Check if the signer is a valid member of the group
		isMember := inSet(api, recoveredSigners[i], signerGroup, signerGroupSize)

		// 2. Check if this is a new signer (i.e., not a duplicate from earlier)
		isNewSigner := frontend.Variable(1) // Assume it's new (1)

		// Loop through all signers *before* this one
		for j := 0; j < i; j++ {
			// Check if recoveredSigners[i] == recoveredSigners[j]
			// api.IsZero(api.Sub(a, b)) is the circuit-safe way to do api.Equal(a, b)
			isDuplicate := api.IsZero(api.Sub(recoveredSigners[i], recoveredSigners[j]))

			// If it's a duplicate (isDuplicate=1), we must set isNewSigner to 0.
			// We use api.And to "clear" the flag: isNewSigner = isNewSigner AND (NOT isDuplicate)
			isNewSigner = api.And(isNewSigner, api.Sub(1, isDuplicate))
		}

		// 3. The signer only counts if it's both a member AND new
		isValidAndNew := api.And(isMember, isNewSigner)

		// 4. Accumulate the count
		validThresholdSigners = api.Add(validThresholdSigners, isValidAndNew)
	}
	// The count of valid signers must be greater than or equal to the policy's threshold.
	thresholdMet := cmp.IsLessOrEqual(api, line.Threshold, validThresholdSigners)
	mSignerThreshold := api.And(mSignerThresholdTag, thresholdMet)

	// Combine all signer policy results. Only one can be true for a given policy line.
	mSigner := orBitwise(api, mSignerAny, orBitwise(api, mSignerExact, orBitwise(api, mSignerGrp, mSignerThreshold)))

	// --- Evaluate Other Policies ---
	// Each `m...` variable represents a match for a specific part of the policy.

	// Transaction Type Match
	mTx := eq(api, line.TxType, txType)

	// Destination Match
	mDestAny := eq(api, line.DestinationTag, DP_ANY)
	mDestGrp := api.And(eq(api, line.DestinationTag, DP_GROUP), inSet(api, destAddr, destGroup, destGroupSize))
	mDestList := api.And(eq(api, line.DestinationTag, DP_ALLOWLIST), inSet(api, destAddr, destList, destListSize))
	mDestExact := api.And(eq(api, line.DestinationTag, DP_EXACT), eq(api, destAddr, line.DestinationAddr))
	mDest := orBitwise(api, mDestAny, orBitwise(api, mDestGrp, orBitwise(api, mDestList, mDestExact)))

	// Asset Match
	mAssetAny := eq(api, line.AssetTag, AP_ANY)
	mAssetExact := api.And(eq(api, line.AssetTag, AP_EXACT), eq(api, assetAddr, line.AssetAddr))
	mAsset := orBitwise(api, mAssetAny, mAssetExact)

	// Amount Match
	noAmountLimit := isZero(api, line.AmountMax) // If AmountMax is 0, there is no limit.
	amountOK := cmp.IsLessOrEqual(api, amount, line.AmountMax)
	mAmount := orBitwise(api, noAmountLimit, amountOK)

	// Function Selector Match
	// If the policy selector is all zeros, it matches any function.
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

	// Special asset handling for contract calls.
	isCall := eq(api, txType, TT_CONTRACTCALL)

	// If the transaction is a contract call (`isCall`=1), then `mAssetAny` must be true.
	// If it's not a contract call (`isCall`=0), this check passes vacuously (`1-isCall`=1).
	// This enforces that policies for general contract calls must use the AP_ANY asset tag.
	callAssetOK := orBitwise(api, api.Sub(1, isCall), mAssetAny)

	// --- Final Assertion ---
	// `ruleMatches` is 1 only if ALL individual policy checks (mTx, mDest, mSigner, etc.) are 1.
	ruleMatches := api.And(mTx, api.And(mDest, api.And(mSigner, api.And(mAsset, api.And(mAmount, api.And(mSelector, callAssetOK))))))

	// The circuit is only satisfied if the rule fully matches the action AND the rule's action is "Allow".
	api.AssertIsEqual(ruleMatches, 1)
	api.AssertIsEqual(line.Action, ACT_ALLOW)

	return nil
}
