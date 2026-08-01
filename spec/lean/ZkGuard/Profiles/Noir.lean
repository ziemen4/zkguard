import ZkGuard.Semantics

/-!
# Noir commitment profiles

The policy decision is always `Rule.complies`. This profile describes only the
canonical encodings and public authentication of a rule. It does not model
compiled ACIR constraints or claim implementation conformance; that separate
bridge requires conformance vectors and differential execution. Noir V1 used a
SHA-256 Merkle membership path, while Noir V2 commits directly to one canonical
rule with Poseidon2.
-/

namespace ZkGuard.Profiles.Noir

open ZkGuard

abbrev Digest256 := Fin (2 ^ 256)

def bn254ScalarModulus : Nat :=
  21888242871839275222246405745257275088548364400416034343698204186575808495617

abbrev Scalar := Fin bn254ScalarModulus

structure Primitives where
  sha256 : List Byte → Digest256
  sha256Pair : Digest256 → Digest256 → Digest256
  nameHash : SetName → Scalar
  poseidon2 : List Scalar → Scalar

def scalarOfNat (n : Nat) : Scalar :=
  ⟨n % bn254ScalarModulus, Nat.mod_lt _ (by decide)⟩

def scalarOfAddress (address : Address) : Scalar := scalarOfNat address.val
def scalarOfSelector (selector : Selector) : Scalar := scalarOfNat selector.val
def scalarOfAmount (amount : Amount) : Scalar := scalarOfNat amount.val
def scalarOfBool (value : Bool) : Scalar := if value then scalarOfNat 1 else scalarOfNat 0

def txTypeTag : TxType → Scalar
  | .transfer => scalarOfNat 0
  | .contractCall => scalarOfNat 1

def destinationFields (primitives : Primitives) : DestinationPattern → Scalar × Scalar × Scalar
  | .any => (scalarOfNat 0, scalarOfNat 0, scalarOfNat 0)
  | .group name => (scalarOfNat 1, primitives.nameHash name, scalarOfNat 0)
  | .allowlist name => (scalarOfNat 2, primitives.nameHash name, scalarOfNat 0)
  | .exact address => (scalarOfNat 3, scalarOfNat 0, scalarOfAddress address)

def signerFields (primitives : Primitives) : SignerPattern → Scalar × Scalar × Scalar × Scalar
  | .any => (scalarOfNat 0, scalarOfNat 0, scalarOfNat 0, scalarOfNat 0)
  | .exact address =>
      (scalarOfNat 1, scalarOfAddress address, scalarOfNat 0, scalarOfNat 0)
  | .group name =>
      (scalarOfNat 2, scalarOfNat 0, primitives.nameHash name, scalarOfNat 0)
  | .threshold group required =>
      (scalarOfNat 3, scalarOfNat 0, primitives.nameHash group, scalarOfNat required)

def assetFields : AssetPattern → Scalar × Scalar
  | .any => (scalarOfNat 0, scalarOfNat 0)
  | .exact address => (scalarOfNat 1, scalarOfAddress address)

/- Exact 14-field preimage used by the optimized Noir circuit. `Rule.id` is
intentionally absent because the current Noir circuit does not commit to it.
-/
def v2PolicyPreimage (primitives : Primitives) (rule : Rule) : List Scalar :=
  let (destinationTag, destinationName, destinationAddress) :=
    destinationFields primitives rule.destination
  let (signerTag, signerAddress, signerGroup, threshold) :=
    signerFields primitives rule.signer
  let (assetTag, assetAddress) := assetFields rule.asset
  let (hasAmount, amount) :=
    match rule.amountMax with
    | none => (false, scalarOfNat 0)
    | some maximum => (true, scalarOfAmount maximum)
  let (hasSelector, selector) :=
    match rule.functionSelector with
    | none => (false, scalarOfNat 0)
    | some value => (true, scalarOfSelector value)
  [ txTypeTag rule.txType,
    destinationTag, destinationName, destinationAddress,
    signerTag, signerAddress, signerGroup, threshold,
    assetTag, assetAddress,
    scalarOfBool hasAmount, amount,
    scalarOfBool hasSelector, selector ]

def v2PolicyCommitment (primitives : Primitives) (rule : Rule) : Scalar :=
  primitives.poseidon2 (v2PolicyPreimage primitives rule)

def bytes32 (value : Nat) : List Byte := natToBytesBE 32 value
def bytes20 (value : Nat) : List Byte := natToBytesBE 20 value
def bytes4 (value : Nat) : List Byte := natToBytesBE 4 value
def byte1 (value : Nat) : List Byte := natToBytesBE 1 value

/- Exact 291-byte canonical leaf encoding used by Noir V1. Like V2, V1 did
not include `Rule.id` in its leaf serialization.
-/
def v1PolicyLeafBytes (primitives : Primitives) (rule : Rule) : List Byte :=
  let (destinationTag, destinationName, destinationAddress) :=
    destinationFields primitives rule.destination
  let (signerTag, signerAddress, signerGroup, threshold) :=
    signerFields primitives rule.signer
  let (assetTag, assetAddress) := assetFields rule.asset
  let (hasAmount, amount) :=
    match rule.amountMax with
    | none => (false, scalarOfNat 0)
    | some maximum => (true, scalarOfAmount maximum)
  let (hasSelector, selector) :=
    match rule.functionSelector with
    | none => (false, scalarOfNat 0)
    | some value => (true, scalarOfSelector value)
  bytes32 (txTypeTag rule.txType).val ++
  bytes32 destinationTag.val ++ bytes32 destinationName.val ++ bytes20 destinationAddress.val ++
  bytes32 signerTag.val ++ bytes20 signerAddress.val ++ bytes32 signerGroup.val ++ byte1 threshold.val ++
  bytes32 assetTag.val ++ bytes20 assetAddress.val ++
  byte1 (if hasAmount then 1 else 0) ++ bytes32 amount.val ++
  byte1 (if hasSelector then 1 else 0) ++ bytes4 selector.val

structure MerklePath where
  leafIndex : Nat
  siblings : List Digest256
  deriving Repr, DecidableEq

def merkleRootFromPath
    (primitives : Primitives) (leaf : Digest256) (path : MerklePath) : Digest256 :=
  (path.siblings.foldl
    (fun (state : Digest256 × Nat) sibling =>
      let (current, index) := state
      let parent :=
        if index % 2 == 0 then
          primitives.sha256Pair current sibling
        else
          primitives.sha256Pair sibling current
      (parent, index / 2))
    (leaf, path.leafIndex)).1

def v1Authenticates
    (primitives : Primitives) (root : Digest256) (rule : Rule) (path : MerklePath) : Bool :=
  decide (path.leafIndex < 2 ^ path.siblings.length) &&
  merkleRootFromPath primitives (primitives.sha256 (v1PolicyLeafBytes primitives rule)) path == root

def v2Authenticates
    (primitives : Primitives) (claimedPolicyHash : Scalar) (rule : Rule) : Bool :=
  v2PolicyCommitment primitives rule == claimedPolicyHash

def collisionFreeNameHashes (primitives : Primitives) : List SetName → Bool
  | [] => true
  | name :: rest =>
      rest.all (fun other => name == other || !(primitives.nameHash name == primitives.nameHash other)) &&
      collisionFreeNameHashes primitives rest

def destinationGroupNames : DestinationPattern → List SetName
  | .group name => [name]
  | _ => []

def destinationAllowlistNames : DestinationPattern → List SetName
  | .allowlist name => [name]
  | _ => []

def signerGroupNames : SignerPattern → List SetName
  | .group name => [name]
  | .threshold name _ => [name]
  | _ => []

/- Noir currently has no nonce input, so its profile only represents the
canonical zero-nonce subset. Values parsed as fields must fit BN254 exactly.
-/
def compatible (primitives : Primitives) (rule : Rule) (context : Context) (action : Action)
    (authentication : Authentication) : Bool :=
  let groupEntries := context.groups.foldl (fun total entry => total + entry.2.length) 0
  let allowlistEntries := context.allowlists.foldl (fun total entry => total + entry.2.length) 0
  let thresholdFits :=
    match rule.signer with
    | .threshold _ required => required < 256
    | _ => true
  let erc20AmountFits :=
    match parseErc20Transfer action.data with
    | some (_, amount) => amount.val < bn254ScalarModulus
    | none => true
  let groupNames :=
    context.groups.map Prod.fst ++ destinationGroupNames rule.destination ++
      signerGroupNames rule.signer
  let allowlistNames :=
    context.allowlists.map Prod.fst ++ destinationAllowlistNames rule.destination
  action.data.length <= 256 &&
  authentication.slots.length <= 5 &&
  rule.wellFormed &&
  context.wellFormed &&
  groupEntries <= 5 && allowlistEntries <= 5 &&
  rule.id < 2 ^ 32 && thresholdFits &&
  action.value.val < bn254ScalarModulus && erc20AmountFits &&
  action.nonce.val == 0 &&
  collisionFreeNameHashes primitives groupNames &&
  collisionFreeNameHashes primitives allowlistNames &&
  (match rule.amountMax with
   | none => true
   | some maximum => maximum.val < bn254ScalarModulus)

theorem v2_authenticates_committed_rule (primitives : Primitives) (rule : Rule) :
    v2Authenticates primitives (v2PolicyCommitment primitives rule) rule = true := by
  simp [v2Authenticates]

theorem v2_commitment_does_not_bind_rule_id
    (primitives : Primitives) (rule : Rule) (replacementId : RuleId) :
    v2PolicyCommitment primitives { rule with id := replacementId } =
      v2PolicyCommitment primitives rule := by
  simp [v2PolicyCommitment, v2PolicyPreimage]

theorem v2_preimage_has_fixed_arity (primitives : Primitives) (rule : Rule) :
    (v2PolicyPreimage primitives rule).length = 14 := by
  simp [v2PolicyPreimage]

theorem v1_leaf_has_fixed_width (primitives : Primitives) (rule : Rule) :
    (v1PolicyLeafBytes primitives rule).length = 291 := by
  simp [v1PolicyLeafBytes, bytes32, bytes20, bytes4, byte1, natToBytesBE]

end ZkGuard.Profiles.Noir
