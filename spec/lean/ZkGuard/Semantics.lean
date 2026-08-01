import ZkGuard.Types

/-!
# ZKGuard policy specification: executable semantics

This module is the proving-system-independent policy compliance algorithm.
Malformed policies and malformed actions fail closed.
-/

namespace ZkGuard

def natToBytesBE (width n : Nat) : List Byte :=
  (List.range width).map fun i =>
    ⟨(n / (256 ^ (width - 1 - i))) % 256, Nat.mod_lt _ (by decide)⟩

def bytesToNatBE (bytes : List Byte) : Nat :=
  bytes.foldl (fun acc byte => acc * 256 + byte.val) 0

def addressOfBytes (bytes : List Byte) : Address :=
  ⟨bytesToNatBE bytes % (2 ^ 160), Nat.mod_lt _ (by decide)⟩

def selectorOfBytes (bytes : List Byte) : Selector :=
  ⟨bytesToNatBE bytes % (2 ^ 32), Nat.mod_lt _ (by decide)⟩

def amountOfBytes (bytes : List Byte) : Amount :=
  ⟨bytesToNatBE bytes % (2 ^ 256), Nat.mod_lt _ (by decide)⟩

def transferSelector : Selector := ⟨0xa9059cbb, by decide⟩

def hasTransferSelector (data : List Byte) : Bool :=
  data.length >= 4 && selectorOfBytes (data.take 4) == transferSelector

def parseErc20Transfer (data : List Byte) : Option (Address × Amount) :=
  if data.length < 68 then
    none
  else
    some
      (addressOfBytes ((data.drop 16).take 20),
       amountOfBytes ((data.drop 36).take 32))

/- Classification is strict about native value combined with calldata. Such an
action is neither a plain native transfer nor an unambiguous zero-value call.
-/
def classify (action : Action) : Except ClassificationError ClassifiedAction :=
  if action.value.val > 0 then
    if action.data.isEmpty then
      .ok {
        txType := .transfer
        destination := action.to
        asset := zeroAddress
        amount := action.value
      }
    else
      .error .nativeValueWithCalldata
  else if hasTransferSelector action.data then
    match parseErc20Transfer action.data with
    | some (recipient, amount) =>
        .ok {
          txType := .transfer
          destination := recipient
          asset := action.to
          amount
        }
    | none => .error .malformedErc20Transfer
  else
    .ok {
      txType := .contractCall
      destination := action.to
      asset := zeroAddress
      amount := 0
    }

def AddressBook.lookup : AddressBook → SetName → Option (List Address)
  | [], _ => none
  | (entryName, members) :: rest, name =>
      if entryName == name then some members else lookup rest name

def AddressBook.member (book : AddressBook) (name : SetName) (address : Address) : Bool :=
  match book.lookup name with
  | none => false
  | some members => members.contains address

def uniqueSetNames : AddressBook → Bool
  | [] => true
  | (name, _) :: rest =>
      !(rest.any fun entry => entry.1 == name) && uniqueSetNames rest

def AddressBook.wellFormed (book : AddressBook) : Bool := uniqueSetNames book

def Context.wellFormed (context : Context) : Bool :=
  context.groups.wellFormed && context.allowlists.wellFormed

def destinationMatches
    (context : Context) (pattern : DestinationPattern) (address : Address) : Bool :=
  match pattern with
  | .any => true
  | .exact required => address == required
  | .group name => context.groups.member name address
  | .allowlist name => context.allowlists.member name address

def authenticatedSigners : List AuthSlot → List Address
  | [] => []
  | .invalid :: rest => authenticatedSigners rest
  | .valid signer :: rest => signer :: authenticatedSigners rest

def insertUnique (address : Address) : List Address → List Address
  | [] => [address]
  | head :: tail =>
      if address == head then head :: tail else head :: insertUnique address tail

def uniqueAddresses : List Address → List Address
  | [] => []
  | head :: tail => insertUnique head (uniqueAddresses tail)

def uniqueAuthenticatedGroupMembers
    (context : Context) (group : SetName) (authentication : Authentication) : List Address :=
  uniqueAddresses <|
    (authenticatedSigners authentication.slots).filter fun signer =>
      context.groups.member group signer

def signerPatternMatches
    (context : Context) (pattern : SignerPattern) (authentication : Authentication) : Bool :=
  match pattern with
  | .any => (authenticatedSigners authentication.slots).isEmpty == false
  | .exact required => decide (authentication.slots = [.valid required])
  | .group name =>
      match authentication.slots with
      | [.valid signer] => context.groups.member name signer
      | _ => false
  | .threshold group required =>
      (uniqueAuthenticatedGroupMembers context group authentication).length >= required

def signerMatches
    (context : Context) (action : Action) (pattern : SignerPattern)
    (authentication : Authentication) : Bool :=
  decide (authentication.action = action) &&
    signerPatternMatches context pattern authentication

def assetMatches (pattern : AssetPattern) (asset : Address) : Bool :=
  match pattern with
  | .any => true
  | .exact required => asset == required

def selectorMatches (expected : Option Selector) (data : List Byte) : Bool :=
  match expected with
  | none => true
  | some selector => data.length >= 4 && selectorOfBytes (data.take 4) == selector

def Rule.wellFormed (rule : Rule) : Bool :=
  let signerValid :=
    match rule.signer with
    | .threshold _ required => required > 0
    | _ => true
  let shapeValid :=
    match rule.txType with
    | .transfer => rule.functionSelector.isNone
    | .contractCall => rule.amountMax.isNone && rule.asset == .any
  signerValid && shapeValid

def Rule.complies
    (rule : Rule) (context : Context) (action : Action)
    (authentication : Authentication) : Bool :=
  if !rule.wellFormed || !context.wellFormed then
    false
  else
    match classify action with
    | .error _ => false
    | .ok classified =>
        let amountMatches :=
          match classified.txType, rule.amountMax with
          | .transfer, some maximum => classified.amount.val <= maximum.val
          | _, _ => true
        let functionMatches :=
          match classified.txType with
          | .contractCall => selectorMatches rule.functionSelector action.data
          | .transfer => true
        rule.txType == classified.txType &&
        destinationMatches context rule.destination classified.destination &&
        signerMatches context action rule.signer authentication &&
        assetMatches rule.asset classified.asset &&
        amountMatches &&
        functionMatches

def uniqueRuleIds : List Rule → Bool
  | [] => true
  | rule :: rest =>
      !(rest.any fun candidate => candidate.id == rule.id) && uniqueRuleIds rest

def Policy.wellFormed (policy : Policy) : Bool :=
  policy.rules.all Rule.wellFormed && uniqueRuleIds policy.rules

def evaluateRules
    (rules : List Rule) (context : Context) (action : Action)
    (authentication : Authentication) : Decision :=
  match rules with
  | [] => .deny
  | rule :: rest =>
      if rule.complies context action authentication then
        .allow rule.id
      else
        evaluateRules rest context action authentication

def evaluate
    (policy : Policy) (context : Context) (action : Action)
    (authentication : Authentication) : Decision :=
  if policy.wellFormed then
    evaluateRules policy.rules context action authentication
  else
    .deny

end ZkGuard
