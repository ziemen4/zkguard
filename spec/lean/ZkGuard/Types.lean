/-!
# ZKGuard policy specification: domain types

These types are the semantic boundary of the policy engine. Cryptographic
authentication produces `AuthSlot.valid signer`; the policy evaluator never
trusts an unauthenticated address supplied by a prover.
-/

namespace ZkGuard

abbrev Byte := Fin 256
abbrev Address := Fin (2 ^ 160)
abbrev Selector := Fin (2 ^ 32)
abbrev Amount := Fin (2 ^ 256)
abbrev Nonce := Fin (2 ^ 64)
abbrev RuleId := Nat
abbrev SetName := String

def zeroAddress : Address := 0

inductive TxType where
  | transfer
  | contractCall
  deriving Repr, DecidableEq, BEq

inductive DestinationPattern where
  | any
  | exact (address : Address)
  | group (name : SetName)
  | allowlist (name : SetName)
  deriving Repr, DecidableEq, BEq

inductive SignerPattern where
  | any
  | exact (address : Address)
  | group (name : SetName)
  | threshold (group : SetName) (required : Nat)
  deriving Repr, DecidableEq, BEq

inductive AssetPattern where
  | any
  | exact (address : Address)
  deriving Repr, DecidableEq, BEq

structure Rule where
  id : RuleId
  txType : TxType
  destination : DestinationPattern
  signer : SignerPattern
  asset : AssetPattern
  amountMax : Option Amount
  functionSelector : Option Selector
  deriving Repr, DecidableEq, BEq

structure Action where
  initiator : Address
  to : Address
  value : Amount
  nonce : Nonce
  data : List Byte
  deriving Repr, DecidableEq, BEq

/- `invalid` means that a submitted signature did not authenticate. A valid
slot contains the address derived from a successfully verified public key.
Keeping slots, rather than only a set of addresses, preserves exact-one rules.
-/
inductive AuthSlot where
  | invalid
  | valid (signer : Address)
  deriving Repr, DecidableEq, BEq

structure Authentication where
  action : Action
  slots : List AuthSlot
  deriving Repr, DecidableEq, BEq

def Authentication.forAction (action : Action) (slots : List AuthSlot) : Authentication :=
  { action, slots }

abbrev AddressBook := List (SetName × List Address)

structure Context where
  groups : AddressBook
  allowlists : AddressBook
  deriving Repr, DecidableEq, BEq

structure ClassifiedAction where
  txType : TxType
  destination : Address
  asset : Address
  amount : Amount
  deriving Repr, DecidableEq, BEq

inductive ClassificationError where
  | nativeValueWithCalldata
  | malformedErc20Transfer
  deriving Repr, DecidableEq, BEq

inductive Decision where
  | allow (ruleId : RuleId)
  | deny
  deriving Repr, DecidableEq, BEq

structure Policy where
  rules : List Rule
  deriving Repr, DecidableEq, BEq

end ZkGuard
