import ZkGuard.Properties

/-!
# Executable examples spanning the base compliance algorithm
-/

namespace ZkGuard.Examples

open ZkGuard

def address (n : Nat) : Address := ⟨n % (2 ^ 160), Nat.mod_lt _ (by decide)⟩
def amount (n : Nat) : Amount := ⟨n % (2 ^ 256), Nat.mod_lt _ (by decide)⟩

def owner := address 0x100
def recipient := address 0x200
def token := address 0x300
def dex := address 0x400

def context : Context := {
  groups := [("Owners", [owner]), ("Recipients", [recipient])]
  allowlists := [("Dexes", [dex])]
}

def baseAction : Action := {
  initiator := address 0x500
  to := token
  value := 0
  nonce := 0
  data := []
}

def transferData (to : Address) (value : Amount) : List Byte :=
  natToBytesBE 4 transferSelector.val ++
  natToBytesBE 32 to.val ++
  natToBytesBE 32 value.val

def transferRule : Rule := {
  id := 1
  txType := .transfer
  destination := .group "Recipients"
  signer := .exact owner
  asset := .exact token
  amountMax := some (amount 100)
  functionSelector := none
}

def authFor (action : Action) (slots : List AuthSlot) : Authentication :=
  .forAction action slots

example :
    let action := { baseAction with data := transferData recipient (amount 100) }
    transferRule.complies context action (authFor action [.valid owner]) = true := by native_decide

example :
    let action := { baseAction with data := transferData recipient (amount 101) }
    transferRule.complies context action (authFor action [.valid owner]) = false := by native_decide

example :
    let action := { baseAction with data := transferData recipient (amount 100) }
    transferRule.complies context action (authFor action [.invalid]) = false := by native_decide

def callRule : Rule := {
  id := 2
  txType := .contractCall
  destination := .allowlist "Dexes"
  signer := .threshold "Owners" 1
  asset := .any
  amountMax := none
  functionSelector := some ⟨0x12345678, by decide⟩
}

example :
    let action := { baseAction with to := dex, data := natToBytesBE 4 0x12345678 }
    callRule.complies context action (authFor action [.valid owner, .valid owner]) = true := by
  native_decide

example :
    signerMatches context baseAction (.threshold "Owners" 2)
      (authFor baseAction [.valid owner, .valid owner]) = false := by
  native_decide

example :
    let action := { baseAction with to := dex, data := natToBytesBE 4 0x87654321 }
    callRule.complies context action (authFor action [.valid owner]) = false := by native_decide

example : signerMatches context baseAction .any (authFor baseAction [.valid owner]) = true := by
  native_decide
example : signerMatches context baseAction (.group "Owners")
    (authFor baseAction [.valid owner]) = true := by native_decide
example : destinationMatches context (.exact dex) dex = true := by native_decide
example : destinationMatches context (.group "Recipients") recipient = true := by native_decide
example : destinationMatches context (.allowlist "Missing") dex = false := by native_decide
example : assetMatches .any token = true := by native_decide
example : context.wellFormed = true := by native_decide

example :
    let ambiguous : Context := {
      groups := [("Owners", [owner]), ("Owners", [recipient])]
      allowlists := []
    }
    transferRule.complies ambiguous baseAction (authFor baseAction [.valid owner]) = false := by
  native_decide

example :
    let action := { baseAction with data := transferData recipient (amount 100) }
    evaluate ⟨[transferRule]⟩ context action (authFor action [.valid owner]) =
      .allow transferRule.id := by native_decide

example :
    let action := { baseAction with data := transferData recipient (amount 101) }
    evaluate ⟨[transferRule]⟩ context action (authFor action [.valid owner]) = .deny := by
  native_decide

example :
    classify { baseAction with to := recipient, value := amount 7, data := [] } =
      .ok { txType := .transfer, destination := recipient, asset := zeroAddress, amount := amount 7 } := by
  rfl

example :
    classify { baseAction with value := amount 7, data := [0] } =
      .error .nativeValueWithCalldata := by
  rfl

end ZkGuard.Examples
