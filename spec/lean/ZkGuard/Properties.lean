import ZkGuard.Semantics

/-!
# ZKGuard policy specification: security properties
-/

namespace ZkGuard

theorem empty_policy_denies
    (context : Context) (action : Action) (authentication : Authentication) :
    evaluate ⟨[]⟩ context action authentication = .deny := by
  rfl

theorem malformed_policy_denies
    (policy : Policy) (context : Context) (action : Action)
    (authentication : Authentication) (h : policy.wellFormed = false) :
    evaluate policy context action authentication = .deny := by
  simp [evaluate, h]

theorem malformed_context_rejects_rule
    (rule : Rule) (context : Context) (action : Action)
    (authentication : Authentication) (h : context.wellFormed = false) :
    rule.complies context action authentication = false := by
  simp [Rule.complies, h]

theorem evaluateRules_allows_only_compliant_rule
    (rules : List Rule) (context : Context) (action : Action)
    (authentication : Authentication) (ruleId : RuleId)
    (h : evaluateRules rules context action authentication = .allow ruleId) :
    ∃ rule ∈ rules, rule.id = ruleId ∧ rule.complies context action authentication = true := by
  induction rules with
  | nil => simp [evaluateRules] at h
  | cons rule rest ih =>
      by_cases hc : rule.complies context action authentication = true
      · simp [evaluateRules, hc] at h
        subst ruleId
        exact ⟨rule, by simp, rfl, hc⟩
      · have hc' : rule.complies context action authentication = false := by
          cases hv : rule.complies context action authentication <;> simp_all
        simp [evaluateRules, hc'] at h
        obtain ⟨found, hmem, hid, hcomplies⟩ := ih h
        exact ⟨found, by simp [hmem], hid, hcomplies⟩

theorem allow_implies_policy_member_complies
    (policy : Policy) (context : Context) (action : Action)
    (authentication : Authentication) (ruleId : RuleId)
    (h : evaluate policy context action authentication = .allow ruleId) :
    ∃ rule ∈ policy.rules,
      rule.id = ruleId ∧ rule.complies context action authentication = true := by
  unfold evaluate at h
  split at h
  · exact evaluateRules_allows_only_compliant_rule _ _ _ _ _ h
  · simp at h

theorem duplicate_authenticated_signer_is_counted_once (signer : Address) :
    uniqueAddresses [signer, signer] = [signer] := by
  simp [uniqueAddresses, insertUnique]

theorem zero_threshold_rule_is_not_well_formed
    (id : RuleId) (txType : TxType) (destination : DestinationPattern)
    (group : SetName) (asset : AssetPattern) (amountMax : Option Amount)
    (selector : Option Selector) :
    (Rule.mk id txType destination (.threshold group 0) asset amountMax selector).wellFormed = false := by
  simp [Rule.wellFormed]

theorem exact_signer_requires_one_authenticated_slot
    (context : Context) (action : Action) (required other : Address) (h : other ≠ required) :
    signerMatches context action (.exact required)
      (.forAction action [.valid other]) = false := by
  simp [signerMatches, signerPatternMatches, Authentication.forAction, h]

theorem invalid_signature_does_not_satisfy_any_signer (context : Context) (action : Action) :
    signerMatches context action .any (.forAction action [.invalid]) = false := by
  simp [signerMatches, signerPatternMatches, Authentication.forAction, authenticatedSigners]

theorem authentication_is_bound_to_action
    (context : Context) (action otherAction : Action) (pattern : SignerPattern)
    (slots : List AuthSlot) (h : otherAction ≠ action) :
    signerMatches context action pattern (.forAction otherAction slots) = false := by
  simp [signerMatches, Authentication.forAction, h]

end ZkGuard
