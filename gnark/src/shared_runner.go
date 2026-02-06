package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/consensys/gnark/frontend"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

type sharedPolicyLine struct {
	ID               int             `json:"id"`
	TxType           string          `json:"tx_type"`
	Destination      json.RawMessage `json:"destination"`
	Signer           json.RawMessage `json:"signer"`
	Asset            json.RawMessage `json:"asset"`
	AmountMax        json.RawMessage `json:"amount_max"`
	FunctionSelector *string         `json:"function_selector"`
}

type sharedScenario struct {
	RuleID      int             `json:"rule_id"`
	From        string          `json:"from"`
	To          string          `json:"to"`
	Value       json.RawMessage `json:"value"`
	Nonce       uint64          `json:"nonce"`
	Data        string          `json:"data"`
	PrivateKeys []string        `json:"private_keys"`
}

type sharedExecutionContext struct {
	policyLines     []PolicyLine
	policyIndexByID map[int]int
	groups          [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	groupSizes      [MAX_GROUPS]frontend.Variable
	groupHash       [32]byte
	allowLists      [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	allowSizes      [MAX_ALLOWLISTS]frontend.Variable
	allowHash       [32]byte
}

var preferredScenarioOrder = []string{
	"contributor_payments",
	"defi_swaps",
	"supply_lending",
	"interact_dapps",
	"amount_limits",
	"function_level_controls",
	"advanced_signer_policies",
}

func runSharedScenarioCLI(
	selected string,
	prove bool,
	policyPath string,
	groupsPath string,
	allowlistsPath string,
	scenariosPath string,
) error {
	ctx, err := loadSharedExecutionContext(policyPath, groupsPath, allowlistsPath)
	if err != nil {
		return err
	}

	scenarios, err := loadSharedScenarios(scenariosPath)
	if err != nil {
		return err
	}

	if strings.EqualFold(selected, "all") {
		fmt.Println("--- Running all shared scenarios ---")
		for _, name := range orderedScenarioNames(scenarios) {
			scenario := scenarios[name]
			if err := runSharedScenario(name, scenario, ctx, prove); err != nil {
				return fmt.Errorf("scenario %q failed: %w", name, err)
			}
		}
		return nil
	}

	scenarioName, ok := resolveScenarioName(selected, scenarios)
	if !ok {
		return fmt.Errorf("unknown scenario %q (available: %s)", selected, strings.Join(orderedScenarioNames(scenarios), ", "))
	}

	return runSharedScenario(scenarioName, scenarios[scenarioName], ctx, prove)
}

func resolveScenarioName(selected string, scenarios map[string]sharedScenario) (string, bool) {
	if _, ok := scenarios[selected]; ok {
		return selected, true
	}

	for name := range scenarios {
		if strings.EqualFold(name, selected) {
			return name, true
		}
	}
	return "", false
}

func orderedScenarioNames(scenarios map[string]sharedScenario) []string {
	out := make([]string, 0, len(scenarios))
	seen := make(map[string]struct{}, len(scenarios))

	for _, name := range preferredScenarioOrder {
		if _, ok := scenarios[name]; ok {
			out = append(out, name)
			seen[name] = struct{}{}
		}
	}

	extra := make([]string, 0, len(scenarios)-len(out))
	for name := range scenarios {
		if _, ok := seen[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	out = append(out, extra...)
	return out
}

func runSharedScenario(
	name string,
	scenario sharedScenario,
	ctx *sharedExecutionContext,
	prove bool,
) error {
	policyIndex, ok := ctx.policyIndexByID[scenario.RuleID]
	if !ok {
		return fmt.Errorf("rule id %d referenced by scenario not found in policy", scenario.RuleID)
	}

	from, err := parseHexAddressBig(scenario.From)
	if err != nil {
		return fmt.Errorf("invalid from address: %w", err)
	}
	to, err := parseHexAddressBig(scenario.To)
	if err != nil {
		return fmt.Errorf("invalid to address: %w", err)
	}
	value, err := parseBigIntFromJSON(scenario.Value)
	if err != nil {
		return fmt.Errorf("invalid value: %w", err)
	}
	calldata, err := parseHexBytes(scenario.Data)
	if err != nil {
		return fmt.Errorf("invalid calldata hex: %w", err)
	}
	if len(calldata) > MAX_DATA_BYTES {
		return fmt.Errorf("calldata too long: got %d bytes, max %d", len(calldata), MAX_DATA_BYTES)
	}

	if len(scenario.PrivateKeys) == 0 {
		return fmt.Errorf("scenario must include at least one private key")
	}
	if len(scenario.PrivateKeys) > MAX_SIGNATURES {
		return fmt.Errorf("scenario has %d private keys, but MAX_SIGNATURES=%d", len(scenario.PrivateKeys), MAX_SIGNATURES)
	}

	signers := make([]*ecdsa.PrivateKey, 0, len(scenario.PrivateKeys))
	for i, keyHex := range scenario.PrivateKeys {
		normalized := strings.TrimSpace(keyHex)
		normalized = strings.TrimPrefix(normalized, "0x")
		normalized = strings.TrimPrefix(normalized, "0X")
		sk, err := eth_crypto.HexToECDSA(normalized)
		if err != nil {
			return fmt.Errorf("invalid private_keys[%d]: %w", i, err)
		}
		signers = append(signers, sk)
	}

	fmt.Printf("\n▶ Running Example: %s\n", name)
	assignment := buildWitness(
		ctx.policyLines,
		policyIndex,
		from,
		to,
		value,
		calldata,
		signers,
		ctx.groups,
		ctx.groupSizes,
		ctx.groupHash,
		ctx.allowLists,
		ctx.allowSizes,
		ctx.allowHash,
	)
	execute(assignment, prove)
	return nil
}

func loadSharedExecutionContext(policyPath, groupsPath, allowlistsPath string) (*sharedExecutionContext, error) {
	rawGroups, err := loadNamedAddressBook(groupsPath)
	if err != nil {
		return nil, err
	}
	rawAllowlists, err := loadNamedAddressBook(allowlistsPath)
	if err != nil {
		return nil, err
	}

	groupNameToIndex, groupSetSizes, groupSizesFrontend, groupAddressSet, groupsFrontend, err := buildGroupInputs(rawGroups)
	if err != nil {
		return nil, err
	}
	allowNameToIndex, allowSetSizes, allowSizesFrontend, allowAddressSet, allowFrontend, err := buildAllowlistInputs(rawAllowlists)
	if err != nil {
		return nil, err
	}

	rawPolicy, err := loadSharedPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	policyLines, indexByID, err := convertPolicyLines(rawPolicy, groupNameToIndex, allowNameToIndex)
	if err != nil {
		return nil, err
	}

	return &sharedExecutionContext{
		policyLines:     policyLines,
		policyIndexByID: indexByID,
		groups:          groupsFrontend,
		groupSizes:      groupSizesFrontend,
		groupHash:       AddressSetHash(groupSetSizes, groupAddressSet),
		allowLists:      allowFrontend,
		allowSizes:      allowSizesFrontend,
		allowHash:       AddressSetHash(allowSetSizes, allowAddressSet),
	}, nil
}

func loadSharedPolicy(path string) ([]sharedPolicyLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy file %q: %w", path, err)
	}
	defer f.Close()

	var lines []sharedPolicyLine
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	if err := decoder.Decode(&lines); err != nil {
		return nil, fmt.Errorf("failed to parse policy file %q: %w", path, err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("policy file %q has no rules", path)
	}
	return lines, nil
}

func loadSharedScenarios(path string) (map[string]sharedScenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open scenarios file %q: %w", path, err)
	}
	defer f.Close()

	var scenarios map[string]sharedScenario
	decoder := json.NewDecoder(f)
	decoder.UseNumber()
	if err := decoder.Decode(&scenarios); err != nil {
		return nil, fmt.Errorf("failed to parse scenarios file %q: %w", path, err)
	}
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("scenarios file %q has no entries", path)
	}
	return scenarios, nil
}

func loadNamedAddressBook(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open address book %q: %w", path, err)
	}
	defer f.Close()

	var book map[string][]string
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&book); err != nil {
		return nil, fmt.Errorf("failed to parse address book %q: %w", path, err)
	}
	if len(book) == 0 {
		return nil, fmt.Errorf("address book %q is empty", path)
	}
	return book, nil
}

func buildGroupInputs(groups map[string][]string) (
	map[string]int,
	[MAX_GROUPS]byte,
	[MAX_GROUPS]frontend.Variable,
	[MAX_GROUPS][MAX_ADDRS_PER_SET]big.Int,
	[MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable,
	error,
) {
	var (
		nameToIndex map[string]int = make(map[string]int, len(groups))
		sizesBytes  [MAX_GROUPS]byte
		sizesFront  [MAX_GROUPS]frontend.Variable
		addressBI   [MAX_GROUPS][MAX_ADDRS_PER_SET]big.Int
		addressFV   [MAX_GROUPS][MAX_ADDRS_PER_SET]frontend.Variable
	)

	for i := 0; i < MAX_GROUPS; i++ {
		sizesFront[i] = 0
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			addressBI[i][j].SetInt64(0)
			addressFV[i][j] = 0
		}
	}

	groupNames := make([]string, 0, len(groups))
	for name := range groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)

	if len(groupNames) > MAX_GROUPS {
		return nil, sizesBytes, sizesFront, addressBI, addressFV,
			fmt.Errorf("groups file contains %d groups but MAX_GROUPS=%d", len(groupNames), MAX_GROUPS)
	}

	for i, name := range groupNames {
		addrs := groups[name]
		if len(addrs) > MAX_ADDRS_PER_SET {
			return nil, sizesBytes, sizesFront, addressBI, addressFV,
				fmt.Errorf("group %q has %d addresses but MAX_ADDRS_PER_SET=%d", name, len(addrs), MAX_ADDRS_PER_SET)
		}
		nameToIndex[name] = i
		sizesBytes[i] = byte(len(addrs))
		sizesFront[i] = len(addrs)

		for j, addrHex := range addrs {
			addrBig, err := parseHexAddressBig(addrHex)
			if err != nil {
				return nil, sizesBytes, sizesFront, addressBI, addressFV,
					fmt.Errorf("invalid address in group %q at index %d: %w", name, j, err)
			}
			addressBI[i][j].Set(addrBig)
			addressFV[i][j] = new(big.Int).Set(addrBig)
		}
	}

	return nameToIndex, sizesBytes, sizesFront, addressBI, addressFV, nil
}

func buildAllowlistInputs(allowlists map[string][]string) (
	map[string]int,
	[MAX_ALLOWLISTS]byte,
	[MAX_ALLOWLISTS]frontend.Variable,
	[MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]big.Int,
	[MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable,
	error,
) {
	var (
		nameToIndex map[string]int = make(map[string]int, len(allowlists))
		sizesBytes  [MAX_ALLOWLISTS]byte
		sizesFront  [MAX_ALLOWLISTS]frontend.Variable
		addressBI   [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]big.Int
		addressFV   [MAX_ALLOWLISTS][MAX_ADDRS_PER_SET]frontend.Variable
	)

	for i := 0; i < MAX_ALLOWLISTS; i++ {
		sizesFront[i] = 0
		for j := 0; j < MAX_ADDRS_PER_SET; j++ {
			addressBI[i][j].SetInt64(0)
			addressFV[i][j] = 0
		}
	}

	allowlistNames := make([]string, 0, len(allowlists))
	for name := range allowlists {
		allowlistNames = append(allowlistNames, name)
	}
	sort.Strings(allowlistNames)

	if len(allowlistNames) > MAX_ALLOWLISTS {
		return nil, sizesBytes, sizesFront, addressBI, addressFV,
			fmt.Errorf("allowlists file contains %d lists but MAX_ALLOWLISTS=%d", len(allowlistNames), MAX_ALLOWLISTS)
	}

	for i, name := range allowlistNames {
		addrs := allowlists[name]
		if len(addrs) > MAX_ADDRS_PER_SET {
			return nil, sizesBytes, sizesFront, addressBI, addressFV,
				fmt.Errorf("allowlist %q has %d addresses but MAX_ADDRS_PER_SET=%d", name, len(addrs), MAX_ADDRS_PER_SET)
		}
		nameToIndex[name] = i
		sizesBytes[i] = byte(len(addrs))
		sizesFront[i] = len(addrs)

		for j, addrHex := range addrs {
			addrBig, err := parseHexAddressBig(addrHex)
			if err != nil {
				return nil, sizesBytes, sizesFront, addressBI, addressFV,
					fmt.Errorf("invalid address in allowlist %q at index %d: %w", name, j, err)
			}
			addressBI[i][j].Set(addrBig)
			addressFV[i][j] = new(big.Int).Set(addrBig)
		}
	}

	return nameToIndex, sizesBytes, sizesFront, addressBI, addressFV, nil
}

func convertPolicyLines(
	rawPolicy []sharedPolicyLine,
	groupNameToIndex map[string]int,
	allowlistNameToIndex map[string]int,
) ([]PolicyLine, map[int]int, error) {
	sort.Slice(rawPolicy, func(i, j int) bool {
		return rawPolicy[i].ID < rawPolicy[j].ID
	})

	policyLines := make([]PolicyLine, 0, len(rawPolicy))
	policyIndexByID := make(map[int]int, len(rawPolicy))

	for idx, raw := range rawPolicy {
		if _, exists := policyIndexByID[raw.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate policy id %d", raw.ID)
		}

		txType, err := parseTxType(raw.TxType)
		if err != nil {
			return nil, nil, fmt.Errorf("policy id %d: %w", raw.ID, err)
		}

		destinationTag, destinationIdx, destinationAddr, err := parseDestination(
			raw.Destination,
			groupNameToIndex,
			allowlistNameToIndex,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("policy id %d destination: %w", raw.ID, err)
		}

		signerTag, signerAddr, signerGroupIdx, threshold, err := parseSigner(raw.Signer, groupNameToIndex)
		if err != nil {
			return nil, nil, fmt.Errorf("policy id %d signer: %w", raw.ID, err)
		}

		assetTag, assetAddr, err := parseAsset(raw.Asset)
		if err != nil {
			return nil, nil, fmt.Errorf("policy id %d asset: %w", raw.ID, err)
		}

		amountMax, err := parseAmountMax(raw.AmountMax)
		if err != nil {
			return nil, nil, fmt.Errorf("policy id %d amount_max: %w", raw.ID, err)
		}

		selector, err := parseFunctionSelector(raw.FunctionSelector)
		if err != nil {
			return nil, nil, fmt.Errorf("policy id %d function_selector: %w", raw.ID, err)
		}

		policyLines = append(policyLines, PolicyLine{
			ID:               raw.ID,
			TxType:           txType,
			DestinationTag:   destinationTag,
			DestinationIdx:   destinationIdx,
			DestinationAddr:  destinationAddr,
			SignerTag:        signerTag,
			SignerAddr:       signerAddr,
			SignerGroupIdx:   signerGroupIdx,
			AssetTag:         assetTag,
			AssetAddr:        assetAddr,
			AmountMax:        amountMax,
			FunctionSelector: selector,
			Action:           ACT_ALLOW,
			Threshold:        threshold,
		})
		policyIndexByID[raw.ID] = idx
	}

	return policyLines, policyIndexByID, nil
}

func parseTxType(txType string) (int, error) {
	switch txType {
	case "Transfer":
		return TT_TRANSFER, nil
	case "ContractCall":
		return TT_CONTRACTCALL, nil
	default:
		return 0, fmt.Errorf("unsupported tx_type %q", txType)
	}
}

func parseDestination(
	raw json.RawMessage,
	groupNameToIndex map[string]int,
	allowlistNameToIndex map[string]int,
) (tag int, idx int, addr *big.Int, err error) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if asString != "Any" {
			return 0, 0, nil, fmt.Errorf("unsupported string destination pattern %q", asString)
		}
		return DP_ANY, 0, nil, nil
	}

	key, value, err := decodeSingleKeyObject(raw)
	if err != nil {
		return 0, 0, nil, err
	}

	switch key {
	case "Exact":
		var exact string
		if err := json.Unmarshal(value, &exact); err != nil {
			return 0, 0, nil, fmt.Errorf("invalid Exact destination payload: %w", err)
		}
		addr, err := parseHexAddressBig(exact)
		if err != nil {
			return 0, 0, nil, err
		}
		return DP_EXACT, 0, addr, nil
	case "Group":
		var group string
		if err := json.Unmarshal(value, &group); err != nil {
			return 0, 0, nil, fmt.Errorf("invalid Group destination payload: %w", err)
		}
		i, ok := groupNameToIndex[group]
		if !ok {
			return 0, 0, nil, fmt.Errorf("group %q not found in groups file", group)
		}
		return DP_GROUP, i, nil, nil
	case "Allowlist":
		var allowlist string
		if err := json.Unmarshal(value, &allowlist); err != nil {
			return 0, 0, nil, fmt.Errorf("invalid Allowlist destination payload: %w", err)
		}
		i, ok := allowlistNameToIndex[allowlist]
		if !ok {
			return 0, 0, nil, fmt.Errorf("allowlist %q not found in allowlists file", allowlist)
		}
		return DP_ALLOWLIST, i, nil, nil
	default:
		return 0, 0, nil, fmt.Errorf("unsupported destination pattern key %q", key)
	}
}

func parseSigner(raw json.RawMessage, groupNameToIndex map[string]int) (
	tag int,
	addr *big.Int,
	groupIdx int,
	threshold int,
	err error,
) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if asString != "Any" {
			return 0, nil, 0, 0, fmt.Errorf("unsupported string signer pattern %q", asString)
		}
		return SP_ANY, nil, 0, 0, nil
	}

	key, value, err := decodeSingleKeyObject(raw)
	if err != nil {
		return 0, nil, 0, 0, err
	}

	switch key {
	case "Exact":
		var exact string
		if err := json.Unmarshal(value, &exact); err != nil {
			return 0, nil, 0, 0, fmt.Errorf("invalid Exact signer payload: %w", err)
		}
		addr, err := parseHexAddressBig(exact)
		if err != nil {
			return 0, nil, 0, 0, err
		}
		return SP_EXACT, addr, 0, 0, nil
	case "Group":
		var group string
		if err := json.Unmarshal(value, &group); err != nil {
			return 0, nil, 0, 0, fmt.Errorf("invalid Group signer payload: %w", err)
		}
		i, ok := groupNameToIndex[group]
		if !ok {
			return 0, nil, 0, 0, fmt.Errorf("group %q not found in groups file", group)
		}
		return SP_GROUP, nil, i, 0, nil
	case "Threshold":
		var thresholdDef struct {
			Group     string `json:"group"`
			Threshold int    `json:"threshold"`
		}
		if err := json.Unmarshal(value, &thresholdDef); err != nil {
			return 0, nil, 0, 0, fmt.Errorf("invalid Threshold signer payload: %w", err)
		}
		i, ok := groupNameToIndex[thresholdDef.Group]
		if !ok {
			return 0, nil, 0, 0, fmt.Errorf("group %q not found in groups file", thresholdDef.Group)
		}
		if thresholdDef.Threshold <= 0 {
			return 0, nil, 0, 0, fmt.Errorf("threshold must be >= 1")
		}
		return SP_THRESHOLD, nil, i, thresholdDef.Threshold, nil
	default:
		return 0, nil, 0, 0, fmt.Errorf("unsupported signer pattern key %q", key)
	}
}

func parseAsset(raw json.RawMessage) (tag int, addr *big.Int, err error) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if asString != "Any" {
			return 0, nil, fmt.Errorf("unsupported string asset pattern %q", asString)
		}
		return AP_ANY, nil, nil
	}

	key, value, err := decodeSingleKeyObject(raw)
	if err != nil {
		return 0, nil, err
	}
	if key != "Exact" {
		return 0, nil, fmt.Errorf("unsupported asset pattern key %q", key)
	}

	var exact string
	if err := json.Unmarshal(value, &exact); err != nil {
		return 0, nil, fmt.Errorf("invalid Exact asset payload: %w", err)
	}
	addr, err = parseHexAddressBig(exact)
	if err != nil {
		return 0, nil, err
	}
	return AP_EXACT, addr, nil
}

func parseAmountMax(raw json.RawMessage) (*big.Int, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	return parseBigIntFromJSON(raw)
}

func parseFunctionSelector(selectorHex *string) ([]byte, error) {
	if selectorHex == nil {
		return nil, nil
	}
	selectorBytes, err := parseHexBytes(*selectorHex)
	if err != nil {
		return nil, err
	}
	if len(selectorBytes) != 4 {
		return nil, fmt.Errorf("function selector must be 4 bytes, got %d", len(selectorBytes))
	}
	return selectorBytes, nil
}

func decodeSingleKeyObject(raw json.RawMessage) (string, json.RawMessage, error) {
	var asObj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObj); err != nil {
		return "", nil, fmt.Errorf("pattern must be a string or single-key object: %w", err)
	}
	if len(asObj) != 1 {
		return "", nil, fmt.Errorf("pattern object must have exactly one key, got %d", len(asObj))
	}

	for key, value := range asObj {
		return key, value, nil
	}
	return "", nil, fmt.Errorf("empty pattern object")
}

func parseBigIntFromJSON(raw json.RawMessage) (*big.Int, error) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return parseBigIntString(asString)
	}

	var asNumber json.Number
	if err := json.Unmarshal(raw, &asNumber); err == nil {
		return parseBigIntString(asNumber.String())
	}

	return nil, fmt.Errorf("expected numeric string or number, got %s", strings.TrimSpace(string(raw)))
}

func parseBigIntString(v string) (*big.Int, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return nil, fmt.Errorf("empty numeric value")
	}

	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}

	out, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("invalid numeric value %q", v)
	}
	if out.Sign() < 0 {
		return nil, fmt.Errorf("negative values are not supported: %q", v)
	}
	return out, nil
}

func parseHexBytes(input string) ([]byte, error) {
	normalized := strings.TrimSpace(input)
	normalized = strings.TrimPrefix(normalized, "0x")
	normalized = strings.TrimPrefix(normalized, "0X")
	if normalized == "" {
		return []byte{}, nil
	}
	if len(normalized)%2 == 1 {
		normalized = "0" + normalized
	}
	out, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid hex value %q: %w", input, err)
	}
	return out, nil
}

func parseHexAddressBig(input string) (*big.Int, error) {
	raw, err := parseHexBytes(input)
	if err != nil {
		return nil, err
	}
	if len(raw) != 20 {
		return nil, fmt.Errorf("expected 20-byte hex address, got %d bytes", len(raw))
	}
	return new(big.Int).SetBytes(raw), nil
}
