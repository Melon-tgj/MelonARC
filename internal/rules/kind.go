package rules

import "strings"

// Kind identifies a rule type. The values are the canonical upper-case tokens
// used in configuration files.
type Kind string

// The twelve rule types of the MVP rule engine.
const (
	KindDomain        Kind = "DOMAIN"
	KindDomainSuffix  Kind = "DOMAIN-SUFFIX"
	KindDomainKeyword Kind = "DOMAIN-KEYWORD"
	KindDomainSet     Kind = "DOMAIN-SET"
	KindIPCIDR        Kind = "IP-CIDR"
	KindIPCIDR6       Kind = "IP-CIDR6"
	KindGeoIP         Kind = "GEOIP"
	KindIPASN         Kind = "IP-ASN"
	KindRuleSet       Kind = "RULE-SET"
	KindDestPort      Kind = "DEST-PORT"
	KindProtocol      Kind = "PROTOCOL"
	KindFinal         Kind = "FINAL"
)

// kinds lists every supported kind in declaration order.
var kinds = [...]Kind{
	KindDomain,
	KindDomainSuffix,
	KindDomainKeyword,
	KindDomainSet,
	KindIPCIDR,
	KindIPCIDR6,
	KindGeoIP,
	KindIPASN,
	KindRuleSet,
	KindDestPort,
	KindProtocol,
	KindFinal,
}

// Kinds returns every supported rule kind, in declaration order.
func Kinds() []Kind { return append([]Kind(nil), kinds[:]...) }

// ParseKind normalises a rule type token, which may arrive in any case.
func ParseKind(s string) (Kind, bool) {
	k := Kind(strings.ToUpper(strings.TrimSpace(s)))
	for _, known := range kinds {
		if k == known {
			return k, true
		}
	}
	return "", false
}

// Valid reports whether k is a supported rule kind.
func (k Kind) Valid() bool {
	_, ok := ParseKind(string(k))
	return ok
}

// MatchKind is the dimension of a request a rule kind inspects.
type MatchKind int

// Match dimensions. A rule kind has exactly one dimension; the dimension
// decides which part of a Query the rule is evaluated against.
const (
	DimensionNone  MatchKind = iota // FINAL
	DimensionName                   // domain name
	DimensionAddr                   // IP address
	DimensionPort                   // destination port
	DimensionProto                  // transport protocol
)

// Dimension reports the query dimension the kind is evaluated against.
func (k Kind) Dimension() MatchKind {
	switch k {
	case KindDomain, KindDomainSuffix, KindDomainKeyword, KindDomainSet:
		return DimensionName
	case KindIPCIDR, KindIPCIDR6, KindGeoIP, KindIPASN:
		return DimensionAddr
	case KindDestPort:
		return DimensionPort
	case KindProtocol:
		return DimensionProto
	default:
		return DimensionNone
	}
}

// IsSet reports whether the kind names an external rule set instead of
// carrying a literal pattern.
func (k Kind) IsSet() bool { return k == KindRuleSet || k == KindDomainSet }

// AllowsNoResolve reports whether the no-resolve option is meaningful for the
// kind. It only applies to kinds matched against an address, where the address
// may have to be looked up from a name first.
func (k Kind) AllowsNoResolve() bool {
	switch k {
	case KindIPCIDR, KindIPCIDR6, KindGeoIP, KindIPASN:
		return true
	}
	return false
}

// String implements fmt.Stringer.
func (k Kind) String() string { return string(k) }
