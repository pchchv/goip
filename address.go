package goip

const (
	HexPrefix                       = "0x"
	OctalPrefix                     = "0"
	BinaryPrefix                    = "0b"
	RangeSeparator                  = '-'
	RangeSeparatorStr               = "-"
	AlternativeRangeSeparator       = '\u00bb'
	AlternativeRangeSeparatorStr    = "\u00bb" // '»'
	ExtendedDigitsRangeSeparatorStr = AlternativeRangeSeparatorStr
	SegmentWildcard                 = '*'
	SegmentWildcardStr              = "*"
	SegmentSqlWildcard              = '%'
	SegmentSqlWildcardStr           = "%"
	SegmentSqlSingleWildcard        = '_'
	SegmentSqlSingleWildcardStr     = "_"
)

var segmentWildcardStr = SegmentWildcardStr

// SegmentValueProvider provides values for segments.
// Values that fall outside the segment value type range will be truncated using standard golang integer type conversions.
type SegmentValueProvider func(segmentIndex int) SegInt

// AddressValueProvider provides values for addresses.
type AddressValueProvider interface {
	GetSegmentCount() int
	GetValues() SegmentValueProvider
	GetUpperValues() SegmentValueProvider
}

// identifierStr is a string representation of an address or host name.
type identifierStr struct {
	idStr HostIdentifierString // MACAddressString or IPAddressString or HostName
}
