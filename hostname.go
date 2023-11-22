package goip

import (
	"strings"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

const (
	PortSeparator    = ':'
	LabelSeparator   = '.'
	IPv6StartBracket = '['
	IPv6EndBracket   = ']'
)

var (
	zeroHost              = NewHostName("")
	defaultHostParameters = new(address_string_param.HostNameParamsBuilder).ToParams()
)

type resolveData struct {
	resolvedAddrs []*IPAddress
	err           error
}

type hostCache struct {
	resolveData      *resolveData
	normalizedString *string
}

// HostName represents an internet host name.  Can be a fully qualified domain name,
// a simple host name, or an ip address string.
// It can also include a port number or service name (which maps to a port).
// It can include a prefix length or mask for either an ipaddress or host name string.
// An IPv6 address can have an IPv6 zone.
//
// # Supported Formats
//
// You can use all host or address formats supported by nmap and all address formats supported by IPAddressString.
// All manners of domain names are supported. When adding a prefix length or mask to a host name string,
// it is to denote the subnet of the resolved address.
//
// Validation is done separately from DNS resolution to avoid unnecessary DNS lookups.
//
// See RFC 3513, RFC 2181, RFC 952, RFC 1035, RFC 1034, RFC 1123, RFC 5890 or the list of rfcs for IPAddress.
// For IPv6 addresses in host, see RFC 2732 specifying "[]" notation
// and RFC 3986 and RFC 4038 (combining IPv6 "[]" notation with prefix or zone)
// and SMTP RFC 2821 for alternative uses of "[]" notation for both IPv4 and IPv6.
type HostName struct {
	str           string
	parsedHost    *parsedHost
	validateError address_error.HostNameError
	*hostCache
}

func (host *HostName) init() *HostName {
	if host.parsedHost == nil && host.validateError == nil { // the only way params can be nil is when str == "" as well
		return zeroHost
	}
	return host
}

func (host *HostName) validate(validationOptions address_string_param.HostNameParams) {
	parsed, validateError := validator.validateHostName(host, validationOptions)
	if validateError != nil && parsed == nil {
		parsed = &parsedHost{originalStr: host.str, params: validationOptions}
	}
	host.parsedHost, host.validateError = parsed, validateError
}

// Validate validates that this string is a valid address, and if not,
// returns an error with a descriptive message indicating why it is not.
func (host *HostName) Validate() address_error.HostNameError {
	return host.init().validateError
}

// String implements the [fmt.Stringer] interface,
// returning the original string used to create this HostName
// (altered by strings.TrimSpace if a host name and not an address),
// or "<nil>" if the receiver is a nil pointer.
func (host *HostName) String() string {
	if host == nil {
		return nilString()
	}
	return host.str
}

func parseHostName(str string, params address_string_param.HostNameParams) *HostName {
	str = strings.TrimSpace(str)
	res := &HostName{
		str:       str,
		hostCache: &hostCache{},
	}
	res.validate(params)
	return res
}

// NewHostName constructs a HostName that will parse
// the given string according to the default parameters.
func NewHostName(str string) *HostName {
	return parseHostName(str, defaultHostParameters)
}
