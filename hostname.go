package goip

import (
	"fmt"
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

// GetValidationOptions returns the validation options supplied
// when constructing the HostName,
// or the default validation options if none were supplied.
// It returns nil if no options were used to construct.
func (host *HostName) GetValidationOptions() address_string_param.HostNameParams {
	return host.init().parsedHost.params
}

// Format implements the [fmt.Formatter] interface.
// It accepts the verbs hat are applicable to strings,
// namely the verbs %s, %q, %x and %X.
func (addrStr HostName) Format(state fmt.State, verb rune) {
	s := flagsFromState(state, verb)
	_, _ = state.Write([]byte(fmt.Sprintf(s, addrStr.str)))
}

// IsValid returns whether this represents a valid host name or IP address format.
func (host *HostName) IsValid() bool {
	return host.init().Validate() == nil
}

// IsAddressString returns whether this host name is
// a string representing an IP address or subnet.
func (host *HostName) IsAddressString() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.isAddressString()
}

// IsAddress returns whether this host name is
// a string representing a valid specific IP address or subnet.
func (host *HostName) IsAddress() bool {
	if host.IsAddressString() {
		addr, _ := host.init().parsedHost.asAddress()
		return addr != nil
	}
	return false
}

// AsAddress returns the address if this host name represents an ip address.
// Otherwise, this returns nil.
// Note that the translation includes prefix lengths and IPv6 zones.
//
// This does not resolve addresses or return resolved addresses.
// Call ToAddress or GetAddress to get the resolved address.
//
// In cases such as IPv6 literals and reverse-DNS hosts,
// you can check the relevant methods isIpv6Literal or isReverseDNS,
// in which case this method should return the associated address.
func (host *HostName) AsAddress() *IPAddress {
	if host.IsAddress() {
		addr, _ := host.parsedHost.asAddress()
		return addr
	}
	return nil
}

// IsAllAddresses returns whether this is
// an IP address that represents the set all all valid IP addresses
// (as opposed to an empty string, a specific address, or an invalid format).
func (host *HostName) IsAllAddresses() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.getAddressProvider().isProvidingAllAddresses()
}

// GetPort returns the port if a port was supplied, otherwise it returns nil.
func (host *HostName) GetPort() Port {
	host = host.init()
	if host.IsValid() {
		return host.parsedHost.getPort().copy()
	}
	return nil
}

// GetNormalizedLabels returns an array of normalized strings for this host name instance.
//
// If this represents an IP address, the address segments are separated into the returned array.
// If this represents a host name string, the domain name segments are separated into the returned array,
// with the top-level domain name (right-most segment) as the last array element.
//
// The individual segment strings are normalized in the same way as ToNormalizedString.
//
// Ports, service name strings, prefix lengths, and masks are all omitted from the returned array.
func (host *HostName) GetNormalizedLabels() []string {
	host = host.init()
	if host.IsValid() {
		return host.parsedHost.getNormalizedLabels()
	} else {
		str := host.str
		if len(str) == 0 {
			return []string{}
		}
		return []string{str}
	}
}

// IsEmpty returns true if the host name is empty (zero-length).
func (host *HostName) IsEmpty() bool {
	host = host.init()
	return host.IsValid() &&
		((host.IsAddressString() &&
			host.parsedHost.getAddressProvider().isProvidingEmpty()) || len(host.GetNormalizedLabels()) == 0)
}

// GetService returns the service name if a service name was supplied
// (which is typically mapped to a port),
// otherwise it returns an empty string.
func (host *HostName) GetService() string {
	host = host.init()
	if host.IsValid() {
		return host.parsedHost.getService()
	}
	return ""
}

// IsUncIPv6Literal returns whether this host name is
// an Uniform Naming Convention IPv6 literal host name.
func (host *HostName) IsUncIPv6Literal() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.isUNCIPv6Literal()
}

// IsReverseDNS returns whether this host name is a reverse-DNS string host name.
func (host *HostName) IsReverseDNS() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.isReverseDNS()
}

// GetMask returns the resulting mask value if a mask was provided with this host name.
func (host *HostName) GetMask() *IPAddress {
	if host.IsValid() {
		if host.parsedHost.isAddressString() {
			return host.parsedHost.getAddressProvider().getProviderMask()
		}
		return host.parsedHost.getMask()
	}
	return nil
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

// NewHostNameParams constructs a HostName that will parse the given string according to the given parameters.
func NewHostNameParams(str string, params address_string_param.HostNameParams) *HostName {
	var prms address_string_param.HostNameParams
	if params == nil {
		prms = defaultHostParameters
	} else {
		prms = address_string_param.CopyHostNameParams(params)
	}
	return parseHostName(str, prms)
}

func toNormalizedPortString(port PortInt, builder *strings.Builder) {
	builder.WriteByte(PortSeparator)
	toUnsignedString(uint64(port), 10, builder)
}

func newHostNameFromAddr(hostStr string, addr *IPAddress) *HostName {
	parsedHost := parsedHost{
		originalStr:     hostStr,
		embeddedAddress: embeddedAddress{addressProvider: addr.getProvider()},
	}
	return &HostName{
		str:        hostStr,
		hostCache:  &hostCache{normalizedString: &hostStr},
		parsedHost: &parsedHost,
	}
}

func translateReserved(addr *IPv6Address, str string, builder *strings.Builder) {
	// This is particularly targeted towards the zone
	if !addr.HasZone() {
		builder.WriteString(str)
		return
	}

	var translated = builder
	index := strings.IndexByte(str, IPv6ZoneSeparator)
	translated.WriteString(str[0:index])
	translated.WriteString("%25")
	for i := index + 1; i < len(str); i++ {
		c := str[i]
		if isReserved(c) {
			translated.WriteByte('%')
			toUnsignedString(uint64(c), 16, translated)
		} else {
			translated.WriteByte(c)
		}
	}
}
