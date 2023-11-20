package goip

import (
	"fmt"
	"strings"

	"github.com/pchchv/goip/address_error"
	"github.com/pchchv/goip/address_string_param"
)

var validator hostIdentifierStringValidator = strValidator{}
var defaultIPAddrParameters = new(address_string_param.IPAddressStringParamsBuilder).ToParams()

// IPAddressString parses the string representation of an IP address.
// Such a string can represent just a single address like "1.2.3.4" or "1:2:3:4:6:7:8",
// or a subnet like "1.2.0.0/16" or "1.*.1-3.1-4" or "1111:222::/64".
//
// This supports a wide range of address string formats.
// It supports subnet formats, provides specific error messages, and allows more specific configuration.
//
// You can control all the supported formats using an IPAddressStringParamsBuilder to
// build a parameters instance of IPAddressStringParams.
// When no IPAddressStringParams is supplied,
// a default instance of IPAddressStringParams is used that is generally permissive.
//
// # Supported Formats
//
// Both IPv4 and IPv6 are supported.
//
// Subnets are supported:
//   - wildcards '*' and ranges '-' (for example "1.*.2-3.4"), useful for working with subnets
//   - the wildcard '*' can span multiple segments, so you can represent all addresses with '*', all IPv4 with '*.*', or all IPv6 with '*:*'
//   - SQL wildcards '%' and '_', although '%' is considered an SQL wildcard only when it is not considered an IPv6 zone indicator
//   - CIDR network prefix length addresses, like "1.2.0.0/16", which is equivalent to "1.2.*.*" (all-zero hosts are the full subnet, non-zero hosts are single addresses)
//   - address/mask pairs, in which the mask is applied to the address, like "1.2.3.4/255.255.0.0", which is also equivalent to "1.2.*.*"
//
// You can combine these variations, such as "1.*.2-3.4/255.255.255.0".
//
// IPv6 is fully supported:
//   - IPv6 addresses like "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
//   - IPv6 zones or scope identifiers, like "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%zone"
//   - IPv6 mixed addresses are supported, which are addresses for which the last two IPv6 segments are represented as IPv4, like "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
//   - IPv6 compressed addresses like "::1"
//   - A single value of 32 hex digits like "00aa00bb00cc00dd00ee00ff00aa00bb" with or without a preceding hex delimiter "0x"
//   - A base 85 address comprising 20 base 85 digits like "4)+k&amp;C#VzJ4br&gt;0wv%Yp" as in RFC 1924 https://tools.ietf.org/html/rfc1924
//   - Binary, preceded by "0b", either with binary segments that comprise all 16 bits like "::0b0000111100001111" or a single segment address of "0b" followed by 128 binary bits.
//
// All of the above subnet variations work for IPv6, whether network prefix lengths, masks, ranges or wildcards.
// Similarly, all the above subnet variations work for any supported IPv4 format,
// such as the standard dotted-decimal IPv4 format as well as the inet_aton formats listed below.
//
// This type support all address formats of the C routine inet_pton and the Java method java.net.InetAddress.getByName.
// This type supports all IPv4 address formats of the C routine inet_aton as follows:
//   - IPv4 hex: "0x1.0x2.0x3.0x4" ("0x" prefix)
//   - IPv4 octal: "01.02.03.0234".
//
// Note this clashes with the same address interpreted as dotted decimal
//   - 3-part IPv4: "1.2.3" (which is interpreted as "1.2.0.3" (ie the third part covers the last two)
//   - 2-part IPv4: "1.2" (which is interpreted as "1.0.0.2" (ie the 2nd part covers the last 3)
//   - 1-part IPv4: "1" (which is interpreted as "0.0.0.1" (ie the number represents all 4 segments, and can be any number of digits less than the 32 digits which would be interpreted as IPv6)
//   - hex or octal variants of 1, 2, and 3 part, such as "0xffffffff" (which is interpreted as "255.255.255.255")
//
// Also supported are binary segments of a "0b" followed by binary digits like "0b1.0b1010.2.3", or a single segment address of "0b" followed by all 32 bits.
//
// inet_aton (and this type) allows mixing octal, hex and decimal (e.g. "0xa.11.013.11" which is equivalent to "11.11.11.11").
// String variations using prefixes, masks, ranges, and wildcards also work for inet_aton style.
// The same can be said of binary segments, they can be mixed with all other formats.
//
// Note that there is ambiguity when supporting both inet_aton octal and dotted-decimal leading zeros, like "010.010.010.010" which can
// be interpreted as octal or decimal, thus it can be either "8.8.8.8" or "10.10.10.10", with the default behaviour using the former interpretation.
// This behaviour can be controlled by IPAddressStringParamsBuilder.GetIPv4AddressParamsBuilder and
// IPv4AddressStringParametersBuilder.allowLeadingZeros(boolean)
//
// Some Additional Formats:
//   - empty strings are interpreted as the zero-address or the loopback
//   - as noted previously, the single wildcard address "*" represents all addresses both ipv4 and ipv6,
//
// although you need to give it some help when converting to [IPAddress] by specifying the IP version in GetVersionedAddress(IPVersion) or ToVersionedAddress(IPVersion).
//
// If you have an address in which segments have been delimited with commas, such as "1,2.3.4,5.6", you can parse this with ParseDelimitedSegments(string)
// which gives an iterator of strings.
// For "1,2.3.4,5.6" you will iterate through "1.3.4.6", "1.3.5.6", "2.3.4.6" and "2.3.5.6".
// You can count the number of elements in such an iterator with CountDelimitedAddresses(String).
// Each string can then be used to construct an IPAddressString.
//
// # Usage
//
// Once you have constructed an IPAddressString object, you can convert it to an [IPAddress] object with various methods.
//
// Most address strings can be converted to an [IPAddress] object using GetAddress or ToAddress.
// In most cases the IP version is determined by the string itself.
//
// There are a few exceptions, cases in which the version is unknown or ambiguous, for which GetAddress returns nil:
//   - strings which do not represent valid addresses (eg "bla")
//   - the "all" address "*" which represents all IPv4 and IPv6 addresses.
//
// For this string you can provide the IPv4/IPv6 version to GetVersionedAddress to get an address representing either all IPv4 or all IPv6 addresses.
//   - empty string "" is interpreted as the zero-address, or optionally the default loopback address.
//
// You can provide the IPv4/IPv6 version to GetVersionedAddress to get the version of your choice.
//
// The other exception is a subnet in which the range of values in a segment of the subnet are not sequential, for which ToAddress returns IncompatibleAddressError because there is no single [IPAddress] value, there would be many.
// An [IPAddress] instance requires that all segments can be represented as a range of values.
//
// There are only two unusual circumstances when this can occur:
//   - using masks on subnets specified with wildcard or range characters causing non-sequential segments such as the final IPv4 segment of "0.0.0.*" with mask "0.0.0.128",
//     this example translating to the two addresses "0.0.0.0" and "0.0.0.128", so the last IPv4 segment cannot be represented as a sequential range of values.
//   - using wildcards or range characters in the IPv4 section of an IPv6 mixed address causing non-sequential segments such as the last IPv6 segment of "::ffff:0.0.*.0",
//     this example translating to the addresses "::ffff:0:100", "::ffff:0:200", "::ffff:0:300", ..., so the last IPv6 segment cannot be represented as a sequential range of values.
//
// These exceptions do not occur with non-subnets (ie individual addresses), nor can they occur with standard CIDR prefix-based subnets.
//
// This type is concurrency-safe.
// In fact, IPAddressString objects are immutable.
// An IPAddressString object represents a single IP address representation that cannot be changed after construction.
// Some derived state is created upon demand and cached, such as the derived [IPAddress] instances.
//
// This type has a few methods with analogs in [IPAddress], such as Contains, GetSequentialRange,
// PrefixEqual, IsIPv4, and IsIPv6.
// Such methods are provided to make creating the [IPAddress] instance unnecessary when no such [IPAddress] instance is needed for other reasons.
type IPAddressString struct {
	str             string
	addressProvider ipAddressProvider
	validateError   address_error.AddressStringError
}

// String implements the [fmt.Stringer] interface,
// returning the original string used to create this IPAddressString (altered by strings.TrimSpace),
// or "<nil>" if the receiver is a nil pointer.
func (addrStr *IPAddressString) String() string {
	if addrStr == nil {
		return nilString()
	}
	return addrStr.str
}

// Format implements the [fmt.Formatter] interface.
// It accepts the verbs hat are applicable to strings,
// namely the verbs %s, %q, %x and %X.
func (addrStr IPAddressString) Format(state fmt.State, verb rune) {
	s := flagsFromState(state, verb)
	_, _ = state.Write([]byte(fmt.Sprintf(s, addrStr.str)))
}

func (addrStr *IPAddressString) init() *IPAddressString {
	if addrStr.addressProvider == nil && addrStr.validateError == nil {
		return zeroIPAddressString
	}
	return addrStr
}

func (addrStr *IPAddressString) validate(validationOptions address_string_param.IPAddressStringParams) {
	addrStr.addressProvider, addrStr.validateError = validator.validateIPAddressStr(addrStr, validationOptions)
}

// Validate validates that this string is a valid IP address, returning nil, and if not, returns an error with a descriptive message indicating why it is not.
func (addrStr *IPAddressString) Validate() address_error.AddressStringError {
	return addrStr.init().validateError
}

func newIPAddressStringFromAddr(str string, addr *IPAddress) *IPAddressString {
	return &IPAddressString{
		str:             str,
		addressProvider: addr.getProvider(),
	}
}
