// The address_string package provides interfaces to define how
// to create certain strings from addresses and address sections,
// as well as the builder types for creating instances of these interfaces.
//
// For example, StringOptionsBuilder creates instances that implement StringOptions to specify generic strings.
//
// For more specific versions and address types,
// there are more specific builders and corresponding interface types.
//
// Each instance created by the builder is immutable.
package address_string

type wildcards struct {
	rangeSeparator, wildcard, singleWildcard string //rangeSeparator cannot be empty, the other two can
}
