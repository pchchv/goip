//
// Copyright 2023 Evgenii Pochechuev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/*
goip is a library for handling IP addresses and subnets, both IPv4 and IPv6.

# Benefits of this Library

The primary goals are:
- Comprehensive parsing of IPv4 and IPv6 addresses along with commonly used host name formats, and supplementary formats.
- Representation of subnets by network prefix length or segment value ranges.
- Decoupling address parsing from host parsing.
- Configurable parsing options for allowed formats, including IPv4, IPv6, subnet formats, inet_aton formats, among others.
- Generation of diverse address strings in various formats for a given IPv4 or IPv6 address and creation of collections of such strings.
- Parsing of prevalent MAC Address formats and generation of strings in various MAC address formats.
- Integration of MAC addresses with IPv6 via standardized conversions.
- Integration of IPv4 Addresses with IPv6 through commonly used address conversions.
- Emphasis on polymorphism by maintaining an address framework of interfaces for addressing independence based on type or version (IPv4, IPv6, or MAC). This enables transparent support for both IPv4 and IPv6 in the codebase.
- Thread-safety and immutability with core types (e.g., host names, address strings, addresses, address sections, segments, ranges) being immutable, facilitating safe sharing among goroutines.
- Address manipulation capabilities such as prefix length alterations, masking, segmentation, network and host section separation, reconstitution from segments, among other operations.
- Address operations and subnetting functionalities including obtaining prefix block subnets, iterating through subnets, prefixes, blocks, or segments of subnets, incrementing and decrementing addresses, reversing address bits, set operations like subtracting subnets, intersections, merging, containment checks, and listing subnets covering specific address spans.
- Sorting and comparison of host names, addresses, address strings, and subnets with all address component types being comparable.
- Integration with Go language primitive types and standard library types like [net.IP], [net.IPAddr], [net.IPMask], [net.IPNet], [net.TCPAddr], [net.UDPAddr], [net/netip.Addr], [net/netip.Prefix], [net/netip.AddrPort], and [math/big.Int].
- Simplification of address manipulations by abstracting complexities involving numeric bytes, integers, signed/unsigned values, bit manipulations, iteration, and implementation intricacies related to IPv4/v6.

# Design Overview

This library revolves around core types:
- `IPAddressString`
- `HostName`
- `MACAddressString`
These are complemented by the base type `Address` and its associated types:
- `IPAddress`
- `IPv4Address`
- `IPv6Address`
- `MACAddress`
Moreover, it includes the sequential address type `SequentialRange`.

#### Choosing Types Based on Representation:

- For textual IP address representation, begin with `IPAddressString` or `HostName`.
- For textual MAC address representation, start with `MACAddressString`.
- Instances can represent either a single address or a subnet. Utilize `HostName` for addresses, host names, or items with a port or service name.
- For numeric bytes or integers, initiate with `IPv4Address`, `IPv6Address`, `IPAddress`, or `MACAddress`.

### Scalability and Polymorphism

- Facilitates scaling down from specific address types to more generic types and vice versa.
- Polymorphism aids in ambiguous IP-version code scenarios, with the most-specific types supporting tailored method sets for the address version or type.
- Scaling up to a specific version or address type requires the lower-level instance to originate from an instance of that specific type.
- Conversion examples: `IPv6Address` to `IPAddress` via `IPv6Address.ToIP`, or to `Address` via `IPv6Address.ToAddressBase`. Conversion back to `IPv6Address` or `IPAddress` using `Address.ToIP` or `Address.ToIPv6`.
- Limitation: Conversion back to IPv4 from `IPv6Address` necessitates the use of `IPv4AddressConverter`.
*/
package goip
