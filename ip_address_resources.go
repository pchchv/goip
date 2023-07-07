package goip

var keyStrMap = map[string]int{
	`ipaddress.error.invalidMACIPv6Range`:                      8,
	`ipaddress.error.address.out.of.range`:                     29,
	`ipaddress.error.single.segment`:                           141,
	`ipaddress.host.error.invalidService.no.letter`:            143,
	`ipaddress.host.error.invalid.service.hyphen.consecutive`:  144,
	`ipaddress.error.mac.invalid.segment.count`:                45,
	`ipaddress.error.address.too.large`:                        52,
	`ipaddress.host.error.invalid.service.hyphen.start`:        68,
	`ipaddress.error.ipv6.has.zone`:                            85,
	`ipaddress.error.cannot.end.with.single.separator`:         136,
	`ipaddress.error.ipMismatch`:                               13,
	`ipaddress.host.error.invalidService.too.long`:             74,
	`ipaddress.error.special.ip`:                               81,
	`ipaddress.error.back.digit.count`:                         106,
	`ipaddress.error.mixedVersions`:                            111,
	`ipaddress.error.ipv6.invalid.segment.count`:               135,
	`ipaddress.host.error.empty.host.resolve`:                  4,
	`ipaddress.error.ipv6.format`:                              5,
	`ipaddress.error.segmentMismatch`:                          41,
	`ipaddress.error.zero.not.allowed`:                         48,
	`ipaddress.error.invalid.character.combination`:            101,
	`ipaddress.error.segment.leading.zeros`:                    112,
	`ipaddress.error.exceeds.size`:                             70,
	`ipaddress.host.error.cidrprefixonly`:                      104,
	`ipaddress.host.error.invalid.type`:                        124,
	`ipaddress.error.ipv6.segment.format`:                      100,
	`ipaddress.host.error.invalid.length`:                      3,
	`ipaddress.error.ip.format`:                                15,
	`ipaddress.error.mask.single.segment`:                      42,
	`ipaddress.host.error.service`:                             43,
	`ipaddress.error.ipv4`:                                     58,
	`ipaddress.error.segment.too.short.at.index`:               9,
	`ipaddress.error.ipv4.segment.hex`:                         16,
	`ipaddress.error.incompatible.position`:                    95,
	`ipaddress.host.error.invalid.character.at.index`:          96,
	`ipaddress.error.mixedNetworks`:                            98,
	`ipaddress.error.too.many.segments`:                        127,
	`ipaddress.error.ipv4.invalid.octal.digit`:                 10,
	`ipaddress.error.ipv4.invalid.segment.count`:               28,
	`ipaddress.host.error.empty`:                               40,
	`ipaddress.host.error.bracketed.missing.end`:               62,
	`ipaddress.error.wildcardOrRangeIPv6`:                      76,
	`ipaddress.error.sizeMismatch`:                             87,
	`ipaddress.host.error.too.many.segments`:                   129,
	`ipaddress.error.invalid.position`:                         130,
	`ipaddress.error.too.few.segments`:                         6,
	`ipaddress.host.error.all.numeric`:                         55,
	`ipaddress.error.invalid.character.combination.at.index`:   53,
	`ipaddress.error.lower.below.range`:                        66,
	`ipaddress.host.error.bracketed.conflicting.prefix.length`: 93,
	`ipaddress.error.nullNetwork`:                              102,
	`ipaddress.error.only.ipv6.square.brackets`:                105,
	`ipaddress.error.invalid.mask.extra.chars`:                 110,
	`ipaddress.host.error`:                                     99,
	`ipaddress.error.splitSeg`:                                 84,
	`ipaddress.mac.error.not.eui.convertible`:                  89,
	`ipaddress.error.invalidRange`:                             128,
	`ipaddress.error.invalid.character.at.index`:               63,
	`ipaddress.error.CIDRNotAllowed`:                           120,
	`ipaddress.error.address.is.ipv4`:                          2,
	`ipaddress.error.prefix.only`:                              59,
	`ipaddress.error.zoneAndCIDRPrefix`:                        75,
	`ipaddress.error.notNetworkMask`:                           92,
	`ipaddress.error.address.lower.exceeds.upper`:              30,
	`ipaddress.host.error.port`:                                32,
	`ipaddress.error.mismatched.bit.size`:                      57,
	`ipaddress.error.ipv6.separator`:                           61,
	`ipaddress.error.ipv4.invalid.byte.count`:                  67,
	`ipaddress.error.ipv4.format`:                              134,
	`ipaddress.error.invalidMultipleMask`:                      108,
	`ipaddress.error.mac.invalid.byte.count`:                   109,
	`ipaddress.error.prefixSize`:                               50,
	`ipaddress.error.only.zone`:                                65,
	`ipaddress.error.too.few.segments.digit.count`:             71,
	`ipaddress.error.ipv4.invalid.decimal.digit`:               73,
	`ipaddress.error.no.single.wildcard`:                       83,
	`ipaddress.error.invalid.mask.wildcard`:                    90,
	`ipaddress.error.ipv6.invalid.byte.count`:                  113,
	`ipaddress.error.ipv4.too.few.segments`:                    33,
	`ipaddress.error.separatePrefixFromMask`:                   78,
	`ipaddress.error.no.range`:                                 118,
	`ipaddress.error.invalid.joined.ranges`:                    126,
	`ipaddress.error.all`:                                      22,
	`ipaddress.error.version.mismatch`:                         37,
	`ipaddress.error.segment.too.long.at.index`:                60,
	`ipaddress.error.maskMismatch`:                             91,
	`ipaddress.host.error.bracketed.not.ipv6`:                  116,
	`ipaddress.error.invalid.character`:                        117,
	`ipaddress.error.address.not.block`:                        131,
	`ipaddress.host.error.invalid.mechanism`:                   132,
	`ipaddress.error.ipv4.too.many.segments`:                   18,
	`ipaddress.error.ipv4.prefix.leading.zeros`:                27,
	`ipaddress.host.error.url`:                                 77,
	`ipaddress.error.inconsistent.prefixes`:                    123,
	`ipaddress.error.address.is.ipv6`:                          139,
	`ipaddress.host.error.ipaddress`:                           140,
	`ipaddress.error.splitMismatch`:                            1,
	`ipaddress.error.no.wildcard`:                              23,
	`ipaddress.error.only.ipv6.has.zone`:                       125,
	`ipaddress.error.separatePrefixFromAddress`:                137,
	`ipaddress.host.error.invalidService.no.chars`:             0,
	`ipaddress.error.index.exceeds.prefix.length`:              12,
	`ipaddress.error.ipv4.segment.too.large`:                   44,
	`ipaddress.error.ipVersionIndeterminate`:                   20,
	`ipaddress.error.ipv6.ambiguous`:                           72,
	`ipaddress.error.ipv6`:                                     86,
	`ipaddress.error.invalid.zone.encoding`:                    94,
	`ipaddress.error.lower.above.range`:                        103,
	`ipaddress.error.null.segment`:                             114,
	`ipaddress.error.invalidMixedRange`:                        24,
	`ipaddress.error.no.iterator.element.to.remove`:            31,
	`ipaddress.error.ipv6.prefix.leading.zeros`:                49,
	`ipaddress.error.empty.start.of.range`:                     19,
	`ipaddress.host.error.invalid.service.hyphen.end`:          47,
	`ipaddress.error.url`:                                      79,
	`ipaddress.host.error.invalidPort.too.large`:               122,
	`ipaddress.error.invalidCIDRPrefixOrMask`:                  142,
	`ipaddress.error.empty`:                                    14,
	`ipaddress.error.ipv6.cannot.start.with.single.separator`:  17,
	`ipaddress.address.error`:                                  39,
	`ipaddress.host.error.host.brackets`:                       80,
	`ipaddress.error.segment.too.long`:                         26,
	`ipaddress.error.zone`:                                     119,
	`ipaddress.error.invalidCIDRPrefix`:                        121,
	`ipaddress.mac.error.mix.format.characters.at.index`:       21,
	`ipaddress.error.unavailable.numeric`:                      34,
	`ipaddress.error.negative`:                                 56,
	`ipaddress.error.invalid.mask.empty`:                       11,
	`ipaddress.error.ipv4.invalid.binary.digit`:                35,
	`ipaddress.host.error.invalidPort.no.digits`:               46,
	`ipaddress.error.single.wildcard.order`:                    107,
	`ipaddress.host.error.host.resolve`:                        69,
	`ipaddress.error.no.mixed`:                                 82,
	`ipaddress.error.front.digit.count`:                        7,
	`ipaddress.mac.error.format`:                               36,
	`ipaddress.error.ipVersionMismatch`:                        38,
	`ipaddress.host.error.bracketed.conflicting.mask`:          51,
	`ipaddress.error.invalid.zone`:                             54,
	`ipaddress.error.invalid.mask.address.empty`:               64,
	`ipaddress.host.error.segment.too.short`:                   88,
	`ipaddress.error.empty.segment.at.index`:                   97,
	`ipaddress.error.reverseRange`:                             115,
	`ipaddress.host.error.invalid`:                             133,
	`ipaddress.host.error.invalid.port.service`:                138,
	`ipaddress.error.invalid.size`:                             25,
}

var strIndices = []int{
	0, 21, 153, 168, 187, 216, 288, 316, 365, 426,
	452, 471, 484, 511, 562, 589, 725, 764, 876, 910,
	929, 963, 1016, 1052, 1100, 1162, 1182, 1198, 1238, 1276,
	1313, 1362, 1391, 1430, 1492, 1535, 1555, 1601, 1646, 1671,
	1688, 1740, 1815, 1873, 1920, 1942, 1979, 1998, 2033, 2063,
	2103, 2178, 2235, 2252, 2314, 2358, 2384, 2406, 2433, 2469,
	2505, 2530, 2564, 2601, 2625, 2648, 2687, 2699, 2734, 2773,
	2796, 2816, 2870, 2906, 2927, 2948, 2972, 3029, 3065, 3102,
	3142, 3211, 3286, 3327, 3392, 3473, 3493, 3529, 3562, 3581,
	3622, 3638, 3707, 3733, 3799, 3833, 3866, 3892, 3922, 3964,
	3975, 3990, 4034, 4048, 4060, 4115, 4159, 4207, 4268, 4305,
	4339, 4377, 4435, 4465, 4500, 4546, 4611, 4641, 4669, 4715,
	4736, 4784, 4952, 4973, 5023, 5046, 5081, 5146, 5175, 5229,
	5246, 5272, 5336, 5367, 5379, 5427, 5465, 5572, 5629, 5677,
	5692, 5733, 5808, 6003, 6045,
}

var strVals = `service name is empty` +
	`splitting digits in range segments results in an invalid string (eg 12-22 becomes 1-2.2-2 which is 12 and 22 and nothing in between)` +
	`address is IPv4` +
	`invalid host length` +
	`empty host cannot be resolved` +
	`invalid format of IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) address` +
	`address has too few segments` +
	`front address in range has an invalid digit count` +
	`MAC segment ranges cannot be converted to IPv6 segment ranges` +
	`segment too short at index` +
	`invalid octal digit` +
	`mask is empty` +
	`index exceeds prefix length` +
	`IP version of address must match IP version of mask` +
	`you must specify an address` +
	`invalid format of IP address, whether IPv4 (255.255.255.255) or IPv6 (ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) or other supported format` +
	`IPv4 segment contains hexadecimal value` +
	`An IPv6 address cannot start with a single colon, it must start with either two colons or with the first segment` +
	`IPv4 address has too many segments` +
	`range start missing` +
	`requested version is indeterminate` +
	`invalid mix of mac address format characters at index` +
	`the universal address is not allowed` +
	`validation options do no allow wildcard segments` +
	`IPv4 segment ranges cannot be converted to IPv6 segment ranges` +
	`invalid address size` +
	`segment too long` +
	`IPv4 CIDR prefix length starts with zero` +
	`IPv4 address has invalid segment count` +
	`Address not within the assigned range` +
	`invalid address range, lower bound exceeds upper:` +
	`no iterator element to remove` +
	`validation options do no allow for port` +
	`options do not allow IPv4 address with less than four segments` +
	`No numeric value available for this address` +
	`invalid binary digit` +
	`validation options do no allow this mac format` +
	`Unable to convert version of argument address` +
	`the IP version must match` +
	`IP Address error:` +
	`validation options do no allow empty string for host` +
	`joining segments results in a joined segment that is not a sequential range` +
	`mask with single segment not allowed by validation options` +
	`validation options do no allow for service name` +
	`IPv4 segment too large` +
	`MAC address has invalid segment count` +
	`port value is empty` +
	`service name cannot end in a hyphen` +
	`a non-zero address is required` +
	`IPv6 CIDR prefix length starts with zero` +
	`the network prefix bit-length is negative or exceeds the address bit-length` +
	`conflicting masks inside and outside of bracketed address` +
	`address too large` +
	`invalid combination with earlier character at character number` +
	`invalid zone or scope id character at index:` +
	`host cannot be all numeric` +
	`negative address value` +
	`mismatched address bit size` +
	`validation options do not allow IPv4` +
	`a prefix-only address is not allowed` +
	`segment too long at index` +
	`invalid position of IPv6 separator` +
	`bracketed address missing end bracket` +
	`invalid character number` +
	`mask with empty address` +
	`with a zone you must specify an address` +
	`below range:` +
	`IPv4 address has invalid byte count` +
	`service name cannot start with a hyphen` +
	`host cannot be resolved` +
	`exceeds address size` +
	`address has too few segments or an invalid digit count` +
	`IPv6 compressed address is ambiguous` +
	`invalid decimal digit` +
	`service name too long` +
	`zone and prefix combined` +
	`Wildcards and ranges are not supported for IPv6 addresses` +
	`please supply a host, not a full URL` +
	`specify a mask or prefix but not both` +
	`please supply an address, not a full URL` +
	`ipv6 addresses must be surrounded by square brackets [] in host names` +
	`a special IP address with first segment larger than 255 cannot be used here` +
	`validation options do no allow mixed IPv6` +
	`validation options do no allow single character wildcard segments` +
	`cannot split ranged segment into smaller ranged segments spanning the same values` +
	`no ipv6 zone allowed` +
	`validation options do not allow IPv6` +
	`the number of segments must match` +
	`zero-length segment` +
	`MAC address cannot be converted to EUI 64` +
	`wildcard in mask` +
	`applying the mask results in a segment that is not a sequential range` +
	`mask is not a network mask` +
	`conflicting prefix lengths inside and outside of bracketed address` +
	`invalid encoding in zone at index:` +
	`Incompatible positions in address` +
	`invalid character at index` +
	`segment value missing at index` +
	`Address components have different networks` +
	`Host error:` +
	`invalid segment` +
	`invalid combination of characters in segment` +
	`network is nil` +
	`above range:` +
	`please supply an address, not a CIDR prefix length only` +
	`only ipv6 can be enclosed in square brackets` +
	`back address in range has an invalid digit count` +
	`single wildcards can appear only as the end of segment values` +
	`mask must specify a single IP address` +
	`MAC address has invalid byte count` +
	`invalid chars following mask at index:` +
	`Please specify either IPv4 or IPv6 addresses, but not both` +
	`segment value starts with zero` +
	`IPv6 address has invalid byte count` +
	`Section or grouping array contains a nil value` +
	`reversing a range of values does not result in a sequential range` +
	`bracketed address must be IPv6` +
	`invalid character in segment` +
	`validation options do not allow range segments` +
	`IPv6 zone not allowed` +
	`CIDR prefix or mask not allowed for this address` +
	`CIDR prefix must indicate the count of subnet bits, between 0 and 32 subnet bits for IP version 4 addresses and between 0 and 128 subnet bits for IP version 6 addresses` +
	`port number too large` +
	`Segments invalid due to inconsistent prefix values` +
	`invalid IP address type` +
	`only ipv6 can have a zone specified` +
	`range of joined segments cannot be divided into individual ranges` +
	`address has too many segments` +
	`in segment range, lower value must precede upper value` +
	`too many segments` +
	`Invalid index into address` +
	`Address is neither a CIDR prefix block nor an individual address` +
	`address mechanism not supported` +
	`invalid host` +
	`invalid format of IPv4 (255.255.255.255) address` +
	`IPv6 address has invalid segment count` +
	`An IPv6 address cannot end with a single colon, it must end with either two colons or with the last segment` +
	`specify the IP address separately from the mask or prefix` +
	`invalid port or service name character at index:` +
	`address is IPv6` +
	`validation options do no allow IP address` +
	`validation options do not allow you to specify a non-segmented single value` +
	`A mask must be a single IP address, while a CIDR prefix length must indicate the count of subnet bits, between 0 and 32 for IP version 4 addresses and between 0 and 128 for IP version 6 addresses` +
	`service name must have at least one letter` +
	`service name cannot have consecutive hyphens`

func lookupStr(key string) (result string) {
	if index, ok := keyStrMap[key]; ok {
		start, end := strIndices[index], strIndices[index+1]
		result = strVals[start:end]
	}
	return
}
