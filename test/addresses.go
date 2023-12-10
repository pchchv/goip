package test

import (
	"net"
	"sync"

	"github.com/pchchv/goip"
	"github.com/pchchv/goip/address_string_param"
)

var (
	hostOptions = new(address_string_param.HostNameParamsBuilder).
			AllowEmpty(false).
			NormalizeToLowercase(true).
			AllowPort(true).
			AllowService(true).
			AllowBracketedIPv6(true).
			AllowBracketedIPv4(true).
			GetIPAddressParamsBuilder().
			AllowPrefix(true).
			AllowMask(true).
			SetRangeParams(address_string_param.NoRange).
			AllowInetAton(false).
			AllowEmpty(false).
			AllowAll(false).
			AllowSingleSegment(false).
			GetIPv4AddressParamsBuilder().
			AllowLeadingZeros(true).
			AllowUnlimitedLeadingZeros(false).
			AllowPrefixLenLeadingZeros(true).
			AllowPrefixesBeyondAddressSize(false).
			AllowWildcardedSeparator(true).
			AllowBinary(true).
			GetParentBuilder().
			GetIPv6AddressParamsBuilder().
			AllowLeadingZeros(true).
			AllowUnlimitedLeadingZeros(false).
			AllowPrefixLenLeadingZeros(true).
			AllowPrefixesBeyondAddressSize(false).
			AllowWildcardedSeparator(true).
			AllowMixed(true).
			AllowZone(true).
			AllowBinary(true).
			GetParentBuilder().GetParentBuilder().ToParams()
	hostInetAtonOptions = new(address_string_param.HostNameParamsBuilder).Set(hostOptions).GetIPAddressParamsBuilder().AllowInetAton(true).AllowSingleSegment(true).GetParentBuilder().ToParams()
	addressOptions      = new(address_string_param.IPAddressStringParamsBuilder).Set(hostOptions.GetIPAddressParams()).ToParams()
	macAddressOptions   = new(address_string_param.MACAddressStringParamsBuilder).
				AllowEmpty(false).
				AllowAll(false).
				GetFormatParamsBuilder().
				SetRangeParams(address_string_param.NoRange).
				AllowLeadingZeros(true).
				AllowUnlimitedLeadingZeros(false).
				AllowWildcardedSeparator(true).
				AllowShortSegments(true).
				GetParentBuilder().
				ToParams()
)

type testAddresses interface {
	createAddress(string) *goip.IPAddressString
	createInetAtonAddress(string) *goip.IPAddressString
	createParametrizedAddress(string, address_string_param.RangeParams) *goip.IPAddressString
	createParamsAddress(string, address_string_param.IPAddressStringParams) *goip.IPAddressString
	createAddressFromIP(ip net.IP) *goip.IPAddress
	createIPv4Address(uint32) *goip.IPv4Address
	createIPv6Address(high, low uint64) *goip.IPv6Address
	createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params address_string_param.RangeParams) *goip.IPAddressString
	createHost(string) *goip.HostName
	createInetAtonHost(string) *goip.HostName
	createParamsHost(string, address_string_param.HostNameParams) *goip.HostName
	createMACAddress(string) *goip.MACAddressString
	createMACAddressFromBytes(bytes net.HardwareAddr) *goip.MACAddress
	createMACAddressFromUint64(bytes uint64, extended bool) *goip.MACAddress
	createMACParamsAddress(string, address_string_param.MACAddressStringParams) *goip.MACAddressString
	isLenient() bool
	allowsRange() bool
	getAllCached() []*goip.IPAddress
	getAllMACCached() []*goip.MACAddress
}

type addresses struct {
	caching                          bool
	strIPAddressStrCache             map[string]*goip.IPAddressString
	strIPAddressStrCacheLock         *sync.Mutex
	inetAtonStrIPAddressStrCache     map[string]*goip.IPAddressString
	inetAtonStrIPAddressStrCacheLock *sync.Mutex
	netIPv4AddressCache              map[[4]byte]*goip.IPAddress
	netIPv4AddressCacheLock          *sync.Mutex
	netIPv6AddressCache              map[[16]byte]*goip.IPAddress
	netIPv6AddressCacheLock          *sync.Mutex
	intIPv4AddressCache              map[uint32]*goip.IPv4Address
	intIPv4AddressCacheLock          *sync.Mutex
	intsIPv6AddressCache             map[[2]uint64]*goip.IPv6Address
	intsIPv6AddressCacheLock         *sync.Mutex
	strMACAddressStrCache            map[string]*goip.MACAddressString
	strMACAddressStrCacheLock        *sync.Mutex
	netMACAddressCache               map[[6]byte]*goip.MACAddress
	netMACAddressCacheLock           *sync.Mutex
	netMACExtAddressCache            map[[8]byte]*goip.MACAddress
	netMACExtAddressCacheLock        *sync.Mutex
	uint64MACAddressCache            map[uint64]*goip.MACAddress
	uint64MACAddressCacheLock        *sync.Mutex
	uint64MACExtAddressCache         map[uint64]*goip.MACAddress
	uint64MACExtAddressCacheLock     *sync.Mutex
	strHostStrCache                  map[string]*goip.HostName
	strHostStrCacheLock              *sync.Mutex
	inetAtonStrHostStrCache          map[string]*goip.HostName
	inetAtonStrIHostStrCacheLock     *sync.Mutex
	strParamsIPAddressStrCache       map[address_string_param.IPAddressStringParams]map[string]*goip.IPAddressString
	strParamsIPAddressStrCacheLock   *sync.Mutex
	strParamsMACAddressStrCache      map[address_string_param.MACAddressStringParams]map[string]*goip.MACAddressString
	strParamsMACAddressStrCacheLock  *sync.Mutex
	strParamsHostStrCache            map[address_string_param.HostNameParams]map[string]*goip.HostName
	strParamsHostStrCacheLock        *sync.Mutex
}

func (t *addresses) useCache(use bool) {
	if use {
		if t.caching {
			return
		}
		t.caching = use
		t.strIPAddressStrCache = make(map[string]*goip.IPAddressString)
		t.strIPAddressStrCacheLock = &sync.Mutex{}
		t.inetAtonStrIPAddressStrCache = make(map[string]*goip.IPAddressString)
		t.inetAtonStrIPAddressStrCacheLock = &sync.Mutex{}
		t.netIPv4AddressCache = make(map[[4]byte]*goip.IPAddress)
		t.netIPv4AddressCacheLock = &sync.Mutex{}
		t.netIPv6AddressCache = make(map[[16]byte]*goip.IPAddress)
		t.netIPv6AddressCacheLock = &sync.Mutex{}
		t.intIPv4AddressCache = make(map[uint32]*goip.IPv4Address)
		t.intIPv4AddressCacheLock = &sync.Mutex{}
		t.intsIPv6AddressCache = make(map[[2]uint64]*goip.IPv6Address)
		t.intsIPv6AddressCacheLock = &sync.Mutex{}

		t.strMACAddressStrCache = make(map[string]*goip.MACAddressString)
		t.strMACAddressStrCacheLock = &sync.Mutex{}

		t.netMACAddressCache = make(map[[6]byte]*goip.MACAddress)
		t.netMACAddressCacheLock = &sync.Mutex{}
		t.netMACExtAddressCache = make(map[[8]byte]*goip.MACAddress)
		t.netMACExtAddressCacheLock = &sync.Mutex{}

		t.uint64MACAddressCache = make(map[uint64]*goip.MACAddress)
		t.uint64MACAddressCacheLock = &sync.Mutex{}
		t.uint64MACExtAddressCache = make(map[uint64]*goip.MACAddress)
		t.uint64MACExtAddressCacheLock = &sync.Mutex{}

		t.strHostStrCache = make(map[string]*goip.HostName)
		t.strHostStrCacheLock = &sync.Mutex{}

		t.inetAtonStrHostStrCache = make(map[string]*goip.HostName)
		t.inetAtonStrIHostStrCacheLock = &sync.Mutex{}

		t.strParamsIPAddressStrCache = make(map[address_string_param.IPAddressStringParams]map[string]*goip.IPAddressString)
		t.strParamsIPAddressStrCacheLock = &sync.Mutex{}

		t.strParamsMACAddressStrCache = make(map[address_string_param.MACAddressStringParams]map[string]*goip.MACAddressString)
		t.strParamsMACAddressStrCacheLock = &sync.Mutex{}

		t.strParamsHostStrCache = make(map[address_string_param.HostNameParams]map[string]*goip.HostName)
		t.strParamsHostStrCacheLock = &sync.Mutex{}
	} else {
		if !t.caching {
			return
		}
		*t = addresses{}
	}
}

func (t *addresses) getAllCached() (all []*goip.IPAddress) {
	if !t.caching {
		return
	}

	t.strIPAddressStrCacheLock.Lock()
	t.netIPv4AddressCacheLock.Lock()
	t.netIPv6AddressCacheLock.Lock()
	t.intIPv4AddressCacheLock.Lock()
	t.intsIPv6AddressCacheLock.Lock()
	all = make([]*goip.IPAddress, 0, len(t.strIPAddressStrCache)+
		len(t.netIPv4AddressCache)+len(t.netIPv6AddressCache)+
		len(t.intIPv4AddressCache)+len(t.intsIPv6AddressCache))

	for _, str := range t.strIPAddressStrCache {
		if addr := str.GetAddress(); addr != nil {
			all = append(all, addr)
		}
	}

	for _, addr := range t.netIPv4AddressCache {
		all = append(all, addr)
	}

	for _, addr := range t.netIPv6AddressCache {
		all = append(all, addr)
	}

	for _, addr := range t.intIPv4AddressCache {
		all = append(all, addr.ToIP())
	}

	for _, addr := range t.intsIPv6AddressCache {
		all = append(all, addr.ToIP())
	}

	t.intsIPv6AddressCacheLock.Unlock()
	t.intIPv4AddressCacheLock.Unlock()
	t.netIPv6AddressCacheLock.Unlock()
	t.netIPv4AddressCacheLock.Unlock()
	t.strIPAddressStrCacheLock.Unlock()
	return
}

func (t *addresses) getAllMACCached() (all []*goip.MACAddress) {
	if !t.caching {
		return
	}

	t.strMACAddressStrCacheLock.Lock()
	t.netMACAddressCacheLock.Lock()
	t.netMACExtAddressCacheLock.Lock()
	t.uint64MACAddressCacheLock.Lock()
	t.uint64MACExtAddressCacheLock.Lock()
	all = make([]*goip.MACAddress, 0, len(t.strMACAddressStrCache)+
		len(t.netMACAddressCache)+len(t.netMACExtAddressCache)+
		len(t.uint64MACAddressCache)+len(t.uint64MACExtAddressCache))
	for _, str := range t.strMACAddressStrCache {
		if addr := str.GetAddress(); addr != nil {
			all = append(all, addr)
		}
	}

	for _, addr := range t.netMACAddressCache {
		all = append(all, addr)
	}

	for _, addr := range t.netMACExtAddressCache {
		all = append(all, addr)
	}

	for _, addr := range t.uint64MACAddressCache {
		all = append(all, addr)
	}

	for _, addr := range t.uint64MACExtAddressCache {
		all = append(all, addr)
	}

	t.uint64MACExtAddressCacheLock.Unlock()
	t.uint64MACAddressCacheLock.Unlock()
	t.netMACExtAddressCacheLock.Unlock()
	t.netMACAddressCacheLock.Unlock()
	t.strMACAddressStrCacheLock.Unlock()
	return
}

func (t *addresses) createParametrizedAddress(str string, params address_string_param.RangeParams) *goip.IPAddressString {
	var opts address_string_param.IPAddressStringParams
	if params == address_string_param.NoRange {
		opts = noRangeAddressOptions
	} else if params == address_string_param.WildcardOnly {
		opts = wildcardOnlyAddressOptions
	} else if params == address_string_param.WildcardAndRange {
		opts = wildcardAndRangeAddressOptions
	} else {
		opts = new(address_string_param.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).
			SetRangeParams(params).ToParams()
	}

	if t.caching {
		return t.createParamsAddress(str, opts)
	}
	return goip.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createParamsAddress(str string, opts address_string_param.IPAddressStringParams) (res *goip.IPAddressString) {
	if t.caching {
		t.strParamsIPAddressStrCacheLock.Lock()
		defer t.strParamsIPAddressStrCacheLock.Unlock()
		mp := t.strParamsIPAddressStrCache[opts]
		if mp == nil {
			t.strParamsIPAddressStrCache[opts] = make(map[string]*goip.IPAddressString)
		} else {
			res = mp[str]
			if res != nil {
				return
			}
		}
	}

	res = goip.NewIPAddressStringParams(str, opts)
	if t.caching {
		t.strParamsIPAddressStrCache[opts][str] = res
	}
	return
}

func (t *addresses) createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params address_string_param.RangeParams) *goip.IPAddressString {
	var opts address_string_param.IPAddressStringParams
	if ipv4Params == ipv6Params {
		if ipv4Params == address_string_param.NoRange {
			opts = noRangeAddressOptions
		} else if ipv4Params == address_string_param.WildcardOnly {
			opts = wildcardOnlyAddressOptions
		} else if ipv4Params == address_string_param.WildcardAndRange {
			opts = wildcardAndRangeAddressOptions
		}
	}

	if opts == nil {
		opts = new(address_string_param.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).
			GetIPv4AddressParamsBuilder().SetRangeParams(ipv4Params).GetParentBuilder().
			GetIPv6AddressParamsBuilder().SetRangeParams(ipv6Params).GetParentBuilder().ToParams()
	}

	if t.caching {
		return t.createParamsAddress(str, opts)
	}
	return goip.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createAddress(str string) (res *goip.IPAddressString) {
	if t.caching {
		t.strIPAddressStrCacheLock.Lock()
		defer t.strIPAddressStrCacheLock.Unlock()
		res = t.strIPAddressStrCache[str]
		if res != nil {
			//fmt.Printf("reusing %v\n", res)
			return
		}
	}

	res = goip.NewIPAddressStringParams(str, addressOptions)
	if t.caching {
		t.strIPAddressStrCache[str] = res
	}
	return
}

func (t *addresses) createInetAtonAddress(str string) (res *goip.IPAddressString) {
	if t.caching {
		t.inetAtonStrIPAddressStrCacheLock.Lock()
		defer t.inetAtonStrIPAddressStrCacheLock.Unlock()
		res = t.inetAtonStrIPAddressStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewIPAddressStringParams(str, inetAtonwildcardAndRangeOptions)
	if t.caching {
		t.inetAtonStrIPAddressStrCache[str] = res
	}
	return
}

func (t *addresses) createAddressFromIP(ip net.IP) (res *goip.IPAddress) {
	if t.caching {
		if ipv4 := ip.To4(); ipv4 != nil {
			t.netIPv4AddressCacheLock.Lock()
			defer t.netIPv4AddressCacheLock.Unlock()
			var key [4]byte
			copy(key[:], ipv4)
			res = t.netIPv4AddressCache[key]
			if res != nil {
				return
			}
			res, _ = goip.NewIPAddressFromNetIP(ip)
			t.netIPv4AddressCache[key] = res
		} else if len(ip) == 16 {
			t.netIPv6AddressCacheLock.Lock()
			defer t.netIPv6AddressCacheLock.Unlock()
			var key [16]byte
			copy(key[:], ip)
			res = t.netIPv6AddressCache[key]
			if res != nil {
				return
			}
			res, _ = goip.NewIPAddressFromNetIP(ip)
			t.netIPv6AddressCache[key] = res
		} else {
			res, _ = goip.NewIPAddressFromNetIP(ip)
		}
		return
	}
	res, _ = goip.NewIPAddressFromNetIP(ip)
	return
}

func (t *addresses) createIPv4Address(val uint32) (res *goip.IPv4Address) {
	if t.caching {
		t.intIPv4AddressCacheLock.Lock()
		defer t.intIPv4AddressCacheLock.Unlock()
		res = t.intIPv4AddressCache[val]
		if res != nil {
			return
		}
	}

	res = goip.NewIPv4AddressFromUint32(val)
	if t.caching {
		t.intIPv4AddressCache[val] = res
	}
	return
}

func (t *addresses) createIPv6Address(high, low uint64) (res *goip.IPv6Address) {
	if t.caching {
		t.intsIPv6AddressCacheLock.Lock()
		defer t.intsIPv6AddressCacheLock.Unlock()
		var key [2]uint64
		key[0], key[1] = low, high
		res = t.intsIPv6AddressCache[key]
		if res != nil {
			return
		}
		res = goip.NewIPv6AddressFromUint64(high, low)
		t.intsIPv6AddressCache[key] = res
		return
	}
	return goip.NewIPv6AddressFromUint64(high, low)
}

func (t *addresses) createMACAddress(str string) (res *goip.MACAddressString) {
	if t.caching {
		t.strMACAddressStrCacheLock.Lock()
		defer t.strMACAddressStrCacheLock.Unlock()
		res = t.strMACAddressStrCache[str]
		if res != nil {
			//fmt.Printf("reusing %v\n", res)
			return
		}
	}

	res = goip.NewMACAddressStringParams(str, macAddressOptions)
	if t.caching {
		t.strMACAddressStrCache[str] = res
	}
	return
}

func (t *addresses) createMACAddressFromBytes(bytes net.HardwareAddr) (res *goip.MACAddress) {
	if t.caching {
		if len(bytes) == 6 {
			t.netMACAddressCacheLock.Lock()
			defer t.netMACAddressCacheLock.Unlock()
			var key [6]byte
			copy(key[:], bytes)
			res = t.netMACAddressCache[key]
			if res != nil {
				return
			}
			res, _ = goip.NewMACAddressFromBytes(bytes)
			t.netMACAddressCache[key] = res
		} else if len(bytes) == 8 {
			t.netMACExtAddressCacheLock.Lock()
			defer t.netMACExtAddressCacheLock.Unlock()
			var key [8]byte
			copy(key[:], bytes)
			res = t.netMACExtAddressCache[key]
			if res != nil {
				return
			}
			res, _ = goip.NewMACAddressFromBytes(bytes)
			t.netMACExtAddressCache[key] = res
		} else {
			res, _ = goip.NewMACAddressFromBytes(bytes)
		}
		return
	}
	res, _ = goip.NewMACAddressFromBytes(bytes)
	return
}

func (t *addresses) createMACAddressFromUint64(bytes uint64, extended bool) (res *goip.MACAddress) {
	if t.caching {
		if extended {
			t.uint64MACExtAddressCacheLock.Lock()
			defer t.uint64MACExtAddressCacheLock.Unlock()
			res = t.uint64MACExtAddressCache[bytes]
			if res != nil {
				return
			}
			res = goip.NewMACAddressFromUint64Ext(bytes, extended)
			t.uint64MACExtAddressCache[bytes] = res
		} else {
			t.uint64MACAddressCacheLock.Lock()
			defer t.uint64MACAddressCacheLock.Unlock()
			res = t.uint64MACAddressCache[bytes]
			if res != nil {
				return
			}
			res = goip.NewMACAddressFromUint64Ext(bytes, extended)
			t.uint64MACAddressCache[bytes] = res
		}
		return
	}
	res = goip.NewMACAddressFromUint64Ext(bytes, extended)
	return
}

func (t *addresses) createMACParamsAddress(str string, opts address_string_param.MACAddressStringParams) (res *goip.MACAddressString) {
	if t.caching {
		t.strParamsMACAddressStrCacheLock.Lock()
		defer t.strParamsMACAddressStrCacheLock.Unlock()
		mp := t.strParamsMACAddressStrCache[opts]
		if mp == nil {
			t.strParamsMACAddressStrCache[opts] = make(map[string]*goip.MACAddressString)
		} else {
			res = mp[str]
			if res != nil {
				return
			}
		}
	}

	res = goip.NewMACAddressStringParams(str, opts)
	if t.caching {
		t.strParamsMACAddressStrCache[opts][str] = res
	}
	return
}

func (t *addresses) createHost(str string) (res *goip.HostName) {
	if t.caching {
		t.strHostStrCacheLock.Lock()
		defer t.strHostStrCacheLock.Unlock()
		res = t.strHostStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewHostNameParams(str, hostOptions)
	if t.caching {
		t.strHostStrCache[str] = res
	}
	return
}

func (t *addresses) createInetAtonHost(str string) (res *goip.HostName) {
	if t.caching {
		t.inetAtonStrIHostStrCacheLock.Lock()
		defer t.inetAtonStrIHostStrCacheLock.Unlock()
		res = t.inetAtonStrHostStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewHostNameParams(str, hostInetAtonOptions)
	if t.caching {
		t.inetAtonStrHostStrCache[str] = res
	}
	return
}

func (t *addresses) createParamsHost(str string, opts address_string_param.HostNameParams) (res *goip.HostName) {
	if t.caching {
		t.strParamsHostStrCacheLock.Lock()
		defer t.strParamsHostStrCacheLock.Unlock()
		mp := t.strParamsHostStrCache[opts]
		if mp == nil {
			t.strParamsHostStrCache[opts] = make(map[string]*goip.HostName)
		} else {
			res = mp[str]
			if res != nil {
				return
			}
		}
	}

	res = goip.NewHostNameParams(str, opts)
	if t.caching {
		t.strParamsHostStrCache[opts][str] = res
	}
	return
}

func (t *addresses) isLenient() bool {
	return false
}

func (t *addresses) allowsRange() bool {
	return false
}

type rangedAddresses struct {
	*addresses
	rstrIPAddressStrCache         map[string]*goip.IPAddressString
	rstrIPAddressStrCacheLock     *sync.Mutex
	rstrMACAddressStrCache        map[string]*goip.MACAddressString
	rstrMACAddressStrCacheLock    *sync.Mutex
	rstrHostStrCache              map[string]*goip.HostName
	rstrHostStrCacheLock          *sync.Mutex
	rinetAtonStrHostStrCache      map[string]*goip.HostName
	rinetAtonStrIHostStrCacheLock *sync.Mutex
}

func (t *rangedAddresses) useCache(use bool) {
	if use {
		if t.caching {
			return
		}
		t.rstrIPAddressStrCache = make(map[string]*goip.IPAddressString)
		t.rstrIPAddressStrCacheLock = &sync.Mutex{}

		t.rstrMACAddressStrCache = make(map[string]*goip.MACAddressString)
		t.rstrMACAddressStrCacheLock = &sync.Mutex{}

		t.rstrHostStrCache = make(map[string]*goip.HostName)
		t.rstrHostStrCacheLock = &sync.Mutex{}

		t.rinetAtonStrHostStrCache = make(map[string]*goip.HostName)
		t.rinetAtonStrIHostStrCacheLock = &sync.Mutex{}
	} else {
		if !t.caching {
			return
		}
		*t = rangedAddresses{}
	}
	t.addresses.useCache(use)
}

var (
	wildcardAndRangeAddressOptions      = new(address_string_param.IPAddressStringParamsBuilder).Set(addressOptions).AllowAll(true).SetRangeParams(address_string_param.WildcardAndRange).ToParams()
	wildcardOnlyAddressOptions          = new(address_string_param.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParams(address_string_param.WildcardOnly).ToParams()
	noRangeAddressOptions               = new(address_string_param.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParams(address_string_param.NoRange).ToParams()
	wildcardAndRangeMACAddressOptions   = new(address_string_param.MACAddressStringParamsBuilder).Set(macAddressOptions).AllowAll(true).GetFormatParamsBuilder().SetRangeParams(address_string_param.WildcardAndRange).GetParentBuilder().ToParams()
	hostInetAtonwildcardAndRangeOptions = new(address_string_param.HostNameParamsBuilder).
						AllowEmpty(false).
						NormalizeToLowercase(true).
						AllowBracketedIPv6(true).
						AllowBracketedIPv4(true).GetIPAddressParamsBuilder().
						AllowPrefix(true).
						AllowMask(true).
						SetRangeParams(address_string_param.WildcardAndRange).
						AllowInetAton(true).
						AllowEmpty(false).
						AllowAll(true).
						GetIPv4AddressParamsBuilder().
						AllowPrefixLenLeadingZeros(true).
						AllowPrefixesBeyondAddressSize(false).
						AllowWildcardedSeparator(true).
						GetParentBuilder().GetParentBuilder().ToParams()
	inetAtonwildcardAndRangeOptions = new(address_string_param.IPAddressStringParamsBuilder).Set(hostInetAtonwildcardAndRangeOptions.GetIPAddressParams()).ToParams()
	hostWildcardOptions             = new(address_string_param.HostNameParamsBuilder).Set(hostOptions).GetIPAddressParamsBuilder().
					AllowAll(true).SetRangeParams(address_string_param.WildcardOnly).GetParentBuilder().ToParams()
	hostOnlyOptions                     = new(address_string_param.HostNameParamsBuilder).Set(hostOptions).AllowIPAddress(false).ToParams()
	hostWildcardAndRangeOptions         = new(address_string_param.HostNameParamsBuilder).Set(hostWildcardOptions).GetIPAddressParamsBuilder().SetRangeParams(address_string_param.WildcardAndRange).GetParentBuilder().ToParams()
	hostWildcardAndRangeInetAtonOptions = new(address_string_param.HostNameParamsBuilder).Set(hostWildcardOptions).GetIPAddressParamsBuilder().SetRangeParams(address_string_param.WildcardAndRange).AllowInetAton(true).GetParentBuilder().ToParams()
)

func (t *rangedAddresses) getAllCached() (all []*goip.IPAddress) {
	if !t.caching {
		return
	}

	others := t.addresses.getAllCached()
	t.rstrIPAddressStrCacheLock.Lock()
	all = make([]*goip.IPAddress, 0, len(t.rstrIPAddressStrCache)+len(others))
	for _, str := range t.rstrIPAddressStrCache {
		if addr := str.GetAddress(); addr != nil {
			all = append(all, addr)
		}
	}

	t.rstrIPAddressStrCacheLock.Unlock()
	all = append(all, others...)
	return
}

func (t *rangedAddresses) createAddress(str string) (res *goip.IPAddressString) {
	if t.caching {
		t.rstrIPAddressStrCacheLock.Lock()
		defer t.rstrIPAddressStrCacheLock.Unlock()
		res = t.rstrIPAddressStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewIPAddressStringParams(str, wildcardAndRangeAddressOptions)
	if t.caching {
		t.rstrIPAddressStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) createMACAddress(str string) (res *goip.MACAddressString) {
	if t.caching {
		t.rstrMACAddressStrCacheLock.Lock()
		defer t.rstrMACAddressStrCacheLock.Unlock()
		res = t.rstrMACAddressStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewMACAddressStringParams(str, wildcardAndRangeMACAddressOptions)
	if t.caching {
		t.rstrMACAddressStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) createHost(str string) (res *goip.HostName) {
	if t.caching {
		t.rstrHostStrCacheLock.Lock()
		defer t.rstrHostStrCacheLock.Unlock()
		res = t.rstrHostStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewHostNameParams(str, hostWildcardOptions)
	if t.caching {
		t.rstrHostStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) createInetAtonHost(str string) (res *goip.HostName) {
	if t.caching {
		t.rinetAtonStrIHostStrCacheLock.Lock()
		defer t.rinetAtonStrIHostStrCacheLock.Unlock()
		res = t.rinetAtonStrHostStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewHostNameParams(str, hostInetAtonwildcardAndRangeOptions)
	if t.caching {
		t.rinetAtonStrHostStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) allowsRange() bool {
	return true
}

var (
	defaultOptions     = new(address_string_param.IPAddressStringParamsBuilder).ToParams()
	defaultHostOptions = new(address_string_param.HostNameParamsBuilder).ToParams()
)

type allAddresses struct {
	*rangedAddresses
	astrIPAddressStrCache         map[string]*goip.IPAddressString
	astrIPAddressStrCacheLock     *sync.Mutex
	astrHostStrCache              map[string]*goip.HostName
	astrHostStrCacheLock          *sync.Mutex
	ainetAtonStrHostStrCache      map[string]*goip.HostName
	ainetAtonStrIHostStrCacheLock *sync.Mutex
}

func (t *allAddresses) useCache(use bool) {
	if use {
		if t.caching {
			return
		}
		t.astrIPAddressStrCache = make(map[string]*goip.IPAddressString)
		t.astrIPAddressStrCacheLock = &sync.Mutex{}

		t.astrHostStrCache = make(map[string]*goip.HostName)
		t.astrHostStrCacheLock = &sync.Mutex{}

		t.ainetAtonStrHostStrCache = make(map[string]*goip.HostName)
		t.ainetAtonStrIHostStrCacheLock = &sync.Mutex{}
	} else {
		if !t.caching {
			return
		}
		*t = allAddresses{}
	}
	t.rangedAddresses.useCache(use)
}

func (t *allAddresses) getAllCached() (all []*goip.IPAddress) {
	if !t.caching {
		return
	}

	others := t.rangedAddresses.getAllCached()
	t.astrIPAddressStrCacheLock.Lock()
	all = make([]*goip.IPAddress, 0, len(t.astrIPAddressStrCache)+len(others))
	for _, str := range t.astrIPAddressStrCache {
		if addr := str.GetAddress(); addr != nil {
			all = append(all, addr)
		}
	}

	t.astrIPAddressStrCacheLock.Unlock()
	all = append(all, others...)
	return
}

func (t *allAddresses) createAddress(str string) (res *goip.IPAddressString) {
	if t.caching {
		t.astrIPAddressStrCacheLock.Lock()
		defer t.astrIPAddressStrCacheLock.Unlock()
		res = t.astrIPAddressStrCache[str]
		if res != nil {
			return
		}
	}
	res = goip.NewIPAddressStringParams(str, defaultOptions)
	if t.caching {
		t.astrIPAddressStrCache[str] = res
	}
	return
}

func (t *allAddresses) createInetAtonAddress(str string) *goip.IPAddressString {
	return t.createAddress(str)
}

func (t *allAddresses) createHost(str string) (res *goip.HostName) {
	if t.caching {
		t.astrHostStrCacheLock.Lock()
		defer t.astrHostStrCacheLock.Unlock()
		res = t.astrHostStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewHostNameParams(str, defaultHostOptions)
	if t.caching {
		t.astrHostStrCache[str] = res
	}
	return
}

func (t *allAddresses) createInetAtonHost(str string) (res *goip.HostName) {
	if t.caching {
		t.ainetAtonStrIHostStrCacheLock.Lock()
		defer t.ainetAtonStrIHostStrCacheLock.Unlock()
		res = t.ainetAtonStrHostStrCache[str]
		if res != nil {
			return
		}
	}

	res = goip.NewHostNameParams(str, defaultHostOptions)
	if t.caching {
		t.ainetAtonStrHostStrCache[str] = res
	}
	return
}

func (t *allAddresses) isLenient() bool {
	return true
}

var _, _, _ testAddresses = &addresses{}, &rangedAddresses{}, &allAddresses{}
