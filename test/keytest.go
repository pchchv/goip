package test

import (
	"fmt"
	"sync/atomic"

	"github.com/pchchv/goip"
)

type keyTester struct {
	testBase
}

var didKeyTest int32

func (t keyTester) run() {
	didIt := atomic.LoadInt32(&didKeyTest)
	if didIt == 0 {
		cached := t.getAllCached()
		cachedMAC := t.getAllMACCached()
		if len(cached) > 0 || len(cachedMAC) > 0 {
			swapped := atomic.CompareAndSwapInt32(&didKeyTest, 0, 1)
			if swapped {
				if len(cached) > 0 {
					zeroAddr := goip.Address{}
					zeroIPAddr := goip.IPAddress{}
					zero4Addr := goip.IPv4Address{}
					zero6Addr := goip.IPv6Address{}
					cached = append(cached, &zeroIPAddr, zero4Addr.ToIP(), zero6Addr.ToIP())

					//fmt.Printf("testing %d IPs\n", len(cached))
					testGenericKeys[*goip.IPAddress](t, cached)

					addrs := make([]*goip.Address, 0, len(cached)+4)
					for _, addr := range cached {
						addrs = append(addrs, addr.ToAddressBase())
					}
					addrs = append(addrs, &zeroAddr, zeroIPAddr.ToAddressBase(), zero4Addr.ToAddressBase(), zero6Addr.ToAddressBase())
					testGenericKeys[*goip.Address](t, addrs)
					t.testKeys(addrs)

					ipv4Addrs := make([]*goip.IPv4Address, 0, len(cached)+1)
					for _, addr := range cached {
						if addr.IsIPv4() {
							ipv4Addrs = append(ipv4Addrs, addr.ToIPv4())
						}
					}
					ipv4Addrs = append(ipv4Addrs, &zero4Addr)
					testGenericKeys[*goip.IPv4Address](t, ipv4Addrs)

					ipv6Addrs := make([]*goip.IPv6Address, 0, len(cached)+1)
					for _, addr := range cached {
						if addr.IsIPv6() {
							ipv6Addrs = append(ipv6Addrs, addr.ToIPv6())
						}
					}
					ipv6Addrs = append(ipv6Addrs, &zero6Addr)
					testGenericKeys[*goip.IPv6Address](t, ipv6Addrs)

					t.testNetNetIPs(cached)
					t.testNetIPAddrs(cached)
					t.testNetIPs(cached)
				}
				if len(cachedMAC) > 0 {
					zeroAddr := goip.Address{}
					zeroMACAddr := goip.MACAddress{}
					cachedMAC = append(cachedMAC, &zeroMACAddr)

					//fmt.Printf("testing %d MACS\n", len(cachedMAC))
					testGenericKeys[*goip.MACAddress](t, cachedMAC)

					addrs := make([]*goip.Address, 0, len(cached)+1)
					for _, addr := range cached {
						addrs = append(addrs, addr.ToAddressBase())
					}
					addrs = append(addrs, &zeroAddr, zeroMACAddr.ToAddressBase())
					testGenericKeys[*goip.Address](t, addrs)
					t.testKeys(addrs)
				}
			}
		}
	}

	key4 := goip.Key[*goip.IPv4Address]{}
	key6 := goip.Key[*goip.IPv6Address]{}
	ipKey := goip.Key[*goip.IPAddress]{}
	macKey := goip.Key[*goip.MACAddress]{}
	key := goip.Key[*goip.Address]{}

	zeroAddr := goip.Address{}

	zeroMACAddr := goip.MACAddress{}

	keyEquals(t, key4, zero4Addr.ToGenericKey())
	keyEquals(t, key6, zero6Addr.ToGenericKey())
	keyEquals(t, ipKey, zeroIPAddr.ToGenericKey())
	keyEquals(t, key, zeroAddr.ToGenericKey())
	keyEquals(t, macKey, zeroMACAddr.ToGenericKey())

	equals(t, key4.ToAddress(), &zero4Addr)
	equals(t, key6.ToAddress(), &zero6Addr)
	equals(t, macKey.ToAddress(), &zeroMACAddr)
	equals(t, ipKey.ToAddress(), &zeroIPAddr)
	equals(t, key.ToAddress(), &zeroAddr)

	ipv4key := goip.IPv4AddressKey{}
	ipv6key := goip.IPv6AddressKey{}
	macAddrKey := goip.MACAddressKey{}

	keyEquals(t, ipv4key, zero4Addr.ToKey())
	keyEquals(t, ipv6key, zero6Addr.ToKey())
	keyEquals(t, macAddrKey, zeroMACAddr.ToKey())

	equals(t, ipv4key.ToAddress(), &zero4Addr)
	equals(t, ipv6key.ToAddress(), &zero6Addr)
	equals(t, macAddrKey.ToAddress(), &zeroMACAddr)
}

var (
	zeroIPAddr = goip.IPAddress{}
	zero4Addr  = goip.IPv4Address{}
	zero6Addr  = goip.IPv6Address{}
)

func keyEquals[TE interface {
	addFailure(failure)
}, T interface {
	comparable
	fmt.Stringer
}](t TE, one, two T) {
	if two != one {
		f := newAddrFailure("comparison of "+one.String()+" with "+two.String(), nil)
		t.addFailure(f)
	}
}

func (t keyTester) testNetNetIPs(cached []*goip.IPAddress) {
	// test that key creation and address creation from keys works
	for _, addr := range cached {
		addr1Lower := addr.GetLower()
		addr1Upper := addr.GetLower()

		addr2Lower := goip.NewIPAddressFromNetNetIPAddr(addr1Lower.GetNetNetIPAddr())
		addr2Upper := goip.NewIPAddressFromNetNetIPAddr(addr1Upper.GetNetNetIPAddr())

		equals(t, addr1Lower, addr2Lower)
		equals(t, addr1Upper, addr2Upper)

		if addrv4 := addr.ToIPv4(); addrv4 != nil {
			addr1Lower := addrv4.GetLower()
			addr1Upper := addrv4.GetLower()

			addr2Lower := goip.NewIPAddressFromNetNetIPAddr(addr1Lower.GetNetNetIPAddr()).ToIPv4()
			addr2Upper := goip.NewIPAddressFromNetNetIPAddr(addr1Upper.GetNetNetIPAddr()).ToIPv4()

			equals(t, addr1Lower, addr2Lower)
			equals(t, addr1Upper, addr2Upper)
		}
		if addrv6 := addr.ToIPv6(); addrv6 != nil {
			addr1Lower := addrv6.GetLower()
			addr1Upper := addrv6.GetLower()

			addr2Lower := goip.NewIPAddressFromNetNetIPAddr(addr1Lower.GetNetNetIPAddr()).ToIPv6()
			addr2Upper := goip.NewIPAddressFromNetNetIPAddr(addr1Upper.GetNetNetIPAddr()).ToIPv6()

			equals(t, addr1Lower, addr2Lower)
			equals(t, addr1Upper, addr2Upper)
		}
	}
}

func (t keyTester) testNetIPAddrs(cached []*goip.IPAddress) {
	// test that key creation and address creation from keys works
	for _, addr := range cached {
		addr1Lower := addr.GetLower()
		addr1Upper := addr.GetLower()

		if addr.IsIPv6() {
			if addr1Lower.ToIPv6().IsIPv4Mapped() { // net.IP will switch to IPv4, so we might as well just do that ourselves
				addr4, _ := addr1Lower.ToIPv6().GetEmbeddedIPv4Address()
				addr1Lower = addr4.ToIP()
			}
			if addr1Upper.ToIPv6().IsIPv4Mapped() {
				addr4, _ := addr1Upper.ToIPv6().GetEmbeddedIPv4Address()
				addr1Upper = addr4.ToIP()
			}
		}

		addr2Lower, _ := goip.NewIPAddressFromNetIPAddr(addr1Lower.GetNetIPAddr())
		addr2Upper, _ := goip.NewIPAddressFromNetIPAddr(addr1Upper.GetUpperNetIPAddr())

		equals(t, addr1Lower, addr2Lower)
		equals(t, addr1Upper, addr2Upper)

		if addrv4 := addr.ToIPv4(); addrv4 != nil {
			addr1Lower := addrv4.GetLower()
			addr1Upper := addrv4.GetLower()

			addr2Lower, _ := goip.NewIPAddressFromNetIPAddr(addr1Lower.GetNetIPAddr())
			addr2Upper, _ := goip.NewIPAddressFromNetIPAddr(addr1Upper.GetUpperNetIPAddr())

			addr2Lower3 := addr2Lower.ToIPv4()
			addr2Upper3 := addr2Upper.ToIPv4()

			equals(t, addr1Lower, addr2Lower3)
			equals(t, addr1Upper, addr2Upper3)
		}
		if addrv6 := addr.ToIPv6(); addrv6 != nil {
			addr1Lower := addrv6.GetLower()
			addr1Upper := addrv6.GetLower()

			if !addr1Lower.IsIPv4Mapped() { // net.IP will switch to IPv4, so we might as well just do that ourselves
				addr2Lower, _ := goip.NewIPAddressFromNetIPAddr(addr1Lower.GetNetIPAddr())
				addr2Lower3 := addr2Lower.ToIPv6()
				equals(t, addr1Lower, addr2Lower3)
			}
			if !addr1Upper.IsIPv4Mapped() {
				addr2Upper, _ := goip.NewIPAddressFromNetIPAddr(addr1Upper.GetUpperNetIPAddr())
				addr2Upper3 := addr2Upper.ToIPv6()
				equals(t, addr1Upper, addr2Upper3)
			}
		}
		t.incrementTestCount()
	}
}

func (t keyTester) testNetIPs(cached []*goip.IPAddress) {
	// test that key creation and address creation from keys works
	for _, addr := range cached {
		addr1Lower := addr.GetLower()
		addr1Upper := addr.GetLower()
		if addr.IsIPv6() {
			if addr.ToIPv6().HasZone() { // net.IP cannot store zone, so we need to drop it to check equality
				addr1Lower = addr1Lower.ToIPv6().WithoutZone().ToIP()
				addr1Upper = addr1Upper.ToIPv6().WithoutZone().ToIP()
			}
			if addr1Lower.ToIPv6().IsIPv4Mapped() { // net.IP will switch to IPv4, so we might as well just do that ourselves
				addr4, _ := addr1Lower.ToIPv6().GetEmbeddedIPv4Address()
				addr1Lower = addr4.ToIP()
			}
			if addr1Upper.ToIPv6().IsIPv4Mapped() {
				addr4, _ := addr1Upper.ToIPv6().GetEmbeddedIPv4Address()
				addr1Upper = addr4.ToIP()
			}
		}

		addr2Lower, _ := goip.NewIPAddressFromNetIP(addr1Lower.GetNetIP())
		addr2Upper, _ := goip.NewIPAddressFromNetIP(addr1Upper.GetUpperNetIP())
		equals(t, addr1Lower, addr2Lower)
		equals(t, addr1Upper, addr2Upper)

		if addrv4 := addr.ToIPv4(); addrv4 != nil {
			addr1Lower := addrv4.GetLower()
			addr1Upper := addrv4.GetLower()

			addr2Lower, _ := goip.NewIPAddressFromNetIPAddr(addr1Lower.GetNetIPAddr())
			addr2Upper, _ := goip.NewIPAddressFromNetIPAddr(addr1Upper.GetUpperNetIPAddr())

			addr2Lower3 := addr2Lower.ToIPv4()
			addr2Upper3 := addr2Upper.ToIPv4()

			equals(t, addr1Lower, addr2Lower3)
			equals(t, addr1Upper, addr2Upper3)
		}
		if addrv6 := addr.ToIPv6(); addrv6 != nil {
			addr1Lower := addrv6.GetLower()
			addr1Upper := addrv6.GetLower()

			if addrv6.HasZone() { // net.IP cannot store zone, so we need to drop it to check equality
				addr1Lower = addr1Lower.WithoutZone()
				addr1Upper = addr1Upper.WithoutZone()
			}
			if !addr1Lower.IsIPv4Mapped() { // net.IP will switch to IPv4, so we might as well just do that ourselves
				addr2Lower, _ := goip.NewIPAddressFromNetIPAddr(addr1Lower.GetNetIPAddr())
				addr2Lower3 := addr2Lower.ToIPv6()
				equals(t, addr1Lower, addr2Lower3)
			}
			if !addr1Upper.IsIPv4Mapped() {
				addr2Upper, _ := goip.NewIPAddressFromNetIPAddr(addr1Upper.GetUpperNetIPAddr())
				addr2Upper3 := addr2Upper.ToIPv6()
				equals(t, addr1Upper, addr2Upper3)
			}
		}
		t.incrementTestCount()
	}
}

func (t keyTester) testKeys(cached []*goip.Address) {
	// test that key creation and address creation from keys works
	//var ipv4Count, ipv6Count, macCount uint64
	for _, addr := range cached {
		addr2 := addr.ToKey().ToAddress()
		equals(t, addr, addr2)
		if ip := addr.ToIP(); ip != nil {
			other := ip.ToKey().ToAddress()
			equals(t, ip, other)
			if !ip.IsMultiple() && !(ip.IsIPv6() && ip.ToIPv6().HasZone()) {
				if !ip.IsMultiple() && !ip.IsMax() {
					oneUp := ip.Increment(1)
					ipRange := goip.NewSequentialRange(ip, oneUp)
					ipRangeBack := ipRange.ToKey().ToSeqRange()
					if !equals(t, ipRangeBack.GetUpper(), oneUp) {
						equals(t, ipRangeBack.GetUpper(), oneUp)
					}
					if !equals(t, ipRangeBack.GetLower(), ip) {
						fmt.Println(ip, oneUp, ipRange, ipRangeBack, ipRangeBack.GetLower(), ip)
						equals(t, ipRangeBack.GetLower(), ip)
					}
				}
			}
		}
		if addrv4 := addr.ToIPv4(); addrv4 != nil {
			other := addrv4.ToKey().ToAddress()
			equals(t, addrv4, other)
			if !addrv4.IsMultiple() {
				ipRange := goip.NewSequentialRange(addrv4, &zero4Addr)
				if ipRange == nil {
					goip.NewSequentialRange(addrv4, &zero4Addr)
				}
				ipRangeBack := ipRange.ToKey().ToSeqRange()
				equals(t, ipRangeBack.GetLower(), &zero4Addr)
				equals(t, ipRangeBack.GetUpper(), addrv4)
				if !addrv4.IsMax() {
					oneUp := addrv4.Increment(1)
					ipRange := goip.NewSequentialRange(addrv4, oneUp)
					ipRangeBack := ipRange.ToKey().ToSeqRange()
					if !equals(t, ipRangeBack.GetUpper(), oneUp) {
						fmt.Println(addrv4, oneUp, ipRange, ipRangeBack, ipRangeBack.GetUpper())
						equals(t, ipRangeBack.GetUpper(), oneUp)
					}
					if !equals(t, ipRangeBack.GetLower(), addrv4) {
						fmt.Println(addrv4, oneUp, ipRange, ipRangeBack, ipRangeBack.GetLower())
						equals(t, ipRangeBack.GetLower(), addrv4)
					}
				}
			}
		}
		if addrv6 := addr.ToIPv6(); addrv6 != nil {
			other := addrv6.ToKey().ToAddress()
			equals(t, addrv6, other)
			if !addrv6.IsMultiple() && !addrv6.HasZone() {
				ipRange := goip.NewSequentialRange(addrv6, &zero6Addr)
				ipRangeBack := ipRange.ToKey().ToSeqRange()
				equals(t, ipRangeBack.GetLower(), &zero6Addr)
				equals(t, ipRangeBack.GetUpper(), addrv6)

				if !addrv6.IsMax() {
					oneUp := addrv6.Increment(1)
					ipRange := goip.NewSequentialRange(addrv6, oneUp)
					ipRangeBack := ipRange.ToKey().ToSeqRange()
					if !equals(t, ipRangeBack.GetUpper(), oneUp) {
						fmt.Println(addrv6, oneUp, ipRange, ipRangeBack, ipRangeBack.GetUpper())
						equals(t, ipRangeBack.GetUpper(), oneUp)
					}
					if !equals(t, ipRangeBack.GetLower(), addrv6) {
						fmt.Println(addrv6, oneUp, ipRange, ipRangeBack, ipRangeBack.GetLower())
						equals(t, ipRangeBack.GetLower(), addrv6)
					}
				}
			}
		}
		if addrmac := addr.ToMAC(); addrmac != nil {
			other := addrmac.ToKey().ToAddress()
			equals(t, addrmac, other)
			//macCount++
		}
		t.incrementTestCount()
	}
}

type AddrConstraint[T goip.KeyConstraint[T]] interface {
	goip.GenericKeyConstraint[T]
	goip.AddressType
}

func testGenericKeys[T AddrConstraint[T]](t keyTester, cached []T) {
	for _, addr := range cached {
		addr2 := addr.ToGenericKey().ToAddress()
		equals(t, addr, addr2)
		t.incrementTestCount()
	}
}

func equals[TE interface{ addFailure(failure) }, T goip.AddressType](t TE, one, two T) bool {
	if !one.Equal(two) || !two.Equal(one) {
		f := newAddrFailure("comparison of "+one.String()+" with "+two.String(), two.ToAddressBase())
		t.addFailure(f)
		return false
	} else if one.Compare(two) != 0 || two.Compare(one) != 0 {
		f := newAddrFailure("comparison of "+one.String()+" with "+two.String(), two.ToAddressBase())
		t.addFailure(f)
		return false
	}
	return true
}
