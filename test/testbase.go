package test

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pchchv/goip"
	"github.com/pchchv/goip/address_string"
)

func Test(isLimited bool) {
	var addresses addresses
	acc := testAccumulator{lock: &sync.Mutex{}}
	fullTest := false
	fmt.Println("Starting TestRunner")
	startTime := time.Now()
	rangedAddresses := rangedAddresses{addresses: &addresses}
	allAddresses := allAddresses{rangedAddresses: &rangedAddresses}
	if isLimited {
		acc = testAll(addresses, rangedAddresses, allAddresses, fullTest)
	} else {
		// warm up with no caching
		acc = testAll(addresses, rangedAddresses, allAddresses, fullTest)
		allAddresses.useCache(true)
		rangedAddresses.useCache(true)
		addresses.useCache(true)
		routineCount := 100
		var wg sync.WaitGroup
		wg.Add(routineCount)
		for i := 0; i < routineCount; i++ {
			go func() {
				defer wg.Done()
				newAcc := testAll(addresses, rangedAddresses, allAddresses, fullTest)
				acc.add(newAcc)
			}()
		}
		wg.Wait()
	}

	endTime := time.Now().Sub(startTime)
	if len(acc.failures) > 0 {
		fmt.Printf("%v\n", acc.failures)
	}
	fmt.Printf("TestRunner\ntest count: %d\nfail count: %d\n", acc.counter, len(acc.failures))
	fmt.Printf("Done: TestRunner\nDone in %v\n", endTime)
}

func testAll(addresses addresses, rangedAddresses rangedAddresses, allAddresses allAddresses, fullTest bool) testAccumulator {
	acc := testAccumulator{lock: &sync.Mutex{}}

	tester := ipAddressTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	tester.run()

	hTester := hostTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	hTester.run()

	macTester := macAddressTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	macTester.run()

	rangeTester := ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}
	rangeTester.run()

	hostRTester := hostRangeTester{hostTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}
	hostRTester.run()

	macRangeTester := macAddressRangeTester{macAddressTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}
	macRangeTester.run()

	allTester := ipAddressAllTester{ipAddressRangeTester{ipAddressTester{testBase{testResults: &acc, testAddresses: &allAddresses, fullTest: fullTest}}}}
	allTester.run()

	hostATester := hostAllTester{hostRangeTester{hostTester{testBase{testResults: &acc, testAddresses: &rangedAddresses, fullTest: fullTest}}}}
	hostATester.run()
	//rangedAddresses.getAllCached()

	sTypesTester := specialTypesTester{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	sTypesTester.run()

	addressOrderTester := addressOrderTest{testBase{testResults: &acc, testAddresses: &addresses, fullTest: fullTest}}
	addressOrderTester.run()
	//addresses.getAllCached()

	// because trie test creates a mega tree from all previously created addresses, it should go last
	genericTrieTester := trieTesterGeneric{testBase{testResults: &acc, testAddresses: &allAddresses, fullTest: fullTest}}
	genericTrieTester.run()

	keyTester := keyTester{testBase{testResults: &acc, testAddresses: &allAddresses, fullTest: fullTest}}
	keyTester.run()

	return acc
}

type testResults interface {

	// test failures
	addFailure(failure)

	// store test counts
	incrementTestCount()
}

type testAccumulator struct {
	counter  int64
	failures []failure
	lock     *sync.Mutex
}

func (t *testAccumulator) add(other testAccumulator) {
	t.lock.Lock()
	t.failures = append(t.failures, other.failures...)
	t.counter += other.counter
	//fmt.Printf("added %d to get %d in counter\n", other.counter, t.counter)
	t.lock.Unlock()
}

func (t *testAccumulator) addFailure(f failure) {
	t.failures = append(t.failures, f)
}

func (t *testAccumulator) incrementTestCount() {
	t.counter++
}

type testBase struct {
	fullTest bool
	testResults
	testAddresses
}

func (t testBase) testReverse(series goip.ExtendedSegmentSeries, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	segmentsReversed := series.ReverseSegments()
	divCount := series.GetDivisionCount()
	for i := 0; i < series.GetSegmentCount(); i++ {
		seg0 := series.GetSegment(i)
		seg1 := segmentsReversed.GetSegment(divCount - i - 1)
		if !seg0.Equal(seg1) {
			t.addFailure(newSegmentSeriesFailure("reversal: "+series.String()+" "+segmentsReversed.String(), series))
			return
		}
	}
	bytesReversed, err := segmentsReversed.ReverseBytes()
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	bytesReversed, err = bytesReversed.ReverseBytes()
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	bytesReversed = bytesReversed.ReverseSegments()
	if !series.Equal(bytesReversed) {
		t.addFailure(newSegmentSeriesFailure("bytes reversal: "+series.String(), series))
		return
	}
	bitsReversed, err := series.ReverseBits(false)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	var equalityResult = series.Equal(bitsReversed)
	if bitsReversedIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		t.addFailure(newSegmentSeriesFailure("bit reversal 2a: "+series.String()+" "+bitsReversed.String(), series))
		return
	}
	bitsReversed, err = bitsReversed.ReverseBits(false)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equal(bitsReversed) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 2: "+series.String(), series))
		return
	}

	bitsReversed2, err := series.ReverseBits(true)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	equalityResult = series.Equal(bitsReversed2)
	if bitsReversedPerByteIsSame {
		equalityResult = !equalityResult
	}
	if equalityResult {
		t.addFailure(newSegmentSeriesFailure("bit reversal 3a: "+series.String(), series))
		return
	}
	bitsReversed2, err = bitsReversed2.ReverseBits(true)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	if !series.Equal(bitsReversed2) {
		t.addFailure(newSegmentSeriesFailure("bit reversal 3: "+series.String(), series))
		return
	}

	bytes := series.Bytes() // ab cd ef becomes fe dc ba
	bitsReversed3, err := series.ReverseBytes()
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed "+err.Error(), series))
		return
	}
	for i, j := 0, len(bytes)-1; i < bitsReversed3.GetSegmentCount(); i++ {
		seg := bitsReversed3.GetSegment(i)
		segBytes := seg.Bytes()
		if !seg.IsMultiple() {
			bytesLen := len(segBytes) >> 1
			last := len(segBytes) - 1
			for m := 0; m < bytesLen; m++ {
				first, lastByte := segBytes[m], segBytes[last-m]
				segBytes[m], segBytes[last-m] = lastByte, first
			}
		}
		for k := seg.GetByteCount() - 1; k >= 0; k-- {
			if segBytes[k] != bytes[j] { //reversal 4: 1:1:1:1-fffe:2:3:3:3 300:300:300:200:1-fffe:100:100:100
				t.addFailure(newSegmentSeriesFailure("reversal 4: "+series.String()+" "+bitsReversed3.String(), series))
				return
			}
			j--
		}
	}
}

func (t testBase) testSegmentSeriesPrefixes(original goip.ExtendedSegmentSeries,
	prefix, adjustment goip.BitCount,
	_, _,
	adjusted,
	prefixSet,
	_ goip.ExtendedSegmentSeries) {
	for j := 0; j < 2; j++ {
		var removed goip.ExtendedSegmentSeries
		var err error
		if j == 0 {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount() + 1)
		} else {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount())
		}
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("removed prefix error: "+err.Error(), original))
			break
		}
		if original.IsPrefixed() {
			prefLength := original.GetPrefixLen().Len()
			bitsSoFar := goip.BitCount(0)
			for i := 0; i < removed.GetSegmentCount(); i++ {
				prevBitsSoFar := bitsSoFar
				seg := removed.GetSegment(i)
				bitsSoFar += seg.GetBitCount()
				if prefLength >= bitsSoFar {
					if !seg.Equal(original.GetSegment(i)) {
						t.addFailure(newSegmentSeriesFailure("removed prefix: "+removed.String(), original))
						break
					}
				} else if prefLength <= prevBitsSoFar {
					if !seg.IsZero() {
						t.addFailure(newSegmentSeriesFailure("removed prefix all: "+removed.String(), original))
						break
					}
				} else {
					segPrefix := prefLength - prevBitsSoFar
					mask := ^goip.SegInt(0) << uint(seg.GetBitCount()-segPrefix)
					lower := seg.GetSegmentValue()
					upper := seg.GetUpperSegmentValue()
					if (lower&mask) != lower || (upper&mask) != upper {
						t.addFailure(newSegmentSeriesFailure("prefix app: "+removed.String()+" "+strconv.Itoa(int(lower&mask))+" "+strconv.Itoa(int(upper&mask)), original))
						break
					}
				}
			}
		} else if !removed.Equal(original) {
			t.addFailure(newSegmentSeriesFailure("prefix removed: "+removed.String(), original))
		}
	}
}

func (t testBase) testPrefixes(original goip.ExtendedIPSegmentSeries,
	prefix, adjustment goip.BitCount,
	_, _,
	adjusted,
	prefixSet,
	_ goip.ExtendedIPSegmentSeries) {
	for j := 0; j < 2; j++ {
		var removed goip.ExtendedIPSegmentSeries
		var err error
		if j == 0 {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount() + 1)
		} else {
			removed, err = original.AdjustPrefixLenZeroed(original.GetBitCount())
		}
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("removed prefix error: "+err.Error(), original))
			break
		}
		if original.IsPrefixed() {
			prefLength := original.GetPrefixLen().Len()
			bitsSoFar := goip.BitCount(0)
			for i := 0; i < removed.GetSegmentCount(); i++ {
				prevBitsSoFar := bitsSoFar
				seg := removed.GetSegment(i)
				bitsSoFar += seg.GetBitCount()
				if prefLength >= bitsSoFar {
					if !seg.Equal(original.GetSegment(i)) {
						t.addFailure(newSegmentSeriesFailure("removed prefix: "+removed.String(), original))
						break
					}
				} else if prefLength <= prevBitsSoFar {
					if !seg.IsZero() {
						t.addFailure(newSegmentSeriesFailure("removed prefix all: "+removed.String(), original))
						break
					}
				} else {
					segPrefix := prefLength - prevBitsSoFar
					mask := ^goip.SegInt(0) << uint(seg.GetBitCount()-segPrefix)
					lower := seg.GetSegmentValue()
					upper := seg.GetUpperSegmentValue()
					if (lower&mask) != lower || (upper&mask) != upper {
						//removed = original.removePrefixLength();
						t.addFailure(newSegmentSeriesFailure("prefix app: "+removed.String()+" "+strconv.Itoa(int(lower&mask))+" "+strconv.Itoa(int(upper&mask)), original))
						break
					}
				}
			}
		} else if !removed.Equal(original) {
			t.addFailure(newSegmentSeriesFailure("prefix removed: "+removed.String(), original))
		}
	}
	var adjustedSeries goip.ExtendedIPSegmentSeries
	adjustedSeries, err := original.AdjustPrefixLenZeroed(adjustment)
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
		return
	}
	adjustedPrefix := adjustedSeries.GetPrefixLen()
	if (original.IsPrefixed() && adjustedPrefix.Matches(original.GetBitCount()+adjustment)) ||
		(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) { //xxxxx if we do not have prefix block, then our positive adjustment creates what would be one, then our expected is one which is wrong
		// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
		adjusted, err = adjusted.ToZeroHost()
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("adjusted prefix error: "+err.Error(), original))
			return
		}
	}

	if !adjustedSeries.Equal(adjusted) {
		t.addFailure(newSegmentSeriesFailure("prefix adjusted: "+adjustedSeries.String(), adjusted))
		_, _ = original.AdjustPrefixLenZeroed(adjustment)
	} else {
		adjustedSeries, err = original.SetPrefixLenZeroed(prefix)
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
			return
		}
		if (original.IsPrefixed() && original.GetPrefixLen().Matches(original.GetBitCount())) ||
			(!original.IsPrefixBlock() && adjustedSeries.IsZeroHost()) {
			// all host bits of matching address are zeroed out, so we must get the zero host and not the prefix subnet
			prefixSet, err = prefixSet.ToZeroHost()
			if err != nil {
				t.addFailure(newSegmentSeriesFailure("set prefix error: "+err.Error(), original))
				return
			}
		}

		setPrefix := adjustedSeries.GetPrefixLen()
		if !adjustedSeries.Equal(prefixSet) {
			//fmt.Println(original.String() + " set: " + adjustedSeries.String() + " expected: " + prefixSet.String() + " set prefix: " + bitCountToString(prefix))
			t.addFailure(newSegmentSeriesFailure("prefix set: "+adjustedSeries.String(), prefixSet))
		} else {
			originalPref := original.GetPrefixLen()
			var expected ExpectedPrefixes
			bitLength := original.GetBitCount()
			if originalPref == nil {
				if adjustment <= 0 {
					expected.adjusted = cacheTestBits(bitLength + adjustment)
				} else {
					expected.adjusted = cacheTestBits(adjustment)
				}
				expected.set = cacheTestBits(prefix)
			} else {
				adj := min(max(0, originalPref.Len()+adjustment), original.GetBitCount())
				expected.adjusted = cacheTestBits(adj)
				expected.set = cacheTestBits(prefix)
			}
			if !expected.compare(adjustedPrefix, setPrefix) {
				t.addFailure(newSegmentSeriesFailure("expected: "+expected.adjusted.String()+" actual "+adjustedPrefix.String()+" expected: "+expected.set.String()+" actual "+setPrefix.String(), original))
			}
		}
	}
}

func (t testBase) testReplace(front, back *goip.Address, fronts, backs []string, sep byte, isMac bool) {
	bitsPerSegment := front.GetBitsPerSegment()
	segmentCount := front.GetSegmentCount()
	isIpv4 := !isMac && segmentCount == goip.IPv4SegmentCount
	prefixes := strings.Builder{}
	prefixes.WriteString("[\n")
	for replaceTargetIndex := 0; replaceTargetIndex < len(fronts); replaceTargetIndex++ {
		if replaceTargetIndex > 0 {
			prefixes.WriteString(",\n")
		}
		prefixes.WriteString("[")
		for replaceCount := 0; replaceCount < len(fronts)-replaceTargetIndex; replaceCount++ {
			if replaceCount > 0 {
				prefixes.WriteString(",\n")
			}
			prefixes.WriteString("    [")
			lowest := strings.Builder{}
			for replaceSourceIndex := 0; replaceSourceIndex < len(backs)-replaceCount; replaceSourceIndex++ {
				//We are replacing replaceCount segments in front at index replaceTargetIndex with the same number of segments starting at replaceSourceIndex in back
				str := strings.Builder{}
				k := 0
				for ; k < replaceTargetIndex; k++ {
					if str.Len() > 0 {
						str.WriteByte(sep)
					}
					str.WriteString(fronts[k])
				}
				current := k
				limit := replaceCount + current
				for ; k < limit; k++ {
					if str.Len() > 0 {
						str.WriteByte(sep)
					}
					str.WriteString(backs[replaceSourceIndex+k-current])
				}
				for ; k < segmentCount; k++ {
					if str.Len() > 0 {
						str.WriteByte(sep)
					}
					str.WriteString(fronts[k])
				}
				var prefix goip.PrefixLen
				frontPrefixed := front.IsPrefixed()
				if frontPrefixed && (front.GetPrefixLen().Len() <= goip.BitCount(replaceTargetIndex)*bitsPerSegment) && (isMac || replaceTargetIndex > 0) { //when replaceTargetIndex is 0, slight difference between mac and ipvx, for ipvx we do not account for a front prefix of 0
					prefix = front.GetPrefixLen()
				} else if back.IsPrefixed() && (back.GetPrefixLen().Len() <= goip.BitCount(replaceSourceIndex+replaceCount)*bitsPerSegment) && (isMac || replaceCount > 0) { //when replaceCount 0, slight difference between mac and ipvx, for ipvx we do not account for a back prefix
					prefix = cacheTestBits((goip.BitCount(replaceTargetIndex) * bitsPerSegment) + max(0, back.GetPrefixLen().Len()-(goip.BitCount(replaceSourceIndex)*bitsPerSegment)))
				} else if frontPrefixed {
					if front.GetPrefixLen().Len() <= goip.BitCount(replaceTargetIndex+replaceCount)*bitsPerSegment {
						prefix = cacheTestBits(goip.BitCount(replaceTargetIndex+replaceCount) * bitsPerSegment)
					} else {
						prefix = front.GetPrefixLen()
					}
				}
				replaceStr := " replacing " + strconv.Itoa(replaceCount) + " segments in " + front.String() + " at index " + strconv.Itoa(replaceTargetIndex) +
					" with segments from " + back.String() + " starting at " + strconv.Itoa(replaceSourceIndex)

				var new1, new2 *goip.Address
				if isMac {
					fromMac := front.ToMAC()
					new1 = fromMac.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToMAC(), replaceSourceIndex).ToAddressBase()
					hostIdStr := t.createMACAddress(str.String())
					new2 = hostIdStr.GetAddress().ToAddressBase()
					if prefix != nil {
						new2 = new2.SetPrefixLen(prefix.Len())
					}
				} else {
					if prefix != nil {
						str.WriteByte('/')
						str.WriteString(prefix.String())
					}
					hostIdStr := t.createAddress(str.String())
					new2 = hostIdStr.GetAddress().ToAddressBase()
					if isIpv4 {
						frontIPv4 := front.ToIPv4()
						new1 = frontIPv4.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToIPv4(), replaceSourceIndex).ToAddressBase()
					} else {
						frontIPv6 := front.ToIPv6()
						new1 = frontIPv6.ReplaceLen(replaceTargetIndex, replaceTargetIndex+replaceCount, back.ToIPv6(), replaceSourceIndex).ToAddressBase()
					}
				}
				if !new1.Equal(new2) {
					failStr := "Replacement was " + new1.String() + " expected was " + new2.String() + " " + replaceStr
					t.addFailure(newIPAddrFailure(failStr, front.ToIP()))

				}
				if lowest.Len() > 0 {
					lowest.WriteByte(',')
				}
				lowest.WriteString(prefix.String())
			}
			prefixes.WriteString(lowest.String())
			prefixes.WriteByte(']')
		}
		prefixes.WriteByte(']')
	}
	prefixes.WriteByte(']')
}

func (t testBase) testAppendAndInsert(front, back *goip.Address, fronts, backs []string, sep byte, expectedPref []goip.PrefixLen, isMac bool) {
	extra := 0
	if isMac {
		extra = goip.ExtendedUniqueIdentifier64SegmentCount - front.GetSegmentCount()
	}
	bitsPerSegment := front.GetBitsPerSegment()
	isIpv4 := !isMac && front.GetSegmentCount() == goip.IPv4SegmentCount
	for i := 0; i < len(fronts); i++ {
		str := strings.Builder{}
		k := 0
		for ; k < i; k++ {
			if str.Len() > 0 {
				str.WriteByte(sep)
			}
			str.WriteString(fronts[k])
		}
		for ; k < len(fronts); k++ {
			if str.Len() > 0 {
				str.WriteByte(sep)
			}
			str.WriteString(backs[k])
		}

		//Split up into two sections to test append
		frontSection := front.GetSubSection(0, i)
		backSection := back.GetTrailingSection(i)
		var backSectionInvalid, frontSectionInvalid *goip.AddressSection
		if i-(1+extra) >= 0 && i+1+extra <= front.GetSegmentCount() {
			backSectionInvalid = back.GetTrailingSection(i - (1 + extra))
			frontSectionInvalid = front.GetSubSection(0, i+1+extra)
		}

		//Split up even further into 3 sections to test insert
		//List<AddressSection[]> splits = new ArrayList<AddressSection[]>(front.getSegmentCount() + 3);
		var splits [][]*goip.AddressSection
		for m := 0; m <= frontSection.GetSegmentCount(); m++ {
			sub1 := frontSection.GetSubSection(0, m)
			sub2 := frontSection.GetSubSection(m, frontSection.GetSegmentCount())
			splits = append(splits, []*goip.AddressSection{sub1, sub2, backSection})
		}
		for m := 0; m <= backSection.GetSegmentCount(); m++ {
			sub1 := backSection.GetSubSection(0, m)
			sub2 := backSection.GetSubSection(m, backSection.GetSegmentCount())
			splits = append(splits, []*goip.AddressSection{frontSection, sub1, sub2})
		}
		//now you can insert the middle one after appending the first and last
		//Keep in mind that inserting the first one is like a prepend, which is like an append
		//Inserting the last one is an append
		//We already test append pretty good
		//So really, just insert the middle one after appending first and last
		var splitsJoined []*goip.Address

		var mixed, mixed2 *goip.Address
		if isMac {
			hostIdStr := t.createMACAddress(str.String())
			mixed = hostIdStr.GetAddress().ToAddressBase()
			ignoreFrontPrefLen := i == 0 // we ignore the front prefix len if we are taking 0 bits from the front
			if !ignoreFrontPrefLen && front.IsPrefixed() && front.GetPrefixLen().Len() <= goip.BitCount(i)*bitsPerSegment {
				mixed = mixed.SetPrefixLen(front.GetPrefixLen().Len())
			} else if back.IsPrefixed() {
				mixed = mixed.SetPrefixLen(max(goip.BitCount(i)*bitsPerSegment, back.GetPrefixLen().Len()))
			}
			sec := frontSection.ToMAC().Append(backSection.ToMAC())
			mixed2x, err := goip.NewMACAddress(sec)
			if err != nil {
				t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
			}
			mixed2 = mixed2x.ToAddressBase()

			if frontSectionInvalid != nil && backSectionInvalid != nil {
				//This doesn't fail anymore because we allow large sections
				newSec := (frontSection.ToMAC()).Append(backSectionInvalid.ToMAC())
				if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
					t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
				}
				newSec = (frontSectionInvalid.ToMAC()).Append(backSection.ToMAC())
				if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
					t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
				}
			}
			for o := 0; o < len(splits); o++ {
				split := splits[o]
				f := split[0]
				g := split[1]
				h := split[2]
				sec = f.ToMAC().Append(h.ToMAC())
				sec = sec.Insert(f.GetSegmentCount(), g.ToMAC())
				if h.IsPrefixed() && h.GetPrefixLen().Len() == 0 && !f.IsPrefixed() {
					gPref := goip.BitCount(g.GetSegmentCount()) * goip.MACBitsPerSegment
					if g.IsPrefixed() {
						gPref = g.GetPrefixLen().Len()
					}
					sec = sec.SetPrefixLen(goip.BitCount(f.GetSegmentCount())*goip.MACBitsPerSegment + gPref)
				}
				mixed3, err := goip.NewMACAddress(sec)
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				splitsJoined = append(splitsJoined, mixed3.ToAddressBase())
			}
		} else {
			if front.IsPrefixed() && front.GetPrefixLen().Len() <= (goip.BitCount(i)*bitsPerSegment) && i > 0 {
				str.WriteByte('/')
				str.WriteString(strconv.Itoa(int(front.GetPrefixLen().Len())))
			} else if back.IsPrefixed() {
				str.WriteByte('/')
				if goip.BitCount(i)*bitsPerSegment > back.GetPrefixLen().Len() {
					str.WriteString(strconv.Itoa(i * int(bitsPerSegment)))
				} else {
					str.WriteString(strconv.Itoa(int(back.GetPrefixLen().Len())))
				}
			}
			hostIdStr := t.createAddress(str.String())
			mixed = hostIdStr.GetAddress().ToAddressBase()

			if isIpv4 {
				sec := (frontSection.ToIPv4()).Append(backSection.ToIPv4())
				mixed2x, err := goip.NewIPv4Address(sec)
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				mixed2 = mixed2x.ToAddressBase()

				if frontSectionInvalid != nil && backSectionInvalid != nil {
					newSec := (frontSection.ToIPv4()).Append(backSectionInvalid.ToIPv4())
					if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					newSec = (frontSectionInvalid.ToIPv4()).Append(backSection.ToIPv4())
					if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
				}
				for o := 0; o < len(splits); o++ {
					split := splits[o]
					f := split[0]
					g := split[1]
					h := split[2]
					sec = (f.ToIPv4()).Append(h.ToIPv4())
					sec = sec.Insert(f.GetSegmentCount(), g.ToIPv4())
					if h.IsPrefixed() && h.GetPrefixLen().Len() == 0 && !f.IsPrefixed() {
						gPref := goip.BitCount(g.GetSegmentCount()) * goip.IPv4BitsPerSegment
						if g.IsPrefixed() {
							gPref = g.GetPrefixLen().Len()
						}
						sec = sec.SetPrefixLen(goip.BitCount(f.GetSegmentCount())*goip.IPv4BitsPerSegment + gPref)
					}
					mixed3, err := goip.NewIPv4Address(sec)
					if err != nil {
						t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
					}
					splitsJoined = append(splitsJoined, mixed3.ToAddressBase())
				}
			} else { // IPv6
				sec := frontSection.ToIPv6().Append(backSection.ToIPv6())
				mixed2x, err := goip.NewIPv6Address(sec)
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
				}
				mixed2 = mixed2x.ToAddressBase()
				if frontSectionInvalid != nil && backSectionInvalid != nil {
					newSec := (frontSection.ToIPv6()).Append(backSectionInvalid.ToIPv6())
					if newSec.GetSegmentCount() != frontSection.GetSegmentCount()+backSectionInvalid.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
					newSec = (frontSectionInvalid.ToIPv6()).Append(backSection.ToIPv6())
					if newSec.GetSegmentCount() != frontSectionInvalid.GetSegmentCount()+backSection.GetSegmentCount() {
						t.addFailure(newSegmentSeriesFailure("unexpected seg count: "+strconv.Itoa(newSec.GetSegmentCount()), newSec))
					}
				}
				for o := 0; o < len(splits); o++ {
					split := splits[o]
					f := split[0]
					g := split[1]
					h := split[2]
					sec = f.ToIPv6().Append(h.ToIPv6())
					sec = sec.Insert(f.GetSegmentCount(), g.ToIPv6())
					if h.IsPrefixed() && h.GetPrefixLen().Len() == 0 && !f.IsPrefixed() {
						gPref := goip.BitCount(g.GetSegmentCount()) * goip.IPv6BitsPerSegment
						if g.IsPrefixed() {
							gPref = g.GetPrefixLen().Len()
						}
						sec = sec.SetPrefixLen(goip.BitCount(f.GetSegmentCount())*goip.IPv6BitsPerSegment + gPref)
					}
					mixed3, err := goip.NewIPv6Address(sec)
					if err != nil {
						t.addFailure(newSegmentSeriesFailure("unexpected error: "+err.Error(), sec))
					}
					splitsJoined = append(splitsJoined, mixed3.ToAddressBase())
				}
			}
		}
		if !mixed.Equal(mixed2) {
			t.addFailure(newSegmentSeriesFailure("mixed was "+mixed.String()+" expected was "+mixed2.String(), mixed))
		}
		if !expectedPref[i].Equal(mixed.GetPrefixLen()) {
			t.addFailure(newSegmentSeriesFailure("mixed prefix was "+mixed.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed))
		}
		if !expectedPref[i].Equal(mixed2.GetPrefixLen()) {
			t.addFailure(newSegmentSeriesFailure("mixed2 prefix was "+mixed2.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed2))
		}
		for o := 0; o < len(splitsJoined); o++ {
			mixed3 := splitsJoined[o]
			if !mixed.Equal(mixed3) {
				t.addFailure(newSegmentSeriesFailure("mixed was "+mixed3.String()+" expected was "+mixed.String(), mixed3))
			}
			if !mixed3.Equal(mixed2) {
				t.addFailure(newSegmentSeriesFailure("mixed was "+mixed3.String()+" expected was "+mixed2.String(), mixed3))
			}
			if !expectedPref[i].Equal(mixed3.GetPrefixLen()) {
				t.addFailure(newSegmentSeriesFailure("mixed3 prefix was "+mixed3.GetPrefixLen().String()+" expected was "+expectedPref[i].String(), mixed3))
			}
		}
	}
	t.incrementTestCount()
}

func (t testBase) testIncrement(orig *goip.Address, increment int64, expectedResult *goip.Address) {
	t.testIncrementF(orig, increment, expectedResult, true)
}

func (t testBase) testIncrementF(orig *goip.Address, increment int64, expectedResult *goip.Address, first bool) {
	result := orig.Increment(increment)
	if expectedResult == nil {
		if result != nil {
			t.addFailure(newSegmentSeriesFailure("increment mismatch result "+result.String()+" vs none expected", orig))
		}
	} else {
		if !result.Equal(expectedResult) {
			t.addFailure(newSegmentSeriesFailure("increment mismatch result "+result.String()+" vs expected "+expectedResult.String(), orig))
		}
		if first && !orig.IsMultiple() && increment > math.MinInt64 { //negating Long.MIN_VALUE results in same address
			t.testIncrementF(expectedResult, -increment, orig, false)
		}
	}
	t.incrementTestCount()
}

func (t testBase) testPrefix(original goip.AddressSegmentSeries, prefixLength goip.PrefixLen, minPrefix goip.BitCount, equivalentPrefix goip.PrefixLen) {
	if !original.GetPrefixLen().Equal(prefixLength) {
		t.addFailure(newSegmentSeriesFailure("prefix: "+original.GetPrefixLen().String()+" expected: "+prefixLength.String(), original))
	} else if !cacheTestBits(original.GetMinPrefixLenForBlock()).Equal(cacheTestBits(minPrefix)) {
		t.addFailure(newSegmentSeriesFailure("min prefix: "+strconv.Itoa(int(original.GetMinPrefixLenForBlock()))+" expected: "+bitCountToString(minPrefix), original))
	} else if !original.GetPrefixLenForSingleBlock().Equal(equivalentPrefix) {
		t.addFailure(newSegmentSeriesFailure("equivalent prefix: "+original.GetPrefixLenForSingleBlock().String()+" expected: "+equivalentPrefix.String(), original))
	}
}

func (t testBase) testIPv6Strings(w *goip.IPAddressString, ipAddr *goip.IPAddress,
	normalizedString,
	normalizedWildcardString,
	canonicalWildcardString,
	sqlString,
	fullString,
	compressedString,
	canonicalString,
	subnetString,
	compressedWildcardString,
	mixedStringNoCompressMixed,
	mixedStringNoCompressHost,
	mixedStringCompressCoveredHost,
	mixedString,
	reverseDNSString,
	uncHostString,
	base85String,
	singleHex,
	singleOctal string) {

	t.testStrings(w, ipAddr, normalizedString, normalizedWildcardString, canonicalWildcardString, sqlString, fullString, compressedString, canonicalString, subnetString, subnetString, compressedWildcardString, reverseDNSString, uncHostString, singleHex, singleOctal)

	//now test some IPv6-only strings
	t.testIPv6OnlyStrings(w, goip.ToIPv6(), mixedStringNoCompressMixed,
		mixedStringNoCompressHost, mixedStringCompressCoveredHost, mixedString, base85String)
}

func (t testBase) testIPv6OnlyStrings(w *goip.IPAddressString, ipAddr *goip.IPv6Address,
	mixedStringNoCompressMixed,
	mixedStringNoCompressHost,
	mixedStringCompressCoveredHost,
	mixedString,
	base85String string) {

	base85 := ""

	var err error
	base85, err = goip.ToBase85String()
	if err != nil {
		isMatch := base85String == ""
		if !isMatch {
			t.addFailure(newIPAddrFailure("failed expected: "+base85String+" actual: "+err.Error(), w.GetAddress()))
		}
	} else {
		b85Match := base85 == base85String
		if !b85Match {
			t.addFailure(newIPAddrFailure("failed expected: "+base85String+" actual: "+base85, w.GetAddress()))
		}
	}

	m, _ := goip.ToMixedString()

	compressOpts := new(address_string.CompressOptionsBuilder).SetCompressSingle(true).SetCompressionChoiceOptions(address_string.ZerosOrHost).SetMixedCompressionOptions(address_string.MixedCompressionCoveredByHost)
	mixedParams := new(address_string.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedCompressCoveredHost, _ := goip.ToCustomString(mixedParams)

	compressOpts = new(address_string.CompressOptionsBuilder).SetCompressSingle(true).SetCompressionChoiceOptions(address_string.ZerosOrHost).SetMixedCompressionOptions(address_string.MixedCompressionNoHost)
	mixedParams = new(address_string.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedNoCompressHost, _ := goip.ToCustomString(mixedParams)

	compressOpts = new(address_string.CompressOptionsBuilder).SetCompressSingle(true).SetCompressionChoiceOptions(address_string.ZerosOrHost).SetMixedCompressionOptions(address_string.NoMixedCompression)
	mixedParams = new(address_string.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressOpts).ToOptions()
	mixedNoCompressMixed, _ := goip.ToCustomString(mixedParams)

	t.confirmAddress_Stringsing(goip.ToIP(), m, mixedCompressCoveredHost, mixedNoCompressHost, mixedNoCompressMixed, base85)
	t.confirmHostStrings(goip.ToIP(), false, m, mixedCompressCoveredHost, mixedNoCompressHost, mixedNoCompressMixed)

	nMatch := m == (mixedString)
	if !nMatch {
		t.addFailure(newFailure("failed expected: "+mixedString+" actual: "+m, w))
	} else {
		mccMatch := mixedCompressCoveredHost == (mixedStringCompressCoveredHost)
		if !mccMatch {
			t.addFailure(newFailure("failed expected: "+mixedStringCompressCoveredHost+" actual: "+mixedCompressCoveredHost, w))
		} else {
			msMatch := mixedNoCompressHost == (mixedStringNoCompressHost)
			if !msMatch {
				t.addFailure(newFailure("failed expected: "+mixedStringNoCompressHost+" actual: "+mixedNoCompressHost, w))
			} else {
				mncmMatch := mixedNoCompressMixed == (mixedStringNoCompressMixed)
				if !mncmMatch {
					t.addFailure(newFailure("failed expected: "+mixedStringNoCompressMixed+" actual: "+mixedNoCompressMixed, w))
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t testBase) confirmMACAddress_Stringsing(macAddr *goip.MACAddress, strs ...string) bool {
	for _, str := range strs {
		address_Stringing := goip.NewMACAddressString(str)
		addr := address_Stringing.GetAddress()
		if !macAddr.Equal(addr) {
			t.addFailure(newSegmentSeriesFailure("failed produced string: "+str, macAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmAddress_Stringsing(ipAddr *goip.IPAddress, strs ...string) bool {
	for _, str := range strs {
		if str == "" {
			continue
		}
		address_Stringing := t.createParamsAddress(str, defaultOptions)
		addr := address_Stringing.GetAddress()
		if !goip.Equal(addr) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmIPAddress_Stringsing(ipAddr *goip.IPAddress, strs ...*goip.IPAddressString) bool {
	for _, str := range strs {
		addr := str.GetAddress()
		if !goip.Equal(addr) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str.String(), ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmHostStrings(ipAddr *goip.IPAddress, omitZone bool, strs ...string) bool {
	for _, str := range strs {
		hostName := goip.NewHostName(str)
		a := hostName.GetAddress()
		if omitZone {
			ipv6Addr := goip.ToIPv6()
			ipv6Addr, _ = goip.NewIPv6Address(ipv6Addr.GetSection())
			ipAddr = ipv6Addr.ToIP()
		}
		if !goip.Equal(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			return false
		}
		again := hostName.ToNormalizedString()
		hostName = goip.NewHostName(again)
		a = hostName.GetAddress()
		if !goip.Equal(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str, ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) confirmHostNameStrings(ipAddr *goip.IPAddress, strs ...*goip.HostName) bool {
	for _, str := range strs {
		a := str.GetAddress()
		if !goip.Equal(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str.String(), ipAddr))
			return false
		}
		again := str.ToNormalizedString()
		str = goip.NewHostName(again)
		a = str.GetAddress()
		if !goip.Equal(a) {
			t.addFailure(newIPAddrFailure("failed produced string: "+str.String(), ipAddr))
			return false
		}
	}
	t.incrementTestCount()
	return true
}

func (t testBase) testMACStrings(w *goip.MACAddressString,
	ipAddr *goip.MACAddress,
	normalizedString, //toColonDelimitedString
	compressedString,
	canonicalString, //toDashedString
	dottedString,
	spaceDelimitedString,
	singleHex string) {
	// testing: could test a leading zero split digit non-reverse string - a funky range string with split digits and leading zeros, like 100-299.*.10-19.4-7 which should be 1-2.0-9.0-9.*.*.*.0.1.0-9.0.0.4-7
	c := goip.ToCompressedString()
	canonical := goip.ToCanonicalString()
	d := goip.ToDashedString()
	n := goip.ToNormalizedString()
	cd := goip.ToColonDelimitedString()
	sd := goip.ToSpaceDelimitedString()

	var hex, hexNoPrefix string
	var err error
	hex, err = goip.ToHexString(true)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newMACFailure("failed expected: "+singleHex+" actual: "+err.Error(), w))
		}
	} else {
		t.confirmMACAddress_Stringsing(ipAddr, hex)
	}
	hexNoPrefix, err = goip.ToHexString(false)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newMACFailure("failed expected non-nil, actual: "+err.Error(), w))
		}
	} else {
		isMatch := singleHex == (hexNoPrefix)
		if !isMatch {
			t.addFailure(newMACFailure("failed expected: "+singleHex+" actual: "+hexNoPrefix, w))
		}
		t.confirmMACAddress_Stringsing(ipAddr, hexNoPrefix) //For ipv4, no 0x means decimal
	}

	t.confirmMACAddress_Stringsing(ipAddr, c, canonical, d, n, cd, sd)

	nMatch := normalizedString == (n)
	if !nMatch {
		t.addFailure(newMACFailure("failed expected: "+normalizedString+" actual: "+n, w))
	} else {
		nwMatch := normalizedString == (cd)
		if !nwMatch {
			t.addFailure(newMACFailure("failed expected: "+normalizedString+" actual: "+cd, w))
		} else {
			cawMatch := spaceDelimitedString == (sd)
			if !cawMatch {
				t.addFailure(newMACFailure("failed expected: "+spaceDelimitedString+" actual: "+sd, w))
			} else {
				cMatch := compressedString == (c)
				if !cMatch {
					t.addFailure(newMACFailure("failed expected: "+compressedString+" actual: "+c, w))
				} else {
					var sMatch bool
					var dotted string
					dotted, err = goip.ToDottedString()
					if err != nil {
						sMatch = dottedString == ""
					} else {
						t.confirmMACAddress_Stringsing(ipAddr, dotted)
						sMatch = dotted == (dottedString)
					}
					if !sMatch {
						t.addFailure(newMACFailure("failed expected: "+dottedString+" actual: "+dotted, w))
					} else {
						dashedMatch := canonicalString == (d)
						if !dashedMatch {
							t.addFailure(newMACFailure("failed expected: "+canonicalString+" actual: "+d, w))
						} else {
							canonicalMatch := canonicalString == (canonical)
							if !canonicalMatch {
								t.addFailure(newMACFailure("failed expected: "+canonicalString+" actual: "+canonical, w))
							}
						}
					}
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t testBase) testHostAddressStr(addressStr string) {
	str := t.createAddress(addressStr)
	address := str.GetAddress()
	if address != nil {
		hostAddress := str.GetHostAddress()
		prefixIndex := strings.IndexByte(addressStr, goip.PrefixLenSeparator)
		if prefixIndex < 0 {
			if !address.Equal(hostAddress) || !address.Contains(hostAddress) {
				t.addFailure(newFailure("failed host address with no prefix: "+hostAddress.String()+" expected: "+address.String(), str))
			}
		} else {
			substr := addressStr[:prefixIndex]
			str2 := t.createAddress(substr)
			address2 := str2.GetAddress()
			if !address2.Equal(hostAddress) {
				t.addFailure(newFailure("failed host address: "+hostAddress.String()+" expected: "+address2.String(), str))
			}
		}
	}
}

func (t testBase) testStrings(w *goip.IPAddressString,
	ipAddr *goip.IPAddress,
	normalizedString,
	normalizedWildcardString,
	canonicalWildcardString,
	sqlString,
	fullString,
	compressedString,
	canonicalString,
	subnetString,
	cidrString,
	compressedWildcardString,
	reverseDNSString,
	uncHostString,
	singleHex,
	singleOctal string) {
	// testing: could test a leading zero split digit non-reverse string - a funky range string with split digits and leading zeros, like 100-299.*.10-19.4-7 which should be 1-2.0-9.0-9.*.*.*.0.1.0-9.0.0.4-7

	if !goip.IsIPv6() || !goip.ToIPv6().HasZone() {
		if singleHex != "" && singleOctal != "" {
			fmtStr := fmt.Sprintf("%s %v %#x %#o", ipAddr, ipAddr, ipAddr, ipAddr)
			expectedFmtStr := canonicalString + " " + canonicalString + " " + singleHex + " " + singleOctal
			if fmtStr != expectedFmtStr {
				t.addFailure(newFailure("failed expected: "+expectedFmtStr+" actual: "+fmtStr, w))
			}
		} else if singleHex == "" && singleOctal == "" {
			fmtStr := fmt.Sprintf("%s %v", ipAddr, ipAddr)
			expectedFmtStr := canonicalString + " " + canonicalString
			if fmtStr != expectedFmtStr {
				t.addFailure(newFailure("failed expected: "+expectedFmtStr+" actual: "+fmtStr, w))
			}
		}
	}

	t.testHostAddressStr(w.String())

	c := goip.ToCompressedString()
	canonical := goip.ToCanonicalString()
	s := goip.ToSubnetString()
	cidr := goip.ToPrefixLenString()
	n := goip.ToNormalizedString()
	nw := goip.ToNormalizedWildcardString()
	caw := goip.ToCanonicalWildcardString()
	cw := goip.ToCompressedWildcardString()
	sql := goip.ToSQLWildcardString()
	full := goip.ToFullString()
	rDNS, _ := goip.ToReverseDNSString()
	unc := goip.ToUNCHostName()

	var hex, hexNoPrefix, octal string
	var err error
	//try {
	hex, err = goip.ToHexString(true)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleHex+" actual: "+err.Error(), w))
		}
	} else {
		isMatch := singleHex == hex
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleHex+" actual: "+hex, w))
		}
		t.confirmAddress_Stringsing(ipAddr, hex)
	}

	hexNoPrefix, err = goip.ToHexString(false)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleHex+" actual: "+err.Error(), w))
		}
	} else {
		if goip.IsIPv6() {
			t.confirmAddress_Stringsing(ipAddr, hexNoPrefix) //For ipv4, no 0x means decimal
		}
	}

	octal, err = goip.ToOctalString(true)
	if err != nil {
		isMatch := singleOctal == ""
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleOctal+" actual: "+err.Error(), w))
		}
	} else {
		isMatch := singleOctal == (octal)
		if !isMatch {
			t.addFailure(newFailure("failed expected: "+singleOctal+" actual: "+octal, w))
		}
		if goip.IsIPv4() {
			t.confirmAddress_Stringsing(ipAddr, octal)
		}
	}

	binary, err := goip.ToBinaryString(false)
	if err != nil {
		isMatch := singleHex == ""
		if !isMatch {
			t.addFailure(newFailure("failed expected non-nil binary string but got: "+err.Error(), w))
		}
	} else if ipAddr == nil {
		if binary != "<nil>" {
			t.addFailure(newFailure("failed expected <nil> for nil binary string but got: "+binary, w))
		}
	} else {
		for i := 0; i < len(binary); i++ {
			c2 := binary[i]
			if c2 == '%' || c2 == '/' { //in most cases we handle prefixed strings by printing the whole address as a range.
				//however, for prefixed non-multiple addresses we still have the prefix
				next := strings.IndexByte(binary[i+1:], '-')
				if next >= 0 {
					i = next + 1
				} else {
					if c2 == '/' && len(binary)-i > 4 {
						t.addFailure(newFailure("failed binary prefix: "+binary, w))
					}
					break
				}
			}
			if c2 != '0' && c2 != '1' && c2 != '-' {
				t.addFailure(newFailure("failed expected non-nil binary string but got: "+binary, w))
				break
			}
		}

		var withStrPrefix string

		next := strings.IndexByte(binary, '-')
		if next >= 0 {
			withStrPrefix = goip.BinaryPrefix + binary[:next+1] + goip.BinaryPrefix + binary[next+1:]
		} else {
			withStrPrefix = goip.BinaryPrefix + binary
		}
		t.confirmAddress_Stringsing(ipAddr, withStrPrefix)
	}

	binary = goip.ToSegmentedBinaryString()
	t.confirmAddress_Stringsing(ipAddr, c, canonical, s, cidr, n, nw, caw, cw, binary)
	if goip.IsIPv6() {
		t.confirmAddress_Stringsing(ipAddr, full)
		t.confirmHostStrings(ipAddr, true, rDNS) // reverse-DNS are valid hosts with embedded addresses
		skipUncParse := false
		zone := strings.IndexByte(unc, 's')
		if zone >= 0 {
			badChar := strings.IndexAny(unc[zone+1:], "%")
			if badChar >= 0 {
				skipUncParse = true
			}
		}
		if !skipUncParse {
			t.confirmHostStrings(ipAddr, false, unc) // UNCs are usually (as long as no abnormal zone) valid hosts with embedded addresses
		}
	} else {
		params := new(address_strparaming.IPAddressStringParamsBuilder).Allow_inet_aton(false).ToParams()
		fullAddress_Stringing := goip.NewIPAddressStringParams(full, params)
		t.confirmIPAddress_Stringsing(ipAddr, fullAddress_Stringing)
		t.confirmHostStrings(ipAddr, false, rDNS, unc) //these two are valid hosts with embedded addresses
	}
	t.confirmHostStrings(ipAddr, false, c, canonical, s, cidr, n, nw, caw, cw)
	if goip.IsIPv6() {
		t.confirmHostStrings(ipAddr, false, full)
	} else {
		params := new(address_strparaming.HostNameParamsBuilder).GetIPAddressParamsBuilder().Allow_inet_aton(false).GetParentBuilder().ToParams()
		fullAddress_Stringing := goip.NewHostNameParams(full, params)
		t.confirmHostNameStrings(ipAddr, fullAddress_Stringing)
	}

	nMatch := normalizedString == (n)
	if !nMatch {
		t.addFailure(newFailure("failed expected: "+normalizedString+" actual: "+n, w))
	} else {
		nwMatch := normalizedWildcardString == (nw)
		if !nwMatch {
			t.addFailure(newFailure("failed expected: "+normalizedWildcardString+" actual: "+nw, w))
		} else {
			cawMatch := canonicalWildcardString == (caw)
			if !cawMatch {
				t.addFailure(newFailure("failed expected: "+canonicalWildcardString+" actual: "+caw, w))
			} else {
				cMatch := compressedString == (c)
				if !cMatch {
					t.addFailure(newFailure("failed expected: "+compressedString+" actual: "+c, w))
				} else {
					sMatch := subnetString == (s)
					if !sMatch {
						t.addFailure(newFailure("failed expected: "+subnetString+" actual: "+s, w))
					} else {
						cwMatch := compressedWildcardString == (cw)
						if !cwMatch {
							t.addFailure(newFailure("failed expected: "+compressedWildcardString+" actual: "+cw, w))
						} else {
							wMatch := sqlString == (sql)
							if !wMatch {
								t.addFailure(newFailure("failed expected: "+sqlString+" actual: "+sql, w))
							} else {
								cidrMatch := cidrString == (cidr)
								if !cidrMatch {
									t.addFailure(newFailure("failed expected: "+cidrString+" actual: "+cidr, w))
								} else {
									canonicalMatch := canonicalString == (canonical)
									if !canonicalMatch {
										t.addFailure(newFailure("failed expected: "+canonicalString+" actual: "+canonical, w))
									} else {
										fullMatch := fullString == (full)
										if !fullMatch {
											t.addFailure(newFailure("failed expected: "+fullString+" actual: "+full, w))
										} else {
											rdnsMatch := reverseDNSString == rDNS
											if !rdnsMatch {
												t.addFailure(newFailure("failed expected: "+reverseDNSString+" actual: "+rDNS, w))
											} else {
												uncMatch := uncHostString == unc
												if !uncMatch {
													t.addFailure(newFailure("failed expected: "+uncHostString+" actual: "+unc, w))
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t testBase) testCountRedirect(w goip.ExtendedIdentifierString, number uint64, excludeZerosNumber uint64) {
	t.testCountImpl(w, number, false)
	if excludeZerosNumber != math.MaxUint64 { // this is used to filter out mac tests
		t.testCountImpl(w, excludeZerosNumber, true)
	}
}

// wrappedAddressIterator converts an address iterator of any address type to an iterator of *Address
type wrappedAddressIterator[T goip.AddressType] struct {
	goip.Iterator[T]
}

func (iter wrappedAddressIterator[T]) Next() *goip.Address {
	return iter.Iterator.Next().ToAddressBase()
}

func (t testBase) testCountImpl(w goip.ExtendedIdentifierString, number uint64, excludeZeroHosts bool) {
	if !t.fullTest && number > countLimit {
		return
	}
	val := w.GetAddress()
	var count *big.Int
	if excludeZeroHosts {
		count = getNonZeroHostCount(val.ToAddressBase().ToIP())
	} else {
		count = val.GetCount()
	}
	var set []goip.AddressItem
	if count.Cmp(new(big.Int).SetUint64(number)) != 0 {
		t.addFailure(newSegmentSeriesFailure("count was "+count.String()+" instead of expected count "+strconv.FormatUint(number, 10), val))
	} else {
		var addrIterator goip.Iterator[*goip.Address]
		if excludeZeroHosts {
			addrIterator = wrappedAddressIterator[*goip.IPAddress]{getNonZeroHostIterator(val.ToAddressBase().ToIP())}
		} else {
			addrIterator = val.ToAddressBase().Iterator()
		}
		var counter uint64
		var next *goip.Address
		for addrIterator.HasNext() {
			next = addrIterator.Next()
			if counter == 0 {
				lower := val.ToAddressBase().GetLower()
				if excludeZeroHosts {
					if lower.ToIP().IsZeroHost() && next.Equal(lower) {
						t.addFailure(newIPAddrFailure("lowest: "+lower.String()+" next: "+next.String(), next.ToIP()))
					}
				} else {
					if !next.Equal(lower) {
						t.addFailure(newSegmentSeriesFailure("lowest: "+lower.String()+" next: "+next.String(), next))
					}
				}

				if !next.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
				if !lower.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" lowest prefix length: "+lower.GetPrefixLen().String(), lower))
				}
			} else if counter == 1 {
				if !next.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
			}
			set = append(set, next)
			counter++
		}
		if number < uint64(maxInt) && len(set) != int(number) {
			t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
		} else if counter != number {
			t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
		} else if number > 0 {
			if !next.Equal(val.ToAddressBase().GetUpper()) {
				t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddressBase().GetUpper().String(), next))
			} else {
				lower := val.ToAddressBase().GetLower()
				if excludeZeroHosts {
					addr := val.ToAddressBase().ToIP()
					if counter == 1 && (!addr.GetUpper().Equal(lower) && !addr.GetUpper().IsZeroHost() && !lower.ToIP().IsZeroHost()) {
						t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddressBase().GetUpper().String()+" lowest: "+val.ToAddressBase().GetLower().String(), next))
					}
				} else {
					if counter == 1 && !val.ToAddressBase().GetUpper().Equal(lower) {
						t.addFailure(newSegmentSeriesFailure("highest: "+val.ToAddressBase().GetUpper().String()+" lowest: "+val.ToAddressBase().GetLower().String(), next))
					}
				}
				if !next.GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+next.GetPrefixLen().String(), next))
				}
				if !val.ToAddressBase().GetUpper().GetPrefixLen().Equal(val.GetPrefixLen()) {
					t.addFailure(newSegmentSeriesFailure("val prefix length: "+val.GetPrefixLen().String()+" upper prefix length: "+val.ToAddressBase().GetUpper().GetPrefixLen().String(), next))
				}
			}
		} else {
			if excludeZeroHosts {
				if !val.ToAddressBase().ToIP().IsZeroHost() {
					t.addFailure(newSegmentSeriesFailure("unexpected non-zero-host: "+val.ToAddressBase().ToIP().String(), val))
				}
			} else {
				t.addFailure(newSegmentSeriesFailure("unexpected zero count ", val))
			}
		}

		//if(!excludeZeroHosts){
		//
		//	//				Function<Address, Spliterator<? extends AddressItem>> spliteratorFunc = excludeZeroHosts ?
		//	//						addr -> ((IPAddress)addr).nonZeroHostSpliterator() : Address::spliterator;
		//	Function<Address, AddressComponentRangeSpliterator<?,? extends AddressItem>> spliteratorFunc = Address::spliterator;
		//
		//	testSpliterate(t, val, 0, number, spliteratorFunc);
		//	testSpliterate(t, val, 1, number, spliteratorFunc);
		//	testSpliterate(t, val, 8, number, spliteratorFunc);
		//	testSpliterate(t, val, -1, number, spliteratorFunc);
		//
		//	testStream(t, val, set, Address::stream);
		//
		//	AddressSection section = val.getSection();
		//
		//	//				Function<AddressSection, Spliterator<? extends AddressItem>> sectionFunc = excludeZeroHosts ?
		//	//						addr -> ((IPAddressSection)section).nonZeroHostSpliterator() : AddressSection::spliterator;
		//	Function<AddressSection, AddressComponentRangeSpliterator<?,? extends AddressItem>> sectionFunc = AddressSection::spliterator;
		//
		//	testSpliterate(t, section, 0, number, sectionFunc);
		//	testSpliterate(t, section, 1, number, sectionFunc);
		//	testSpliterate(t, section, 2, number, sectionFunc);
		//	set = testSpliterate(t, section, 7, number, sectionFunc);
		//	testSpliterate(t, section, -1, number, sectionFunc);
		//
		//	testStream(t, section, set, AddressSection::stream);
		//
		//	Set<AddressItem> createdSet = null;
		//	if(section instanceof IPv6AddressSection) {
		//		createdSet = ((IPv6AddressSection) section).segmentsStream().map(IPv6AddressSection::new).collect(Collectors.toSet());
		//	} else if(section instanceof IPv4AddressSection) {
		//		createdSet = ((IPv4AddressSection) section).segmentsStream().map(IPv4AddressSection::new).collect(Collectors.toSet());
		//	} else if(section instanceof MACAddressSection) {
		//		createdSet = ((MACAddressSection) section).segmentsStream().map(MACAddressSection::new).collect(Collectors.toSet());
		//	}
		//
		//	testStream(t, section, createdSet, AddressSection::stream);
		//
		//}
	}
	t.incrementTestCount()
}

const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<uint(intSize-1) - 1
)

func (t testBase) testPrefixCountImpl(w goip.ExtendedIdentifierString, number uint64) {
	if !t.fullTest && number > countLimit {
		return
	}
	val := w.GetAddress()
	_, isIp := val.(*goip.IPAddress)
	isPrefixed := val.IsPrefixed()
	count := val.GetPrefixCount()
	var prefixSet, prefixBlockSet []goip.AddressItem
	//HashSet<AddressItem> prefixSet = new HashSet<AddressItem>();
	//HashSet<AddressItem> prefixBlockSet = new HashSet<AddressItem>();
	if count.Cmp(new(big.Int).SetUint64(number)) != 0 {
		t.addFailure(newSegmentSeriesFailure("count was "+count.String()+" instead of expected count "+strconv.FormatUint(number, 10), val))
	} else {
		loopCount := 0
		totalCount := val.GetCount()
		var countedCount *big.Int
		originalIsPrefixBlock := val.IsPrefixBlock()
		for loopCount++; loopCount <= 2; loopCount++ {
			countedCount = bigZero()
			isBlock := loopCount == 1
			var addrIterator goip.Iterator[*goip.Address]
			var set []goip.AddressItem
			if isBlock {
				set = prefixBlockSet
				addrIterator = val.ToAddressBase().PrefixBlockIterator()
			} else {
				set = prefixSet
				addrIterator = val.ToAddressBase().PrefixIterator()
			}
			var counter uint64
			var previous, next *goip.Address
			for addrIterator.HasNext() {
				next = addrIterator.Next()
				if isBlock || (originalIsPrefixBlock && previous != nil && addrIterator.HasNext()) {
					if isPrefixed {
						if !next.IsPrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not prefix block next: "+next.String(), next))
							break
						}
						if !next.IsSinglePrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not single prefix block next: "+next.String(), next))
							break
						}
					} else {
						if next.IsPrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not prefix block next: "+next.String(), next))
							break
						}
						if next.IsPrefixBlock() {
							t.addFailure(newSegmentSeriesFailure("not single prefix block next: "+next.String(), next))
							break
						}
					}
				}
				if !isBlock {
					countedCount.Add(countedCount, next.GetCount())
				}
				if isIp && previous != nil {
					if next.ToIP().Intersect(previous.ToIP()) != nil {
						t.addFailure(newSegmentSeriesFailure("intersection of "+previous.String()+" when iterating: "+next.ToIP().Intersect(previous.ToIP()).String(), next))
						break
					}
				}
				set = append(set, next)

				counter++
				previous = next
			}
			if number < uint64(maxInt) && len(set) != int(number) {
				t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
			} else if counter != number {
				t.addFailure(newSegmentSeriesFailure("set count was "+strconv.Itoa(len(set))+" instead of expected "+strconv.FormatUint(number, 10), val.ToAddressBase()))
			} else if number < 0 {
				t.addFailure(newSegmentSeriesFailure("unexpected zero count ", val.ToAddressBase()))
			} else if !isBlock && countedCount.Cmp(totalCount) != 0 {
				t.addFailure(newSegmentSeriesFailure("count mismatch, expected "+totalCount.String()+" got "+countedCount.String(), val.ToAddressBase()))
			}

			//	Function<Address, AddressComponentRangeSpliterator<?,? extends AddressItem>> spliteratorFunc = isBlock ?
			//Address::prefixBlockSpliterator : Address::prefixSpliterator;
			//
			//	testSpliterate(t, val, 0, number, spliteratorFunc);
			//	testSpliterate(t, val, 1, number, spliteratorFunc);
			//	testSpliterate(t, val, 8, number, spliteratorFunc);
			//	testSpliterate(t, val, -1, number, spliteratorFunc);
			//
			//	if(isIp && isPrefixed) {
			//		// use val to indicate prefix length,
			//		// but we actually iterate on a value with different prefix length, while assigning the prefix length with the spliterator call
			//		IPAddress ipAddr = ((IPAddress) val);
			//		Integer prefLength = goip.getPrefixLength();
			//		IPAddress iteratedVal = null;
			//		if(prefLength >= val.getBitCount() - 3) {
			//			if(!val.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			//				iteratedVal = goip.setPrefixLength(prefLength - 3, false, false);
			//			}
			//		} else {
			//			iteratedVal = goip.adjustPrefixLength(3, false);
			//		}
			//
			//
			//		if(iteratedVal != null) {
			//			IPAddress ival = iteratedVal;
			//			spliteratorFunc = isBlock ? addr -> ival.prefixBlockSpliterator(prefLength):
			//			addr -> ival.prefixSpliterator(prefLength);
			//
			//			testSpliterate(t, val, 0, number, spliteratorFunc);
			//			testSpliterate(t, val, 1, number, spliteratorFunc);
			//			testSpliterate(t, val, 3, number, spliteratorFunc);
			//		}
			//	}
		}
		//testStream(t, val, prefixSet, Address::prefixStream);
		//testStream(t, val, prefixBlockSet, Address::prefixBlockStream);
	}
	// segment tests
	//AddressSegment lastSeg = null;
	//for(int i = 0; i < val.getSegmentCount(); i++) {// note this can be a little slow with IPv6
	//	AddressSegment seg = val.getSegment(i);
	//if(i == 0 || !seg.equals(lastSeg)) {
	//Function<AddressSegment, AddressComponentRangeSpliterator<?,? extends AddressItem>> funct = segm -> segm.spliterator();
	//int segCount = seg.getValueCount();
	//Set<AddressItem> segmentSet = testSpliterate(t, seg, 0, segCount, funct);
	//testSpliterate(t, seg, 1, segCount, funct);
	//testSpliterate(t, seg, 8, segCount, funct);
	//testSpliterate(t, seg, -1, segCount, funct);
	//
	//testStream(t, seg, segmentSet, AddressSegment::stream);
	//
	//if(seg instanceof IPAddressSegment) {
	//	IPAddressSegment ipseg = ((IPAddressSegment)seg);
	//	if(ipseg.isPrefixed()) {
	//		Function<IPAddressSegment, AddressComponentRangeSpliterator<?,? extends AddressItem>> func = segm -> segm.prefixSpliterator();
	//		segCount = ipseg.getPrefixValueCount();
	//		testSpliterate(t, ipseg, 0, segCount, func);
	//		testSpliterate(t, ipseg, 1, segCount, func);
	//		segmentSet = testSpliterate(t, ipseg, 8, segCount, func);
	//		testSpliterate(t, ipseg, -1, segCount, func);
	//
	//		testStream(t, ipseg, segmentSet, IPAddressSegment::prefixStream);
	//
	//		func = segm -> segm.prefixBlockSpliterator();
	//		testSpliterate(t, ipseg, 0, segCount, func);
	//		testSpliterate(t, ipseg, 1, segCount, func);
	//		testSpliterate(t, ipseg, 8, segCount, func);
	//		segmentSet = testSpliterate(t, ipseg, -1, segCount, func);
	//
	//		testStream(t, ipseg, segmentSet, IPAddressSegment::prefixBlockStream);
	//	}
	//}
	//}
	//lastSeg = seg;
	//}
	t.incrementTestCount()
}

func (t testBase) hostLabelsTest(x string, labels []string) {
	host := t.createHost(x)
	t.hostLabelsHostTest(host, labels)
}

func (t testBase) hostLabelsHostTest(host *goip.HostName, labels []string) {
	normalizedLabels := host.GetNormalizedLabels()
	if len(normalizedLabels) != len(labels) {
		t.addFailure(newHostFailure("normalization length "+strconv.Itoa(len(host.GetNormalizedLabels())), host))
	} else {
		for i := 0; i < len(labels); i++ {
			normalizedLabels := host.GetNormalizedLabels()
			if labels[i] != (normalizedLabels[i]) {
				t.addFailure(newHostFailure("normalization label "+host.GetNormalizedLabels()[i]+" not expected label "+labels[i], host))
				break
			}
		}
	}
	t.incrementTestCount()
}

func min(a, b goip.BitCount) goip.BitCount {
	if a < b {
		return a
	}
	return b
}

func max(a, b goip.BitCount) goip.BitCount {
	if a > b {
		return a
	}
	return b
}

type ExpectedPrefixes struct {
	//next, previous, adjusted, set goip.PrefixLen
	adjusted, set goip.PrefixLen
}

func (exp ExpectedPrefixes) compare(adjusted, set goip.PrefixLen) bool {
	return adjusted.Equal(exp.adjusted) && set.Equal(exp.set)
}

type failure struct {
	str string

	rng    *goip.IPAddressSeqRange
	idStr  goip.HostIdentifierString
	series goip.AddressSegmentSeries
	div    goip.DivisionType
	item   goip.AddressItem
	//trie         *goip.AddressTrie
	trieAssocNew *goip.AssociativeTrie[*goip.Address, any]
	trieNew      *goip.Trie[*goip.Address]
}

func (f failure) String() string {
	return concat(
		concat(
			concat(
				concat(
					//concat(
					concat(
						"", f.series),
					//f.trie),
					f.idStr),
				f.rng),
			f.div),
		f.item) + ": " + f.str
}

func concat(str string, stringer fmt.Stringer) string {
	if stringer != nil {
		stringerStr := stringer.String()
		if stringerStr == "<nil>" {
			stringerStr = ""
		}
		if stringerStr != "" {
			if str != "" {
				return stringerStr + ": " + str
			}
			return stringerStr
		}
	}
	return str
}

func newAddressItemFailure(str string, item goip.AddressItem) failure {
	return failure{
		str:  str,
		item: item,
	}
}

func newDivisionFailure(str string, div goip.DivisionType) failure {
	return failure{
		str: str,
		div: div,
	}
}

func newSegmentSeriesFailure(str string, series goip.AddressSegmentSeries) failure {
	return failure{
		str:    str,
		series: series,
	}
}

func newSeqRangeFailure(str string, rng *goip.IPAddressSeqRange) failure {
	return failure{
		str: str,
		rng: rng,
	}
}

func newHostIdFailure(str string, idStr goip.HostIdentifierString) failure {
	return failure{
		str:   str,
		idStr: idStr,
	}
}

func newTrieFailure(str string, trie *goip.Trie[*goip.Address]) failure {
	return failure{
		str:     str,
		trieNew: trie,
	}
}

func newAssocTrieFailure(str string, trie *goip.AssociativeTrie[*goip.Address, any]) failure {
	return failure{
		str:          str,
		trieAssocNew: trie,
	}
}

func newAddrFailure(str string, addr *goip.Address) failure {
	return newSegmentSeriesFailure(str, addr)
}

func newIPAddrFailure(str string, addr *goip.IPAddress) failure {
	return newSegmentSeriesFailure(str, addr)
}

func newMACAddrFailure(str string, addr *goip.MACAddress) failure {
	return newSegmentSeriesFailure(str, addr)
}

func newHostFailure(str string, host *goip.HostName) failure {
	return newHostIdFailure(str, host)
}

func newMACFailure(str string, address_String *goip.MACAddressString) failure {
	return newHostIdFailure(str, address_String)
}

func newFailure(str string, address_String *goip.IPAddressString) failure {
	return newHostIdFailure(str, address_String)
}

func cacheTestBits(i goip.BitCount) goip.PrefixLen {
	return goip.ToPrefixLen(i)
}

var (
	pnil goip.PrefixLen = nil

	p0  = cacheTestBits(0)
	p4  = cacheTestBits(4)
	p8  = cacheTestBits(8)
	p9  = cacheTestBits(9)
	p11 = cacheTestBits(11)
	//p15  = cacheTestBits(15)
	p16 = cacheTestBits(16)
	p17 = cacheTestBits(17)
	p23 = cacheTestBits(23)
	p24 = cacheTestBits(24)
	p30 = cacheTestBits(30)
	p31 = cacheTestBits(31)
	p32 = cacheTestBits(32)
	p33 = cacheTestBits(33)
	p40 = cacheTestBits(40)
	p48 = cacheTestBits(48)
	p49 = cacheTestBits(49)
	p56 = cacheTestBits(56)
	p63 = cacheTestBits(63)
	p64 = cacheTestBits(64)
	p65 = cacheTestBits(65)
	//p97  = cacheTestBits(97)
	//p104 = cacheTestBits(104)
	p110 = cacheTestBits(110)
	p112 = cacheTestBits(112)
	//p127 = cacheTestBits(127)
	p128 = cacheTestBits(128)
)

func bigOne() *big.Int {
	return big.NewInt(1)
}

var one = bigOne()

func bigOneConst() *big.Int {
	return one
}

func bigZero() *big.Int {
	return new(big.Int)
}

var zero = bigZero()

func bigZeroConst() *big.Int {
	return zero
}
