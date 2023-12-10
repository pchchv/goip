package test

import (
	"bytes"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/pchchv/goip"
	"github.com/pchchv/goip/address_string"
	"github.com/pchchv/goip/address_string_param"
)

type macAddressTester struct {
	testBase
}

func (t macAddressTester) run() {
	t.mactest(true, "aa:b:cc:d:ee:f")
	t.mactest(false, "aaa:b:cc:d:ee:f")
	t.mactest(false, "aa:bbb:cc:d:ee:f")
	t.mactest(false, "aa:bb:ccc:d:ee:f")
	t.mactest(false, "aa:bb:cc:ddd:ee:f")
	t.mactest(false, "aa:bb:cc:dd:eee:f")
	t.mactest(false, "aa:bb:cc:dd:ee:fff")
	t.mactest(false, "aa:bb:cc:dd:ee:ff:eee:aa")
	t.mactest(false, "aa:bb:cc:dd:ee:ff:ee:aaa")
	t.mactest(true, "aa:bb:cc:dd:ee:ff:ee:aa")
	t.mactest(false, "0xaa:b:cc:d:ee:f")
	t.mactest(false, "aa:0xb:cc:d:ee:f")
	t.mactest(false, "aa:b:0xcc:d:ee:f")
	t.mactest(false, "aa:b:cx:d:ee:f")
	t.mactest(false, "aa:b:cx:d:ee:fg")
	t.mactest(true, "aa-b-cc-d-ee-f")
	t.mactest(false, "aaa-b-cc-d-ee-f")
	t.mactest(false, "aa-bbb-cc-d-ee-f")
	t.mactest(false, "aa-bb-ccc-d-ee-f")
	t.mactest(false, "aa-bb-cc-ddd-ee-f")
	t.mactest(false, "aa-bb-cc-dd-eee-f")
	t.mactest(false, "aa-bb-cc-dd-ee-fff")
	t.mactest(false, "aa-bb-cc-dd-ee-ff-eee-aa")
	t.mactest(false, "aa-bb-cc-dd-ee-ff-ee-aaa")
	t.mactest(true, "aa-bb-cc-dd-ee-ff-ee-aa")
	t.mactest(false, "0xaa-b-cc-d-ee-f")
	t.mactest(false, "xaa-b-cc-d-ee-f")
	t.mactest(false, "aa-b-cc-d-ee-0xf")
	t.mactest(false, "aa-b-cc-d-ee-0xff")
	t.mactest(false, "aa-0xb-cc-d-ee-f")
	t.mactest(false, "aa-b-cx-d-ee-f")
	t.mactest(false, "aa-b-0xc-d-ee-f")
	t.mactest(false, "aa-b-cx-d-ee-fg")
	t.mactest(true, "aabb.ccdd.eeff")
	t.mactest(false, "aabbc.ccdd.eeff")
	t.mactest(false, "aabb.ccddc.eeff")
	t.mactest(false, "aabb.ccdd.eeffc")
	t.mactest(false, "aabb.ccdd.eeff.ccdde")
	t.mactest(true, "aabb.ccdd.eeff.ccde")
	t.mactest(false, "aabb.ccdd.eeff.0xccdd")
	t.mactest(false, "0xaabb.ccdd.eeff.ccdd")
	t.mactest(false, "aabb.0xccdd.eeff.ccdd")
	t.mactest(false, "aabb.ccgd.eeff.ccdd")
	t.mactest(true, "1:2:3:4:5:6")
	t.mactest(true, "11:22:33:44:55:66")
	t.mactest(false, "11:22:33:444:55:66")
	t.mactest(false, "aa:x:cc:d:ee:f")
	t.mactest(false, "aa:g:cc:d:ee:f")
	t.mactest(t.allowsRange(), "aa:-1:cc:d:ee:f")  //same as "aa:0-1:cc:d:ee:f"
	t.mactest(t.allowsRange(), "aa:-dd:cc:d:ee:f") //same as "aa:0-dd:cc:d:ee:f"
	t.mactest(t.allowsRange(), "aa:1-:cc:d:ee:f")  //same as "aa:1-ff:cc:d:ee:f"
	t.mactest(t.allowsRange(), "-1:aa:cc:d:ee:f")  //same as "aa:0-1:cc:d:ee:f"
	t.mactest(t.allowsRange(), "1-:aa:cc:d:ee:f")  //same as "aa:0-1:cc:d:ee:f"
	t.mactest(t.allowsRange(), "aa:cc:d:ee:f:1-")
	t.mactest(t.allowsRange(), "aa:0-1:cc:d:ee:f")
	t.mactest(t.allowsRange(), "aa:1-ff:cc:d:ee:f")
	t.mactest(t.allowsRange(), "aa-|1-cc-d-ee-f")
	t.mactest(t.allowsRange(), "|1-aa-cc-d-ee-f")
	t.mactest(t.allowsRange(), "aa-1|-cc-d-ee-f")
	t.mactest(t.allowsRange(), "1|-aa-cc-d-ee-f")
	t.mactest(t.allowsRange(), "aa-0|1-cc-d-ee-f")
	t.mactest(t.allowsRange(), "aa-1|ff-cc-d-ee-f")
	t.mactest(t.allowsRange(), "aa-ff-cc|dd-d-ee-f")
	t.mactest(false, "aa-||1-cc-d-ee-f")
	t.mactest(false, "aa-1||-cc-d-ee-f")
	t.mactest(true, "a:bb:c:dd:e:ff")
	t.mactest(true, "aa:bb:cc:dd:ee:ff")
	t.mactest(false, "aa:bb:cc:dd::ee:ff")
	t.mactest(false, "aa:bb::dd:ee:ff")
	t.mactest(false, "aa:bb-cc:dd:ee:ff")
	t.mactest(true, "aabbcc-ddeeff")
	t.mactest(false, "aaabbcc-ddeeff")
	t.mactest(false, "aabbcc-ddeefff")
	t.mactest(false, "aabbcc-ddeeffff")
	t.mactest(false, "aabbcc-ddeefffff")
	t.mactest(true, "aabbcc-ddeeffffff")
	t.mactest(false, "aaabbcc-ddeeffffff")
	t.mactest(false, "aaaabbcc-ddeeffffff")
	t.mactest(false, "aaaaaabbcc-ddeeffffff")
	t.mactest(false, "aaabbcc-ddeeffff")
	t.mactest(false, "aabbcc.ddeeff")
	t.mactest(false, "aabbcc:ddeeff")
	t.mactest(false, "aabbcc ddeeff")
	t.mactest(false, "aa-bb-cc dd-ee-ff")
	t.mactest(false, "aa bb cc dd ee-ff")
	t.mactest(false, "aa:bb:cc dd:ee:ff")
	t.mactest(false, "aa bb cc dd ee:ff")
	t.mactest(false, "aa-bb-cc:dd-ee-ff")
	t.mactest(false, "aa.b.cc.d.ee.f")
	t.mactest(false, "aa.bb.cc.dd.ee.ff")
	t.mactest(false, "aa.bb.cc dd.ee.ff")
	t.mactest(false, "aa-bb-cc-dd:ee-ff")
	t.mactest(false, "aa-bb-cc-dd-ee:-ff")
	t.mactest(false, "aa-bb-cc-dd-ee--ff")
	t.mactest(false, "aa-bb-cc-dd--ee")
	t.mactest(false, "aa:bb:cc:dd:ee:ff:")
	t.mactest(false, "aa:bb:cc:dd:ee:ff:aa")
	t.mactest(false, "ff:aa:bb:cc:dd:ee:ff")
	t.mactest(true, "aa:bb:cc:dd:ee:ff:aa:bb")
	t.mactest(true, "ee:ff:aa:bb:cc:dd:ee:ff")
	t.mactest(false, ":aa:bb:cc:dd:ee:ff:aa:bb")
	t.mactest(false, "ee:ff:aa:bb:cc:dd:ee:ff:")
	t.mactest(false, "aa:aa:bb:cc:dd:ee:ff:aa:bb")
	t.mactest(false, "ee:ff:aa:bb:cc:dd:ee:ff:ee")
	t.mactest(false, ":aa:bb:cc:dd:ee:ff")
	t.mactest(false, "aa:bb cc:dd:ee:ff")
	t.mactest(false, "aa:bb:cc:dd.ee:ff")
	t.mactest(false, "aaa:bb:cc:dd:ee:ff")
	t.mactest(false, "aa:bbb:cc:dd:ee:ff")
	t.mactest(false, "aa:bb:ccc:dd:ee:ff")
	t.mactest(false, "aa:bb:cc:ddd:ee:ff")
	t.mactest(false, "aa:bb:cc:dd:eee:ff")
	t.mactest(false, "aa:bb:cc:dd:ee:fff")
	t.mactest(true, "f-a-b-c-d-e")
	t.mactest(false, "-a-b-c-d-e")
	t.mactest(false, "f--b-c-d-e")
	t.mactest(false, "f-b-c-d-e")
	t.mactest(false, "f-a-b-c-d-")
	t.mactest(false, "f-a-b-c--e")
	t.mactestZero(true, "0:0:0:0:0:0", true)
	t.mactestZero(true, "00:0:0:0:0:0", true)
	t.mactestZero(true, "0:00:0:0:0:0", true)
	t.mactestZero(true, "0:0:00:0:0:0", true)
	t.mactestZero(true, "0:0:0:00:0:0", true)
	t.mactestZero(true, "0:0:0:0:00:0", true)
	t.mactestZero(true, "0:0:0:0:0:00", true)
	t.mactestZero(t.isLenient(), "000:0:0:0:0:0", true)
	t.mactestZero(t.isLenient(), "0:000:0:0:0:0", true)
	t.mactestZero(t.isLenient(), "0:0:000:0:0:0", true)
	t.mactestZero(t.isLenient(), "0:0:0:000:0:0", true)
	t.mactestZero(t.isLenient(), "0:0:0:0:000:0", true)
	t.mactestZero(t.isLenient(), "0:0:0:0:0:000", true)
	t.mactestZero(t.isLenient(), "0:0:0:0:0:0:000:0", true)
	t.mactestZero(t.isLenient(), "0:0:0:0:0:0:0:000", true)
	t.mactestZero(t.isLenient(), "000:000:000:000", true)
	t.mactestZero(true, "00.0.0", true)
	t.mactestZero(true, "0.00.0", true)
	t.mactestZero(true, "0.0.00", true)
	t.mactestZero(true, "0.0.0.00", true)
	t.mactestZero(true, "000.0.0", true)
	t.mactestZero(true, "0.000.0", true)
	t.mactestZero(true, "0.00.000", true)
	t.mactestZero(true, "0000.0.0", true)
	t.mactestZero(true, "0.0000.0", true)
	t.mactestZero(true, "0.00.0000", true)
	t.mactestZero(t.isLenient(), "00000.0.0", true)
	t.mactestZero(t.isLenient(), "0.00000.0", true)
	t.mactestZero(t.isLenient(), "0.0.00000", true)
	t.mactestZero(t.isLenient(), "00000.00000.00000", true)
	t.mactestZero(t.isLenient(), "00000.00000.00000.00000", true)
	t.mactestZero(true, "3:3:3:3:3:3", false)
	t.mactestZero(true, "33:3:3:3:3:3", false)
	t.mactestZero(true, "3:33:3:3:3:3", false)
	t.mactestZero(true, "3:3:33:3:3:3", false)
	t.mactestZero(true, "3:3:3:33:3:3", false)
	t.mactestZero(true, "3:3:3:3:33:3", false)
	t.mactestZero(true, "3:3:3:3:3:33", false)
	t.mactestZero(t.isLenient(), "033:3:3:3:3:3", false)
	t.mactestZero(t.isLenient(), "3:033:3:3:3:3", false)
	t.mactestZero(t.isLenient(), "3:3:033:3:3:3", false)
	t.mactestZero(t.isLenient(), "3:3:3:033:3:3", false)
	t.mactestZero(t.isLenient(), "3:3:3:3:033:3", false)
	t.mactestZero(t.isLenient(), "3:3:3:3:3:033", false)
	t.mactestZero(t.isLenient(), "3:3:3:3:3:3:033:3", false)
	t.mactestZero(t.isLenient(), "3:3:3:3:3:3:3:033", false)
	t.mactestZero(t.isLenient(), "033:033:033:033", false)
	t.mactestZero(true, "33.3.3", false)
	t.mactestZero(true, "3.33.3", false)
	t.mactestZero(true, "3.3.33", false)
	t.mactestZero(true, "3.3.3.33", false)
	t.mactestZero(true, "333.3.3", false)
	t.mactestZero(true, "3.333.3", false)
	t.mactestZero(true, "3.33.333", false)
	t.mactestZero(true, "3333.3.3", false)
	t.mactestZero(true, "3.3333.3", false)
	t.mactestZero(true, "3.33.3333", false)
	t.mactestZero(t.isLenient(), "03333.3.3", false)
	t.mactestZero(t.isLenient(), "3.03333.3", false)
	t.mactestZero(t.isLenient(), "3.3.03333", false)
	t.mactestZero(t.isLenient(), "03333.03333.03333", false)
	t.mactestZero(t.isLenient(), "03333.03333.03333.03333", false)

	eight := [8]byte{}
	t.testFromBytes([]byte{255, 255, 255, 255, 255, 255}, "ff:ff:ff:ff:ff:ff")
	t.testFromBytes([]byte{1, 2, 3, 4, 5, 6}, "1:2:3:4:5:6")
	t.testFromBytes([]byte{0x12, 127, 0xf, 0x7f, 0x7a, 0x7b}, "12:7f:f:7f:7a:7b")
	t.testFromBytes(eight[:], "0-0-0-0-0-0-0-0")
	t.testFromBytes([]byte{0, 0, 0, 1, 0, 0, 0, 1}, "0-0-0-1-0-0-0-1")
	t.testFromBytes([]byte{10, 11, 12, 13, 14, 15, 1, 2}, "a:b:c:d:e:f:1:2")
	t.testReverse("1:2:3:4:5:6", false, false)
	t.testReverse("1:1:2:2:3:3", false, false)
	t.testReverse("1:1:1:1:1:1", false, false)
	t.testReverse("0:0:0:0:0:0", true, true)
	t.testReverse("ff:ff:ff:ff:ff:ff", true, true)
	t.testReverse("ff:ff:ff:ff:ff:ff:ff:ff", true, true)
	t.testReverse("ff:80:ff:ff:01:ff", true, false)
	t.testReverse("ff:81:ff:ff:ff:ff", false, true)
	t.testReverse("ff:81:c3:42:24:ff", false, true)
	t.testReverse("ff:1:ff:ff:ff:ff", false, false)
	t.testReverse("11:22:33:44:55:66", false, false)
	t.testReverse("11:11:22:22:33:33", false, false)
	t.testReverse("11:11:22:22:33:33:44:55", false, false)
	t.testReverse("11:11:11:11:11:11:11:11", false, false)
	t.testReverse("0:0:0:0:0:0:00:00", true, true)
	t.testIncrement("ff:ff:ff:ff:f0:0:0:0", 1, "ff:ff:ff:ff:f0:0:0:1")
	t.testIncrement("ff:ff:ff:ff:f0:0:0:0", -1, "ff:ff:ff:ff:ef:ff:ff:ff")
	t.testIncrement("ff:ff:f0:0:0:0", 1, "ff:ff:f0:0:0:1")
	t.testIncrement("ff:ff:f0:0:0:0", -1, "ff:ff:ef:ff:ff:ff")
	t.testIncrement("80:0:0:0:0:0:0:0", math.MinInt64, "0:0:0:0:0:0:0:0")
	t.testIncrement("7f:ff:ff:ff:ff:ff:ff:ff", math.MinInt64, "")
	t.testIncrement("7f:ff:ff:ff:ff:ff:ff:fe", math.MinInt64, "")
	t.testIncrement("0:0:0:0:80:0:0:0", math.MinInt64, "")
	t.testIncrement("80:0:0:0:0:0:0:0", math.MaxInt64, "ff:ff:ff:ff:ff:ff:ff:ff")
	t.testIncrement("80:0:0:0:0:0:0:1", math.MaxInt64, "")
	t.testIncrement("ff:ff:ff:ff:80:0:0:0", -0x80000000, "ff:ff:ff:ff:0:0:0:0")
	t.testIncrement("ff:ff:ff:ff:7f:ff:ff:ff", -0x80000000, "ff:ff:ff:fe:ff:ff:ff:ff")
	t.testIncrement("ff:ff:ff:ff:7f:ff:ff:fe", -0x80000000, "ff:ff:ff:fe:ff:ff:ff:fe")
	t.testIncrement("0:0:0:0:80:0:0:0", -0x80000000, "0:0:0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:0:0:7f:ff:ff:fe", -0x80000000, "")
	t.testIncrement("ff:ff:ff:ff:80:0:0:0", 0x7fffffff, "ff:ff:ff:ff:ff:ff:ff:ff")
	t.testIncrement("ff:ff:ff:ff:80:0:0:1", 0x7fffffff, "")
	t.testIncrement("ff:ff:80:0:0:0", -0x80000000, "ff:ff:0:0:0:0")
	t.testIncrement("ff:ff:7f:ff:ff:ff", -0x80000000, "ff:fe:ff:ff:ff:ff")
	t.testIncrement("ff:ff:7f:ff:ff:fe", -0x80000000, "ff:fe:ff:ff:ff:fe")
	t.testIncrement("0:0:80:0:0:0", -0x80000000, "0:0:0:0:0:0")
	t.testIncrement("0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:7f:ff:ff:fe", -0x80000000, "")
	t.testIncrement("ff:ff:80:0:0:0", 0x7fffffff, "ff:ff:ff:ff:ff:ff")
	t.testIncrement("ff:ff:80:0:0:1", 0x7fffffff, "")
	t.testIncrement("0:0:0:0:0:0:0:1", 1, "0:0:0:0:0:0:0:2")
	t.testIncrement("0:0:0:0:0:0:0:1", 0, "0:0:0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:0:0:1", -1, "0:0:0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:0:0:1", -2, "")
	t.testIncrement("0:0:0:0:0:0:0:2", 1, "0:0:0:0:0:0:0:3")
	t.testIncrement("0:0:0:0:0:0:0:2", -1, "0:0:0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:0:0:2", -2, "0:0:0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:0:0:2", -3, "")
	t.testIncrement("0:0:0:0:0:1", 1, "0:0:0:0:0:2")
	t.testIncrement("0:0:0:0:0:1", 0, "0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:1", -1, "0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:1", -2, "")
	t.testIncrement("0:0:0:0:0:2", 1, "0:0:0:0:0:3")
	t.testIncrement("0:0:0:0:0:2", -1, "0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:2", -2, "0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:2", -3, "")
	t.testIncrement("1:0:0:0:0:0:0:1", 0, "1:0:0:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:0:0:1", 1, "1:0:0:0:0:0:0:2")
	t.testIncrement("1:0:0:0:0:0:0:1", -1, "1:0:0:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:0:0:1", -2, "0:ff:ff:ff:ff:ff:ff:ff")
	t.testIncrement("1:0:0:0:0:0:0:2", 1, "1:0:0:0:0:0:0:3")
	t.testIncrement("1:0:0:0:0:0:0:2", -1, "1:0:0:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:0:0:2", -2, "1:0:0:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:0:0:2", -3, "0:ff:ff:ff:ff:ff:ff:ff")
	t.testIncrement("1:0:0:0:0:1", 0, "1:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:1", 1, "1:0:0:0:0:2")
	t.testIncrement("1:0:0:0:0:1", -1, "1:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:1", -2, "0:ff:ff:ff:ff:ff")
	t.testIncrement("1:0:0:0:0:2", 1, "1:0:0:0:0:3")
	t.testIncrement("1:0:0:0:0:2", -1, "1:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:2", -2, "1:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:2", -3, "0:ff:ff:ff:ff:ff")
	t.testIncrement("0:0:0:0:0:0:0:fe", 2, "0:0:0:0:0:0:1:0")
	t.testIncrement("0:0:0:0:0:0:0:ff", 2, "0:0:0:0:0:0:1:1")
	t.testIncrement("0:0:0:0:0:0:1:ff", 2, "0:0:0:0:0:0:2:1")
	t.testIncrement("0:0:0:0:0:0:1:ff", -2, "0:0:0:0:0:0:1:fd")
	t.testIncrement("0:0:0:0:0:0:1:ff", -0x100, "0:0:0:0:0:0:0:ff")
	t.testIncrement("0:0:0:0:0:0:1:ff", -0x101, "0:0:0:0:0:0:0:fe")
	t.testIncrement("0:0:0:0:0:fe", 2, "0:0:0:0:1:0")
	t.testIncrement("0:0:0:0:0:ff", 2, "0:0:0:0:1:1")
	t.testIncrement("0:0:0:0:1:ff", 2, "0:0:0:0:2:1")
	t.testIncrement("0:0:0:0:1:ff", -2, "0:0:0:0:1:fd")
	t.testIncrement("0:0:0:0:1:ff", -0x100, "0:0:0:0:0:ff")
	t.testIncrement("0:0:0:0:1:ff", -0x101, "0:0:0:0:0:fe")
	t.testPrefixes("25:51:27:12:82:55",
		16, -5,
		"25:51:27:12:82:55",
		"25:51:27:12:82:0",
		"25:51:27:12:82:40",
		"25:51:0:0:0:0",
		"25:51:0:0:0:0")
	t.testRadices("11:10:ff:7f:f3:2", "10001:10000:11111111:1111111:11110011:10", 2)
	t.testRadices("2:fe:7f:ff:10:11", "10:11111110:1111111:11111111:10000:10001", 2)
	t.testRadices("5:10:5:10:5:10", "101:10000:101:10000:101:10000", 2)
	t.testRadices("0:1:0:1:0:1:0:1", "0:1:0:1:0:1:0:1", 2)
	t.testRadices("1:0:1:0:1:0:1:0", "1:0:1:0:1:0:1:0", 2)
	t.testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 2)
	t.testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 2)
	t.testRadices("ff:7f:fe:2:7f:fe", "ff:7f:fe:2:7f:fe", 16)
	t.testRadices("2:fe:7f:ff:7f:fe", "2:fe:7f:ff:7f:fe", 16)
	t.testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 16)
	t.testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 16)
	t.testRadices("ff:7f:fe:2:7f:fe", "255:127:254:2:127:254", 10)
	t.testRadices("2:fe:7f:ff:7f:fe", "2:254:127:255:127:254", 10)
	t.testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 10)
	t.testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 10)
	t.testRadices("ff:7f:fe:2:7f:fe", "513:241:512:2:241:512", 7)
	t.testRadices("2:fe:7f:ff:7f:fe", "2:512:241:513:241:512", 7)
	t.testRadices("0:1:0:1:0:1:0:1", "0:1:0:1:0:1:0:1", 7)
	t.testRadices("1:0:1:0:1:0:1:0", "1:0:1:0:1:0:1:0", 7)
	t.testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 7)
	t.testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 7)
	t.testRadices("ff:7f:fe:2:7f:fe", "377:177:376:2:177:376", 8)
	t.testRadices("2:fe:7f:ff:7f:fe", "2:376:177:377:177:376", 8)
	t.testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 8)
	t.testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 8)
	t.testRadices("ff:7f:fe:2:7f:fe", "120:87:11e:2:87:11e", 15)
	t.testRadices("2:fe:7f:ff:7f:fe", "2:11e:87:120:87:11e", 15)
	t.testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 15)
	t.testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 15)
	t.testNormalized("A:B:C:D:E:F:A:B", "0a:0b:0c:0d:0e:0f:0a:0b")
	t.testNormalized("AB:AB:CC:Dd:Ee:fF:aA:Bb", "ab:ab:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12:CD:CC:dd:Ee:fF:AA:Bb", "12:cd:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12:CD:CC:dd:Ee:fF", "12:cd:cc:dd:ee:ff")
	t.testNormalized("0:0:0:0:0:0:0:0", "00:00:00:00:00:00:00:00")
	t.testNormalized("0:0:0:0:0:0", "00:00:00:00:00:00")
	t.testNormalized("0:1:0:2:0:3:0:0", "00:01:00:02:00:03:00:00")
	t.testNormalized("0:1:0:2:0:3", "00:01:00:02:00:03")
	t.testNormalized("A-B-C-D-E-F-A-B", "0a:0b:0c:0d:0e:0f:0a:0b")
	t.testNormalized("AB-AB-CC-Dd-Ee-fF-aA-Bb", "ab:ab:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12-CD-CC-dd-Ee-fF-AA-Bb", "12:cd:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12-CD-CC-dd-Ee-fF", "12:cd:cc:dd:ee:ff")
	t.testNormalized("0-0-0-0-0-0-0-0", "00:00:00:00:00:00:00:00")
	t.testNormalized("0-0-0-0-0-0", "00:00:00:00:00:00")
	t.testNormalized("0-1-0-2-0-3-0-0", "00:01:00:02:00:03:00:00")
	t.testNormalized("0-1-0-2-0-3", "00:01:00:02:00:03")
	t.testNormalized("A B C D E F A B", "0a:0b:0c:0d:0e:0f:0a:0b")
	t.testNormalized("AB AB CC Dd Ee fF aA Bb", "ab:ab:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12 CD CC dd Ee fF AA Bb", "12:cd:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12 CD CC dd Ee fF", "12:cd:cc:dd:ee:ff")
	t.testNormalized("0 0 0 0 0 0 0 0", "00:00:00:00:00:00:00:00")
	t.testNormalized("0 0 0 0 0 0", "00:00:00:00:00:00")
	t.testNormalized("0 1 0 2 0 3 0 0", "00:01:00:02:00:03:00:00")
	t.testNormalized("0 1 0 2 0 3", "00:01:00:02:00:03")
	t.testNormalized("0A0B.0C0D.0E0F", "0a:0b:0c:0d:0e:0f")
	t.testNormalized("A0B.C0D.E0F", "0a:0b:0c:0d:0e:0f")
	t.testNormalized("AB.C00.DE0F", "00:ab:0c:00:de:0f")
	t.testNormalized("A0.B00.c00d", "00:a0:0b:00:c0:0d")
	t.testNormalized("0A0B.0C0D.0E0F.0a0b", "0a:0b:0c:0d:0e:0f:0a:0b")
	t.testNormalized("A0B.C0D.E0F.1234", "0a:0b:0c:0d:0e:0f:12:34")
	t.testNormalized("AB.C00.DE0F.123", "00:ab:0c:00:de:0f:01:23")
	t.testNormalized("A0.B00.c00d.4", "00:a0:0b:00:c0:0d:00:04")
	t.testNormalized("12CD.CCdd.EefF", "12:cd:cc:dd:ee:ff")
	t.testNormalized("0000.0000.0000", "00:00:00:00:00:00")
	t.testNormalized("0002.0003.0003", "00:02:00:03:00:03")
	t.testNormalized("0A0B0C-0D0E0F", "0a:0b:0c:0d:0e:0f")
	t.testNormalized("0A0B0C-0D0E0F", "0a:0b:0c:0d:0e:0f")
	t.testNormalized("0A0B0C-0D0E0F0A0B", "0a:0b:0c:0d:0e:0f:0a:0b")
	t.testNormalized("ABABCC-DdEefFaABb", "ab:ab:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12CDCC-ddEefFAABb", "12:cd:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12CDCC-ddEefF", "12:cd:cc:dd:ee:ff")
	t.testNormalized("aaaabb-bbcccc", "aa:aa:bb:bb:cc:cc")
	t.testNormalized("010233045506", "01:02:33:04:55:06")
	t.testNormalized("000000-0000000000", "00:00:00:00:00:00:00:00")
	t.testNormalized("000000-000000", "00:00:00:00:00:00")
	t.testNormalized("000100-0200030000", "00:01:00:02:00:03:00:00")
	t.testNormalized("000100-020003", "00:01:00:02:00:03")
	t.testNormalized("0A0B0C0D0E0F", "0a:0b:0c:0d:0e:0f")
	t.testNormalized("0x0A0B0C0D0E0F", "0a:0b:0c:0d:0e:0f")
	t.testNormalized("0A0B0C0D0E0F0A0B", "0a:0b:0c:0d:0e:0f:0a:0b")
	t.testNormalized("ABABCCDdEefFaABb", "ab:ab:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12CDCCddEefFAABb", "12:cd:cc:dd:ee:ff:aa:bb")
	t.testNormalized("12CDCCddEefF", "12:cd:cc:dd:ee:ff")
	t.testNormalized("0000000000000000", "00:00:00:00:00:00:00:00")
	t.testNormalized("000000000000", "00:00:00:00:00:00")
	t.testNormalized("0001000200030000", "00:01:00:02:00:03:00:00")
	t.testNormalized("000100020003", "00:01:00:02:00:03")
	t.testCanonical("A:B:C:D:E:F:A:B", "0a-0b-0c-0d-0e-0f-0a-0b")
	t.testCanonical("AB:AB:CC:Dd:Ee:fF:aA:Bb", "ab-ab-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12:CD:CC:dd:Ee:fF:AA:Bb", "12-cd-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12:CD:CC:dd:Ee:fF", "12-cd-cc-dd-ee-ff")
	t.testCanonical("0:0:0:0:0:0:0:0", "00-00-00-00-00-00-00-00")
	t.testCanonical("0:0:0:0:0:0", "00-00-00-00-00-00")
	t.testCanonical("0:1:0:2:0:3:0:0", "00-01-00-02-00-03-00-00")
	t.testCanonical("0:1:0:2:0:3", "00-01-00-02-00-03")
	t.testCanonical("A-B-C-D-E-F-A-B", "0a-0b-0c-0d-0e-0f-0a-0b")
	t.testCanonical("AB-AB-CC-Dd-Ee-fF-aA-Bb", "ab-ab-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12-CD-CC-dd-Ee-fF-AA-Bb", "12-cd-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12-CD-CC-dd-Ee-fF", "12-cd-cc-dd-ee-ff")
	t.testCanonical("0-0-0-0-0-0-0-0", "00-00-00-00-00-00-00-00")
	t.testCanonical("0-0-0-0-0-0", "00-00-00-00-00-00")
	t.testCanonical("0-1-0-2-0-3-0-0", "00-01-00-02-00-03-00-00")
	t.testCanonical("0-1-0-2-0-3", "00-01-00-02-00-03")
	t.testCanonical("A B C D E F A B", "0a-0b-0c-0d-0e-0f-0a-0b")
	t.testCanonical("AB AB CC Dd Ee fF aA Bb", "ab-ab-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12 CD CC dd Ee fF AA Bb", "12-cd-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12 CD CC dd Ee fF", "12-cd-cc-dd-ee-ff")
	t.testCanonical("0 0 0 0 0 0 0 0", "00-00-00-00-00-00-00-00")
	t.testCanonical("0 0 0 0 0 0", "00-00-00-00-00-00")
	t.testCanonical("0 1 0 2 0 3 0 0", "00-01-00-02-00-03-00-00")
	t.testCanonical("0 1 0 2 0 3", "00-01-00-02-00-03")
	t.testCanonical("0A0B.0C0D.0E0F", "0a-0b-0c-0d-0e-0f")
	t.testCanonical("BA0B.DC0D.FE0F", "ba-0b-dc-0d-fe-0f")
	t.testCanonical("A0B.C0D.E0F", "0a-0b-0c-0d-0e-0f")
	t.testCanonical("AB.C00.DE0F", "00-ab-0c-00-de-0f")
	t.testCanonical("A.B.c", "00-0a-00-0b-00-0c")
	t.testCanonical("12CD.CCdd.EefF", "12-cd-cc-dd-ee-ff")
	t.testCanonical("0000.0000.0000", "00-00-00-00-00-00")
	t.testCanonical("0002.0003.0003", "00-02-00-03-00-03")
	t.testCanonical("0020.0030.0030", "00-20-00-30-00-30")
	t.testCanonical("0A0B0C-0D0E0F", "0a-0b-0c-0d-0e-0f")
	t.testCanonical("0A0B0C-0D0E0F0A0B", "0a-0b-0c-0d-0e-0f-0a-0b")
	t.testCanonical("ABABCC-DdEefFaABb", "ab-ab-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12CDCC-ddEefFAABb", "12-cd-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12CDCC-ddEefF", "12-cd-cc-dd-ee-ff")
	t.testCanonical("000000-0000000000", "00-00-00-00-00-00-00-00")
	t.testCanonical("000000-000000", "00-00-00-00-00-00")
	t.testCanonical("000100-0200030000", "00-01-00-02-00-03-00-00")
	t.testCanonical("000100-020003", "00-01-00-02-00-03")
	t.testCanonical("0A0B0C0D0E0F", "0a-0b-0c-0d-0e-0f")
	t.testCanonical("0A0B0C0D0E0F0A0B", "0a-0b-0c-0d-0e-0f-0a-0b")
	t.testCanonical("ABABCCDdEefFaABb", "ab-ab-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12CDCCddEefFAABb", "12-cd-cc-dd-ee-ff-aa-bb")
	t.testCanonical("12CDCCddEefF", "12-cd-cc-dd-ee-ff")
	t.testCanonical("0000000000000000", "00-00-00-00-00-00-00-00")
	t.testCanonical("000000000000", "00-00-00-00-00-00")
	t.testCanonical("0001000200030000", "00-01-00-02-00-03-00-00")
	t.testCanonical("000100020003", "00-01-00-02-00-03")
	t.testMatches(true, "0A0B0C0D0E0F", "0a0b0c-0d0e0f")
	t.testMatches(true, "0A0B0C0D0E0F", "0a:0b:0c:0d:0e:0f")
	t.testMatches(true, "0A 0B 0C 0D 0E 0F", "0a:0b:0c:0d:0e:0f")
	t.testMatches(true, "0A 0B 0C 0D 0E 0F", "0a-0b-0c-0d-0e-0f")
	t.testMatches(true, "0A 0B 0C 0D 0E 0F", "a-b-c-d-e-f")
	t.testMatches(false, "0A 0B 0C 0D 0E 0F", "a-b-c-d-e-f-a-b")
	t.testMatches(true, "0A0B.0C0D.0E0F", "0a:0b:0c:0d:0e:0f")
	t.testMatches(false, "0A0B.1C0D.0E0F", "0a:0b:0c:0d:0e:0f")
	t.testMatches(false, "0A0B.1C0D.0E0F", "aa:bb:0a:0b:0c:0d:0e:0f")
	t.testDelimitedCount("1,2-3-4,5-6-7-8", 4)            //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1,2-3,6-7-8-4,5-6,8", 16)       //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1:2:3:6:4:5", 1)                //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testDelimitedCount("1:2,3,4:3:6:4:5,ff,7,8,99", 15) //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
	t.testContains("1.2.3.4", "1.2.3.4", true)
	t.testContains("1111.2222.3333", "1111.2222.3333", true)
	t.testNotContains("1111.2222.3333", "1111.2222.3233")
	t.testContains("a:b:c:d:e:f:a:b", "a:b:c:d:e:f:a:b", true)
	t.testLongShort("ff:ff:ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff")
	t.testLongShort("12-cd-cc-dd-ee-ff-aa-bb", "12-cd-cc-dd-ee-ff")
	t.testLongShort("12CD.CCdd.EefF.a", "12CD.EefF.a")
	t.testLongShort("0A0B0C-0D0E0F0A0B", "0A0B0C-0D0E0F")
	t.testLongShort("ee:ff:aa:bb:cc:dd:ee:ff", "ee:ff:aa:bb:cc:dd")
	t.testLongShort("e:f:a:b:c:d:e:f", "e:f:a:b:c:d")
	t.testSections("00:21:2f:b5:6e:10")
	t.testSections("39-A7-94-07-CB-D0")
	t.testSections("0012.7feb.6b40")
	t.testSections("fe:ef:00:21:2f:b5:6e:10")
	t.testSections("fe-ef-39-A7-94-07-CB-D0")
	t.testSections("1234.0012.7feb.6b40")

	zerosPref := [9]goip.PrefixLen{}
	t.testInsertAndAppendPrefs("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8", zerosPref[:])
	t.testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8")
	t.testInvalidMACValues()

	var sixZeros [6]int
	var eightZeros [8]int

	t.testMACValues([]int{1, 2, 3, 4, 5, 6}, "1108152157446")
	t.testMACValues([]int{1, 2, 3, 4, 5, 6, 7, 8}, "72623859790382856")
	t.testMACValues(sixZeros[:], "0")
	t.testMACValues(eightZeros[:], "0")
	t.testMACValues([]int{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, strconv.Itoa(0xffffffffffff))

	sixty4 := new(big.Int).SetUint64(0xffffffffffffffff)
	//BigInteger thirtyTwo = BigInteger.valueOf(0xffffffffL);
	//BigInteger sixty4 = thirtyTwo.shiftLeft(32).or(thirtyTwo);
	t.testMACValuesBig([]int{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, sixty4.String(), "-1")
	t.testMACIPv6("aaaa:bbbb:cccc:dddd:0221:2fff:feb5:6e10", "00:21:2f:b5:6e:10")
	t.testMACIPv6("fe80::0e3a:bbff:fe2a:cd23", "0c:3a:bb:2a:cd:23")
	t.testMACIPv6("ffff:ffff:ffff:ffff:3BA7:94FF:FE07:CBD0", "39-A7-94-07-CB-D0")
	t.testMACIPv6("FE80::212:7FFF:FEEB:6B40", "0012.7feb.6b40")
	t.testMACIPv6("2001:DB8::212:7FFF:FEEB:6B40", "0012.7feb.6b40")
	t.testStrings()
}

func (t macAddressTester) testMACValues(segs []int, decimal string) {
	t.testMACValuesBig(segs, decimal, "")
}

func (t macAddressTester) testMACValuesBig(segs []int, decimal, negativeDecimal string) {
	vals := make([]byte, len(segs))
	strb := strings.Builder{}
	var longval uint64
	bigInteger := bigZero()
	bitsPerSegment := goip.MACBitsPerSegment
	for i := 0; i < len(segs); i++ {
		seg := segs[i]
		if strb.Len() > 0 {
			strb.WriteByte(':')
		}
		strb.WriteString(strconv.FormatInt(int64(seg), 16))
		vals[i] = byte(seg)
		longval = (longval << uint(bitsPerSegment)) | uint64(seg)
		bigInteger = bigInteger.Add(bigInteger.Lsh(bigInteger, uint(bitsPerSegment)), new(big.Int).SetInt64(int64(seg)))
	}

	addr := [3]*goip.MACAddress{}
	i := 0
	addr[i] = t.createMACAddressFromBytes(vals)
	i++
	addr[i] = t.createMACAddress(strb.String()).GetAddress()
	i++
	addr[i] = t.createMACAddressFromUint64(longval, len(segs) == 8)
	for j := 0; j < len(addr); j++ {
		for k := j; k < len(addr); k++ {
			if !addr[k].Equal(addr[j]) || !addr[j].Equal(addr[k]) {
				t.addFailure(newSegmentSeriesFailure("failed equals: "+addr[k].String()+" and "+addr[j].String(), addr[k]))
			}
		}
	}

	if decimal != "" {
		for i = 0; i < len(addr); i++ {
			if decimal != (addr[i].GetValue().String()) {
				t.addFailure(newSegmentSeriesFailure("failed equals: "+addr[i].GetValue().String()+" and "+decimal, addr[i]))
			}
			longVal := addr[i].Uint64Value()
			lv := strconv.FormatUint(longVal, 10)
			if longVal < 0 {
				if lv != negativeDecimal {
					t.addFailure(newSegmentSeriesFailure("failed equals: "+lv+" and "+decimal, addr[i]))
				}
			} else if decimal != lv {
				t.addFailure(newSegmentSeriesFailure("failed equals: "+lv+" and "+decimal, addr[i]))
			}
		}
	}
}

func (t macAddressTester) testInvalidMACValues() {
	thebytes := [9]byte{}
	thebytes[0] = 1
	addr, err := goip.NewMACAddressFromBytes(thebytes[:])
	if err == nil {
		t.addFailure(newSegmentSeriesFailure("failed expected error for "+addr.String(), addr))
	}
	thebytes = [9]byte{}
	addr, err = goip.NewMACAddressFromBytes(thebytes[:])
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed unexpected error for "+addr.String(), addr))
	}
	bytes2 := [8]byte{}
	addr, err = goip.NewMACAddressFromBytes(bytes2[:])
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed unexpected error for "+addr.String(), addr))
	}
	bytes3 := [7]byte{}
	addr, err = goip.NewMACAddressFromBytes(bytes3[:])
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed unexpected error for "+addr.String(), addr))
	}
	bytes4 := [6]byte{}
	addr, err = goip.NewMACAddressFromBytes(bytes4[:])
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed unexpected error for "+addr.String(), addr))
	}
	bytes5 := [5]byte{}
	addr, err = goip.NewMACAddressFromBytes(bytes5[:])
	if err != nil {
		t.addFailure(newSegmentSeriesFailure("failed unexpected error for "+addr.String(), addr))
	}

	addr = goip.NewMACAddressFromVals(func(segmentIndex int) goip.MACSegInt {
		var val = 256 // will be truncated to 0
		return goip.MACSegInt(val)
	})
	if !addr.IsZero() {
		t.addFailure(newSegmentSeriesFailure("failed expected exception for "+addr.String(), addr))
	}
	addr = goip.NewMACAddressFromVals(func(segmentIndex int) goip.MACSegInt {
		var val = -1 // will be truncated to 0
		return goip.MACSegInt(val)
	})
	if !addr.IsMax() {
		t.addFailure(newSegmentSeriesFailure("failed expected exception for "+addr.String(), addr))
	}
	addr = goip.NewMACAddressFromVals(func(segmentIndex int) goip.MACSegInt {
		var val = 255 // will be truncated to 0
		return goip.MACSegInt(val)
	})
	if !addr.IsMax() {
		t.addFailure(newSegmentSeriesFailure("failed expected exception for "+addr.String(), addr))
	}
}

func (t macAddressTester) testInsertAndAppend(front, back string, expectedPref []goip.BitCount) {
	is := make([]goip.PrefixLen, len(expectedPref))
	for i := 0; i < len(expectedPref); i++ {
		is[i] = cacheTestBits(expectedPref[i])
	}
	t.testInsertAndAppendPrefs(front, back, is)
}

func (t macAddressTester) testInsertAndAppendPrefs(front, back string, expectedPref []goip.PrefixLen) {
	f := t.createMACAddress(front).GetAddress()
	b := t.createMACAddress(back).GetAddress()
	t.testAppendAndInsert(f.ToAddressBase(), b.ToAddressBase(), f.GetSegmentStrings(), b.GetSegmentStrings(),
		goip.MACColonSegmentSeparator, expectedPref, true)
}

func (t macAddressTester) testReplace(front, back string) {
	f := t.createMACAddress(front).GetAddress()
	b := t.createMACAddress(back).GetAddress()
	t.testBase.testReplace(f.ToAddressBase(), b.ToAddressBase(), f.GetSegmentStrings(), b.GetSegmentStrings(),
		goip.MACColonSegmentSeparator, true)
}

func (t macAddressTester) testSections(address_Stringing string) {
	w := t.createMACAddress(address_Stringing)
	v := w.GetAddress()
	odiSection := v.GetODISection()
	ouiSection := v.GetOUISection()
	front := v.GetSubSection(0, 3)
	back := v.GetTrailingSection(front.GetSegmentCount())
	first := !ouiSection.Equal(front)
	if (first) || !all3Equals(ouiSection.GetPrefixLen(), front.GetPrefixLen(), prefixAdjust(v.GetPrefixLen(), 24, 0)) {
		if first {
			t.addFailure(newMACFailure("failed oui "+ouiSection.String()+" expected "+front.String(), w))
		} else {
			t.addFailure(newMACFailure("failed oui pref "+ouiSection.GetPrefixLen().String()+" expected "+prefixAdjust(v.GetPrefixLen(), 24, 0).String()+" for "+front.String(), w))
		}
	} else {
		first = !odiSection.Equal(back)
		if (first) || !all3Equals(odiSection.GetPrefixLen(), back.GetPrefixLen(), prefixAdjust(v.GetPrefixLen(), 64, -24)) {
			if first {
				t.addFailure(newMACFailure("failed odi "+odiSection.String()+" expected "+back.String(), w))
			} else {
				t.addFailure(newMACFailure("failed odi pref "+odiSection.GetPrefixLen().String()+" expected "+prefixAdjust(v.GetPrefixLen(), 64, -24).String()+" for "+back.String(), w))
			}
		} else {
			middle := v.GetSubSection(1, 5)
			odiSection2 := odiSection.GetSubSection(0, 5-ouiSection.GetSegmentCount())
			ouiSection2 := ouiSection.GetTrailingSection(1)
			odiSection = middle.GetTrailingSection(2)
			ouiSection = middle.GetSubSection(0, 2)
			if !ouiSection.Equal(ouiSection2) || !ouiSection.GetPrefixLen().Equal(ouiSection2.GetPrefixLen()) {
				t.addFailure(newMACFailure("failed odi "+ouiSection.String()+" expected "+ouiSection2.String(), w))
			} else if !odiSection.Equal(odiSection2) || !odiSection.GetPrefixLen().Equal(odiSection2.GetPrefixLen()) {
				t.addFailure(newMACFailure("failed odi "+odiSection.String()+" expected "+odiSection2.String(), w))
			} else if ouiSection.GetSegmentCount() != 2 || ouiSection2.GetSegmentCount() != 2 {
				t.addFailure(newMACFailure("failed oui count "+strconv.Itoa(ouiSection.GetSegmentCount())+" expected 2", w))
			} else if odiSection.GetSegmentCount() != 2 || odiSection2.GetSegmentCount() != 2 {
				t.addFailure(newMACFailure("failed oui count "+strconv.Itoa(odiSection.GetSegmentCount())+" expected 2", w))
			} else {
				odiEmpty := odiSection.GetSubSection(0, 0)
				ouiEmpty := ouiSection.GetSubSection(0, 0)
				if !odiEmpty.Equal(ouiEmpty) || odiEmpty.GetSegmentCount() > 0 || ouiEmpty.GetSegmentCount() > 0 {
					t.addFailure(newMACFailure("failed odi empty "+odiEmpty.String()+" oui empty "+ouiEmpty.String(), w))
				} else {
					midEmpty := middle.GetSubSection(0, 0)
					if !ouiEmpty.Equal(midEmpty) || midEmpty.GetSegmentCount() != 0 {
						t.addFailure(newMACFailure("failed odi empty "+midEmpty.String()+" expected "+ouiEmpty.String(), w))
					} else {
						midEmpty2 := middle.GetSubSection(1, 1)
						if !ouiEmpty.Equal(midEmpty2) || midEmpty2.GetSegmentCount() != 0 {
							t.addFailure(newMACFailure("failed odi empty "+midEmpty2.String()+" expected "+ouiEmpty.String(), w))
						}
					}
				}
			}
		}
	}
	t.incrementTestCount()
}

func prefixAdjust(existing goip.PrefixLen, max, adj goip.BitCount) goip.PrefixLen {
	if existing == nil {
		return nil
	}
	if existing.Len() > max {
		return nil
	}
	res := existing.Len() + adj
	if res < 0 {
		return cacheTestBits(0)
	}
	return cacheTestBits(res)
}

func (t macAddressTester) testLongShort(longAddr, shortAddr string) {
	t.testLongShort2(longAddr, shortAddr, false)
}

func (t macAddressTester) testLongShort2(longAddr, shortAddr string, shortCanBeLong bool) {
	params := new(address_string_param.MACAddressStringParamsBuilder).SetPreferredLen(address_string_param.MAC48Len).ToParams()
	longString := goip.NewMACAddressStringParams(longAddr, params)
	shortString := goip.NewMACAddressStringParams(shortAddr, params)
	if !shortString.IsValid() {
		t.addFailure(newMACFailure("short not valid "+shortString.String(), shortString))
	}
	if longString.IsValid() {
		t.addFailure(newMACFailure("long valid "+longString.String(), longString))
	}
	params = new(address_string_param.MACAddressStringParamsBuilder).SetPreferredLen(address_string_param.EUI64Len).ToParams()
	longString = goip.NewMACAddressStringParams(longAddr, params)
	shortString = goip.NewMACAddressStringParams(shortAddr, params)
	isValid := shortString.IsValid()
	if shortCanBeLong {
		isValid = !isValid
	}
	if isValid {
		t.addFailure(newMACFailure("short valid "+shortString.String(), shortString))
	}
	if !longString.IsValid() {
		t.addFailure(newMACFailure("long not valid "+longString.String(), longString))
	}
	if longString.GetAddress().GetSegmentCount() != goip.ExtendedUniqueIdentifier64SegmentCount {
		t.addFailure(newMACFailure("long not enough segments "+longString.String(), longString))
	}
	if shortCanBeLong && shortString.GetAddress().GetSegmentCount() != goip.ExtendedUniqueIdentifier64SegmentCount {
		t.addFailure(newMACFailure("also not enough segments "+shortString.String(), shortString))
	}
	params = new(address_string_param.MACAddressStringParamsBuilder).SetPreferredLen(address_string_param.UnspecifiedMACLen).ToParams()
	longString = goip.NewMACAddressStringParams(longAddr, params)
	shortString = goip.NewMACAddressStringParams(shortAddr, params)
	if !shortString.IsValid() {
		t.addFailure(newMACFailure("short not valid "+shortString.String(), shortString))
	}
	if !longString.IsValid() {
		t.addFailure(newMACFailure("long not valid "+longString.String(), longString))
	}
	t.incrementTestCount()
}

func (t macAddressTester) testContains(addr1, addr2 string, equal bool) {
	w := t.createMACAddress(addr1).GetAddress()
	w2 := t.createMACAddress(addr2).GetAddress()
	if !w.Contains(w2) {
		t.addFailure(newSegmentSeriesFailure("failed "+w2.String(), w))
	} else {
		otherContains := w2.Contains(w)
		if equal {
			otherContains = !otherContains
		}
		if otherContains {
			t.addFailure(newSegmentSeriesFailure("failed "+w.String(), w2))
		}
	}
	t.incrementTestCount()
}

func (t macAddressTester) testNotContains(cidr1, cidr2 string) {
	w := t.createMACAddress(cidr1).GetAddress()
	w2 := t.createMACAddress(cidr2).GetAddress()
	if w.Contains(w2) {
		t.addFailure(newSegmentSeriesFailure("failed "+w2.String(), w))
	} else if w2.Contains(w) {
		t.addFailure(newSegmentSeriesFailure("failed "+w.String(), w2))
	}
	t.incrementTestCount()
}

func (t macAddressTester) testDelimitedCount(str string, expectedCount int) {
	delims := goip.DelimitedAddressString(str)
	strs := delims.ParseDelimitedSegments()
	var set []*goip.MACAddress
	count := 0
	for strs.HasNext() {
		addr, err := t.createMACAddress(strs.Next()).ToAddress()
		if err != nil {
			t.addFailure(newFailure("unexpected error "+err.Error(), nil))
			return
		}
		if addr == nil {
			t.addFailure(newFailure("unexpected nil address", nil))
			return
		}
		set = append(set, addr)
		count++
	}
	if count != expectedCount || len(set) != count || count != delims.CountDelimitedAddresses() {
		t.addFailure(newFailure("count mismatch, count: "+strconv.Itoa(count)+" set count: "+strconv.Itoa(len(set))+" calculated count: "+strconv.Itoa(delims.CountDelimitedAddresses())+" expected: "+strconv.Itoa(expectedCount), nil))
	}
	t.incrementTestCount()
}

func (t macAddressTester) testMatches(matches bool, host1Str, host2Str string) {
	h1 := t.createMACAddress(host1Str)
	h2 := t.createMACAddress(host2Str)
	if matches != h1.Equal(h2) {
		t.addFailure(newMACFailure("failed: match with "+h2.String(), h1))
	} else {
		if matches != h2.Equal(h1) {
			t.addFailure(newMACFailure("failed: match with "+h1.String(), h2))
		} else {
			comparison := h1.Compare(h2) == 0
			if matches {
				comparison = !comparison
			}
			if comparison {
				t.addFailure(newMACFailure("failed: match with "+h1.String(), h2))
			} else {
				comparison := h2.Compare(h1) == 0
				if matches {
					comparison = !comparison
				}
				if comparison {
					t.addFailure(newMACFailure("failed: match with "+h2.String(), h1))
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t macAddressTester) testNormalized(original, expected string) {
	w := t.createMACAddress(original)
	val := w.GetAddress()
	if val == nil {
		t.addFailure(newMACFailure("normalization was nil", w))
	} else {
		normalized := val.ToNormalizedString()
		if expected != normalized {
			t.addFailure(newMACFailure("mac normalization was "+normalized, w))
		}
	}
	t.incrementTestCount()
}

func (t macAddressTester) testCanonical(original, expected string) {
	w := t.createMACAddress(original)
	val := w.GetAddress()
	if val == nil {
		t.addFailure(newMACFailure("normalization was nil", w))
	} else {
		normalized := val.ToCanonicalString()
		if expected != normalized {
			t.addFailure(newMACFailure("canonical was "+normalized, w))
		}
	}
	t.incrementTestCount()
}

func (t macAddressTester) testRadices(original, expected string, radix int) {
	w := t.createMACAddress(original)
	val := w.GetAddress()
	options := new(address_string.MACStringOptionsBuilder).SetRadix(radix).ToOptions()
	normalized := val.ToCustomString(options)
	if normalized != expected {
		t.addFailure(newMACFailure("string was "+normalized+" expected was "+expected, w))
	}
	t.incrementTestCount()
}

func (t macAddressTester) testReverse(addressStr string, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	str := t.createMACAddress(addressStr)
	t.testBase.testReverse(str.GetAddress().ToAddressBase().Wrap(), bitsReversedIsSame, bitsReversedPerByteIsSame)
	t.incrementTestCount()
}

func (t macAddressTester) testIncrement(originalStr string, increment int64, resultStr string) {
	var addr *goip.MACAddress
	if resultStr != "" {
		addr = t.createMACAddress(resultStr).GetAddress()
	}
	t.testBase.testIncrement(t.createMACAddress(originalStr).GetAddress().ToAddressBase(), increment, addr.ToAddressBase())
}

func (t macAddressTester) testPrefix(original string, prefixLength, equivalentPrefix goip.PrefixLen) {
	mac := t.createMACAddress(original).GetAddress()
	var bc = mac.GetBitCount()
	if prefixLength != nil {
		bc = prefixLength.Len()
	}
	t.testBase.testPrefix(mac, prefixLength, bc, equivalentPrefix)
	t.incrementTestCount()
}

func (t macAddressTester) testPrefixes(original string,
	prefix, adjustment goip.BitCount,
	next string,
	previous,
	adjusted,
	prefixSet,
	prefixApplied string) {
	t.testBase.testSegmentSeriesPrefixes(t.createMACAddress(original).GetAddress().Wrap(),
		prefix, adjustment,
		t.createMACAddress(next).GetAddress().Wrap(),
		t.createMACAddress(previous).GetAddress().Wrap(),
		t.createMACAddress(adjusted).GetAddress().Wrap(),
		t.createMACAddress(prefixSet).GetAddress().Wrap(),
		t.createMACAddress(prefixApplied).GetAddress().Wrap())
	t.incrementTestCount()
}

func (t macAddressTester) testMACStrings(addr,
	normalizedString, //toColonDelimitedString
	compressedString,
	canonicalString, //toDashedString
	dottedString,
	spaceDelimitedString,
	singleHex string) {
	w := t.createMACAddress(addr)
	ipAddr := w.GetAddress()
	t.testBase.testMACStrings(w, ipAddr, normalizedString, compressedString, canonicalString, dottedString, spaceDelimitedString, singleHex)
}

func (t macAddressTester) mactest(pass bool, x string) {
	t.mactestZero(pass, x, false)
}

func (t macAddressTester) mactestZero(pass bool, x string, isZero bool) {
	t.mactestImpl(pass, t.createMACAddress(x), isZero)
}

func (t macAddressTester) mactestImpl(pass bool, addr *goip.MACAddressString, isZero bool) {
	//notBoth means we validate as IPv4 or as IPv6, we don't validate as either one
	if t.isNotExpected(pass, addr) {
		t.addFailure(newMACFailure("parse failure: "+addr.String(), addr))
	} else {
		zeroPass := pass && !isZero
		if t.isNotExpectedNonZero(zeroPass, addr) {
			t.addFailure(newMACFailure("zero parse failure: "+addr.String(), addr))
		} else {
			//test the bytes
			if pass && len(addr.String()) > 0 && addr.GetAddress() != nil {
				taddr := addr.GetAddress()
				if t.allowsRange() && taddr.IsMultiple() {

				} else if !t.testBytes(taddr) {
					t.addFailure(newMACFailure("parse bytes failure: "+addr.String(), addr))
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t macAddressTester) testBytes(addr *goip.MACAddress) bool {
	failed := false
	macAddrbytes := addr.Bytes()
	another := t.createMACAddressFromBytes(macAddrbytes)
	if !addr.Equal(another) {
		t.addFailure(newSegmentSeriesFailure(addr.String(), addr))
	}
	var builder strings.Builder
	builder.WriteString(addr.ToColonDelimitedString())
	if addr.GetSegmentCount() < 8 {
		builder.WriteString("::")
	}
	ipstr := builder.String()
	inetAddress := net.ParseIP(ipstr)
	ipv6Bytes := inetAddress
	macBytes := make([]byte, len(macAddrbytes))
	for i := 0; i < len(macBytes); i++ {
		macBytes[i] = ipv6Bytes[(i<<1)+1]
	}
	if !bytes.Equal(macBytes, macAddrbytes) {
		failed = true
		t.addFailure(newSegmentSeriesFailure("bytes on addr "+inetAddress.String(), addr))
	}
	return !failed
}

func (t macAddressTester) testFromBytes(bytes []byte, expected string) {
	addr := t.createMACAddressFromBytes(bytes)
	addr2 := t.createMACAddress(expected)
	result := addr.Equal(addr2.GetAddress())
	if !result {
		t.addFailure(newSegmentSeriesFailure("created was "+addr.String()+" expected was "+addr2.String(), addr))
	} else {
		var val uint64
		for i := 0; i < len(bytes); i++ {
			val <<= 8
			val |= uint64(bytes[i])
		}
		addr = t.createMACAddressFromUint64(val, len(bytes) > 6)
		result = addr.Equal(addr2.GetAddress())
		if !result {
			t.addFailure(newSegmentSeriesFailure("created was "+addr.String()+" expected was "+addr2.String(), addr))
		}
	}
	t.incrementTestCount()
}

func (t macAddressTester) isNotExpected(expectedPass bool, addr *goip.MACAddressString) bool {
	err := addr.Validate()
	if err != nil {
		return expectedPass
	}
	return !expectedPass
}

func (t macAddressTester) isNotExpectedNonZero(expectedPass bool, addr *goip.MACAddressString) bool {
	if !addr.IsValid() {
		return expectedPass
	}
	//if expectedPass is true, we are expecting a non-zero address
	//return true to indicate we have gotten something not expected
	if addr.GetAddress() != nil && addr.GetAddress().IsZero() {
		return expectedPass
	}
	return !expectedPass
}

func (t macAddressTester) testMACIPv6(ipv6, mac string) {
	ipv6Str := t.createAddress(ipv6)
	macStr := t.createMACAddress(mac)
	addr := ipv6Str.GetAddress().ToIPv6()
	back := addr.GetHostSectionLen(64)

	if !addr.IsEUI64() {
		t.addFailure(newSegmentSeriesFailure("eui 64 check "+back.String(), back))
	} else {
		macAddr := macStr.GetAddress()
		macBack, err := macAddr.ToEUI64IPv6()
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("unexpected error "+err.Error(), macAddr))
		}
		linkLocal, err := macAddr.ToLinkLocalIPv6()
		if err != nil {
			t.addFailure(newSegmentSeriesFailure("unexpected error for link local "+err.Error(), macAddr))
			return
		}
		if !linkLocal.IsLinkLocal() {
			t.addFailure(newSegmentSeriesFailure("eui 64 conv link local "+macAddr.String(), linkLocal))
		} else {
			if !macBack.Equal(back) {
				t.addFailure(newSegmentSeriesFailure("eui 64 conv "+back.String(), macBack))
			} else {
				macAddr64, err := macAddr.ToEUI64(false)
				if err != nil {
					t.addFailure(newSegmentSeriesFailure("unexpected error for mac address to EUI64 "+err.Error(), macAddr))
					return
				}

				if macAddr.IsEUI64(true) || macAddr.IsEUI64(false) || !macAddr64.IsEUI64(false) {
					t.addFailure(newSegmentSeriesFailure("mac eui test "+macAddr64.String(), macAddr))
				} else {
					backFromMac64Addr, err := goip.NewIPv6AddressFromMAC(addr, macAddr64)
					if err != nil {
						t.addFailure(newSegmentSeriesFailure("unexpected error for mac address 64 to EUI64 "+err.Error(), macAddr))
						return
					}
					backFromMac64 := backFromMac64Addr.GetHostSectionLen(64)
					if !backFromMac64.Equal(back) {
						t.addFailure(newSegmentSeriesFailure("eui 64 conv 2"+back.String(), backFromMac64))
					} else {
						backFromMacAddr, err := goip.NewIPv6AddressFromMAC(addr, macAddr)
						if err != nil {
							t.addFailure(newSegmentSeriesFailure("unexpected error for mac address to EUI64 "+err.Error(), macAddr))
							return
						}
						backFromMac := backFromMacAddr.GetHostSectionLen(64)
						if !backFromMac.Equal(back) {
							t.addFailure(newSegmentSeriesFailure("eui 64 conv 3"+back.String(), backFromMac))
						} else {
							withPrefix := false //we do the loop twice, once with prefixes, the other without
							origAddr := addr
							origBackFromMac := backFromMac
							for {
								addr = origAddr
								backFromMac = origBackFromMac
								frontIpv6 := addr.GetNetworkSectionLen(64)

								backLinkLocal := linkLocal.GetHostSectionLen(64)
								backIpv6 := addr.GetHostSectionLen(64)
								if withPrefix {
									addr = addr.SetPrefixLen(64)
								} else {
									frontIpv6 = frontIpv6.WithoutPrefixLen()
									backFromMac = backFromMac.WithoutPrefixLen()
									backLinkLocal = backLinkLocal.WithoutPrefixLen()
									backIpv6 = backIpv6.WithoutPrefixLen()
								}
								backIPv6_1, err := addr.ToEUI(true)
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error 1 for address to EUI64 "+err.Error(), addr))
								}
								backIPv6_2, err := addr.ToEUI(false)
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error 2 for address to EUI64 "+err.Error(), addr))
								}
								splitJoined1, err := goip.NewIPv6AddressFromMACSection(frontIpv6, backIPv6_1.GetSection())
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), macAddr))
								}
								splitJoined2, err := goip.NewIPv6AddressFromMACSection(frontIpv6, backIPv6_2.GetSection())
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), macAddr))
								}
								splitJoined3, err := goip.NewIPv6Address(frontIpv6.Append(backIpv6))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), macAddr))
								}
								bk, err := goip.NewIPv6SectionFromMAC(backIPv6_1)
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), macAddr))
								}
								splitJoined4, err := goip.NewIPv6Address(frontIpv6.Append(bk))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), macAddr))
								}
								bk, err = goip.NewIPv6SectionFromMAC(backIPv6_2)
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), macAddr))
								}
								splitJoined5, err := goip.NewIPv6Address(frontIpv6.Append(bk))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), macAddr))
								}
								both3 := backFromMac
								var all []*goip.IPv6Address
								ipa, err := goip.NewIPv6Address(addr.GetSection().Replace(4, both3))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), addr))
								}
								all = append(all, ipa)
								ipa, err = goip.NewIPv6Address(frontIpv6.Append(both3))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), addr))
								}
								all = append(all, ipa)
								ipa, err = goip.NewIPv6Address(frontIpv6.Append(both3))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), addr))
								}
								all = append(all, ipa)

								all = append(all, splitJoined1)
								all = append(all, splitJoined2)
								all = append(all, splitJoined3)
								all = append(all, splitJoined4)
								all = append(all, splitJoined5)

								ipa, err = goip.NewIPv6Address(addr.GetSection().Replace(4, backLinkLocal))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), addr))
								}
								all = append(all, ipa)

								ipa, err = goip.NewIPv6Address(frontIpv6.Append(backLinkLocal))
								if err != nil {
									t.addFailure(newSegmentSeriesFailure("unexpected error for ipv6 construction "+err.Error(), addr))
								}
								all = append(all, ipa)

								//All of these should be equal!
								for i := range all {
									for j := range all {
										if !all[i].Equal(all[j]) {
											t.addFailure(newSegmentSeriesFailure("failure matching "+all[i].String()+" to "+all[j].String(), addr))
										}
										if !all[i].GetNetworkPrefixLen().Equal(all[j].GetNetworkPrefixLen()) {
											t.addFailure(newSegmentSeriesFailure("failure matching "+all[i].GetNetworkPrefixLen().String()+" to "+all[j].GetNetworkPrefixLen().String(), addr))
										}
									}
								}
								if withPrefix {
									break
								}
								withPrefix = true
							}
						}
					}
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t macAddressTester) testStrings() {

	t.testMACStrings("a:b:c:d:e:f:a:b",
		"0a:0b:0c:0d:0e:0f:0a:0b", //normalizedString, //toColonDelimitedString
		"a:b:c:d:e:f:a:b",         //compressedString,
		"0a-0b-0c-0d-0e-0f-0a-0b", //canonicalString, //toDashedString
		"0a0b.0c0d.0e0f.0a0b",     //dottedString,
		"0a 0b 0c 0d 0e 0f 0a 0b", //spaceDelimitedString,
		"0a0b0c0d0e0f0a0b")        //singleHex

	t.testMACStrings("ab:ab:bc:cd:De:ef",
		"ab:ab:bc:cd:de:ef", //normalizedString, //toColonDelimitedString
		"ab:ab:bc:cd:de:ef", //compressedString,
		"ab-ab-bc-cd-de-ef", //canonicalString, //toDashedString
		"abab.bccd.deef",    //dottedString,
		"ab ab bc cd de ef", //spaceDelimitedString,
		"ababbccddeef")      //singleHex

	t.testMACStrings("ab:AB:bc:cd:de:ef:aB:aB",
		"ab:ab:bc:cd:de:ef:ab:ab", //normalizedString, //toColonDelimitedString
		"ab:ab:bc:cd:de:ef:ab:ab", //compressedString,
		"ab-ab-bc-cd-de-ef-ab-ab", //canonicalString, //toDashedString
		"abab.bccd.deef.abab",     //dottedString,
		"ab ab bc cd de ef ab ab", //spaceDelimitedString,
		"ababbccddeefabab")        //singleHex

	t.testMACStrings("a:b:c:d:0:0",
		"0a:0b:0c:0d:00:00", //normalizedString, //toColonDelimitedString
		"a:b:c:d:0:0",       //compressedString,
		"0a-0b-0c-0d-00-00", //canonicalString, //toDashedString
		"0a0b.0c0d.0000",    //dottedString,
		"0a 0b 0c 0d 00 00", //spaceDelimitedString,
		"0a0b0c0d0000")      //singleHex

	t.testMACStrings("ff:00:10:01:10:11",
		"ff:00:10:01:10:11", //normalizedString, //toColonDelimitedString
		"ff:0:10:1:10:11",   //compressedString,
		"ff-00-10-01-10-11", //canonicalString, //toDashedString
		"ff00.1001.1011",    //dottedString,
		"ff 00 10 01 10 11", //spaceDelimitedString,
		"ff0010011011")      //singleHex

	t.testMACStrings("0aa0bbb00cff",
		"0a:a0:bb:b0:0c:ff",
		"a:a0:bb:b0:c:ff",
		"0a-a0-bb-b0-0c-ff",
		"0aa0.bbb0.0cff",
		"0a a0 bb b0 0c ff",
		"0aa0bbb00cff")

	t.testMACStrings("0aa0bb-b00cff",
		"0a:a0:bb:b0:0c:ff",
		"a:a0:bb:b0:c:ff",
		"0a-a0-bb-b0-0c-ff",
		"0aa0.bbb0.0cff",
		"0a a0 bb b0 0c ff",
		"0aa0bbb00cff")
}

func all3Equals(one, two, three goip.PrefixLen) bool {
	return one.Equal(two) && one.Equal(three)
}
