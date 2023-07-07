package goip

type addressError struct {
	key string // to look up the error message
	str string // an optional string with the address
}

func (a *addressError) Error() string {
	return getStr(a.str) + lookupStr("ipaddress.address.error") + " " + lookupStr(a.key)
}

func getStr(str string) (res string) {
	if len(str) > 0 {
		res = str + " "
	}
	return
}
