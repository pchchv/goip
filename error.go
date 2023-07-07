package goip

type addressError struct {
	key string // to look up the error message
	str string // an optional string with the address
}

func (a *addressError) Error() string {
	return getStr(a.str) + lookupStr("ipaddress.address.error") + " " + lookupStr(a.key)
}

// GetKey can be used to internationalize error strings in the IPAddress library.
// The list of keys and their English translations are listed in the IPAddressResources.properties file.
// Use your own method to map keys to your translations.
// One such method is golang.org/x/text, which provides language tags
// (https://pkg.go.dev/golang.org/x/text/language?utm_source=godoc#Tag)
// that can then be mapped to catalogs, each catalog being a translation list for the set of keys presented here.
// In the code, you specify the language key to use the right catalog.
// You can use the gotext tool to integrate these translations into your application.
func (a *addressError) GetKey() string {
	return a.key
}

func getStr(str string) (res string) {
	if len(str) > 0 {
		res = str + " "
	}
	return
}

type incompatibleAddressError struct {
	addressError
}

type sizeMismatchError struct {
	incompatibleAddressError
}

type addressValueError struct {
	addressError
	val int
}
