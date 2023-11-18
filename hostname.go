package goip

type resolveData struct {
	resolvedAddrs []*IPAddress
	err           error
}

type hostCache struct {
	resolveData      *resolveData
	normalizedString *string
}
