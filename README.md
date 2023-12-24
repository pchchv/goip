# goip [![Go Reference](https://pkg.go.dev/badge/github.com/pchchv/goip.svg)](https://pkg.go.dev/github.com/pchchv/goip)

Go package for handling IP addresses and subnets. IPv4 and IPv6.

Working with IP addresses and networks, CIDR, address and subnet operations, iterations, content checks, IP to CIDR block lookup, longest prefix match, creating subnets, spanning, merging, ranges and address tries, with polymorphic code

## Usage

starting with address or subnet strings
```go
import "github.com/pchchv/goip"

ipv6AddrStr := goip.NewIPAddressString("a:b:c:d::a:b/64")
if ipAddr, err := ipv6AddrStr.ToAddress(); err != nil {
	// error validation
} else {
	// use the address
}
```
...or checking for nil:
```go
str := goip.NewIPAddressString("a:b:c:d:e-f:f:1.2-3.3.4/64")
addr := str.GetAddress()
if addr != nil {
	// use address
}
```
starting with host name:
```go
hostStr := "[::1]"
host := goip.NewHostName(hostStr)
if err := host.Validate(); err != nil {
    panic(err)
}

// use host
if host.IsAddress() {
    fmt.Println("address: " + host.AsAddress().String())
} else {
    fmt.Println("host name: " + host.String())
}
```
