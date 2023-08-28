package goip

type addressNetwork interface {
	getAddressCreator() parsedAddressCreator
}
