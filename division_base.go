package goip

type divCache struct {
	cachedString,
	cachedWildcardString,
	cached0xHexString,
	cachedHexString,
	cachedNormalizedString *string
	isSinglePrefBlock *bool
}
