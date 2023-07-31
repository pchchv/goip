package goip

type IPv6SegInt = uint16

type IPv6SegmentValueProvider func(segmentIndex int) IPv6SegInt
