package goip

var chars, extendedChars = createChars()

type strValidator struct{}

func createChars() (chars [int('z') + 1]byte, extendedChars [int('~') + 1]byte) {
	i := byte(1)
	for c := '1'; i < 10; i, c = i+1, c+1 {
		chars[c] = i
	}

	for c, c2 := 'a', 'A'; i < 26; i, c, c2 = i+1, c+1, c2+1 {
		chars[c] = i
		chars[c2] = i
	}

	var extendedDigits = []byte{
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
		'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
		'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
		'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
		'y', 'z', '!', '#', '$', '%', '&', '(', ')', '*', '+', '-',
		';', '<', '=', '>', '?', '@', '^', '_', '`', '{', '|', '}',
		'~'}
	extLen := byte(len(extendedDigits))

	for i = 0; i < extLen; i++ {
		c := extendedDigits[i]
		extendedChars[c] = i
	}
	return
}
