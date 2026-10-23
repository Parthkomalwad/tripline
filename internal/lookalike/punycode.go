package lookalike

import "errors"

// RFC 3492 Punycode parameters.
const (
	pBase, pTmin, pTmax, pSkew, pDamp = 36, 1, 26, 38, 700
	pInitialBias, pInitialN           = 72, 128
)

var errPuny = errors.New("lookalike: bad punycode")

func adapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pBase-pTmin)*pTmax)/2 {
		delta /= pBase - pTmin
		k += pBase
	}
	return k + ((pBase-pTmin+1)*delta)/(delta+pSkew)
}

func digit(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= '0' && c <= '9':
		return int(c-'0') + 26
	}
	return -1
}

// punyDecode decodes an RFC 3492 string (without the "xn--" prefix).
func punyDecode(s string) (string, error) {
	var out []rune
	rest := s
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '-' {
			for _, c := range []byte(s[:i]) {
				if c >= 0x80 {
					return "", errPuny
				}
				out = append(out, rune(c))
			}
			rest = s[i+1:]
			break
		}
	}
	n, i, bias := pInitialN, 0, pInitialBias
	for p := 0; p < len(rest); {
		oldi, w := i, 1
		for k := pBase; ; k += pBase {
			if p >= len(rest) {
				return "", errPuny
			}
			d := digit(rest[p])
			p++
			if d < 0 || d > (1<<30)/w { // overflow guard
				return "", errPuny
			}
			i += d * w
			t := k - bias
			if t < pTmin {
				t = pTmin
			} else if t > pTmax {
				t = pTmax
			}
			if d < t {
				break
			}
			w *= pBase - t
			if w > 1<<30 {
				return "", errPuny
			}
		}
		bias = adapt(i-oldi, len(out)+1, oldi == 0)
		n += i / (len(out) + 1)
		i %= len(out) + 1
		if n < 0x80 || n > 0x10FFFF {
			return "", errPuny
		}
		out = append(out[:i], append([]rune{rune(n)}, out[i:]...)...)
		i++
	}
	return string(out), nil
}
