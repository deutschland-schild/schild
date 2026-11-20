package websites

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// Punycode (RFC 3492) for one label, without any further IDNA mapping: the
// derivation lower-cases ASCII only and refuses upper-case non-ASCII letters,
// so the encoding is the same in every implementation (Python's "punycode"
// codec, contracts/tools/crosscheck.py).

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

var errPunycode = errors.New("punycode")

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// punyEncode returns the RFC 3492 encoding of s (without the xn-- prefix).
func punyEncode(s string) (string, error) {
	in := []rune(s)
	var out strings.Builder
	b := 0
	for _, r := range in {
		if r < 0x80 {
			out.WriteByte(byte(r))
			b++
		}
	}
	h := b
	if b > 0 {
		out.WriteByte('-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	for h < len(in) {
		m := int(^uint(0) >> 1)
		for _, r := range in {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if (m-n)*(h+1) < 0 {
			return "", errPunycode
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range in {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					t := k - bias
					if t < pcTMin {
						t = pcTMin
					} else if t > pcTMax {
						t = pcTMax
					}
					if q < t {
						break
					}
					out.WriteByte(pcDigit(t + (q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				out.WriteByte(pcDigit(q))
				bias = pcAdapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return out.String(), nil
}

// punyDecode decodes an RFC 3492 string (without the xn-- prefix).
func punyDecode(s string) (string, error) {
	var out []rune
	i := strings.LastIndexByte(s, '-')
	if i >= 0 {
		for _, c := range s[:i] {
			if c >= 0x80 {
				return "", errPunycode
			}
			out = append(out, c)
		}
		s = s[i+1:]
	}
	n, bias, idx := pcInitialN, pcInitialBias, 0
	for p := 0; p < len(s); {
		oldi, w := idx, 1
		for k := pcBase; ; k += pcBase {
			if p >= len(s) {
				return "", errPunycode
			}
			c := s[p]
			p++
			var d int
			switch {
			case c >= 'a' && c <= 'z':
				d = int(c - 'a')
			case c >= 'A' && c <= 'Z':
				d = int(c - 'A')
			case c >= '0' && c <= '9':
				d = int(c-'0') + 26
			default:
				return "", errPunycode
			}
			idx += d * w
			if idx < 0 || idx > 1<<30 {
				return "", errPunycode
			}
			t := k - bias
			if t < pcTMin {
				t = pcTMin
			} else if t > pcTMax {
				t = pcTMax
			}
			if d < t {
				break
			}
			w *= pcBase - t
			if w > 1<<30 {
				return "", errPunycode
			}
		}
		bias = pcAdapt(idx-oldi, len(out)+1, oldi == 0)
		n += idx / (len(out) + 1)
		idx %= len(out) + 1
		if n > utf8.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return "", errPunycode
		}
		out = append(out, 0)
		copy(out[idx+1:], out[idx:])
		out[idx] = rune(n)
		idx++
	}
	return string(out), nil
}
