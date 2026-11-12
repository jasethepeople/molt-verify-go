package main

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type jsonError struct {
	canonical bool
	msg       string
}

func (e *jsonError) Error() string { return e.msg }

func syntaxErr(msg string) *jsonError {
	return &jsonError{canonical: false, msg: msg}
}

func canonicalErr(msg string) *jsonError {
	return &jsonError{canonical: true, msg: msg}
}

var numberRE = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`)

type jsonParser struct {
	text  string
	index int
}

func parseJSON(text string) (any, *jsonError) {
	p := &jsonParser{text: text}
	p.whitespace()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.whitespace()
	if p.index != len(p.text) {
		return nil, syntaxErr("unexpected trailing content")
	}
	return v, nil
}

func (p *jsonParser) whitespace() {
	for p.index < len(p.text) {
		switch p.text[p.index] {
		case ' ', '\t', '\n', '\r':
			p.index++
		default:
			return
		}
	}
}

func (p *jsonParser) value() (any, *jsonError) {
	p.whitespace()
	if p.index >= len(p.text) {
		return nil, syntaxErr("expected a JSON value")
	}

	switch p.text[p.index] {
	case '"':
		return p.string()
	case '{':
		return p.object()
	case '[':
		return p.array()
	}

	if strings.HasPrefix(p.text[p.index:], "true") {
		p.index += 4
		return true, nil
	}
	if strings.HasPrefix(p.text[p.index:], "false") {
		p.index += 5
		return false, nil
	}
	if strings.HasPrefix(p.text[p.index:], "null") {
		p.index += 4
		return nil, nil
	}

	loc := numberRE.FindStringIndex(p.text[p.index:])
	if loc == nil {
		return nil, syntaxErr("expected a JSON value")
	}

	match := p.text[p.index : p.index+loc[1]]
	p.index += loc[1]

	f, err := strconv.ParseFloat(match, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			// Keep +/-Inf. The canonical serializer rejects non-finite values.
		} else {
			return nil, syntaxErr("invalid number")
		}
	}
	return f, nil
}

func (p *jsonParser) string() (string, *jsonError) {
	if p.index >= len(p.text) || p.text[p.index] != '"' {
		return "", syntaxErr("expected a string")
	}
	p.index++

	var units []uint16

	for p.index < len(p.text) {
		c := p.text[p.index]

		if c == '"' {
			p.index++
			if err := validateSurrogates(units); err != nil {
				return "", err
			}
			return string(utf16.Decode(units)), nil
		}

		if c < 0x20 {
			return "", syntaxErr("unescaped control character in string")
		}

		if c == '\\' {
			p.index++
			if p.index >= len(p.text) {
				return "", syntaxErr("unterminated string")
			}
			esc := p.text[p.index]
			switch esc {
			case '"', '\\', '/':
				units = append(units, uint16(esc))
				p.index++
			case 'b':
				units = append(units, '\b')
				p.index++
			case 'f':
				units = append(units, '\f')
				p.index++
			case 'n':
				units = append(units, '\n')
				p.index++
			case 'r':
				units = append(units, '\r')
				p.index++
			case 't':
				units = append(units, '\t')
				p.index++
			case 'u':
				if p.index+5 > len(p.text) {
					return "", syntaxErr("invalid unicode escape")
				}
				hexText := p.text[p.index+1 : p.index+5]
				v, err := strconv.ParseUint(hexText, 16, 16)
				if err != nil {
					return "", syntaxErr("invalid unicode escape")
				}
				units = append(units, uint16(v))
				p.index += 5
			default:
				return "", syntaxErr("invalid string escape")
			}
			continue
		}

		r, size := utf8.DecodeRuneInString(p.text[p.index:])
		if r == utf8.RuneError && size == 1 {
			return "", syntaxErr("invalid UTF-8")
		}

		if r <= 0xFFFF {
			units = append(units, uint16(r))
		} else {
			r1, r2 := utf16.EncodeRune(r)
			units = append(units, uint16(r1), uint16(r2))
		}
		p.index += size
	}

	return "", syntaxErr("unterminated string")
}

func validateSurrogates(units []uint16) *jsonError {
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xD800 && u <= 0xDBFF {
			if i+1 >= len(units) {
				return canonicalErr("unpaired high surrogate")
			}
			next := units[i+1]
			if next < 0xDC00 || next > 0xDFFF {
				return canonicalErr("unpaired high surrogate")
			}
			i++
		} else if u >= 0xDC00 && u <= 0xDFFF {
			return canonicalErr("unpaired low surrogate")
		}
	}
	return nil
}

func (p *jsonParser) object() (any, *jsonError) {
	p.index++ // '{'
	p.whitespace()

	obj := make(map[string]any)

	if p.index < len(p.text) && p.text[p.index] == '}' {
		p.index++
		return obj, nil
	}

	for {
		p.whitespace()
		if p.index >= len(p.text) || p.text[p.index] != '"' {
			return nil, syntaxErr("expected an object key")
		}

		key, err := p.string()
		if err != nil {
			return nil, err
		}

		if _, exists := obj[key]; exists {
			return nil, canonicalErr("duplicate object key")
		}

		p.whitespace()
		if p.index >= len(p.text) || p.text[p.index] != ':' {
			return nil, syntaxErr("expected colon after object key")
		}
		p.index++

		val, err := p.value()
		if err != nil {
			return nil, err
		}
		obj[key] = val

		p.whitespace()
		if p.index < len(p.text) && p.text[p.index] == '}' {
			p.index++
			return obj, nil
		}
		if p.index >= len(p.text) || p.text[p.index] != ',' {
			return nil, syntaxErr("expected comma or closing brace")
		}
		p.index++
	}
}

func (p *jsonParser) array() (any, *jsonError) {
	p.index++ // '['
	p.whitespace()

	arr := make([]any, 0)

	if p.index < len(p.text) && p.text[p.index] == ']' {
		p.index++
		return arr, nil
	}

	for {
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		arr = append(arr, val)

		p.whitespace()
		if p.index < len(p.text) && p.text[p.index] == ']' {
			p.index++
			return arr, nil
		}
		if p.index >= len(p.text) || p.text[p.index] != ',' {
			return nil, syntaxErr("expected comma or closing bracket")
		}
		p.index++
	}
}

func serializeJSON(v any) (string, *jsonError) {
	var b strings.Builder
	if err := serializeValue(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func serializeValue(b *strings.Builder, v any) *jsonError {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		b.WriteString(quoteJSONString(x))
	case float64:
		s, err := formatNumber(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return compareUTF16(keys[i], keys[j]) < 0
		})

		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quoteJSONString(k))
			b.WriteByte(':')
			if err := serializeValue(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := serializeValue(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		return canonicalErr("unsupported JSON value")
	}
	return nil
}

func quoteJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')

	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}

	b.WriteByte('"')
	return b.String()
}

func formatNumber(f float64) (string, *jsonError) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", canonicalErr("cannot canonicalize a non-finite number")
	}
	if f == 0 {
		return "0", nil
	}

	b, err := json.Marshal(f)
	if err != nil {
		return "", canonicalErr(err.Error())
	}
	return string(b), nil
}

func compareUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))

	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] < ub[i] {
			return -1
		}
		if ua[i] > ub[i] {
			return 1
		}
	}
	if len(ua) < len(ub) {
		return -1
	}
	if len(ua) > len(ub) {
		return 1
	}
	return 0
}
