package netwrap

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// ComputeJA4H computes a deterministic JA4H HTTP client fingerprint from method, protocol,
// cookies, referer, Accept-Language, sorted header names, and cookie pairs.
func ComputeJA4H(r *http.Request) string {
	if r == nil {
		return ""
	}
	method := strings.ToLower(strings.TrimSpace(r.Method))
	if len(method) < 2 {
		method = method + strings.Repeat("x", 2-len(method))
	} else {
		method = method[:2]
	}

	ver := "11"
	if r.ProtoMajor == 2 {
		ver = "20"
	} else if r.ProtoMajor == 3 {
		ver = "30"
	} else if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		ver = "10"
	}

	cookies := r.Cookies()
	cookieFlag := "n"
	if len(cookies) > 0 {
		cookieFlag = "c"
	}
	refererFlag := "n"
	if r.Header.Get("Referer") != "" {
		refererFlag = "r"
	}

	var hdrNames []string
	for k := range r.Header {
		lk := strings.ToLower(k)
		if lk == "cookie" {
			continue
		}
		hdrNames = append(hdrNames, lk)
	}
	sort.Strings(hdrNames)

	lang := normalizeLang4(r.Header.Get("Accept-Language"))
	hdrHash := sha12(strings.Join(hdrNames, ","))

	var cNames, cKVs []string
	for _, ck := range cookies {
		cNames = append(cNames, ck.Name)
		cKVs = append(cKVs, ck.Name+"="+ck.Value)
	}
	sort.Strings(cNames)
	sort.Strings(cKVs)

	return fmt.Sprintf("%s%s%s%s%02d%s_%s_%s_%s",
		method, ver, cookieFlag, refererFlag,
		clampTwoDigits(len(hdrNames)), lang,
		hdrHash, sha12(strings.Join(cNames, ",")), sha12(strings.Join(cKVs, ",")),
	)
}

func normalizeLang4(acceptLang string) string {
	first := strings.Split(acceptLang, ",")[0]
	first = strings.Split(first, ";")[0]
	var b strings.Builder
	for i := 0; i < len(first); i++ {
		c := first[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			if b.Len() == 4 {
				break
			}
		}
	}
	s := b.String()
	for len(s) < 4 {
		s += "0"
	}
	return s
}
