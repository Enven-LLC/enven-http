package tls_client

import (
	"strings"
	"sync"
)

type BetterJar struct {
	cookies map[string]string
	mu      sync.RWMutex
}

func NewBetterJar() *BetterJar {
	return &BetterJar{
		cookies: make(map[string]string),
	}
}

func (bj *BetterJar) SetCookies(cookieString string) {
	bj.mu.Lock()
	cookies := strings.Split(cookieString, ";")
	for _, cookie := range cookies {
		nameI := strings.Index(cookie, "=")
		if nameI == -1 {
			continue
		}
		name := strings.TrimSpace(cookie[:nameI])
		value := strings.TrimSpace(cookie[nameI+1:])

		if shouldProcessCookie(name, value) {
			bj.cookies[name] = value
		}
	}
	bj.mu.Unlock()
}
func (bj *BetterJar) processCookies(resp *WebResp) {
	setCookies := resp.Header.Values("Set-Cookie")
	// c.logger.Debug("set cookies from response header: %s", setCookies)

	if len(setCookies) == 0 {
		resp.Cookies = bj.GetCookies()
		return
	}
	bj.mu.Lock()
	for _, setCookie := range setCookies {
		cookieAttributes := strings.Split(setCookie, ";")

		// Parse and process each attribute
		var found = false
		for _, attr := range cookieAttributes {
			if found {
				break
			}
			attr = strings.TrimSpace(attr)
			parts := strings.SplitN(attr, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch strings.ToLower(name) {
			case "path", "domain", "expires":
				continue
			default:
				if shouldProcessCookie(name, value) {
					bj.cookies[name] = value
				}
				found = true
			}
		}
	}
	bj.mu.Unlock()
	resp.Cookies = bj.GetCookies()
}

func (bj *BetterJar) GetCookies() string {
	bj.mu.RLock()
	cookies := ""
	for name, value := range bj.cookies {
		if shouldProcessCookie(name, value) {
			cookies += name + "=" + value + "; "
		}
	}
	bj.mu.RUnlock()
	return strings.TrimSuffix(cookies, ";")
}
func shouldProcessCookie(name, value string) bool {
	return name != "" && value != "" && value != `""` && value != "undefined"
}

// func (jar *cookieJar) GetCookie(find string) string {
// 	jar.Lock()
// 	defer jar.Unlock()
// 	for name, value := range jar.Cookies {
// 		if name == find {
// 			return value
// 		}
// 	}
// 	return ""
// }
