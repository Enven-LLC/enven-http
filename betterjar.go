package tls_client

import (
	"strings"
	"sync"
)

type BetterJar struct {
	cookies map[string]string
	mu      sync.RWMutex
	// GetCookieStr() string
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
	// c.BJar.Lock()
	// if c.BJar.Cookies == nil {
	// 	c.BJar.Cookies = make(map[string]string)
	// }
	setCookies := resp.Header.Values("Set-Cookie")
	// c.logger.Debug("set cookies from response header: %s", setCookies)

	if len(setCookies) == 0 {
		resp.Cookies = bj.GetCookies()
		// bjar.Unlock()
		return
	}
	bj.mu.Lock()
	for _, setCookie := range setCookies {
		//handle if multiple cookies are set in one set-cookie header
		setSplit := strings.Split(setCookie, ",")
		for _, cookie := range setSplit {
			// Split the cookie string into attributes
			cookieAttributes := strings.Split(cookie, ";")

			// Parse and process each attribute
			var name, value string
			for _, attr := range cookieAttributes {
				attr = strings.TrimSpace(attr)
				parts := strings.SplitN(attr, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

				switch key {
				case "Path":
				case "Domain":
				case "Expires":
				default:
					name = key
					value = val
					if shouldProcessCookie(name, value) {
						bj.cookies[name] = value
					}
				}
			}
		}
	}
	bj.mu.Unlock()
	resp.Cookies = bj.GetCookies()
	// c.BJar.Unlock()
	// resp.Cookies = c.BJar.GetCookies()
}

func (bj *BetterJar) GetCookies() string {
	// if lock {
	// 	jar.Lock()
	// 	defer jar.Unlock()
	// }
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
