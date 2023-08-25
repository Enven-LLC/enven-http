package tls_client

import (
	"fmt"
	"strings"
	"sync"
)

// TODO: consider adding an easy way to support multiple domains nicely, unlike the ugly ass default cookiejar
type BetterJar struct {
	Cookies map[string]string
	sync.RWMutex
	// GetCookieStr() string
}

func NewBetterJar() *BetterJar {
	return &BetterJar{
		Cookies: make(map[string]string),
	}
}

func (bj *BetterJar) SetCookies(cookieString string) {
	cookies := strings.Split(cookieString, ";")
	for _, cookie := range cookies {
		nameI := strings.Index(cookie, "=")
		if nameI == -1 {
			continue
		}
		name := strings.TrimSpace(cookie[:nameI])
		value := strings.TrimSpace(cookie[nameI+1:])

		if shouldProcessCookie(name, value) {
			bj.Cookies[name] = value
		}
	}
}
func (c *httpClient) processCookies(resp *WebResp) {
	c.BJar.Lock()
	if c.BJar.Cookies == nil {
		c.BJar.Cookies = make(map[string]string)
	}
	resp.Header.Get("Set-Cookie")

	setCookies := resp.Header.Values("Set-Cookie")
	c.logger.Debug("set cookies from response header: %s", setCookies)

	if len(setCookies) == 0 {
		resp.Cookies = c.BJar.GetCookieStr(false)
		c.BJar.Unlock()
		return
	}
	resp.Request.Cookies()
	// for _, cook := range setCookies {
	// 	parts := strings.Split(cook, ";")

	// 	cookie := parts[0]
	// 	nameI := strings.Index(cookie, "=")
	// 	if nameI == -1 {
	// 		continue
	// 	}
	// 	name := strings.TrimSpace(cookie[:nameI])
	// 	value := strings.TrimSpace(cookie[nameI+1:])

	// 	c.logger.Debug("cookie: %s, value: %s", name, value)

	// 	if name != "" && value != "" && value != `""` && value != "undefined" {
	// 		c.BJar.Cookies[name] = value
	// 	}
	// }
	for _, setCookie := range setCookies {

		fmt.Println("set-cookie", setCookie)
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
						c.BJar.Cookies[name] = value
					}
				}
			}
		}

		// c.BJar.SetCookies(cookie)
	}
	resp.Cookies = c.BJar.GetCookieStr(false)
	c.BJar.Unlock()
}

func (jar *BetterJar) GetCookieStr(lock bool) string {
	if lock {
		jar.Lock()
		defer jar.Unlock()
	}
	cookies := ""
	for name, value := range jar.Cookies {
		if shouldProcessCookie(name, value) {
			cookies += name + "=" + value + "; "
		}
	}
	return strings.TrimSpace(cookies)
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
