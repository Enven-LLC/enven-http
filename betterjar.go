package tls_client

import (
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

// type betterJar struct {
// 	jar     *BetterJar
// 	cookies map[string]string
// 	sync.RWMutex
// }

func (c *httpClient) processCookies(resp *WebResp) {
	c.BJar.Lock()
	defer c.BJar.Unlock()
	if c.BJar.Cookies == nil {
		c.BJar.Cookies = make(map[string]string)
	}
	resp.Header.Get("Set-Cookie")

	setCookies := resp.Header.Values("Set-Cookie")
	c.logger.Debug("set cookies from response header: %s", setCookies)

	if len(setCookies) == 0 {
		resp.Cookies = c.BJar.GetCookieStr(false)
		return
	}

	for _, cook := range setCookies {
		parts := strings.Split(cook, ";")

		cookie := parts[0]
		nameI := strings.Index(cookie, "=")
		if nameI == -1 {
			continue
		}
		name := strings.TrimSpace(cookie[:nameI])
		value := strings.TrimSpace(cookie[nameI+1:])

		c.logger.Debug("cookie: %s, value: %s", name, value)

		if name != "" && value != "" && value != `""` && value != "undefined" {
			c.BJar.Cookies[name] = value
		}
	}
	resp.Cookies = c.BJar.GetCookieStr(false)
}

// func (jar *cookieJar) ImportCookies(cookies string) {
// 	if jar.Cookies == nil {
// 		jar.Cookies = make(map[string]string)
// 	}
// 	parts := strings.Split(cookies, ";")
// 	for _, cookie := range parts {
// 		nameI := strings.Index(cookie, "=")
// 		if nameI == -1 {
// 			continue
// 		}
// 		name := strings.TrimSpace(cookie[:nameI])
// 		value := strings.TrimSpace(cookie[nameI+1:])

//			if value != "" && value != `""` {
//				jar.Cookies[name] = value
//			}
//		}
//	}
func (jar *BetterJar) GetCookieStr(lock bool) string {
	if lock {
		jar.Lock()
		defer jar.Unlock()
	}
	cookies := ""
	for name, value := range jar.Cookies {
		if value != "" && value != `""` {
			cookies += name + "=" + value + "; "
		}
	}
	return strings.TrimSpace(cookies)
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
