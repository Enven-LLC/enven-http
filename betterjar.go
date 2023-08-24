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
	for _, cookie := range setCookies {
		c.BJar.SetCookies(cookie)
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
