package tls_client

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"
)

var defaultRedirectFunc = func(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

type HttpClient interface {
	// GetCookies(u *url.URL) []*http.Cookie
	// SetCookies(u *url.URL, cookies []*http.Cookie)
	SetCookieJar(jar http.CookieJar)
	SetProxy(proxyUrl string) error
	GetProxy() string
	SetFollowRedirect(followRedirect bool)
	GetFollowRedirect() bool
	Do(req *WebReq) (*WebResp, error)
}

type httpClient struct {
	BJar *BetterJar
	http.Client
	logger Logger
	config *httpClientConfig
}

var DefaultTimeoutSeconds = 30

var DefaultOptions = []HttpClientOption{
	WithTimeoutSeconds(DefaultTimeoutSeconds),
	WithClientProfile(DefaultClientProfile),
	WithRandomTLSExtensionOrder(),
	WithNotFollowRedirects(),
}

func ProvideDefaultClient(logger Logger) (HttpClient, error) {
	// jar := NewCookieJar()

	// return NewHttpClient(logger, append(DefaultOptions, WithCookieJar(jar))...)
	return NewHttpClient(logger, DefaultOptions...)
}

// NewHttpClient constructs a new HTTP client with the given logger and client options.
func NewHttpClient(logger Logger, options ...HttpClientOption) (HttpClient, error) {
	config := &httpClientConfig{
		followRedirects:    true,
		badPinHandler:      nil,
		customRedirectFunc: nil,
		timeout:            time.Duration(DefaultTimeoutSeconds) * time.Second,
	}

	for _, opt := range options {
		opt(config)
	}

	err := validateConfig(config)

	if err != nil {
		return nil, err
	}

	if config.withRandomTlsExtensionOrder {
		rand.Seed(time.Now().UnixNano())
	}

	client, clientProfile, err := buildFromConfig(config)

	if err != nil {
		return nil, err
	}

	config.clientProfile = clientProfile

	if config.debug {
		if logger == nil {
			logger = NewLogger()
		}

		logger = NewDebugLogger(logger)
	}

	if logger == nil {
		logger = NewNoopLogger()
	}

	c := &httpClient{
		Client: *client,
		logger: logger,
		config: config,
	}
	if config.betterJar != nil {
		c.BJar = config.betterJar
	}

	return c, nil
}

func validateConfig(config *httpClientConfig) error {
	return nil
}

func buildFromConfig(config *httpClientConfig) (*http.Client, ClientProfile, error) {
	var dialer proxy.ContextDialer
	dialer = newDirectDialer(config.timeout)

	if config.proxyUrl != "" {
		proxyDialer, err := newConnectDialer(config.proxyUrl, config.timeout)
		if err != nil {
			return nil, ClientProfile{}, err
		}

		dialer = proxyDialer
	}

	var redirectFunc func(req *http.Request, via []*http.Request) error
	if !config.followRedirects {
		redirectFunc = defaultRedirectFunc
	} else {
		redirectFunc = nil
	}

	if config.customRedirectFunc != nil {
		redirectFunc = config.customRedirectFunc
	}

	clientProfile := config.clientProfile

	transport, err := newRoundTripper(clientProfile, config.transportOptions, config.serverNameOverwrite, config.insecureSkipVerify, config.withRandomTlsExtensionOrder, config.forceHttp1, config.certificatePins, config.badPinHandler, dialer)

	if err != nil {
		return nil, clientProfile, err
	}

	client := &http.Client{
		Timeout:       config.timeout,
		Transport:     transport,
		CheckRedirect: redirectFunc,
	}

	if config.cookieJar != nil {
		client.Jar = config.cookieJar
	}
	return client, clientProfile, nil
}

// SetFollowRedirect configures the client's HTTP redirect following policy.
func (c *httpClient) SetFollowRedirect(followRedirect bool) {
	c.logger.Debug("set follow redirect from %v to %v", c.config.followRedirects, followRedirect)

	c.config.followRedirects = followRedirect
	c.applyFollowRedirect()
}

// GetFollowredirect returns the client's HTTP redirect following policy.
func (c *httpClient) GetFollowRedirect() bool {
	return c.config.followRedirects
}

func (c *httpClient) applyFollowRedirect() {
	if c.config.followRedirects {
		c.logger.Info("automatic redirect following is enabled")
		c.CheckRedirect = nil
	} else {
		c.logger.Info("automatic redirect following is disabled")
		c.CheckRedirect = defaultRedirectFunc
	}

	if c.config.customRedirectFunc != nil {
		c.CheckRedirect = c.config.customRedirectFunc
	}
}

// SetProxy configures the client to use the given proxy URL.
//
// proxyUrl should be formatted as:
//
//	"http://user:pass@host:port"
func (c *httpClient) SetProxy(proxyUrl string) error {
	c.logger.Debug("set proxy from %s to %s", c.config.proxyUrl, proxyUrl)
	c.config.proxyUrl = proxyUrl
	c.logger.Info(fmt.Sprintf("set proxy to: %s", proxyUrl))

	return c.applyProxy()
}

// GetProxy returns the proxy URL used by the client.
func (c *httpClient) GetProxy() string {
	return c.config.proxyUrl
}

func (c *httpClient) applyProxy() error {
	var dialer proxy.ContextDialer
	dialer = proxy.Direct

	if c.config.proxyUrl != "" {
		c.logger.Debug("proxy url %s supplied - using proxy connect dialer", c.config.proxyUrl)
		proxyDialer, err := newConnectDialer(c.config.proxyUrl, c.config.timeout)
		if err != nil {
			c.logger.Error("failed to create proxy connect dialer: %s", err.Error())
			return err
		}

		dialer = proxyDialer
	}

	transport, err := newRoundTripper(c.config.clientProfile, c.config.transportOptions, c.config.serverNameOverwrite, c.config.insecureSkipVerify, c.config.withRandomTlsExtensionOrder, c.config.forceHttp1, c.config.certificatePins, c.config.badPinHandler, dialer)

	if err != nil {
		return err
	}

	c.Transport = transport

	return nil
}

// GetCookies returns the cookies in the client's cookie jar for a given URL.
// func (c *httpClient) GetCookies(u *url.URL) []*http.Cookie {
// 	c.logger.Info(fmt.Sprintf("get cookies for url: %s", u.String()))
// 	if c.Jar == nil {
// 		c.logger.Warn("you did not setup a cookie jar")
// 		return nil
// 	}

// 	return c.Jar.Cookies(u)
// }

// // SetCookies sets a list of cookies for a given URL in the client's cookie jar.
// func (c *httpClient) SetCookies(u *url.URL, cookies []*http.Cookie) {
// 	c.logger.Info(fmt.Sprintf("set cookies for url: %s", u.String()))

// 	if c.Jar == nil {
// 		c.logger.Warn("you did not setup a cookie jar")
// 		return
// 	}

// 	c.Jar.SetCookies(u, cookies)
// }

// SetCookieJar sets a jar as the clients cookie jar. This is the recommended way when you want to "clear" the existing cookiejar
func (c *httpClient) SetCookieJar(jar http.CookieJar) {
	c.Jar = jar
}

func (c *httpClient) Do(req *WebReq) (*WebResp, error) {
	// Header order must be defined in all lowercase. On HTTP 1 people sometimes define them also in uppercase and then ordering does not work.
	req.Header[http.HeaderOrderKey] = allToLower(req.Header[http.HeaderOrderKey])

	reqq := &http.Request{
		Method:           req.Method,
		URL:              req.URL,
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           req.Header,
		Body:             req.Body,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Close:            req.Close,
		Host:             req.Host,
		Form:             req.Form,
		PostForm:         req.PostForm,
		MultipartForm:    req.MultipartForm,
		Trailer:          req.Trailer,
		RemoteAddr:       req.RemoteAddr,
		RequestURI:       req.RequestURI,
		TLS:              req.TLS,
		Cancel:           req.Cancel,
		Response:         req.Response,
	}

	resp, err := c.Client.Do(reqq)

	if err != nil {
		c.logger.Debug("failed to do request: %s", err.Error())
		return &WebResp{StatusCode: -1}, err
	}

	c.logger.Debug("requested %s : status %d", req.URL.String(), resp.StatusCode)

	webResp := &WebResp{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         resp.Proto,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Header:        resp.Header,
		ContentLength: resp.ContentLength,
		Close:         resp.Close,
		Uncompressed:  resp.Uncompressed,
		Trailer:       resp.Trailer,
		Request:       resp.Request, // ? should this be reqq
		TLS:           resp.TLS,
	}

	// c.processCookies(webResp)

	if c.Jar != nil {
		cookies := c.Jar.Cookies(reqq.URL)
		cookieStr := ""
		for _, cook := range cookies {
			c.logger.Debug("cookie: %s", cook.String())

			if cook.Name != "" && cook.Value != "" && cook.Value != `""` && cook.Value != "undefined" {
				cookieStr += cook.Name + "=" + cook.Value + "; "
			}
		}
		webResp.Cookies = strings.TrimSuffix(cookieStr, "; ")
	} else if c.BJar != nil {
		// * Use better jar
		c.processCookies(webResp)
	}

	if !req.NoDecodeBody {
		defer resp.Body.Close()
		bodyBytes, err2 := ioutil.ReadAll(resp.Body)
		if err2 != nil {
			return &WebResp{StatusCode: -1}, err2
		}
		webResp.BodyBytes = bodyBytes
		webResp.Body = string(webResp.BodyBytes)
	}

	return webResp, nil
}

// NewRequest wraps NewRequestWithContext using the background context.
func NewRequest(method, url string, body io.Reader) (*WebReq, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		return nil, err
	}

	webReq := &WebReq{
		Method:        req.Method,
		URL:           req.URL,
		Proto:         req.Proto,
		ProtoMajor:    req.ProtoMajor,
		ProtoMinor:    req.ProtoMinor,
		Header:        req.Header,
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Close:         req.Close,
		Host:          req.Host,
		Form:          req.Form,
		PostForm:      req.PostForm,
		MultipartForm: req.MultipartForm,
		Trailer:       req.Trailer,
		RemoteAddr:    req.RemoteAddr,
		RequestURI:    req.RequestURI,
		TLS:           req.TLS,
		Response:      req.Response,
	}

	return webReq, nil
}

// Do issues a given HTTP request and returns the corresponding response.
//
// If the returned error is nil, the response contains a non-nil body, which the user is expected to close.
// func (c *httpClient) Do(req *http.Request) (*http.Response, error) {
// 	// Header order must be defined in all lowercase. On HTTP 1 people sometimes define them also in uppercase and then ordering does not work.
// 	req.Header[http.HeaderOrderKey] = allToLower(req.Header[http.HeaderOrderKey])

// 	if c.config.debug {
// 		debugReq := req.Clone(context.Background())

// 		if req.Body != nil {
// 			buf, err := ioutil.ReadAll(req.Body)

// 			if err != nil {
// 				return nil, err
// 			}

// 			debugBody := ioutil.NopCloser(bytes.NewBuffer(buf))
// 			requestBody := ioutil.NopCloser(bytes.NewBuffer(buf))

// 			debugReq.Body = debugBody
// 			req.Body = requestBody
// 		}

// 		requestBytes, err := httputil.DumpRequestOut(debugReq, debugReq.ContentLength > 0)

// 		if err != nil {
// 			return nil, err
// 		}

// 		c.logger.Debug("raw request bytes sent over wire: %d (%d kb)", len(requestBytes), len(requestBytes)/1024)
// 	}

// 	resp, err := c.Client.Do(req)

// 	if err != nil {
// 		c.logger.Debug("failed to do request: %s", err.Error())
// 		return nil, err
// 	}

// 	c.logger.Debug("cookies on request: %v", resp.Request.Cookies())
// 	c.logger.Debug("requested %s : status %d", req.URL.String(), resp.StatusCode)

// 	if c.config.debug {
// 		responseBytes, err := httputil.DumpResponse(resp, resp.ContentLength > 0)

// 		if err != nil {
// 			return nil, err
// 		}

// 		c.logger.Debug("raw response bytes received over wire: %d (%d kb)", len(responseBytes), len(responseBytes)/1024)
// 	}

// 	return resp, nil
// }

func allToLower(list []string) []string {
	var lower []string

	for _, elem := range list {
		lower = append(lower, strings.ToLower(elem))
	}

	return lower
}
