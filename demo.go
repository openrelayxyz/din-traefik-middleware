// Package plugindemo a demo plugin.
package din_traefik_middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"text/template"
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"sync"
	"hash/fnv"
)

// Config the plugin configuration.
type Config struct {
	// Providers map[string]string `json:"providers,omitempty"`
	// Methods map[string][]string `json:"methods,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	log.Printf("Creating din middleware config")
	return &Config{
		// Providers: make(map[string]string),
		// Methods: make(map[string][]string),
	}
}

// type methodChoice struct {
// 	counter int
// 	methods []*url.URL
// }

// func (mc *methodChoice) next() *url.URL {
// 	mc.counter++
// 	return mc.methods[mc.counter % len(mc.methods)]
// }

// Demo a Demo plugin.
type Demo struct {
	client    *http.Client
	next      http.Handler
	// methods   map[string]*methodChoice
	name      string
	template  *template.Template
	sessTokMap map[string]map[string]struct{}
	sessToks  []string
	sessTokLock sync.RWMutex
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.Printf("Creating din middleware object")
	return &Demo{
		client: &http.Client{},
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
		sessTokMap: make(map[string]map[string]struct{}),
		sessToks: []string{},
	}, nil
}

type rpcCall struct {
	Method string `json:"method"`
}

// parseSetCookies takes an http.Header (which could be obtained from an http.Response)
// and parses the Set-Cookie headers to return a map of cookie names to cookie values.
func parseSetCookies(headers http.Header) []string {
	cookies := []string{}
	for _, cookieHeader := range headers["Set-Cookie"] {
		// Split the cookie string on the first '=' to separate the name and value
		parts := strings.SplitN(cookieHeader, "=", 2)
		if len(parts) == 2 {
			// Further split the value part on ';' to ignore attributes like Path, Expires etc.
			valueParts := strings.SplitN(parts[1], ";", 2)
			cookieName := parts[0]
			cookieValue := valueParts[0]
			cookies = append(cookies, fmt.Sprintf("%v=%v", cookieName, cookieValue))
		}
	}
	return cookies
}

func insert(ss []string, s string) []string {
    i := sort.SearchStrings(ss, s)
    ss = append(ss, "")
    copy(ss[i+1:], ss[i:])
    ss[i] = s
    return ss
}

func (a *Demo) addSessions(prePath string, headers http.Header) {
	cookies := parseSetCookies(headers)
	for _, v := range cookies {
		if strings.HasPrefix(v, "_") {
			a.sessTokLock.RLock()
			if _, ok := a.sessTokMap[prePath]; !ok {
				a.sessTokLock.RUnlock()
				a.sessTokLock.Lock()
				a.sessTokMap[prePath] = make(map[string]struct{})
				a.sessTokMap[prePath][v] = struct{}{}
				a.sessToks = insert(a.sessToks, v)
				a.sessTokLock.Unlock()
				continue
			}
			if _, ok := a.sessTokMap[prePath][v]; !ok {
				a.sessTokLock.RUnlock()
				a.sessTokLock.Lock()
				a.sessTokMap[prePath][v] = struct{}{}
				a.sessToks = insert(a.sessToks, v)
				a.sessTokLock.Unlock()
				continue
			}
			a.sessTokLock.RUnlock()
		}
	}
	// log.Printf("Sessions: %v (%v) (%v)", a.sessToks, cookies, a.sessTokMap)
}

func hashStringToIndex(s string, listSize int) int {
    hasher := fnv.New32a() // Initialize a new 32-bit FNV-1a hash
    hasher.Write([]byte(s)) // Hash the string
    hash := hasher.Sum32() // Get the hash as a 32-bit unsigned integer
    index := int(hash) % listSize // Use modulo to ensure the index is within the bounds of the list
    return index
}

func (a *Demo) getSession(prePath, key string) string {
	if len(a.sessToks) == 0 {
		return ""
	}
	a.sessTokLock.RLock()
	defer a.sessTokLock.RUnlock()
	// log.Printf("Using index %v", hashStringToIndex(prePath + key, len(a.sessToks)))
	return a.sessToks[hashStringToIndex(prePath + key, len(a.sessToks))]
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// log.Printf("Got request: '%v'", req.URL)
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(rw, "Server Error1", http.StatusInternalServerError)
		return
	}
	var rpc rpcCall
	if err := json.Unmarshal(body, &rpc); err != nil {
		log.Printf("Error unmarshalling")
		http.Error(rw, err.Error(), http.StatusOK)
		// a.next.ServeHTTP(rw, req)
		return
	}
	prePath := req.URL.Path

	path := req.URL.Path + "/" + strings.Join(strings.Split(rpc.Method, "_"), "/")
	
	req.URL.RawPath = path
	
	req.URL.Path, err = url.PathUnescape(req.URL.RawPath)
	if err != nil {
		// middlewares.GetLogger(context.Background(), r.name, typeName).Error().Err(err).Send()
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	if v := req.Header.Get("Din-Session-Id"); v != "" {
		if sessionToken := a.getSession(prePath, v); sessionToken != "" {
			req.Header.Add("Cookie", sessionToken)
		}
	}
	req.RequestURI = req.URL.RequestURI()
	
	// log.Printf("Path %v", req.RequestURI)

	a.next.ServeHTTP(rw, req)
	a.addSessions(prePath, rw.Header())

	// TODO: Look at SetCookie header to remove session IDs that get rerouted
}
