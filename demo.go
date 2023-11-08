// Package plugindemo a demo plugin.
package plugindemo

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
	"strings"
)

// Config the plugin configuration.
type Config struct {
	// Providers map[string]string `json:"providers,omitempty"`
	// Methods map[string][]string `json:"methods,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
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
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	return &Demo{
		client: &http.Client{},
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

type rpcCall struct {
	Method string `json:"method"`
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log.Printf("Got request: '%v'", req.URL)
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(rw, "Server Error1", http.StatusInternalServerError)
		return
	}
	var rpc rpcCall
	if err := json.Unmarshal(body, &rpc); err != nil {
		log.Printf("Error unmarshalling")
		a.next.ServeHTTP(rw, req)
		return
	}

	path := req.URL.Path + "/" + strings.Join(strings.Split(rpc.Method, "_"), "/")
	
	req.URL.RawPath = path
	
	req.URL.Path, err = url.PathUnescape(req.URL.RawPath)
	if err != nil {
		// middlewares.GetLogger(context.Background(), r.name, typeName).Error().Err(err).Send()
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	
	req.RequestURI = req.URL.RequestURI()
	
	log.Printf("Path %v", req.RequestURI)

	a.next.ServeHTTP(rw, req)
}
