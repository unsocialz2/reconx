package scope

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// StartProxy enforces the same host scope for supported external HTTP tools.
// HTTPS CONNECT is checked before opening its TCP connection; credentials are never decrypted.
func (f *Filter) StartProxy(ctx context.Context) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !f.IsInScope(r.Host) {
			http.Error(w, "outside scan scope", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodConnect {
			if !f.IsInScope("https://" + r.Host) {
				http.Error(w, "origin outside scan scope", http.StatusForbidden)
				return
			}
			dest := r.Host
			if _, _, err := net.SplitHostPort(dest); err != nil {
				http.Error(w, "CONNECT requires host:port", 400)
				return
			}
			upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", dest)
			if err != nil {
				http.Error(w, "upstream unavailable", 502)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				upstream.Close()
				http.Error(w, "tunneling unsupported", 500)
				return
			}
			client, buf, err := hijacker.Hijack()
			if err != nil {
				upstream.Close()
				return
			}
			mu.Lock()
			connections[client] = true
			connections[upstream] = true
			mu.Unlock()
			defer func() {
				client.Close()
				upstream.Close()
				mu.Lock()
				delete(connections, client)
				delete(connections, upstream)
				mu.Unlock()
			}()
			_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = buf.Flush()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(upstream, buf); upstream.Close(); close(done) }()
			_, _ = io.Copy(client, upstream)
			client.Close()
			<-done
			return
		}
		if !f.IsInScope(r.URL.String()) {
			http.Error(w, "outside scan scope", 403)
			return
		}
		r.RequestURI = ""
		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")
		response, err := (scopedTransport{f, transport}).RoundTrip(r)
		if err != nil {
			http.Error(w, "upstream unavailable", 502)
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})}
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
			server.Close()
			transport.CloseIdleConnections()
			mu.Lock()
			for conn := range connections {
				conn.Close()
			}
			mu.Unlock()
		})
	}
	go func() { _ = server.Serve(listener) }()
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	return fmt.Sprintf("http://%s", listener.Addr()), stop, nil
}
