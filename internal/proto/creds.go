package proto

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"strings"
)

// PlaintextCredential describes a credential-like value found in cleartext
// traffic, for the plaintext-credential security detector.
type PlaintextCredential struct {
	Protocol string // "HTTP", "FTP", "TELNET", "POP3", "IMAP", "HTTP-FORM"
	Detail   string // human-readable description (header, command, field name)
	Username string
	Password string // may be empty if only a username/command was recoverable
}

// ScanHTTPCleartext inspects a single HTTP request buffer (as seen on one
// TCP segment) for Basic-Auth headers, a Host header, and password-looking
// form fields. It is intentionally best-effort/single-packet since full TCP
// stream reassembly is out of scope.
func ScanHTTPCleartext(payload []byte) (creds []PlaintextCredential, host string) {
	if !looksLikeHTTP(payload) {
		return nil, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(payload))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "host:"):
			host = strings.TrimSpace(line[len("host:"):])
		case strings.HasPrefix(lower, "authorization:") && strings.Contains(lower, "basic "):
			idx := strings.Index(line, "Basic ")
			if idx == -1 {
				idx = strings.Index(lower, "basic ")
			}
			enc := strings.TrimSpace(line[idx+len("Basic "):])
			if dec, err := base64.StdEncoding.DecodeString(enc); err == nil {
				user, pass, _ := strings.Cut(string(dec), ":")
				creds = append(creds, PlaintextCredential{
					Protocol: "HTTP", Detail: "Authorization: Basic header",
					Username: user, Password: pass,
				})
			}
		}
	}
	// Best-effort scan of a urlencoded body for password-looking fields.
	if body := httpBody(payload); body != "" {
		for _, field := range strings.Split(body, "&") {
			k, v, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			lk := strings.ToLower(k)
			if strings.Contains(lk, "passwd") || strings.Contains(lk, "password") || lk == "pwd" {
				creds = append(creds, PlaintextCredential{
					Protocol: "HTTP-FORM", Detail: "form field " + k, Password: v,
				})
			}
		}
	}
	return creds, host
}

func looksLikeHTTP(b []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "HTTP/1."}
	for _, m := range methods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

func httpBody(b []byte) string {
	idx := bytes.Index(b, []byte("\r\n\r\n"))
	if idx == -1 || idx+4 >= len(b) {
		return ""
	}
	return string(b[idx+4:])
}

// ScanFTP inspects a single FTP control-channel line for USER/PASS commands.
func ScanFTP(line string) *PlaintextCredential {
	trimmed := strings.TrimSpace(line)
	upper := strings.ToUpper(trimmed)
	switch {
	case strings.HasPrefix(upper, "USER "):
		return &PlaintextCredential{Protocol: "FTP", Detail: "USER command", Username: strings.TrimSpace(trimmed[5:])}
	case strings.HasPrefix(upper, "PASS "):
		return &PlaintextCredential{Protocol: "FTP", Detail: "PASS command", Password: strings.TrimSpace(trimmed[5:])}
	}
	return nil
}

// ScanTelnetLogin does a best-effort check for a Telnet "login:"/"Password:"
// prompt/response pattern in raw payload text.
func ScanTelnetLogin(payload []byte) *PlaintextCredential {
	s := string(payload)
	lower := strings.ToLower(s)
	if strings.Contains(lower, "login:") || strings.Contains(lower, "password:") || strings.Contains(lower, "username:") {
		return &PlaintextCredential{Protocol: "TELNET", Detail: "login/password prompt observed in cleartext"}
	}
	return nil
}

// ScanMailLogin inspects a POP3/IMAP control line for plaintext USER/PASS
// (POP3) or LOGIN (IMAP) commands.
func ScanMailLogin(protocol, line string) *PlaintextCredential {
	trimmed := strings.TrimSpace(line)
	upper := strings.ToUpper(trimmed)
	switch {
	case strings.HasPrefix(upper, "USER "):
		return &PlaintextCredential{Protocol: protocol, Detail: "USER command", Username: strings.TrimSpace(trimmed[5:])}
	case strings.HasPrefix(upper, "PASS "):
		return &PlaintextCredential{Protocol: protocol, Detail: "PASS command", Password: strings.TrimSpace(trimmed[5:])}
	case strings.Contains(upper, " LOGIN "):
		fields := strings.Fields(trimmed)
		for i, f := range fields {
			if strings.EqualFold(f, "LOGIN") && i+2 < len(fields) {
				return &PlaintextCredential{
					Protocol: protocol, Detail: "LOGIN command",
					Username: strings.Trim(fields[i+1], `"`), Password: strings.Trim(fields[i+2], `"`),
				}
			}
		}
	}
	return nil
}
