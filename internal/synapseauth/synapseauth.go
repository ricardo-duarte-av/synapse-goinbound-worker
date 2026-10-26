// Package synapseauth is Synapse's federation request authentication
// (federation/transport/server/_base.py), for a /send request: the body
// parsed first (parse_json_object_from_request), then Authenticator.
// authenticate_request, with Synapse's errors as Synapse words them.
//
// The front door verifies requests with its own verifier, which is fast and
// right for requests that authenticate. A request it refuses is judged here
// before being answered: when this port refuses it too, with an error whose
// words it reproduces, that error is Synapse's answer; anything else (this
// port accepting it, or an error it cannot word exactly) is left to Synapse.
package synapseauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// Answer is a SynapseError as the federation resource sends it.
type Answer struct {
	Status  int
	Errcode string
	Error   string
}

// Result of authenticating a request: an Answer (Synapse refuses it), an
// Origin (it accepts it), or Uncertain (we cannot say which, or not in
// Synapse's words).
type Result struct {
	Answer    *Answer
	Origin    string
	Uncertain string
}

func refuse(status int, errcode, msg string) Result {
	return Result{Answer: &Answer{Status: status, Errcode: errcode, Error: msg}}
}

func uncertain(why string) Result { return Result{Uncertain: why} }

// Authenticator authenticates requests for one server.
type Authenticator struct {
	server string
	// whitelist is federation_domain_whitelist; nil when not set.
	whitelist map[string]bool
	// keys finds signing keys as Synapse's Keyring does (internal/keyring).
	keys func(ctx context.Context) pdu.KeyFetch
}

// New builds an authenticator for server.
func New(server string, whitelist map[string]bool, keys func(ctx context.Context) pdu.KeyFetch) *Authenticator {
	return &Authenticator{server: server, whitelist: whitelist, keys: keys}
}

// Request is what Synapse authenticates: the method, the URI as received,
// the Authorization headers, and the body.
type Request struct {
	Method string
	URI    string
	Auth   []string
	Body   []byte
}

// FromHTTP takes a request's parts as Twisted gives them to Synapse.
func FromHTTP(r *http.Request, body []byte) Request {
	return Request{Method: r.Method, URI: r.RequestURI, Auth: r.Header.Values("Authorization"), Body: body}
}

// Prechecked is a request through every check before the keyring.
type Prechecked struct {
	origin string
	// sigs are signatures[origin], in insertion order.
	sigs []sig
	// content is the parsed body.
	content json.RawMessage
}

type sig struct{ key, value string }

// Precheck is everything up to the keyring: the body, the headers, the
// destination, the whitelist. A nil Prechecked comes with the Result to give.
func (a *Authenticator) Precheck(req Request) (*Prechecked, Result) {
	// parse_json_object_from_request.
	if !utf8.Valid(req.Body) || !json.Valid(req.Body) {
		return nil, refuse(http.StatusBadRequest, "M_NOT_JSON", "Content not JSON.")
	}
	if tooDeep(req.Body) {
		// Python's json raises RecursionError somewhere past ~1000
		// levels: "Content not JSON." too, but where exactly is not ours
		// to guess.
		return nil, uncertain("deeply nested body")
	}
	if !gjson.ParseBytes(req.Body).IsObject() {
		return nil, refuse(http.StatusBadRequest, "M_BAD_JSON", "Content must be a JSON object.")
	}

	if len(req.Auth) == 0 {
		return nil, refuse(http.StatusUnauthorized, "M_UNAUTHORIZED", "Missing Authorization headers")
	}
	p := &Prechecked{content: req.Body}
	sigs := map[string]map[string]int{} // origin -> key -> index in its list
	lists := map[string][]sig{}
	have := false
	for _, h := range req.Auth {
		if !strings.HasPrefix(h, "X-Matrix") {
			continue
		}
		origin, key, value, dest, ok := parseAuthHeader(h)
		if !ok {
			return nil, refuse(http.StatusBadRequest, "M_UNAUTHORIZED", "Malformed Authorization header")
		}
		p.origin, have = origin, true
		if sigs[origin] == nil {
			sigs[origin] = map[string]int{}
		}
		if i, ok := sigs[origin][key]; ok {
			lists[origin][i].value = value
		} else {
			sigs[origin][key] = len(lists[origin])
			lists[origin] = append(lists[origin], sig{key, value})
		}
		if dest != nil && *dest != a.server {
			r, ok := pyRepr(*dest)
			if !ok {
				return nil, uncertain("destination's repr")
			}
			return nil, refuse(http.StatusUnauthorized, "M_UNAUTHORIZED", "Destination mismatch in auth header, received: "+r)
		}
	}
	if a.whitelist != nil && (!have || !a.whitelist[p.origin]) {
		name := "None"
		if have {
			name = p.origin
		}
		return nil, refuse(http.StatusForbidden, "M_FORBIDDEN", fmt.Sprintf("Federation denied with %s.", name))
	}
	if !have {
		return nil, refuse(http.StatusUnauthorized, "M_UNAUTHORIZED", "Missing Authorization headers")
	}
	p.sigs = lists[p.origin]
	return p, Result{}
}

// Verify is Keyring.verify_json_for_server(origin, json_request, now) for a
// prechecked request.
func (a *Authenticator) Verify(ctx context.Context, req Request, p *Prechecked, nowMS int64) Result {
	signed, err := a.signedObject(req, p)
	if err != nil {
		return uncertain(err.Error())
	}
	if !pythonCanonical(p.content) {
		return uncertain("a body whose canonical JSON Python writes differently")
	}
	err = pdu.VerifyJSONForServer(p.origin, signed, nowMS, a.keys(ctx))
	if err == nil {
		return Result{Origin: p.origin}
	}
	var se *pdu.SignatureError
	if !errors.As(err, &se) {
		return uncertain("key lookup: " + err.Error())
	}
	text, ok := se.RequestText()
	if !ok {
		return uncertain("not in Synapse's words: " + se.Error())
	}
	status := http.StatusUnauthorized
	if se.Kind == pdu.SigNotSigned {
		status = http.StatusBadRequest
	}
	return refuse(status, "M_UNAUTHORIZED", text)
}

// signedObject is json_request: method, uri, destination, origin,
// signatures and content.
func (a *Authenticator) signedObject(req Request, p *Prechecked) ([]byte, error) {
	sigs := make([]string, 0, len(p.sigs))
	for _, s := range p.sigs {
		k, _ := json.Marshal(s.key)
		v, _ := json.Marshal(s.value)
		sigs = append(sigs, string(k)+":"+string(v))
	}
	o, _ := json.Marshal(p.origin)
	m, _ := json.Marshal(req.Method)
	u, _ := json.Marshal(req.URI)
	d, _ := json.Marshal(a.server)
	return []byte(`{"method":` + string(m) + `,"uri":` + string(u) + `,"destination":` + string(d) +
		`,"signatures":{` + string(o) + `:{` + strings.Join(sigs, ",") + `}},"content":` + string(p.content) +
		`,"origin":` + string(o) + `}`), nil
}

var (
	xMatrixPrefix = regexp.MustCompile(`^X-Matrix +`)
	paramSep      = regexp.MustCompile(`[ \t]*,[ \t]*`)
	backslashed   = regexp.MustCompile(`\\(.)`)
)

// parseAuthHeader is _parse_auth_header: ok is false where it raises.
func parseAuthHeader(h string) (origin, key, sig string, dest *string, ok bool) {
	if !utf8.ValidString(h) {
		return "", "", "", nil, false
	}
	loc := xMatrixPrefix.FindStringIndex(h)
	if loc == nil {
		// re.split(...)[1]: IndexError.
		return "", "", "", nil, false
	}
	params := map[string]string{}
	for _, param := range paramSep.Split(h[loc[1]:], -1) {
		k, v, found := strings.Cut(param, "=")
		if !found {
			return "", "", "", nil, false
		}
		params[pyLower(k)] = v
	}
	strip := func(v string) string {
		if strings.HasPrefix(v, `"`) {
			inner := ""
			if len(v) >= 2 {
				inner = v[1 : len(v)-1]
			}
			return backslashed.ReplaceAllString(inner, "$1")
		}
		return v
	}
	o, okO := params["origin"]
	if !okO {
		return "", "", "", nil, false
	}
	origin = strip(o)
	if !validServerName(origin) {
		return "", "", "", nil, false
	}
	k, okK := params["key"]
	s, okS := params["sig"]
	if !okK || !okS {
		return "", "", "", nil, false
	}
	if d, okD := params["destination"]; okD {
		d = strip(d)
		dest = &d
	}
	return origin, strip(k), strip(s), dest, true
}

// pyLower is str.lower for the ASCII parameter names that matter; other
// characters are left as they are, which only affects names that match
// nothing.
func pyLower(s string) string { return strings.ToLower(s) }

var validHost = regexp.MustCompile(`\A[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*\z`)

// validServerName is parse_and_validate_server_name not raising.
func validServerName(name string) bool {
	host := name
	if !(name != "" && name[len(name)-1] == ']') {
		if i := strings.LastIndexByte(name, ':'); i >= 0 {
			host = name[:i]
			if !pyIntOK(name[i+1:]) {
				return false
			}
		}
	}
	if host != "" && host[0] == '[' {
		if host[len(host)-1] != ']' {
			return false
		}
		ip := net.ParseIP(host[1 : len(host)-1])
		return ip != nil && strings.Contains(host, ":")
	}
	return validHost.MatchString(host)
}

// pyIntOK is int(s) not raising, for ASCII: optional whitespace and sign,
// digits with single underscores between them.
var pyInt = regexp.MustCompile(`^[ \t\n\r\f\v]*[+-]?[0-9](?:_?[0-9])*[ \t\n\r\f\v]*$`)

func pyIntOK(s string) bool { return pyInt.MatchString(s) }

// pyRepr is repr(s) for a printable-ASCII string: single quotes, unless it
// holds one and no double quote.
func pyRepr(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return "", false
		}
	}
	q := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = `"`
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	if q == "'" {
		s = strings.ReplaceAll(s, "'", `\'`)
	}
	return q + s + q, true
}

// tooDeep says the body nests past what we take Python to parse.
func tooDeep(b []byte) bool {
	depth, inString, esc := 0, false, false
	for _, c := range b {
		switch {
		case esc:
			esc = false
		case inString && c == '\\':
			esc = true
		case c == '"':
			inString = !inString
		case inString:
		case c == '{' || c == '[':
			if depth++; depth > 500 {
				return true
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return false
}

// pythonCanonical says encode_canonical_json(json.loads(body)) is
// pdu.Canonical(body): no duplicate keys (Python keeps the last), and no
// number but a plain integer (Python rewrites 1e3 and -0).
func pythonCanonical(body []byte) bool {
	ok := true
	var walk func(v gjson.Result)
	walk = func(v gjson.Result) {
		if !ok {
			return
		}
		switch {
		case v.IsObject():
			seen := map[string]bool{}
			v.ForEach(func(k, x gjson.Result) bool {
				if seen[k.Str] {
					ok = false
					return false
				}
				seen[k.Str] = true
				walk(x)
				return ok
			})
		case v.IsArray():
			v.ForEach(func(_, x gjson.Result) bool { walk(x); return ok })
		case v.Type == gjson.Number:
			if !plainInt.MatchString(v.Raw) || v.Raw == "-0" {
				ok = false
			}
		case v.Type == gjson.String:
			if loneSurrogate.MatchString(v.Raw) {
				ok = false
			}
		}
	}
	walk(gjson.ParseBytes(body))
	return ok
}

var (
	plainInt = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)
	// Any surrogate escape: a paired one encodes alike, a lone one does
	// not, and telling them apart is not worth it.
	loneSurrogate = regexp.MustCompile(`(?i)\\ud[89a-f][0-9a-f]{2}`)
)
