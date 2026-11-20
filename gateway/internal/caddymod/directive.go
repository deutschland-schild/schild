package caddymod

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Directive is the Caddyfile directive of http.handlers.schild (MVP-19).
const Directive = "schild"

// DirectiveBefore is the stock directive that `schild` is ordered before.
// "redir" is the first directive of Caddy's default order that answers or
// changes a request (after header, request_body and variables), so schild
// runs before redir, method, rewrite, uri, try_files, basic_auth,
// forward_auth, encode, handle, handle_path, route, respond, reverse_proxy,
// php_fastcgi and file_server, and sees the request as the client sent it.
// Inside an explicit route block the operator decides the position.
const DirectiveBefore = "redir"

func init() {
	httpcaddyfile.RegisterHandlerDirective(Directive, parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder(Directive, httpcaddyfile.Before, DirectiveBefore)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	schild
//
// The directive takes no arguments and no block (besides the optional
// matcher every handler directive accepts); all settings live in
// schild.yaml.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if d.NextArg() {
		return d.ArgErr()
	}
	if d.NextBlock(0) {
		return d.Err("schild takes no block; settings live in schild.yaml")
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(Handler)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

var _ caddyfile.Unmarshaler = (*Handler)(nil)
