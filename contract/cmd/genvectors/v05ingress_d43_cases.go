//go:build !release

package main

// Code generated from Caddyfiles adapted with the stock Caddyfile adapter of the
// embedded Caddy (v2.11.4), as v05ingress_cases.go. DO NOT EDIT by hand:
// re-adapt the Caddyfiles instead. Server-side values (D43): both directions
// of header_hidden_from_schild.

var ingressD43Cases = []ingressCase{
	{name: "header-server-proto", desc: "Accepted (D43, measurement finding 5): the scheme is a server-side value, so writing it again behind schild brings nothing back.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header X-Forwarded-Proto {http.request.scheme}\n\t\tschild\n\t\treverse_proxy 127.0.0.1:18082 {\n\t\t\theader_up X-Forwarded-Proto {http.request.scheme}\n\t\t}\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"set":{"X-Forwarded-Proto":["{http.request.scheme}"]}}},{"handler":"schild"},{"handler":"reverse_proxy","headers":{"request":{"set":{"X-Forwarded-Proto":["{http.request.scheme}"]}}},"upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  0},
	{name: "header-server-host", desc: "Accepted (D43): {host} is the Host schild inspected, as long as nothing before schild changed Host.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header X-Forwarded-Host {host}\n\t\tschild\n\t\treverse_proxy 127.0.0.1:18082 {\n\t\t\theader_up X-Forwarded-Host {host}\n\t\t}\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"set":{"X-Forwarded-Host":["{http.request.host}"]}}},{"handler":"schild"},{"handler":"reverse_proxy","headers":{"request":{"set":{"X-Forwarded-Host":["{http.request.host}"]}}},"upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  0},
	{name: "header-server-request-id", desc: "Accepted (D43): a request id made by the server.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header X-Request-Id {http.request.uuid}\n\t\tschild\n\t\treverse_proxy 127.0.0.1:18082 {\n\t\t\theader_up X-Request-Id {http.request.uuid}\n\t\t}\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"set":{"X-Request-Id":["{http.request.uuid}"]}}},{"handler":"schild"},{"handler":"reverse_proxy","headers":{"request":{"set":{"X-Request-Id":["{http.request.uuid}"]}}},"upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  0},
	{name: "header-server-forwarded", desc: "Accepted (D43): the client's Forwarded is removed and replaced by what the server knows about the peer.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header -Forwarded\n\t\tschild\n\t\treverse_proxy 127.0.0.1:18082 {\n\t\t\theader_up Forwarded \"for={remote_host}\"\n\t\t}\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"delete":["Forwarded"]}},{"handler":"schild"},{"handler":"reverse_proxy","headers":{"request":{"set":{"Forwarded":["for={http.request.remote.host}"]}}},"upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  0},
	{name: "header-server-mixed-text", desc: "Accepted (D43): text around server-side values is no client value.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header -X-Client\n\t\tschild\n\t\treverse_proxy 127.0.0.1:18082 {\n\t\t\theader_up X-Client \"{remote_host}:{remote_port} via {upstream_hostport}\"\n\t\t}\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"delete":["X-Client"]}},{"handler":"schild"},{"handler":"reverse_proxy","headers":{"request":{"set":{"X-Client":["{http.request.remote.host}:{http.request.remote.port} via {http.reverse_proxy.upstream.hostport}"]}}},"upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  0},
	{name: "header-hider-server-value-restored", desc: "Refused (D43): a server-side value in the hider changes nothing: the hider hides, and the writer brings the client value back.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header X-Saved {http.request.header.Referer}\n\t\trequest_header Referer {http.request.scheme}\n\t\tschild\n\t\trequest_header Referer {http.request.header.X-Saved}\n\t\treverse_proxy 127.0.0.1:18082\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"set":{"X-Saved":["{http.request.header.Referer}"]}}},{"handler":"headers","request":{"set":{"Referer":["{http.request.scheme}"]}}},{"handler":"schild"},{"handler":"headers","request":{"set":{"Referer":["{http.request.header.X-Saved}"]}}},{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  1},
	{name: "header-server-value-beside-client", desc: "Refused (D43): one client placeholder in a value is enough, also next to server-side ones.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header -Referer\n\t\tschild\n\t\trequest_header Referer \"{http.request.scheme}{vars.r}\"\n\t\treverse_proxy 127.0.0.1:18082\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"delete":["Referer"]}},{"handler":"schild"},{"handler":"headers","request":{"set":{"Referer":["{http.request.scheme}{http.vars.r}"]}}},{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  1},
	{name: "header-host-carries-value", desc: "Refused (D43): Host was changed before schild, so {host} can carry a value schild saw under another name.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header Host {http.request.header.Referer}\n\t\trequest_header -Referer\n\t\tschild\n\t\trequest_header Referer {host}\n\t\treverse_proxy 127.0.0.1:18082\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"set":{"Host":["{http.request.header.Referer}"]}}},{"handler":"headers","request":{"delete":["Referer"]}},{"handler":"schild"},{"handler":"headers","request":{"set":{"Referer":["{http.request.host}"]}}},{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  1},
	{name: "header-client-ip-var", desc: "Refused (D43): vars can overwrite client_ip, so no variable counts as server-side.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\tvars client_ip {http.request.header.Referer}\n\t\trequest_header -Referer\n\t\tschild\n\t\trequest_header Referer {client_ip}\n\t\treverse_proxy 127.0.0.1:18082\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"client_ip":"{http.request.header.Referer}","handler":"vars"},{"handler":"headers","request":{"delete":["Referer"]}},{"handler":"schild"},{"handler":"headers","request":{"set":{"Referer":["{http.vars.client_ip}"]}}},{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  1},
	{name: "header-placeholder-default", desc: "Refused (D43): a placeholder with a default is not on the list.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header -Referer\n\t\tschild\n\t\trequest_header Referer {http.request.scheme:x}\n\t\treverse_proxy 127.0.0.1:18082\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"delete":["Referer"]}},{"handler":"schild"},{"handler":"headers","request":{"set":{"Referer":["{http.request.scheme:x}"]}}},{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  1},
	{name: "header-orig-uri-placeholder", desc: "Refused (D43): a placeholder that is not on the list counts as a client value.",
		caddyfile: "http://a.example.test {\n\troute {\n\t\trequest_header -Referer\n\t\tschild\n\t\trequest_header Referer {http.request.orig_uri}\n\t\treverse_proxy 127.0.0.1:18082\n\t}\n}\n",
		servers:   `{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"headers","request":{"delete":["Referer"]}},{"handler":"schild"},{"handler":"headers","request":{"set":{"Referer":["{http.request.orig_uri}"]}}},{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:18082"}]}]}]}]}]}],"match":[{"host":["a.example.test"]}],"terminal":true}]}}`,
		findings:  1},
}
