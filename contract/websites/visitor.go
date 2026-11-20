package websites

import "github.com/deutschland-schild/schild/contract/monitoring"

// SchemaVisitor is the input schema of the website-visitor vectors (D36
// amendment 2026-10-29: "Besucher" are people, not bots).
const SchemaVisitor = "website-visitor"

// RunVisitorVector parses and validates a website-visitor vector input and
// returns whether the request counts its client as a visitor and as a bot
// client (monitoring.Visitor, monitoring.BotClient).
func RunVisitorVector(raw []byte) (monitoring.VisitorResult, error) {
	v, err := parse(raw, SchemaVisitor)
	if err != nil {
		return monitoring.VisitorResult{}, err
	}
	ua, cat, out := v["ua_class"].(string), v["bot_category"].(string), v["outcome"].(string)
	return monitoring.VisitorResult{Visitor: monitoring.Visitor(ua, cat, out), BotClient: monitoring.BotClient(ua, cat)}, nil
}
