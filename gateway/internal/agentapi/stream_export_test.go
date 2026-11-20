package agentapi

import "time"

// SetStreamCheck shortens how often an open stream re-checks its token
// (external tests).
func SetStreamCheck(s *Server, d time.Duration) { s.streamCheck = d }
