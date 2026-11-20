package dashboard

import "time"

// SetStreamCheck shortens the keep-alive and session check of the event
// stream for the external tests.
func SetStreamCheck(s *Server, d time.Duration) { s.streamCheck = d }
