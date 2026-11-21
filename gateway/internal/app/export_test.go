package app

// ConfigHash is the config version the agent API shows (tests).
func (a *App) ConfigHash() string {
	if p := a.configHash.Load(); p != nil {
		return *p
	}
	return ""
}

// GroupConfigVersion is the config version a node tells its group (tests).
var GroupConfigVersion = groupConfigVersion
