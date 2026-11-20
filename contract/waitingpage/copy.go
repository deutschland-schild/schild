package waitingpage

// Copy of the waiting page (illustration A "Parkbank", chosen by the
// initiator on 2026-10-29; tests/results/waiting-page-2026-10-29/variant-a.html).
// German is the default, du-form; English by Accept-Language (Language).
// {site} is the HTML-escaped website name in <strong> (SiteName); without a
// name LeadNoSite is used. {n} is Retry-After, {time} the UTC time
// (2006-01-02 15:04:05). The page has no incident number: it is no block.
type Copy struct {
	Title      string // <title>
	Headline   string // <h1>
	Lead       string // with {site}
	LeadNoSite string
	NextReload string // variant reload (GET, HEAD)
	NextForm   string // variant form (POST): no meta refresh, no countdown
	Countdown  string // variant reload only, with {n}
	Footer     string // with {time}
}

// Texts by language.
var Texts = map[string]Copy{
	LangDE: {
		Title:      "Einen Moment, bitte",
		Headline:   "Kurz Platz nehmen, bitte.",
		Lead:       "{site} bekommt gerade sehr viele Anfragen auf einmal. Deine Anfrage kommt deshalb in diesem Moment nicht durch.",
		LeadNoSite: "Diese Website bekommt gerade sehr viele Anfragen auf einmal. Deine Anfrage kommt deshalb in diesem Moment nicht durch.",
		NextReload: "Du musst nichts tun. Die Seite lädt in ein paar Sekunden von selbst neu.",
		NextForm:   "Was du abgeschickt hast, ist nicht angekommen. Warte bitte ein paar Sekunden, geh dann einen Schritt zurück und schick es noch einmal ab.",
		Countdown:  "Neuer Versuch in {n} s",
		Footer:     "Zeit: {time} UTC",
	},
	LangEN: {
		Title:      "One moment, please",
		Headline:   "Please take a seat for a moment.",
		Lead:       "{site} is getting a lot of requests at once right now, so yours can't get through at this moment.",
		LeadNoSite: "This website is getting a lot of requests at once right now, so yours can't get through at this moment.",
		NextReload: "No need to do anything. This page reloads by itself in a few seconds.",
		NextForm:   "What you sent did not arrive. Please wait a few seconds, then go back one step and send it again.",
		Countdown:  "Next try in {n} s",
		Footer:     "Time: {time} UTC",
	},
}
