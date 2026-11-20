/** Short explanations for terms that cannot be avoided in the dashboard (brand rule: no jargon without explanation). */
export const GLOSSARY = {
  waf: { term: 'Filter (WAF)', text: 'Eine Web Application Firewall: ein Filter vor deiner Website, der Angriffe erkennt und abwehrt. Er läuft auf deinem Server.' },
  crs: { term: 'CRS', text: 'Das OWASP Core Rule Set: frei verfügbare Grundregeln gegen die häufigsten Angriffe. Sie laufen lokal auf deinem Server.' },
  asn: { term: 'ASN', text: 'Nummer des Netzes, aus dem eine Anfrage kommt, z. B. ein Hoster oder ein Internetanbieter. Hilft zu erkennen, ob jemand aus einem Rechenzentrum oder von zu Hause kommt.' },
  probelauf: { term: 'Probelauf', text: 'Eine Regel zählt nur mit und sperrt nichts. So siehst du vorher, ob sie echte Besucher:innen treffen würde.' },
  score: { term: 'Score', text: 'Punkte einer Anfrage, von 0 bis 100. Jede Regel, die anschlägt, gibt Punkte, je schwerer der Fund, desto mehr. Ab 40 ist die Sperrschwelle erreicht: Dann sperrt Schild die Anfrage, wenn OWASP CRS auf „Sperren“ steht. 40 von 100 heißt also: genau an der Grenze.' },
  incident: { term: 'Vorfallnummer', text: 'Steht auf der Sperrseite, z. B. K7QM-4XWD. Mit ihr findest du die gestoppte Anfrage und lässt die Person wieder durch.' },
  session: { term: 'Sitzung', text: 'Mehrere Anfragen, die zeitlich zusammengehören. Lokal und kurzlebig, keine Person.' },
  pseudonym: { term: 'pseudonym', text: 'Ohne Namen oder IP-Adresse, aber nicht anonym: Mit anderen Daten ließe sich im Einzelfall ein Bezug herstellen. Darum speichert Schild so wenig wie möglich.' },
  ja4: { term: 'JA4', text: 'Ein Fingerabdruck der verschlüsselten Verbindung. Er beschreibt das Programm (z. B. ein Angriffswerkzeug), nicht die Person.' },
  gateway: { term: 'Gateway', text: 'Der Server, auf dem Schild vor deinen Websites steht: Reverse-Proxy mit Filter und diesem Dashboard. App-Server dahinter bekommen ihre Anfragen über das Gateway.' },
  agent: { term: 'Agent', text: 'Ein kleines eigenes Programm (schild-agent) auf einem App-Server hinter dem Gateway. Es liest den Server nur und schickt seinen Bericht signiert an dieses Gateway. Der Bericht bleibt auf deinen Servern. Der Agent nimmt keine Befehle an und filtert keinen Traffic.' },
  fingerabdruck: { term: 'Fingerabdruck', text: 'Eine Prüfsumme des Schlüssels, den der Agent auf dem App-Server erzeugt hat. Stimmt sie hier und dort überein, sprichst du wirklich mit diesem Server.' },
  cgnat: { term: 'Mobilfunk/CGNAT', text: 'Viele Internetanbieter, vor allem im Mobilfunk, teilen eine öffentliche Adresse unter vielen Menschen auf. Würde Schild so eine Adresse sperren, träfe es viele Unbeteiligte. Darum sperren Szenarien und Limits sie nie.' },
  ratelimit: { term: 'Limit', text: 'Wie viele Anfragen eine Adresse in einer Zeitspanne an eine bestimmte Adresse deiner Website schicken darf, z. B. 10 Anmeldeversuche pro Minute. Darüber antwortet Schild kurz mit „zu viele Anfragen“.' },
} as const

export type GlossaryKey = keyof typeof GLOSSARY
