package humancheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"

	hc "github.com/deutschland-schild/schild/contract/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/pagekit"
)

type interstitialData struct {
	SiteName  string
	Prefix    string
	Token     string
	Salt      string
	Challenge string
	Max       int
	Return    string
}

// inlineScript solves the SHA-256 PoW in a Web Worker (or main thread fallback)
// using WebCrypto without any external resources, fingerprinting or storage.
// Parameters are read from data-* attributes on #schild-hc so the script body
// is byte-identical across every request and pinned by a single CSP sha256 hash.
const inlineScript = `(function(){
var el=document.getElementById('schild-hc');
if(!el)return;
var salt=el.getAttribute('data-salt');
var chal=el.getAttribute('data-challenge');
var max=parseInt(el.getAttribute('data-max'),10)||50000;
var form=document.getElementById('schild-verify');
var numIn=document.getElementById('schild-num');
var status=document.getElementById('schild-status');
var nojs=document.getElementById('schild-nojs');
if(!salt||!chal||!form||!numIn)return;
if(!window.crypto||!window.crypto.subtle){
  if(status)status.textContent='Automatische Prüfung in diesem Browser nicht verfügbar. Nutz den Button unten.';
  return;
}
if(nojs)nojs.hidden=true;
var workerCode="self.onmessage=async function(e){var s=e.data.s,c=e.data.c,m=e.data.m,enc=new TextEncoder();for(var i=0;i<=m;i++){var buf=await crypto.subtle.digest('SHA-256',enc.encode(s+i));var a=new Uint8Array(buf),h='';for(var j=0;j<a.length;j++){h+=(a[j]<16?'0':'')+a[j].toString(16);}if(h===c){self.postMessage({ok:true,n:i});return;}}self.postMessage({ok:false});};";
var t0=Date.now();
function done(n){
  numIn.value=String(n);
  // A fast device solves the task in a few milliseconds and the page would only flash by.
  // Keep it up long enough to read what happened: about a second of checking, then the result.
  setTimeout(function(){
    if(status)status.textContent='✓ Prüfung bestanden, du wirst weitergeleitet …';
    setTimeout(function(){form.submit();},600);
  },Math.max(0,1000-(Date.now()-t0)));
}
function fail(){
  if(status)status.textContent='Automatische Prüfung fehlgeschlagen. Nutz den Button unten.';
  if(nojs)nojs.hidden=false;
}
try{
  var blob=new Blob([workerCode],{type:'application/javascript'});
  var url=URL.createObjectURL(blob);
  var w=new Worker(url);
  w.onmessage=function(e){URL.revokeObjectURL(url);w.terminate();if(e.data&&e.data.ok)done(e.data.n);else fail();};
  w.onerror=function(){URL.revokeObjectURL(url);w.terminate();fail();};
  w.postMessage({s:salt,c:chal,m:max});
}catch(_){
  (async function(){
    var enc=new TextEncoder();
    for(var i=0;i<=max;i++){
      var buf=await crypto.subtle.digest('SHA-256',enc.encode(salt+i));
      var a=new Uint8Array(buf),h='';
      for(var j=0;j<a.length;j++){h+=(a[j]<16?'0':'')+a[j].toString(16);}
      if(h===chal){done(i);return;}
    }
    fail();
  })().catch(fail);
}
})();`

var (
	scriptCSPHash = func() string {
		sum := sha256.Sum256([]byte(inlineScript))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}()

	interstitialCSP = "default-src 'none'; script-src " + scriptCSPHash + "; style-src 'unsafe-inline'; worker-src blob:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

	interstitialTmpl = template.Must(template.New("hc").Parse(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Kurze Prüfung{{if .SiteName}} – {{.SiteName}}{{end}}</title>
<style>` + pagekit.CSS + `
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line);border-top-color:var(--fg);border-radius:50%;vertical-align:-2px;margin-right:8px;animation:s .8s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation:none}}
.status{font-size:.95rem;color:var(--fg);margin:18px 0 0}
.muted-btn{background:var(--soft);color:var(--fg);border:1px solid var(--soft-line)}
</style>
</head>
<body>
<main id="schild-hc" data-salt="{{.Salt}}" data-challenge="{{.Challenge}}" data-max="{{.Max}}">
` + pagekit.Mark + `
<h1>Kurze Prüfung</h1>
<p>Dein Browser löst gerade eine kleine Rechenaufgabe, damit automatisierte Abrufe diese Seite nicht überlasten. Das dauert ein bis zwei Sekunden und speichert keine persönlichen Daten.</p>
<p class="status" id="schild-status" role="status" aria-live="polite"><span class="spin" aria-hidden="true"></span>Prüfung läuft …</p>
<form id="schild-verify" method="post" action="{{.Prefix}}verify" hidden>
<input type="hidden" name="token" value="{{.Token}}">
<input type="hidden" name="number" id="schild-num" value="">
</form>
<form id="schild-nojs" class="below" method="post" action="{{.Prefix}}continue">
<input type="hidden" name="token" value="{{.Token}}">
<button type="submit" class="muted-btn">Ohne JavaScript weiter zur Seite</button>
</form>
<footer>{{if .SiteName}}{{.SiteName}} · {{end}}Deutschland-Schild</footer>
</main>
<script>` + inlineScript + `</script>
</body>
</html>
`))
)

// ScriptCSPHash returns the pinned CSP hash of the embedded PoW script.
func ScriptCSPHash() string { return scriptCSPHash }

func writeInterstitial(w http.ResponseWriter, r *http.Request, d interstitialData) {
	var buf bytes.Buffer
	if err := interstitialTmpl.Execute(&buf, d); err != nil {
		pagekit.WriteSimple(w, r, hc.StatusChallenge, "Kurze Prüfung", "Bitte lade die Seite noch einmal neu.")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", interstitialCSP)
	w.WriteHeader(hc.StatusChallenge)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}
