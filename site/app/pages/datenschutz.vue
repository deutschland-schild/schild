<script setup lang="ts">
useHead({ title: 'Datenschutz – Deutschland-Schild' })
useSeoMeta({ description: 'Welche Daten diese Website verarbeitet: Server-Logs beim Hosting und deine E-Mail, wenn du uns schreibst. Keine Cookies, kein Tracking.' })
</script>

<template>
  <div class="prose prose-lg prose-slate mx-auto max-w-3xl px-5 py-16 sm:py-24 prose-headings:text-ink prose-h1:font-bold prose-h1:tracking-tight prose-h1:text-4xl prose-h2:text-2xl prose-a:text-link">
    <h1>Datenschutzerklärung</h1>

    <h2>Verantwortliche Stelle</h2>
    <p>
      PrioPad GmbH<br>
      Hainhäuser Weg 126<br>
      30855 Langenhagen<br>
      E-Mail: info@deutschland-schild.de
    </p>

    <h2>Hosting</h2>
    <p>
      Diese Website wird bei Netlify, Inc. (512 2nd Street, Suite 200, San Francisco, CA 94107, USA) gehostet. Beim Besuch
      der Website werden automatisch Server-Log-Daten erhoben (z.&nbsp;B. IP-Adresse, Browsertyp, Uhrzeit des Zugriffs).
      Diese Daten sind technisch notwendig und werden auf Grundlage von Art. 6 Abs. 1 lit. f DSGVO verarbeitet. Dabei
      können Daten in die USA übertragen werden. Weitere Informationen:
      <a href="https://www.netlify.com/privacy/" target="_blank" rel="noopener noreferrer">netlify.com/privacy</a>
    </p>

    <h2>Kontakt per E-Mail</h2>
    <p>
      Diese Website hat keine Formulare. Wenn du uns eine E-Mail schreibst, verarbeiten wir deine E-Mail-Adresse und das,
      was du uns schreibst, um dir zu antworten. Rechtsgrundlage ist unser berechtigtes Interesse, Anfragen zu beantworten
      (Art. 6 Abs. 1 lit. f DSGVO). Wir geben diese Daten nicht weiter und löschen sie, wenn dein Anliegen erledigt ist und
      keine gesetzliche Pflicht zur Aufbewahrung besteht.
    </p>

    <h2>Cookies und Tracking</h2>
    <p>
      Diese Website setzt keine Analyse- oder Tracking-Tools ein. Schriftarten, Skripte und Bilder liefert sie selbst aus;
      dein Browser lädt beim Besuch nichts von anderen Anbietern nach.
    </p>
    <p>Die Website setzt keine Cookies.</p>

    <h2>Links zu anderen Websites</h2>
    <p>
      Die Website verlinkt auf andere Angebote, zum Beispiel auf GitHub für Quellcode, Releases und Issues, auf LinkedIn und
      auf Quellen. Daten gehen dorthin erst, wenn du einen solchen Link anklickst. Dann gilt die Datenschutzerklärung des
      jeweiligen Anbieters. Wer auf GitHub ein Issue anlegt oder Dateien herunterlädt, nutzt GitHub und nicht diese Website.
    </p>

    <h2>Das Schild Gateway</h2>
    <p>
      Diese Erklärung gilt für die Website. Wenn du das Schild Gateway auf deinem Server betreibst, verarbeitet es Daten
      deiner Besucher:innen bei dir, und verantwortlich bist du. Was das Gateway speichert und was den Server verlässt,
      steht in der <NuxtLink to="/doku/gateway/02-betrieb#welche-daten-wo-bleiben">Dokumentation zum Betrieb</NuxtLink>.
    </p>

    <h2>Deine Rechte</h2>
    <p>
      Du hast gemäß DSGVO das Recht auf Auskunft (Art. 15), Berichtigung (Art. 16), Löschung (Art. 17), Einschränkung der
      Verarbeitung (Art. 18), Datenübertragbarkeit (Art. 20) und Widerspruch (Art. 21). Schreib uns dazu einfach an
      info@deutschland-schild.de.
    </p>

    <h2>Aufsichtsbehörde</h2>
    <p>
      Du hast das Recht, dich bei der zuständigen Aufsichtsbehörde zu beschweren:<br>
      Die Landesbeauftragte für den Datenschutz Niedersachsen<br>
      Prinzenstraße 5, 30159 Hannover
    </p>
  </div>
</template>
