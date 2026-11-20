<script setup lang="ts">
import { CONTRIBUTING_URL, ISSUES_URL } from '~/utils/release'

// Dark finale of the start page, /netz and /ueber. What a developer can do today comes first: install, report an
// issue, contribute. Labs and partners follow as mailto links (useMailto), then a personal contact line with the
// founder's photo, an e-mail link and LinkedIn.
const mailto = useMailto()
</script>

<template>
  <section id="kontakt" class="bg-ink text-white" aria-labelledby="kontakt-title">
    <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-28">
      <h2 id="kontakt-title" class="h2">Mitmachen</h2>
      <p class="mt-5 max-w-2xl text-lg leading-relaxed text-ink-muted">
        Das Schild Gateway ist Open Source und als Alpha veröffentlicht. Am meisten hilft gerade, wenn du es ausprobierst und uns sagst, wo es hakt.
      </p>
      <div class="mt-10 grid gap-6 md:grid-cols-3">
        <NuxtLink to="/#installieren" class="group flex flex-col rounded-xl border-2 border-signal bg-white/5 p-6 transition hover:bg-white/10">
          <p class="text-xs font-bold tracking-widest text-signal-soft uppercase">Alpha</p>
          <h3 class="mt-2 text-lg font-semibold">Installieren und ausprobieren</h3>
          <p class="mt-1 text-sm leading-relaxed text-ink-muted">Auf einem eigenen Server. Willst du erst zusehen, stellst du die Regeln auf „erkennen“.</p>
          <p class="mt-auto pt-4"><span class="btn-signal px-4 py-2 text-sm">Zur Installation <span class="inline-block transition group-hover:translate-x-0.5" aria-hidden="true">→</span></span></p>
        </NuxtLink>
        <a :href="ISSUES_URL" target="_blank" rel="noopener" class="group flex flex-col rounded-xl border border-white/15 p-6 transition hover:border-white/60 hover:bg-white/5">
          <h3 class="font-semibold">Fehler melden</h3>
          <p class="mt-1 text-sm leading-relaxed text-ink-muted">Etwas läuft nicht, eine Regel sperrt echte Eingaben, oder die Doku ist unklar? Leg ein Issue an.</p>
          <p class="mt-auto pt-4 text-sm font-semibold text-signal-soft">Issues auf GitHub <span class="inline-block transition group-hover:translate-x-0.5" aria-hidden="true">→</span></p>
        </a>
        <a :href="CONTRIBUTING_URL" target="_blank" rel="noopener" class="group flex flex-col rounded-xl border border-white/15 p-6 transition hover:border-white/60 hover:bg-white/5">
          <h3 class="font-semibold">Mitentwickeln</h3>
          <p class="mt-1 text-sm leading-relaxed text-ink-muted">Code, Tests, Regeln oder Doku: Wie du einen Pull Request einreichst, steht in CONTRIBUTING.md.</p>
          <p class="mt-auto pt-4 text-sm font-semibold text-signal-soft">So trägst du bei <span class="inline-block transition group-hover:translate-x-0.5" aria-hidden="true">→</span></p>
        </a>
      </div>
      <p class="mt-8 max-w-3xl text-sm leading-relaxed text-ink-muted">
        Du willst das geplante Netz mit aufbauen? Schreib uns, wenn du
        <a :href="mailto('Kritik / Lab')" class="font-semibold text-white underline underline-offset-2 hover:text-signal-soft">mitprüfen oder ein Lab betreiben</a>
        möchtest oder das Projekt
        <a :href="mailto('Unterstützung und Trägerschaft')" class="font-semibold text-white underline underline-offset-2 hover:text-signal-soft">als Partner unterstützen</a>
        willst, zum Beispiel mit Rechenkapazität.
      </p>
      <!-- Personal contact: the founder with photo, e-mail link and LinkedIn -->
      <div class="mt-10 flex items-start gap-4 border-t border-white/15 pt-8 sm:items-center sm:gap-5">
        <!-- Avatar links to the About page too; the text link below carries the accessible name, so this one stays out of the tab order -->
        <NuxtLink to="/ueber" tabindex="-1" aria-hidden="true" class="shrink-0 rounded-full transition hover:opacity-90">
          <img src="/img/martin-brueggemann-avatar.jpg" alt="" width="192" height="192" loading="lazy" decoding="async" class="grayscale size-14 rounded-full object-cover ring-2 ring-white/20 transition hover:ring-white/60 sm:size-16">
        </NuxtLink>
        <div class="min-w-0 text-sm">
          <p class="font-semibold text-white">Martin Brüggemann <span class="font-normal text-ink-muted">· Initiator</span></p>
          <p class="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1">
            <a :href="mailto('Kontakt')" class="font-semibold text-white underline underline-offset-2 hover:text-signal-soft">E-Mail schreiben</a>
            <a href="https://www.linkedin.com/in/martin-brueggemann/" target="_blank" rel="noopener" class="font-semibold text-white underline underline-offset-2 hover:text-signal-soft">LinkedIn</a>
            <NuxtLink to="/ueber" class="font-semibold text-white underline underline-offset-2 hover:text-signal-soft">Über den Initiator</NuxtLink>
          </p>
        </div>
      </div>
    </div>
  </section>
</template>
