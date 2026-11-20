<script setup lang="ts">
// Audience page, split off the landing page (header menu „Für dich“ / „Über“).
useHead({ title: 'Über den Projektinitiator – Deutschland-Schild' })
useSeoMeta({ description: 'Martin Brüggemann hat Deutschland-Schild initiiert: bedingungsloser Grundschutz als Gemeinschaftsinitiative.' })
const fmt = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString('de-DE', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' })
</script>

<template>
  <div class="bg-white">
    <section id="about" class="relative overflow-hidden border-b border-line" aria-labelledby="about-title">
      <div class="mx-auto grid max-w-6xl gap-12 px-5 py-20 sm:px-8 lg:grid-cols-[0.75fr_1.25fr] lg:gap-16 lg:py-28">
        <!-- portrait -->
        <figure class="mx-auto w-full max-w-[16rem] sm:max-w-sm lg:sticky lg:top-24 lg:self-start">
          <div class="relative">
            <div class="absolute -inset-3 -z-0 rotate-2 rounded-3xl bg-ink-800" aria-hidden="true" />
            <img src="/img/martin-brueggemann.webp" alt="Martin Brüggemann" width="720" height="900" fetchpriority="high" class="relative aspect-[4/5] w-full rounded-2xl object-cover grayscale shadow-xl ring-1 ring-ink/10">
          </div>
          <figcaption class="mt-6">
            <p class="text-xl font-bold tracking-tight">Martin Brüggemann</p>
            <p class="mt-1 text-sm leading-relaxed text-slate">Familienvater, über 20 Jahre CTO, TECH-Coach, Unternehmer und Product-Discovery-Fan</p>
            <p class="mt-4 flex flex-wrap gap-2 text-sm">
              <a href="https://brgmn.de/about/" target="_blank" rel="noopener" class="rounded-full border border-line bg-white px-3 py-1.5 font-semibold transition hover:border-ink">brgmn.de</a>
              <a href="https://www.linkedin.com/in/martin-brueggemann/" target="_blank" rel="noopener" class="rounded-full border border-line bg-white px-3 py-1.5 font-semibold transition hover:border-ink">LinkedIn</a>
            </p>
          </figcaption>
        </figure>

        <!-- story -->
        <div>
          <p class="kicker">Über</p>
          <h1 id="about-title" class="h2 mt-3">Über den Projektinitiator</h1>

          <div class="mt-10 space-y-5 text-lg leading-relaxed text-slate">
            <p>
              Martin Brüggemann hat <a href="https://t3n.de" target="_blank" rel="noopener" class="font-semibold text-ink underline decoration-signal decoration-2 underline-offset-4 hover:decoration-ink">t3n.de</a> und das t3n Magazin mitgegründet und als CTO aufgebaut.
              Groß geworden ist er in der Open-Source-Community rund um PHP und TYPO3. Seitdem hat er fast jede Art von Hosting
              selbst betrieben, vom eigenen Server über Managed Hosting und Cloud bis zum lokalen GPU-Cluster.
              Die Erkenntnis daraus: Das ist toll, aber wer soll das noch verstehen?
            </p>
            <!-- The core question, set apart within the text column -->
            <p class="!my-9 border-l-2 border-signal pl-5 sm:pl-6">
              <span class="block text-xs font-semibold tracking-widest text-signal-deep uppercase">Die Kernfrage</span>
              <strong class="mt-2 block text-xl/snug font-semibold tracking-tight text-balance text-ink sm:text-2xl/snug">Wie können wir möglichst viele Menschen, die nicht mehr mitkommen, gemeinschaftlich schützen?</strong>
            </p>
            <p>
              Martin ist weder Vollzeit-Admin noch Sicherheitsforscher. Als langjähriger CTO und Medienunternehmer erlebt er jeden Tag,
              wie mühsam es geworden ist, Web-Projekte abzusichern. Im CTO-Netzwerk <a href="https://alphalist.com" target="_blank" rel="noopener" class="font-semibold text-ink underline decoration-signal decoration-2 underline-offset-4 hover:decoration-ink">alphalist.com</a>
              spricht er darüber mit anderen CTOs, immer öfter auch über die Frage, welche gesellschaftliche Verantwortung Techies haben.
            </p>
            <p class="text-ink">
              Der Deutschland-Schild soll ein bedingungsloser Grundschutz als Gemeinschaftsinitiative sein: Code unter MIT-Lizenz,
              ohne Abhängigkeiten, wirtschaftliche Interessen oder Vendor Lock-in. Damit man Webanwendungen in Deutschland weiter frei
              betreiben kann und wir uns auf das konzentrieren, was wir gern tun: Unternehmen, Gemeinschaften und Produkte bauen.
            </p>
          </div>

        </div>
      </div>
    </section>

    <section id="changelog" class="border-b border-line bg-mist" aria-labelledby="changelog-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Verlauf</p>
        <h2 id="changelog-title" class="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">Was bisher geschah</h2>
        <ol class="relative mt-10 border-l border-line">
          <li v-for="e in CHANGELOG" :key="e.date" class="relative pb-10 pl-8 last:pb-0">
            <span class="absolute top-1.5 -left-[7px] size-3.5 rounded-full border-2 border-white bg-signal ring-1 ring-signal-deep/30" aria-hidden="true" />
            <p class="text-sm font-semibold text-signal-deep"><time :datetime="e.date">{{ fmt(e.date) }}</time></p>
            <h3 class="mt-1 text-lg font-bold tracking-tight">{{ e.title }}</h3>
            <ul class="mt-2 max-w-3xl space-y-1.5 text-sm leading-relaxed text-slate">
              <li v-for="i in e.items" :key="i">{{ i }}</li>
            </ul>
          </li>
        </ol>
      </div>
    </section>

    <MitmachenSection />
  </div>
</template>
