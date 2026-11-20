<script setup lang="ts">
import { COMPONENTS } from '~/utils/hub'
import { ISSUES_URL, REPO_URL } from '~/utils/release'

// Documentation hub overview, ordered by the parts of Deutschland-Schild: the gateway first (usable today), labs and
// relays marked as planned, then the project. Status markers stay in the Markdown for the agents and are left out of
// the rendered docs (nuxt.config.ts).
definePageMeta({ layout: 'doku' })

const { sections } = useHub()
// "Allgemeines" starts before the first general section.
const firstGeneral = computed(() => sections.value.find(s => s.general)?.id)

useHead({ title: 'Dokumentation – Deutschland-Schild' })
useSeoMeta({ description: 'Dokumentation zu Deutschland-Schild: das Schild Gateway mit allen Funktionen, dazu die geplanten Labs und Relays, Tests, Strategie und Marke.' })
</script>

<template>
  <div class="max-w-5xl py-8 lg:py-12">
    <p class="kicker">Dokumentation</p>
    <h1 class="mt-2 text-3xl font-bold tracking-tight text-balance sm:text-4xl">Deutschland-Schild, Teil für Teil</h1>
    <p class="mt-4 max-w-[70ch] leading-relaxed text-slate">
      Heute gibt es das <strong class="text-ink">Schild Gateway</strong>: eine kostenlose Firewall, die allein auf deinem Server läuft.
      Labs, Relays und Managed Schild sollen später dazukommen. Das Gateway braucht keins davon, du kannst also gleich anfangen.
    </p>

    <ul class="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-4" aria-label="Teile von Deutschland-Schild">
      <li v-for="c in COMPONENTS" :key="c.name">
        <NuxtLink
          :to="c.to" class="group flex h-full flex-col rounded-xl p-4 transition"
          :class="c.status === 'live' ? 'border-2 border-ink hover:bg-paper' : 'border border-line hover:border-ink'"
        >
          <StatusBadge :status="c.status" class="self-start" />
          <span class="mt-3 block font-semibold group-hover:underline">{{ c.name }}</span>
          <span class="mt-1 block text-sm leading-relaxed text-slate">{{ c.text }}</span>
        </NuxtLink>
      </li>
    </ul>
    <div class="mt-6 flex flex-wrap gap-3">
      <NuxtLink to="/doku/gateway/01-funktionen" class="btn-primary">Funktionen des Gateways</NuxtLink>
      <NuxtLink to="/doku/gateway/00-installieren" class="btn-ghost">Installieren</NuxtLink>
    </div>

    <template v-for="s in sections" :key="s.id">
      <div v-if="s.id === firstGeneral" id="allgemeines" class="mt-20 scroll-mt-20">
        <p class="kicker">Allgemeines</p>
        <p class="mt-1.5 max-w-[70ch] text-sm leading-relaxed text-slate">Was alle Teile verbindet und wie das Projekt arbeitet: Gesamtsystem, Qualität, Strategie, Personas, Werte und Marke.</p>
      </div>
      <section :id="s.id" class="mt-14 scroll-mt-20 border-t border-line pt-8" :aria-labelledby="`h-${s.id}`">
        <h2 :id="`h-${s.id}`" class="flex flex-wrap items-center gap-3 text-2xl font-bold tracking-tight">
          {{ s.label }}
          <StatusBadge v-if="s.status" :status="s.status" />
        </h2>
        <p class="mt-1.5 max-w-[70ch] text-sm leading-relaxed text-slate">{{ s.intro }}</p>
        <ul class="mt-5 grid gap-3 md:grid-cols-2">
          <li v-for="l in s.links ?? []" :key="l.to">
            <NuxtLink :to="l.to" class="group flex h-full flex-col rounded-xl border border-ink p-4 transition hover:bg-paper">
              <span class="block font-semibold group-hover:underline">{{ l.label }} <span aria-hidden="true">→</span></span>
              <span class="mt-1 line-clamp-3 block text-sm leading-relaxed text-slate">{{ l.description }}</span>
            </NuxtLink>
          </li>
          <li v-for="c in s.chapters" :key="c.path">
            <NuxtLink :to="c.path" class="group flex h-full flex-col rounded-xl border border-line p-4 transition hover:border-ink">
              <span class="flex gap-3">
                <span class="min-w-0">
                  <span class="block font-semibold group-hover:underline">{{ c.short }}</span>
                  <span v-if="c.description" class="mt-1 line-clamp-3 block text-sm leading-relaxed text-slate">{{ c.description }}</span>
                </span>
              </span>
            </NuxtLink>
          </li>
        </ul>
      </section>
    </template>

    <p class="mt-14 max-w-[70ch] border-t border-line pt-6 text-sm leading-relaxed text-slate">
      Alle Texte liegen als Markdown im Repository unter <code class="code">docs/</code>, versioniert nach dem Prinzip Company as Code. Diskutieren kannst du per
      <a :href="ISSUES_URL" target="_blank" rel="noopener" class="font-semibold text-link hover:underline">Issue</a> oder Pull Request auf
      <a :href="REPO_URL" target="_blank" rel="noopener" class="font-semibold text-link hover:underline">GitHub</a>. Jede Seite nennt ihre Datei.
    </p>
  </div>
</template>
