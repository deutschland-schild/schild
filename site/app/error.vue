<script setup lang="ts">
import type { NuxtError } from '#app'

// Branded error page (404 and everything else) inside the default layout: calm, German, installing first, then three ways back.
const props = defineProps<{ error: NuxtError }>()
const notFound = computed(() => props.error?.statusCode === 404)
useHead({ title: computed(() => `${notFound.value ? 'Seite nicht gefunden' : 'Fehler'} – Deutschland-Schild`) })
useSeoMeta({ robots: 'noindex' })
const links = [
  { to: '/#installieren', label: 'Schild Gateway installieren' },
  { to: '/', label: 'Zur Startseite' },
  { to: '/netz#so-arbeitet-schild', label: 'Schild erklärt in 5 Minuten' },
  { to: '/doku', label: 'Dokumentation' },
]
</script>

<template>
  <NuxtLayout>
    <section class="bg-white" aria-labelledby="error-title">
      <div class="mx-auto max-w-6xl px-5 py-24 sm:px-8 lg:py-32">
        <p class="kicker">{{ notFound ? 'Fehler 404' : `Fehler ${error?.statusCode ?? 500}` }}</p>
        <h1 id="error-title" class="h2 mt-3">{{ notFound ? 'Diese Seite gibt es nicht.' : 'Hier ist etwas schiefgelaufen.' }}</h1>
        <p class="mt-5 max-w-2xl text-lg leading-relaxed text-pretty text-slate">
          <template v-if="notFound">Vielleicht wurde sie verschoben, oder der Link hat einen Tippfehler. Von hier aus kommst du weiter:</template>
          <template v-else>Das liegt an uns, nicht an dir. Lade die Seite neu oder nimm einen dieser Wege:</template>
        </p>
        <div class="mt-8 flex flex-wrap gap-3">
          <NuxtLink v-for="(l, i) in links" :key="l.to" :to="l.to" :class="i === 0 ? 'btn-primary' : 'btn-ghost'" @click="clearError({ redirect: l.to })">{{ l.label }}</NuxtLink>
        </div>
      </div>
    </section>
  </NuxtLayout>
</template>
