<script setup lang="ts">
import { COLLECTIONS, LEGACY_BRAND, type DocCollection } from '~/utils/hub'

// One documentation page: /doku/gateway/<slug>, /doku/konzept/<slug>, /doku/marke/<slug>, /doku/personas/<slug>.
// Renders the Markdown file from docs/ directly (gateway, concept, brand, stories collections).
definePageMeta({ layout: 'doku' })

const KINDS: Record<string, DocCollection> = { gateway: 'gateway', konzept: 'concept', marke: 'brand', personas: 'stories' }
const route = useRoute()
const collection = KINDS[String(route.params.kind)]
const slug = String(route.params.slug).replace(/\/+$/, '').toLowerCase()
// Old brand pages (merged into 01-marke) redirect; in the static build this is a small HTML page with a meta refresh.
const legacy = collection === 'brand' ? LEGACY_BRAND[slug] : undefined
if (legacy) await navigateTo(legacy, { redirectCode: 301 })
const path = collection && !legacy ? `${COLLECTIONS[collection].base}/${slug}` : ''
const { data: page } = await useAsyncData(`doku-${path}`, () =>
  path ? queryCollection(collection!).path(path).first() : Promise.resolve(null))
if (!page.value && !legacy) throw createError({ statusCode: 404, statusMessage: 'Seite nicht gefunden', fatal: true })

const { neighbours } = useHub()
const short = computed(() => neighbours(path).chapter?.short ?? page.value?.title)
useHead({ title: () => `${short.value} – Dokumentation – Deutschland-Schild` })
useSeoMeta({ description: () => neighbours(path).chapter?.description ?? page.value?.description })
</script>

<template>
  <HubChapter v-if="page" :page="page" :path="path" />
  <div v-else-if="legacy" class="py-20">
    <NuxtLink :to="legacy" class="font-semibold text-link hover:underline">Weiter zu Marke, Sprache und Gestaltung</NuxtLink>
  </div>
</template>
