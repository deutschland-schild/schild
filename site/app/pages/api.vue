<script setup lang="ts">
import { API_SPEC_URL, scalarConfiguration } from '~/utils/scalar'

// Reference of the gateway's agent API, rendered with Scalar (bundled, loaded on mount). Separate from /doku.
definePageMeta({ layout: 'api' })
useHead({ title: 'Gateway API – Deutschland-Schild' })
useSeoMeta({ description: 'Referenz der Agent-API des Schild Gateways: Status, Ereignisse, Zugriffe, Ausnahmen und Sperren für Agenten, mit Token und nur auf dem Server erreichbar.' })

const host = ref<HTMLElement>()
const loading = ref(true)
const failed = ref(false)
let instance: { destroy: () => void } | null = null

onMounted(async () => {
  try {
    const [{ createApiReference }] = await Promise.all([
      import('@scalar/api-reference'),
      import('@scalar/api-reference/style.css'),
    ])
    if (host.value) instance = createApiReference(host.value, scalarConfiguration() as any)
  }
  catch (error) {
    console.error(error)
    failed.value = true
  }
  finally {
    loading.value = false
  }
})
onBeforeUnmount(() => {
  instance?.destroy()
  instance = null
})
</script>

<template>
  <div class="api-reference">
    <p v-if="loading" class="mx-auto max-w-[90rem] px-4 py-10 text-sm text-slate sm:px-6 lg:px-8" role="status">API-Referenz wird geladen …</p>
    <p v-if="failed" class="mx-auto max-w-[90rem] px-4 py-10 text-sm text-ink sm:px-6 lg:px-8" role="alert">
      Die Referenz konnte nicht geladen werden. Lade die Seite neu oder öffne die
      <a :href="API_SPEC_URL" class="font-semibold text-link hover:underline">OpenAPI-Datei</a> direkt.
    </p>
    <div ref="host" />
  </div>
</template>

<style>
/* The language picker in the introduction stands without an example next to it; every example has its own picker. */
.api-reference .scalar-reference-intro-clients {
  display: none;
}
/* Scalar has no option for its "Powered by Scalar" link in the sidebar footer; the page links nowhere outside. */
.api-reference div:has(> a[href*="utm_source=powered-by"]) {
  display: none;
}
/* Scalar focuses the section a link jumps to; the site's focus ring (main.css) would frame the whole section. */
.api-reference [tabindex="-1"]:focus-visible {
  outline: none;
  box-shadow: none;
}
/* Scalar's modern layout assumes a full page; here its sidebar sticks below the 3.5 rem header. */
.api-reference .scalar-app {
  --scalar-custom-header-height: 3.5rem;
}
</style>
