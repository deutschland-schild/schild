<script setup lang="ts">
import { legacyHubRoute } from '~/utils/hub'

// The documentation hub moved from /handbuch to /doku, the user handbook was removed.
// Old links keep working: in the static build each old URL becomes a small HTML page with a meta refresh.
const target = legacyHubRoute(useRoute().path)
await navigateTo(target, { redirectCode: 301 })
</script>

<template>
  <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8">
    <NuxtLink :to="target" class="font-semibold text-link hover:underline">Weiter zur Dokumentation</NuxtLink>
  </div>
</template>
