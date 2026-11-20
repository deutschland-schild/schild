<script setup lang="ts">
// Architecture V1 lives in the documentation hub (concept 21). Kept as a redirect so old links keep working;
// in the static build this becomes a small HTML page with a meta refresh.
await navigateTo('/doku/konzept/21-architektur-v1', { redirectCode: 301 })
</script>

<template>
  <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8">
    <NuxtLink to="/doku/konzept/21-architektur-v1" class="font-semibold text-link hover:underline">Architektur V1: weiter zur Dokumentation</NuxtLink>
  </div>
</template>
