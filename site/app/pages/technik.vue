<script setup lang="ts">
// "Schild erklärt in 5 Minuten" moved from /technik to /netz, the comparison to the start page; the section ids stayed the same.
// The script keeps the anchor (/technik#zero-day → /netz#zero-day); the meta refresh is the fallback without JS.
useHead({
  link: [{ rel: 'canonical', href: '/netz' }],
  meta: [{ name: 'robots', content: 'noindex' }, { 'http-equiv': 'refresh', 'content': '0; url=/netz' }],
  script: [{ innerHTML: 'location.replace((location.hash === "#vergleich" ? "/" : "/netz") + location.hash)' }],
})
</script>

<template>
  <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8">
    <NuxtLink to="/netz" class="font-semibold text-link hover:underline">Weiter zum Schild-Netz</NuxtLink>
  </div>
</template>
