<script setup lang="ts">
const route = useRoute()
</script>

<template>
  <div class="flex min-h-screen flex-col">
    <a href="#inhalt" class="skip-link">Zum Inhalt springen</a>
    <SiteHeader :dark="!!route.meta.darkHeader" />
    <main id="inhalt" class="flex-1" tabindex="-1"><slot /></main>
    <SiteFooter />
  </div>
</template>
