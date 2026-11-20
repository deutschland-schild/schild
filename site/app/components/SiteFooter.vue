<script setup lang="ts">
import { REPO_URL } from '~/utils/release'

// siteStand: date of the last commit at build time (nuxt.config.ts).
const { siteStand } = useRuntimeConfig().public
</script>

<template>
  <footer class="border-t border-line bg-white text-sm text-slate">
    <div class="mx-auto flex max-w-6xl flex-col gap-6 px-5 py-10 sm:px-8 md:flex-row md:items-start md:justify-between">
      <div class="max-w-md space-y-2">
        <BrandLogo />
        <p>Gemeinnützig, überparteilich, Code unter MIT-Lizenz. Bis eine gemeinnützige Trägerschaft geklärt ist, betreut die <a href="https://priopad.com" class="text-ink underline underline-offset-2">PrioPad GmbH</a> die Initiative. Stand {{ siteStand }}.</p>
      </div>
      <nav class="flex flex-wrap gap-x-5 gap-y-1" aria-label="Weitere Seiten">
        <NuxtLink to="/#installieren" class="py-1 hover:text-ink">Installieren</NuxtLink>
        <NuxtLink to="/netz" class="py-1 hover:text-ink">Das Schild-Netz</NuxtLink>
        <NuxtLink to="/doku" class="py-1 hover:text-ink">Dokumentation</NuxtLink>
        <NuxtLink to="/api" class="py-1 hover:text-ink">Gateway API</NuxtLink>
        <a :href="REPO_URL" target="_blank" rel="noopener" class="py-1 hover:text-ink">GitHub</a>
        <NuxtLink to="/impressum" class="py-1 hover:text-ink">Impressum</NuxtLink>
        <NuxtLink to="/datenschutz" class="py-1 hover:text-ink">Datenschutz</NuxtLink>
      </nav>
    </div>
  </footer>
</template>
