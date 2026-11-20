<script setup lang="ts">
// API reference layout for /api: slim header like the docs, the rest of the page belongs to Scalar.
</script>

<template>
  <div class="flex min-h-screen flex-col bg-white">
    <a href="#inhalt" class="skip-link">Zum Inhalt springen</a>

    <header class="sticky top-0 z-40 border-b border-line bg-white/95 backdrop-blur">
      <!-- Full width like Scalar: left edge on the sidebar entries, right edge on the content cards. -->
      <div class="flex h-14 items-center gap-3 pr-6 pl-5 xl:pr-[60px]">
        <NuxtLink to="/api" class="flex min-w-0 items-center gap-2.5" aria-label="Gateway API">
          <BrandMark class="size-7 shrink-0" />
          <span class="truncate text-sm font-bold tracking-tight text-ink max-sm:hidden">Deutschland-Schild</span>
          <AlphaBadge class="max-sm:hidden" />
          <span class="h-4 w-px bg-line max-sm:hidden" aria-hidden="true" />
          <span class="text-sm font-semibold whitespace-nowrap text-slate">Gateway API</span>
        </NuxtLink>
        <div class="ml-auto flex items-center gap-1 whitespace-nowrap max-sm:-mr-2.5">
          <NuxtLink to="/doku" class="rounded-lg px-2.5 py-1.5 text-sm font-semibold text-ink hover:bg-mist">Dokumentation</NuxtLink>
          <NuxtLink to="/" class="rounded-lg px-2.5 py-1.5 text-sm font-semibold text-ink hover:bg-mist">
            <span aria-hidden="true">←</span> <span class="max-sm:hidden">Zur </span>Website
          </NuxtLink>
        </div>
      </div>
    </header>

    <main id="inhalt" class="flex-1" tabindex="-1"><slot /></main>
  </div>
</template>
