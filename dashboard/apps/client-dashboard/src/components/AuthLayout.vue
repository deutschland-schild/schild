<script setup lang="ts">
import { BrandMark, ThemeToggle } from '@schild/ui'

/** Frame for login and first-run setup: centered, calm, no navigation. */
defineProps<{ title: string, description?: string, wide?: boolean }>()
</script>

<template>
  <div class="flex min-h-svh flex-col bg-muted">
    <header class="flex items-center justify-between px-4 py-3 sm:px-6">
      <span class="flex items-center gap-2 font-semibold">
        <BrandMark :size="28" />
        Schild
      </span>
      <ThemeToggle />
    </header>
    <main id="main" tabindex="-1" class="flex flex-1 items-start justify-center px-4 py-8 focus:outline-none sm:items-center sm:py-12">
      <div :class="['w-full rounded-xl border bg-card p-6 shadow-sm sm:p-8', wide ? 'max-w-2xl' : 'max-w-md']">
        <slot name="top" />
        <h1 class="text-2xl font-semibold tracking-tight">
          {{ title }}
        </h1>
        <p v-if="description" class="mt-1 text-sm text-muted-foreground">
          {{ description }}
        </p>
        <div class="mt-6">
          <slot />
        </div>
      </div>
    </main>
    <footer class="px-4 py-4 text-center text-xs text-muted-foreground">
      Das Dashboard läuft auf deinem Server. Es lädt nichts von fremden Servern.
    </footer>
  </div>
</template>
