<script setup lang="ts">
import { BrandMark, Card, ThemeToggle } from '@schild/ui'

defineProps<{ title: string, description?: string }>()
</script>

<template>
  <main id="main" class="relative grid min-h-svh place-items-center bg-muted/30 p-4">
    <div class="absolute top-3 right-3">
      <ThemeToggle />
    </div>
    <Card class="w-full max-w-sm gap-5 p-6">
      <div class="flex items-center gap-3">
        <BrandMark class="size-8" />
        <div>
          <p class="text-sm font-semibold">
            Schild-Lab
          </p>
          <p class="text-xs text-muted-foreground">
            Lab-Dashboard
          </p>
        </div>
      </div>
      <div class="space-y-1">
        <h1 class="text-xl font-semibold tracking-tight">
          {{ title }}
        </h1>
        <p v-if="description" class="text-sm text-muted-foreground">
          {{ description }}
        </p>
      </div>
      <slot />
    </Card>
  </main>
</template>
