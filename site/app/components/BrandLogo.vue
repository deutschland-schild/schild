<script setup lang="ts">
defineProps<{ dark?: boolean }>()
</script>

<template>
  <NuxtLink to="/" class="flex items-center gap-2.5" aria-label="Deutschland-Schild – Startseite">
    <BrandMark class="size-8" />
    <span class="text-base font-bold tracking-tight whitespace-nowrap" :class="dark ? 'text-white' : 'text-ink'">Deutschland-Schild</span>
  </NuxtLink>
</template>
