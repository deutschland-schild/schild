<script setup lang="ts">
import type { RuleLink } from '@/lib/explain'
import { ExternalLink } from '@lucide/vue'

/**
 * Public references for a rule (OWASP, CRS docs). Static links only, in a new tab, without referrer:
 * the dashboard URL is private and must not reach a third party.
 */
defineProps<{ links: RuleLink[] }>()
</script>

<template>
  <ul v-if="links.length" class="flex flex-wrap gap-x-3 gap-y-1" data-testid="rule-links">
    <li v-for="l in links" :key="l.href">
      <a
        :href="l.href"
        target="_blank"
        rel="noopener noreferrer"
        referrerpolicy="no-referrer"
        class="inline-flex items-center gap-1 text-muted-foreground underline underline-offset-4 hover:text-foreground hover:no-underline"
      >
        {{ l.label }}
        <span class="sr-only">(englisch, öffnet in neuem Tab)</span>
        <span aria-hidden="true">(englisch)</span>
        <ExternalLink class="size-3 shrink-0" aria-hidden="true" />
      </a>
    </li>
  </ul>
</template>
