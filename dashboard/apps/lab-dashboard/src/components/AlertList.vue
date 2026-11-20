<script setup lang="ts">
import type { Alert } from '@/lib/alerts'
import { StatusPill } from '@schild/ui'
import { CircleCheck } from '@lucide/vue'

defineProps<{ alerts: Alert[] }>()
const toneText = { danger: 'Dringend', warning: 'Achtung', info: 'Hinweis', signal: 'Hinweis', success: 'OK', neutral: 'Hinweis' } as const
</script>

<template>
  <section aria-labelledby="alerts-title" class="rounded-xl border bg-card">
    <h2 id="alerts-title" class="border-b px-4 py-2.5 text-sm font-bold">
      Offene Punkte
    </h2>
    <p v-if="!alerts.length" class="flex items-center gap-2 px-4 py-3 text-sm text-muted-foreground" data-testid="no-alerts">
      <CircleCheck class="size-4 text-status-success" aria-hidden="true" />
      Keine offenen Punkte. Eingang, Worker und Feed laufen normal.
    </p>
    <ul v-else class="divide-y" data-testid="alerts">
      <li v-for="a in alerts" :key="a.id" class="flex flex-wrap items-start gap-x-3 gap-y-1 px-4 py-3">
        <StatusPill :tone="a.tone" size="sm">
          {{ toneText[a.tone] }}
        </StatusPill>
        <div class="min-w-0 flex-1">
          <p class="text-sm font-medium">
            {{ a.title }}
          </p>
          <p class="text-sm text-muted-foreground">
            {{ a.text }}
          </p>
        </div>
        <RouterLink v-if="a.to" :to="a.to" class="text-sm font-medium underline-offset-4 hover:underline">
          {{ a.linkLabel ?? 'Ansehen' }}
        </RouterLink>
      </li>
    </ul>
  </section>
</template>
