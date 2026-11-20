<script setup lang="ts">
import type { WebsiteSummary } from '@/api/websites'
import { Skeleton, StatusDot, StatusPill } from '@schild/ui'
import { STATUS, reasonText, runsOnText, websiteName } from '@/lib/websites'

/**
 * Title of a website page (D36): name, status in words with its reasons (a server problem as one
 * short line, "web-1: Platte fast voll") and the servers it runs on, each linking to the server page.
 */
defineProps<{ website?: WebsiteSummary, id: string, title?: string }>()
</script>

<template>
  <header class="mb-5 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between" data-testid="website-header">
    <div class="min-w-0 space-y-1.5 lg:min-w-64 lg:flex-1">
      <div class="flex flex-wrap items-center gap-2">
        <h1 class="truncate text-2xl font-bold tracking-tight">
          {{ title ?? websiteName(website, id) }}
        </h1>
        <StatusPill v-if="website" :tone="STATUS[website.status].tone" size="sm" data-testid="website-status">
          {{ STATUS[website.status].label }}
        </StatusPill>
      </div>
      <Skeleton v-if="!website" class="h-4 w-64" />
      <p v-else class="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
        <span v-if="title">{{ websiteName(website, id) }}</span>
        <span v-if="website.hosts_total > 1" :title="website.hosts.join(', ')">{{ website.hosts_total }} Adressen</span>
        <span class="inline-flex flex-wrap items-center gap-x-1.5">
          {{ runsOnText(website.runs_on) }}:
          <RouterLink v-for="s in website.runs_on" :key="s.node" to="/server" class="inline-flex items-center gap-1 font-medium text-foreground underline-offset-4 hover:underline" :data-server="s.node">
            {{ s.node }}
            <StatusDot :tone="STATUS[s.status].tone" :label="`Server ${STATUS[s.status].label}`" />
          </RouterLink>
        </span>
      </p>
      <ul v-if="website?.reasons.length" class="flex flex-wrap gap-x-4 gap-y-1 text-sm" data-testid="website-reasons">
        <li v-for="(r, i) in website.reasons" :key="i" class="flex items-center gap-1.5">
          <StatusDot :tone="r.code === 'server_hint' || r.code === 'site_hint' ? 'warning' : STATUS[website.status].tone" />
          <RouterLink v-if="r.code === 'server_hint'" to="/server" class="underline-offset-4 hover:underline">
            {{ reasonText(r) }}
          </RouterLink>
          <span v-else>{{ reasonText(r) }}</span>
        </li>
      </ul>
    </div>
    <!-- The actions wrap among themselves before they squeeze the title (Zugriffe has three). -->
    <div class="flex min-w-0 flex-wrap items-center gap-2 lg:justify-end">
      <slot name="actions" />
    </div>
  </header>
</template>
