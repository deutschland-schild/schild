<script setup lang="ts">
import type { AuditFilters } from '@/lib/audit'
import { RelativeTime } from '@schild/ui'
import { computed } from 'vue'
import { useAuditLast } from '@/api/audit'
import { actorName, auditLink, entryTitle, toAuditQuery } from '@/lib/audit'

/**
 * What was done because of an event or an incident: the entries of the audit log whose cause it is
 * (filter `event` or `incident`), each with a link to it, and a link to all of them. Shows nothing while
 * the log holds no such entry.
 */
const props = defineProps<{ filters: AuditFilters, title: string }>()
const LIMIT = 5
const q = useAuditLast(() => toAuditQuery(props.filters), LIMIT)
const items = computed(() => q.data.value?.items ?? [])
</script>

<template>
  <section v-if="items.length" class="space-y-1 text-sm" data-testid="audit-trail">
    <h3 class="font-medium">
      {{ title }}
    </h3>
    <ul class="space-y-0.5">
      <li v-for="e in items" :key="e.id" data-testid="audit-trail-item">
        <RouterLink :to="auditLink(filters, e.id)" class="underline underline-offset-4 hover:no-underline">{{ entryTitle(e) }}</RouterLink>
        <span class="text-muted-foreground"> · {{ actorName(e.actor) }} · <RelativeTime :value="e.time" /></span>
      </li>
    </ul>
    <p v-if="q.data.value?.next_cursor">
      <RouterLink :to="auditLink(filters)" class="text-xs text-muted-foreground underline underline-offset-4 hover:no-underline" data-testid="audit-trail-all">
        Alle im Protokoll ansehen
      </RouterLink>
    </p>
  </section>
</template>
