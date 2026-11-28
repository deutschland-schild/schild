<script setup lang="ts">
import type { AuditEntry, AuditQuery } from '@/api/audit'
import type { AuditFilters } from '@/lib/audit'
import { RelativeTime } from '@schild/ui'
import { computed } from 'vue'
import { useAuditLast } from '@/api/audit'
import { AUDIT_COPY as COPY, auditLink, filtersOfQuery, lastChangedText } from '@/lib/audit'

/**
 * "Zuletzt geändert von …" at an object or a setting, with a link to that entry of the audit log
 * (contracts/audit.md section 8). Two ways to use it:
 *
 * - `query`: the component asks listAudit itself with limit 1 (a setting, one object).
 * - `entry` and `filters`: a list asked once for all its rows and hands each row its newest entry;
 *   `entry` is null when the log holds none, undefined while that is not known.
 *
 * An object that exists and has no entry is older than the log keeps. A setting without an entry may
 * also never have been changed, so its text says both.
 */
const props = defineProps<{
  query?: AuditQuery
  entry?: AuditEntry | null
  filters?: AuditFilters
  /** A setting: no entry can also mean that nobody changed it. */
  setting?: boolean
}>()

const q = useAuditLast(() => props.query ?? {}, 1, () => !!props.query)
const found = computed<AuditEntry | null | undefined>(() => {
  if (!props.query) return props.entry
  if (!q.data.value) return undefined
  return q.data.value.items[0] ?? null
})
const filters = computed(() => props.filters ?? (props.query ? filtersOfQuery(props.query) : {}))
</script>

<template>
  <p v-if="found" class="text-xs text-muted-foreground" data-testid="last-change" :data-entry="found.id">
    <RouterLink :to="auditLink(filters, found.id)" class="underline underline-offset-4 hover:text-foreground hover:no-underline" data-testid="last-change-link">{{ lastChangedText(found.actor) }}</RouterLink>,
    <RelativeTime :value="found.time" />
  </p>
  <p v-else-if="found === null" class="text-xs text-muted-foreground" data-testid="last-change-older">
    {{ setting ? COPY.noChange : COPY.older }}
  </p>
</template>
