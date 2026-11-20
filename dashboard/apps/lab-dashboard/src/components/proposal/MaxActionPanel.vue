<script setup lang="ts">
import type { Proposal } from '@/api/types'
import { computed } from 'vue'
import { actionRank, labCapReasons, missingFor } from '@/lib/evidence'
import { ACTION_LABEL } from '@/lib/labels'
import ActionPill from '../ActionPill.vue'

/** Requested vs. allowed max action, with the missing evidence in plain words. */
const props = defineProps<{ proposal: Proposal }>()
const p = computed(() => props.proposal)
const blocked = computed(() => actionRank(p.value.requested_max_action) > actionRank(p.value.allowed_max_action))
// The G2 table's gaps plus the lab's own gates (negative corpus, simulated operators), so a step
// shown as reached in the ladder never contradicts the allowed action without an explanation.
const reasons = computed(() => [...missingFor(p.value.requested_max_action, p.value.class, p.value.evidence), ...labCapReasons(p.value.class, p.value.evidence, p.value.allowed_max_action)])
const blockReasons = computed(() => (p.value.requested_max_action !== 'block' && p.value.allowed_max_action !== 'block' ? missingFor('block', p.value.class, p.value.evidence) : []))
</script>

<template>
  <div class="rounded-xl border bg-card p-4" data-testid="max-action-panel">
    <dl class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
      <div>
        <dt class="text-muted-foreground">
          Gewünscht
        </dt>
        <dd class="mt-1">
          <ActionPill :action="p.requested_max_action" />
        </dd>
      </div>
      <div>
        <dt class="text-muted-foreground">
          Belege erlauben
        </dt>
        <dd class="mt-1">
          <ActionPill :action="p.allowed_max_action" />
        </dd>
      </div>
      <div v-if="p.max_action_until" class="col-span-2 sm:col-span-1">
        <dt class="text-muted-foreground">
          Gilt bis
        </dt>
        <dd class="mt-1 tabular-nums">
          {{ new Date(p.max_action_until).toLocaleString('de-DE') }}
        </dd>
      </div>
    </dl>
    <div v-if="blocked" class="mt-3 rounded-md bg-status-warning-subtle p-3 text-sm" data-testid="missing-evidence">
      <p class="font-medium">
        {{ ACTION_LABEL[p.requested_max_action] }} ist noch nicht möglich.
        <template v-if="p.allowed_max_action">
          Eine Freigabe kann höchstens {{ ACTION_LABEL[p.allowed_max_action] }} setzen.
        </template>
      </p>
      <ul class="mt-1 list-disc space-y-0.5 pl-5">
        <li v-for="r in reasons" :key="r">
          {{ r }}
        </li>
      </ul>
    </div>
    <p v-else-if="blockReasons.length" class="mt-3 text-xs text-muted-foreground">
      Für Sperren fehlt: {{ blockReasons.join(' ') }}
    </p>
  </div>
</template>
