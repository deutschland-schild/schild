<script setup lang="ts">
import { StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { useRelays } from '@/api/queries'
import { RELAY_STATUS } from '@/lib/labels'
import { splitSubscribers, subscriberKey } from '@/lib/relays'

/**
 * Which relays carry the lab's feed. With `version` (contracts v0.1, Relay.bundle_version) it counts the relays
 * this lab has delivered that bundle version (or a newer one) to; without it, connected relays without backlog.
 */
const props = defineProps<{ what: string, version?: number }>()
const relays = useRelays()
// Peer labs follow the feed too (Relay.kind, contracts v0.2); they are listed apart and never count as relays.
const split = computed(() => splitSubscribers(relays.data.value?.items ?? []))
const items = computed(() => split.value.relays)
const peerLabs = computed(() => split.value.peerLabs)
type Sub = (typeof items.value)[number]
const has = (r: Sub) => props.version !== undefined && (r.bundle_version ?? 0) >= props.version
const upToDate = (r: Sub) => props.version !== undefined ? has(r) : r.status === 'connected' && (r.lag_events ?? 0) === 0
const current = computed(() => items.value.filter(upToDate).length)
const peersCurrent = computed(() => peerLabs.value.filter(upToDate).length)
</script>

<template>
  <div class="space-y-2">
    <p class="text-sm">
      <span class="font-medium tabular-nums" data-testid="relay-coverage-count">{{ current }} von {{ items.length }}</span> {{ items.length === 1 ? 'Relay liefert' : 'Relays liefern' }} {{ what }} ohne Rückstand.
      <span v-if="peerLabs.length" class="text-muted-foreground" data-testid="relay-coverage-peers">Dazu folgen {{ peerLabs.length }} {{ peerLabs.length === 1 ? 'Peer-Lab' : 'Peer-Labs' }} dem Feed ({{ peersCurrent }} aktuell); sie zählen nicht als Relays.</span>
    </p>
    <ul class="divide-y rounded-xl border text-sm">
      <li v-for="r in [...items, ...peerLabs]" :key="subscriberKey(r)" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
        <span class="font-medium">{{ r.id }}</span>
        <StatusPill v-if="r.kind === 'peer_lab'" tone="neutral" size="sm">
          Peer-Lab
        </StatusPill>
        <StatusPill :tone="RELAY_STATUS[r.status].tone" size="sm">
          {{ RELAY_STATUS[r.status].text }}
        </StatusPill>
        <span class="ml-auto text-xs text-muted-foreground tabular-nums">
          <template v-if="r.bundle_version">Bündel v{{ r.bundle_version }}<template v-if="r.withdrawal_seq"> · Rückzug {{ r.withdrawal_seq }}</template> · </template>
          {{ r.status === 'disconnected' ? 'bekommt nichts' : (r.lag_events ?? 0) === 0 ? 'aktuell' : `${r.lag_events} Ereignisse zurück` }}
        </span>
      </li>
      <li v-if="!items.length && !peerLabs.length" class="px-3 py-2 text-muted-foreground">
        Kein Relay abonniert den Feed.
      </li>
    </ul>
  </div>
</template>
