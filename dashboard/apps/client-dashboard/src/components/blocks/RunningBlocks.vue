<script setup lang="ts">
import type { RunningBlock } from '@/api/blocks'
import {
  Button,
  Card,
  CardContent,
  EmptyState,
  ErrorState,
  formatNumber,
  IpAddress,
  RelativeTime,
  Skeleton,
  StatusPill,
} from '@schild/ui'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'
import { blockKeys, useBlocks } from '@/api/blocks'
import { errorMessage } from '@/api/client'
import { useIncident } from '@/api/queries'
import UnblockDialog from '@/components/UnblockDialog.vue'
import BlockAddressDialog from './BlockAddressDialog.vue'
import { formatDuration } from '@/lib/behaviour'
import { blockReason, BLOCKS_COPY as C, FIREWALL_ROW, firewallText, netClassText } from '@/lib/blocks'

/**
 * Every address block that runs (D87): scenario or agent, since and until, and whether the host's firewall holds
 * it. "Sperre aufheben" opens the unblock of its incident, as on the incident page: false positive or not, and the address
 * as an own IP if wanted. The block ends at once, in schild and with the next sync in the firewall.
 */
const q = useBlocks()
const list = computed(() => q.data.value)
const fw = computed(() => list.value ? firewallText(list.value.firewall) : null)
const qc = useQueryClient()
const lifting = ref<RunningBlock | null>(null)
const incidentQ = useIncident(() => lifting.value?.incident)
const liftOpen = ref(false)
// The dialog needs the incident: it opens once that is loaded.
watch(() => incidentQ.data.value, (inc) => {
  if (inc && lifting.value && inc.incident === lifting.value.incident) liftOpen.value = true
})
function askLift(b: RunningBlock) {
  lifting.value = b
  if (incidentQ.data.value?.incident === b.incident) liftOpen.value = true
}
watch(liftOpen, (v) => {
  if (!v) lifting.value = null
})
const blockOpen = ref(false)
function lifted() {
  void qc.invalidateQueries({ queryKey: blockKeys.all })
}
</script>

<template>
  <div class="space-y-4">
    <ErrorState v-if="q.isError.value && !list" title="Die Sperren lassen sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
    <Skeleton v-else-if="!list" class="h-40 w-full" />
    <template v-else>
      <div class="flex justify-end">
        <Button data-testid="block-add" @click="blockOpen = true">
          Adresse sperren
        </Button>
      </div>
      <p class="flex items-start gap-2 rounded-xl border bg-card p-4 text-sm" data-testid="firewall-state" :data-state="list.firewall.state">
        <StatusPill :tone="fw!.tone" size="sm" class="shrink-0">
          Firewall
        </StatusPill>
        <span class="text-muted-foreground">{{ fw!.text }}</span>
      </p>
      <EmptyState v-if="!list.items.length" :title="C.none" :description="C.noneExplain" data-testid="blocks-empty" />
      <Card v-else class="py-0">
        <CardContent class="overflow-x-auto px-0">
          <table class="w-full text-sm" data-testid="blocks-table">
            <thead class="text-left text-xs text-muted-foreground">
              <tr class="border-b">
                <th scope="col" class="px-4 py-2 font-medium">
                  Adresse
                </th>
                <th scope="col" class="px-4 py-2 font-medium">
                  Grund
                </th>
                <th scope="col" class="px-4 py-2 font-medium">
                  Gesperrt
                </th>
                <th scope="col" class="px-4 py-2 font-medium">
                  Firewall
                </th>
                <th scope="col" class="px-4 py-2">
                  <span class="sr-only">Aktion</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="b in list.items" :key="b.client" class="border-b last:border-0" data-testid="block-row" :data-client="b.client">
                <td class="px-4 py-3 align-top">
                  <IpAddress :ip="b.client" />
                  <p class="mt-0.5 text-xs text-muted-foreground">
                    {{ netClassText(b.net_class) }}
                  </p>
                </td>
                <td class="px-4 py-3 align-top">
                  <p>{{ blockReason(b) }}</p>
                  <p class="mt-0.5 text-xs text-muted-foreground">
                    <RouterLink v-if="b.incident" :to="`/incidents/${b.incident}`" class="font-mono underline-offset-4 hover:underline">
                      {{ b.incident }}
                    </RouterLink>
                    <template v-if="b.level > 1">
                      · {{ formatNumber(b.level) }}. Sperre in Folge
                    </template>
                  </p>
                </td>
                <td class="px-4 py-3 align-top">
                  <p>{{ formatDuration(b.duration_s) }}, seit <RelativeTime :value="b.since" /></p>
                  <p class="mt-0.5 text-xs text-muted-foreground">
                    endet <RelativeTime :value="b.until" /><template v-if="b.kept">
                      · übersteht einen Neustart
                    </template>
                  </p>
                </td>
                <td class="px-4 py-3 align-top">
                  <StatusPill :tone="FIREWALL_ROW[b.firewall].tone" size="sm" :title="FIREWALL_ROW[b.firewall].title" data-testid="block-firewall">
                    {{ FIREWALL_ROW[b.firewall].label }}
                  </StatusPill>
                </td>
                <td class="px-4 py-3 text-right align-top">
                  <Button v-if="b.incident" variant="outline" size="sm" :disabled="!!lifting && incidentQ.isFetching.value" data-testid="block-lift" @click="askLift(b)">
                    {{ C.lift }}
                  </Button>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-if="list.total > list.items.length" class="px-4 py-3 text-xs text-muted-foreground">
            Die neuesten {{ formatNumber(list.items.length) }} von {{ formatNumber(list.total) }} Sperren.
          </p>
        </CardContent>
      </Card>
    </template>

    <UnblockDialog v-if="incidentQ.data.value && lifting" v-model:open="liftOpen" :incident="incidentQ.data.value" @done="lifted" />
    <BlockAddressDialog v-model:open="blockOpen" @done="lifted" />
  </div>
</template>
