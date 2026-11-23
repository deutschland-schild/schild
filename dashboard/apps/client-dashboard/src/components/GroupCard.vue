<script setup lang="ts">
import { Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, formatNumber, RelativeTime, Skeleton, StatusPill, Tag } from '@schild/ui'
import { computed } from 'vue'
import { errorMessage } from '@/api/client'
import { useGroupStatus } from '@/api/group'
import { CONFIG_STATE, configHint, countersText, edges, gateways, MEMBER_STATE, removedMembers, sharedText, shortVersion, stateView } from '@/lib/group'

/**
 * Card "Cluster" of the server page (MVP-27, D105): whether this gateway runs alone or as a node of a group,
 * the state of the sync in words, the gateways with their last contact, version and configuration, the
 * balancer VMs (edges) apart. Read only: membership is changed on the host with `schild cluster`.
 */
/** `brief`: on the page of the group, which shows the state and the gateways itself: only the edges and the sync. */
const props = withDefaults(defineProps<{ heading?: string, brief?: boolean }>(), { heading: 'Cluster', brief: false })
const q = useGroupStatus()
const s = computed(() => q.data.value)
const single = computed(() => s.value?.mode === 'single')
const state = computed(() => s.value && s.value.state ? stateView(s.value) : null)
const hint = computed(() => s.value ? configHint(s.value) : null)
const nodes = computed(() => s.value ? gateways(s.value) : [])
const edgeRows = computed(() => s.value ? edges(s.value) : [])
const gone = computed(() => s.value ? removedMembers(s.value) : [])
/** The later of the two contacts: when this server last heard of the member in either direction. */
const lastContact = (m: { last_out?: string, last_in?: string }) => [m.last_out, m.last_in].filter(Boolean).sort().at(-1)
</script>

<template>
  <Card class="min-w-0" data-testid="group-card" :data-mode="s?.mode ?? ''" :data-state="s?.state ?? ''">
    <CardHeader>
      <CardTitle>{{ heading }}</CardTitle>
      <CardDescription v-if="!props.brief">
        Mehrere Gateways können als Cluster laufen und Sperren, Einstellungen und Logins teilen.
      </CardDescription>
    </CardHeader>
    <CardContent class="space-y-4 text-sm">
      <ErrorState v-if="q.isError.value && !s" title="Der Stand des Clusters lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
      <Skeleton v-else-if="!s" class="h-16 w-full" />
      <template v-else>
        <p v-if="single && !state" data-testid="group-single">
          <strong class="font-medium">Einzelner Server.</strong>
          Dieses Gateway läuft allein und teilt nichts mit anderen.
        </p>
        <p v-if="state && !props.brief" class="flex flex-wrap items-start gap-x-3 gap-y-1" data-testid="group-state">
          <StatusPill :tone="state.tone" size="sm" class="shrink-0">
            {{ state.label }}
          </StatusPill>
          <span class="min-w-0 flex-1 basis-56">
            {{ state.text }}
          </span>
        </p>
        <p v-if="hint && !props.brief" class="rounded-lg border border-status-warning/30 bg-status-warning-subtle px-3 py-2" role="note" data-testid="group-config-hint">
          {{ hint }}
        </p>

        <template v-if="!single">
          <div v-if="!props.brief" class="overflow-x-auto rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none" tabindex="0" role="region" aria-label="Gateways des Clusters">
            <table class="w-full text-sm" data-testid="group-members">
              <caption class="sr-only">
                Gateways des Clusters
              </caption>
              <thead class="text-left text-xs text-muted-foreground">
                <tr class="border-b">
                  <th scope="col" class="py-2 pr-4 font-medium">
                    Server
                  </th>
                  <th scope="col" class="py-2 pr-4 font-medium">
                    Zustand
                  </th>
                  <th scope="col" class="py-2 pr-4 font-medium">
                    Letzter Kontakt
                  </th>
                  <th scope="col" class="py-2 pr-4 font-medium">
                    Rückstand
                  </th>
                  <th scope="col" class="py-2 pr-4 font-medium">
                    Version
                  </th>
                  <th scope="col" class="py-2 font-medium">
                    Konfiguration
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="m in nodes" :key="m.id" class="border-b last:border-0" data-testid="group-member" :data-state="m.state" :data-name="m.name">
                  <td class="py-2.5 pr-4 align-top">
                    <span class="font-medium">{{ m.name }}</span>
                    <Tag v-if="m.state === 'self'" class="ml-2" data-testid="group-self">
                      dieser Server
                    </Tag>
                    <p class="mt-0.5 font-mono text-xs text-muted-foreground">
                      {{ m.address }}
                    </p>
                  </td>
                  <td class="py-2.5 pr-4 align-top">
                    <template v-if="m.state === 'self'">
                      –
                    </template>
                    <StatusPill v-else :tone="MEMBER_STATE[m.state].tone" size="sm">
                      {{ MEMBER_STATE[m.state].label }}
                    </StatusPill>
                    <p v-if="m.error" class="mt-1 max-w-xs text-xs break-words text-muted-foreground">
                      {{ m.error }}
                    </p>
                  </td>
                  <td class="py-2.5 pr-4 align-top">
                    <RelativeTime v-if="lastContact(m)" :value="lastContact(m)!" />
                    <template v-else>
                      {{ m.state === 'self' ? '–' : 'noch keiner' }}
                    </template>
                  </td>
                  <td class="py-2.5 pr-4 align-top tabular-nums">
                    {{ m.behind === undefined ? '–' : m.behind === 0 ? 'keiner' : `${formatNumber(m.behind)} Änderungen` }}
                  </td>
                  <td class="py-2.5 pr-4 align-top">
                    {{ shortVersion(m.version) || 'unbekannt' }}
                  </td>
                  <td class="py-2.5 align-top" :data-config="m.config ?? ''">
                    {{ m.state === 'self' ? (s.config?.version ?? '–') : CONFIG_STATE[m.config ?? 'unknown'] }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <section v-if="edgeRows.length" aria-labelledby="group-edges-title" data-testid="group-edges">
            <h3 id="group-edges-title" class="mb-1 font-medium">
              Balancer-VMs
            </h3>
            <p class="mb-2 text-xs text-muted-foreground">
              Sie halten die Sperren des Clusters in ihrer Firewall und lesen sonst nichts.
            </p>
            <ul class="divide-y rounded-lg border">
              <li v-for="m in edgeRows" :key="m.id" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2" data-testid="group-edge" :data-state="m.state">
                <span class="font-medium">{{ m.name }}</span>
                <StatusPill :tone="MEMBER_STATE[m.state].tone" size="sm" :title="MEMBER_STATE[m.state].title">
                  {{ MEMBER_STATE[m.state].label }}
                </StatusPill>
                <span v-if="m.last_in" class="text-xs text-muted-foreground">
                  zuletzt gefragt <RelativeTime :value="m.last_in" /><template v-if="m.blocks_held !== undefined">
                    · {{ formatNumber(m.blocks_held) }} {{ m.blocks_held === 1 ? 'Adresse' : 'Adressen' }} in der Firewall
                  </template>
                </span>
                <span v-if="m.error" class="basis-full text-xs break-words text-muted-foreground">{{ m.error }}</span>
              </li>
            </ul>
          </section>

          <p v-if="gone.length" class="text-xs text-muted-foreground" data-testid="group-removed">
            Aus dem Cluster genommen: {{ gone.map(m => m.name).join(', ') }}
          </p>
          <p v-if="s.shared" class="text-muted-foreground" data-testid="group-shared">
            {{ sharedText(s) }}
          </p>
          <p v-if="s.counters" class="text-xs text-muted-foreground" data-testid="group-counters">
            {{ countersText(s) }}
            <template v-if="s.replaced">
              Beim ersten Abgleich hat dieser Server {{ formatNumber(s.replaced) }} eigene {{ s.replaced === 1 ? 'Wert' : 'Werte' }} durch die des Clusters ersetzt. Die eigenen sind auf dem Server aufbewahrt.
            </template>
          </p>
        </template>
      </template>
    </CardContent>
  </Card>
</template>
