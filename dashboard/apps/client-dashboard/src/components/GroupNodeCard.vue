<script setup lang="ts">
import type { GroupMember } from '@/api/group'
import { Card, CardContent, cn, formatDecimal, formatMs, formatNumber, formatPercent, RelativeTime, StatusDot, StatusPill, Tag } from '@schild/ui'
import { computed } from 'vue'
import { CLOCK_SKEW_HINT_MS, clockText, CONFIG_STATE, loadTone, nodeView, shortVersion } from '@/lib/group'

/**
 * One gateway of the group (MVP-27) on the page "Cluster": whether it takes traffic, what it serves and how
 * loaded it is, as it told this server within the last seconds. Read only.
 */
const props = defineProps<{ member: GroupMember, configVersion?: string }>()
const m = computed(() => props.member)
const view = computed(() => nodeView(m.value))
const v = computed(() => m.value.state === 'unreachable' || m.value.state === 'no_contact' ? undefined : m.value.vitals)
const self = computed(() => m.value.state === 'self')
const lastContact = computed(() => [m.value.last_out, m.value.last_in].filter(Boolean).sort().at(-1))
const meters = computed(() => [
  { key: 'cpu', label: 'CPU', ratio: v.value?.cpu_usage },
  { key: 'memory', label: 'Arbeitsspeicher', ratio: v.value?.memory_used_ratio },
  { key: 'disk', label: 'Festplatte', ratio: v.value?.disk_used_ratio },
])
const barClass = { success: 'bg-status-success', warning: 'bg-status-warning', danger: 'bg-status-danger' } as Record<string, string>
</script>

<template>
  <Card class="min-w-0" data-testid="group-node" :data-name="m.name" :data-state="m.state" :data-service="v?.service ?? ''">
    <CardContent class="space-y-4 text-sm">
      <header class="flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
        <div class="min-w-0">
          <h3 class="flex flex-wrap items-center gap-2 text-base font-semibold">
            <StatusDot :tone="view.tone" />
            <span class="break-all">{{ m.name }}</span>
            <Tag v-if="self" data-testid="group-node-self">
              dieser Server
            </Tag>
          </h3>
          <p class="mt-0.5 font-mono text-xs text-muted-foreground">
            {{ m.address }}
          </p>
        </div>
        <StatusPill :tone="view.tone" size="sm" :title="view.text" data-testid="group-node-service">
          {{ view.label }}
        </StatusPill>
      </header>

      <template v-if="v">
        <div class="flex flex-wrap items-end gap-x-6 gap-y-2">
          <p>
            <span class="text-3xl font-semibold tabular-nums" data-testid="group-node-rps">{{ formatDecimal(v.requests_per_s) }}</span>
            <span class="ml-1.5 text-muted-foreground">Anfragen pro Sekunde</span>
          </p>
          <dl class="flex gap-x-5 text-xs text-muted-foreground">
            <div>
              <dt>gestoppt</dt>
              <dd class="text-sm text-foreground tabular-nums">
                {{ formatPercent(v.stopped_share) }}
              </dd>
            </div>
            <div>
              <dt>Antwortzeit (95 %)</dt>
              <dd class="text-sm text-foreground tabular-nums">
                {{ formatMs(v.latency_p95_ms) }}
              </dd>
            </div>
          </dl>
        </div>

        <ul class="space-y-2">
          <li v-for="b in meters" :key="b.key" class="grid grid-cols-[7.5rem_1fr_3rem] items-center gap-x-3" :data-testid="`group-node-${b.key}`">
            <span :id="`${m.id}-${b.key}`" class="text-xs text-muted-foreground">{{ b.label }}</span>
            <span
              class="h-1.5 overflow-hidden rounded-full bg-muted" role="meter" :aria-labelledby="`${m.id}-${b.key}`"
              aria-valuemin="0" aria-valuemax="100" :aria-valuenow="b.ratio == null ? undefined : Math.round(b.ratio * 100)"
              :aria-valuetext="b.ratio == null ? 'nicht sichtbar' : formatPercent(b.ratio)"
            >
              <span v-if="b.ratio != null" :class="cn('block h-full rounded-full', barClass[loadTone(b.ratio)])" :style="{ width: `${Math.max(2, Math.round(b.ratio * 100))}%` }" />
            </span>
            <span class="text-right text-xs tabular-nums">{{ b.ratio == null ? '–' : formatPercent(b.ratio) }}</span>
          </li>
        </ul>
      </template>
      <p v-else class="text-muted-foreground" data-testid="group-node-note">
        {{ view.text }}
      </p>
      <p v-if="m.error" class="rounded-lg border border-status-warning/30 bg-status-warning-subtle px-3 py-2 text-xs break-words" role="note">
        {{ m.error }}
      </p>

      <dl class="grid grid-cols-2 gap-x-4 gap-y-2 border-t pt-3 text-xs">
        <div v-if="v?.started_at">
          <dt class="text-muted-foreground">
            Gestartet
          </dt>
          <dd><RelativeTime :value="v.started_at" /></dd>
        </div>
        <div v-if="!self">
          <dt class="text-muted-foreground">
            Letzter Kontakt
          </dt>
          <dd>
            <RelativeTime v-if="lastContact" :value="lastContact" />
            <template v-else>
              noch keiner
            </template>
          </dd>
        </div>
        <div v-if="!self">
          <dt class="text-muted-foreground">
            Rückstand
          </dt>
          <dd class="tabular-nums">
            {{ m.behind === undefined ? '–' : m.behind === 0 ? 'keiner' : `${formatNumber(m.behind)} Änderungen` }}
          </dd>
        </div>
        <div>
          <dt class="text-muted-foreground">
            Version
          </dt>
          <dd>{{ shortVersion(m.version) || 'unbekannt' }}</dd>
        </div>
        <div v-if="clockText(m.clock_skew_ms)" data-testid="group-node-clock">
          <dt class="text-muted-foreground">
            Uhr
          </dt>
          <dd :class="Math.abs(m.clock_skew_ms ?? 0) >= CLOCK_SKEW_HINT_MS ? 'font-medium' : ''">
            {{ clockText(m.clock_skew_ms) }}
          </dd>
        </div>
        <div :data-config="m.config ?? ''">
          <dt class="text-muted-foreground">
            Konfiguration
          </dt>
          <dd :class="m.config === 'differs' ? 'font-medium' : ''">
            {{ self ? (configVersion ?? 'gleich') : CONFIG_STATE[m.config ?? 'unknown'] }}
          </dd>
        </div>
      </dl>
    </CardContent>
  </Card>
</template>
