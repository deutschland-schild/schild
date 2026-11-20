<script setup lang="ts">
import type { ServersSummary } from '@/api/hosts'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, StatusPill, Tag } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed } from 'vue'
import { FEATURES, openCount, serversSentence, SEVERITY, SEVERITY_ORDER } from '@/lib/hosts'
import { plural } from '@/lib/summary'

/** Overview: compact "Server" card (hosts, open findings by severity, agents not reporting). */
const props = defineProps<{ servers: ServersSummary }>()
const s = computed(() => props.servers)
const severities = computed(() => SEVERITY_ORDER.filter(k => k !== 'info' && s.value.findings[k] > 0).map(k => ({ k, n: s.value.findings[k], ...SEVERITY[k] })))
</script>

<template>
  <Card class="min-w-0" data-testid="servers-card">
    <CardHeader>
      <CardTitle>Server</CardTitle>
      <CardDescription>{{ FEATURES.hostAgents ? 'Server-Check auf dem Gateway und den App-Servern dahinter.' : 'Server-Check auf diesem Server.' }} Er liest nur und ändert nichts.</CardDescription>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <p data-testid="servers-sentence">
        {{ serversSentence(s) }}
      </p>
      <ul v-if="severities.length" class="flex flex-wrap gap-1.5" aria-label="Offene Befunde nach Stufe">
        <li v-for="x in severities" :key="x.k">
          <Tag :tone="x.tone">
            {{ x.n }} {{ x.label.toLowerCase() }}
          </Tag>
        </li>
      </ul>
      <div v-if="s.silent || (FEATURES.hostAgents && s.pending_agents) || s.unreadable" class="flex flex-wrap gap-2">
        <StatusPill v-if="s.silent" tone="warning" size="sm" data-testid="servers-silent">
          {{ plural(s.silent, 'meldet sich nicht', 'melden sich nicht') }}
        </StatusPill>
        <StatusPill v-if="FEATURES.hostAgents && s.pending_agents" tone="info" size="sm">
          {{ plural(s.pending_agents, 'Agent wartet', 'Agenten warten') }} auf Bestätigung
        </StatusPill>
        <StatusPill v-if="s.unreadable" tone="neutral" size="sm">
          {{ plural(s.unreadable, 'Prüfung', 'Prüfungen') }} nicht lesbar
        </StatusPill>
      </div>
      <p v-if="!openCount(s.findings) && !s.silent" class="text-muted-foreground">
        Der Check läuft nach Plan. Neue Befunde erscheinen hier.
      </p>
      <Button as-child variant="link" size="sm" class="h-auto p-0">
        <RouterLink to="/server/check" data-testid="servers-link">
          {{ FEATURES.hostAgents ? 'Zu den Servern' : 'Zum Server-Check' }}
          <ArrowRight aria-hidden="true" />
        </RouterLink>
      </Button>
    </CardContent>
  </Card>
</template>
