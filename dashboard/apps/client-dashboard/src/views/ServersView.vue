<script setup lang="ts">
import type { Agent, HostSummary } from '@/api/hosts'
import {
  Button,
  CommandBlock,
  EffectFooter,
  EmptyState,
  ErrorState,
  formatRelative,
  MetaLine,
  Skeleton,
  SplitPane,
  StatusPill,
  Tabs,
  TabsList,
  TabsTrigger,
  toast,
} from '@schild/ui'
import { LoaderCircle, Plus, RefreshCw, Server, ServerCog } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage, problemOf } from '@/api/client'
import { hostKeys, useAgents, useHost, useHosts, useRevokeAgent, useRunLocalCheck } from '@/api/hosts'
import { keys } from '@/api/queries'
import EnrolAgentDialog from '@/components/EnrolAgentDialog.vue'
import HostDetailPanel from '@/components/HostDetailPanel.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import ServerHeader from '@/components/ServerHeader.vue'
import Term from '@/components/Term.vue'
import { AGENT_STATUS, countsText, FEATURES, groupFingerprint, hostStatusText, hostTone, lastReportText, openCount } from '@/lib/hosts'
import { plural } from '@/lib/summary'

const route = useRoute()
const router = useRouter()
const qc = useQueryClient()

function setQuery(patch: Record<string, string | undefined>) {
  const query = { ...route.query }
  for (const [k, v] of Object.entries(patch)) {
    if (!v) delete query[k]
    else query[k] = v
  }
  void router.replace({ query })
}
const tab = computed(() => FEATURES.hostAgents && route.query.view === 'agents' ? 'agents' : 'server')
const tabModel = computed({ get: () => tab.value, set: v => setQuery({ view: v === 'server' ? undefined : String(v) }) })

// ---------------------------------------------------------------- hosts
const hostsQ = useHosts()
const hosts = computed<HostSummary[]>(() => {
  const all = hostsQ.data.value?.items ?? []
  const byName = (a: HostSummary, b: HostSummary) => a.hostname.localeCompare(b.hostname)
  return [
    ...all.filter(h => h.role === 'gateway'),
    ...all.filter(h => h.role === 'agent' && h.status !== 'revoked').sort(byName),
    ...all.filter(h => h.role === 'agent' && h.status === 'revoked').sort(byName),
  ]
})
// One server at a time (2026-11-02): the one the sidebar switcher holds, ?server=<agent id> or the gateway.
const selectedId = computed(() => {
  const q = FEATURES.hostAgents && typeof route.query.server === 'string' ? route.query.server : null
  if (q && hosts.value.some(h => h.id === q)) return q
  return hosts.value.find(h => h.role === 'gateway')?.id ?? hosts.value[0]?.id ?? null
})

// ---------------------------------------------------------------- "Jetzt prüfen" (local host only)
const checking = ref<{ prevReport: string | null, since: number } | null>(null)
const detailQ = useHost(selectedId, () => checking.value && selectedId.value === 'local' ? 2000 : 60_000)
// While a local run is requested, watch the local host even when another host is selected.
const localQ = useHost(() => checking.value ? 'local' : null, () => checking.value ? 2000 : false)
const detail = computed(() => detailQ.data.value?.host.id === selectedId.value ? detailQ.data.value : undefined)
const host = computed(() => detail.value?.host ?? hosts.value.find(h => h.id === selectedId.value))
const runCheck = useRunLocalCheck()
const CHECK_TIMEOUT_MS = 3 * 60_000

async function checkNow() {
  const prevReport = qc.getQueryData<{ report: { report_id: string } | null }>(hostKeys.host('local'))?.report?.report_id ?? null
  try {
    await runCheck.mutateAsync()
    checking.value = { prevReport, since: Date.now() }
    toast('Prüfung angefordert', { description: 'Der Check liest den Server jetzt. Das dauert meist unter einer Minute.' })
  }
  catch (err) {
    const code = problemOf(err)?.code
    if (code === 'check_running') {
      checking.value = { prevReport, since: Date.now() }
      toast('Die Prüfung läuft schon', { description: 'Das Ergebnis erscheint hier, sobald sie fertig ist.' })
    }
    else if (code === 'check_unavailable') {
      toast.error('Aus dem Dashboard lässt sich die Prüfung hier nicht starten', { description: 'Der Lauf nach Plan geht weiter. Auf dem Server startest du ihn mit: sudo systemctl start schild-check.service' })
    }
    else {
      toast.error('Die Prüfung ließ sich nicht starten', { description: errorMessage(err) })
    }
  }
}
watch(() => localQ.data.value?.report?.report_id, (id) => {
  const c = checking.value
  if (!c || !id || id === c.prevReport) return
  checking.value = null
  const d = localQ.data.value!
  const n = openCount(d.host.counts)
  toast.success('Prüfung fertig', { description: n ? `${plural(n, 'offener Befund', 'offene Befunde')}: ${countsText(d.host.counts)}.` : 'Keine offenen Befunde.' })
  void qc.invalidateQueries({ queryKey: hostKeys.hosts })
  void qc.invalidateQueries({ queryKey: keys.overview })
})
const timeout = setInterval(() => {
  if (checking.value && Date.now() - checking.value.since > CHECK_TIMEOUT_MS) {
    checking.value = null
    toast('Die Prüfung dauert länger als sonst', { description: 'Das Ergebnis erscheint hier, sobald es da ist.' })
  }
}, 5000)
onBeforeUnmount(() => clearInterval(timeout))

// ---------------------------------------------------------------- agents
const agentsQ = useAgents()
const agents = computed(() => {
  const order = { pending: 0, enrolled: 1, revoked: 2 } as const
  return [...(agentsQ.data.value?.items ?? [])].sort((a, b) => order[a.status] - order[b.status] || a.hostname.localeCompare(b.hostname))
})
const pendingAgents = computed(() => agents.value.filter(a => a.status === 'pending'))
const hostAgent = computed(() => host.value?.agent_id ? agents.value.find(a => a.id === host.value!.agent_id) : undefined)
const isGateway = computed(() => !host.value || host.value.role === 'gateway')
/** The gateway manages every agent; an agent shows only its own entry. */
const shownAgents = computed(() => isGateway.value ? agents.value : agents.value.filter(a => a.id === hostAgent.value?.id))

const enrolOpen = ref(false)
const enrolAgent = ref<Agent | null>(null)
function addServer() {
  enrolAgent.value = null
  enrolOpen.value = true
}
function confirmPending(a: Agent) {
  enrolAgent.value = a
  enrolOpen.value = true
}
function onEnrolled(a: Agent) {
  setQuery({ view: undefined, server: a.id })
}
watch(() => route.query.new, (v) => {
  if (v === '1' && FEATURES.hostAgents) {
    addServer()
    setQuery({ new: undefined })
  }
}, { immediate: true })

const revokeTarget = ref<Agent | null>(null)
const revokeError = ref<string | null>(null)
const revokeOpen = computed({
  get: () => !!revokeTarget.value,
  set: (v) => {
    if (!v) {
      revokeTarget.value = null
      revokeError.value = null
    }
  },
})
const revoke = useRevokeAgent()
async function doRevoke() {
  const a = revokeTarget.value
  if (!a) return
  revokeError.value = null
  try {
    await revoke.mutateAsync({ id: a.id })
    revokeTarget.value = null
    toast(`${a.hostname} zurückgezogen`, { description: 'Schild nimmt von diesem Schlüssel keine Berichte mehr an. Für einen neuen Anfang erstellst du einen neuen Code.' })
  }
  catch (err) {
    revokeTarget.value = null
    toast.error('Zurückziehen hat nicht geklappt', { description: problemOf(err)?.code === 'config_agent' ? 'Dieser Agent steht in schild.yaml. Setz dort revoked: true.' : errorMessage(err) })
  }
}

// ---------------------------------------------------------------- header and footer copy
const headerMeta = computed(() => {
  const h = host.value
  if (!h) return []
  const open = openCount(h.counts)
  return [
    h.role === 'gateway' ? 'Gateway' : 'App-Server mit Agent',
    open ? plural(open, 'offener Befund', 'offene Befunde') : 'keine offenen Befunde',
    lastReportText(h),
    h.silent ? { text: 'meldet sich nicht', tone: 'warning' as const } : '',
    isGateway.value && pendingAgents.value.length ? { text: `${plural(pendingAgents.value.length, 'Agent wartet', 'Agenten warten')} auf Bestätigung`, tone: 'warning' as const } : '',
  ]
})
/** The title of an agent's page is its host name with its state; the gateway keeps the node name. */
const agentTitle = computed(() => !isGateway.value && host.value ? { title: host.value.hostname, tone: hostTone(host.value), label: hostStatusText(host.value) } : undefined)
const footerText = computed(() => {
  const h = host.value
  if (!h) return ''
  if (!detail.value?.report) return `${h.hostname}: noch kein Bericht.`
  const n = openCount(h.counts)
  const counts = n ? `${plural(n, 'offener Befund', 'offene Befunde')} (${countsText(h.counts)})` : 'keine offenen Befunde'
  const unreadable = h.unreadable ? `, ${plural(h.unreadable, 'Prüfung', 'Prüfungen')} nicht lesbar` : ''
  return `${counts}${unreadable}.`
})
const checkRunning = computed(() => !!checking.value || runCheck.isPending.value)
</script>

<template>
  <div>
    <ServerHeader
      :title="agentTitle?.title"
      :status="agentTitle ? { tone: agentTitle.tone, label: agentTitle.label } : undefined"
      :description="isGateway
        ? 'Was der Server-Check auf diesem Server findet. Er liest nur, ändert nichts und der Bericht bleibt auf dem Gateway.'
        : 'Was der Agent auf diesem App-Server findet. Er liest nur, ändert nichts und schickt seinen Bericht an das Gateway. Der Bericht bleibt auf deinen Servern.'"
    >
      <template v-if="isGateway && FEATURES.hostAgents" #actions>
        <Button variant="outline" data-testid="add-server" @click="addServer">
          <Plus aria-hidden="true" /> Server hinzufügen
        </Button>
      </template>
    </ServerHeader>

    <ErrorState
      v-if="hostsQ.isError.value && !hostsQ.data.value"
      title="Die Server lassen sich gerade nicht laden"
      :description="errorMessage(hostsQ.error.value)"
      :retrying="hostsQ.isFetching.value"
      @retry="hostsQ.refetch()"
    />

    <div v-else-if="hostsQ.isPending.value" class="space-y-3 rounded-xl border p-5">
      <Skeleton class="h-6 w-1/3" />
      <Skeleton class="h-24 w-full" />
    </div>

    <EmptyState
      v-else-if="!hosts.length"
      :icon="ServerCog"
      title="Der Server-Check ist noch nicht eingerichtet"
      description="Er läuft auf dem Server als eigener Prozess, liest nur und legt seinen Bericht in ein Verzeichnis, das Schild lesen darf. Zum Einrichten trägst du host_check in schild.yaml ein, startest Schild neu und schaltest den täglichen Lauf ein (Runbook, Abschnitt 17):"
      data-testid="hostcheck-off"
    >
      <CommandBlock command="sudo systemctl enable --now schild-check.timer" class="mx-auto max-w-md text-left" />
    </EmptyState>

    <SplitPane v-else data-testid="servers-pane">
      <template #header>
        <MetaLine :items="headerMeta" class="text-sm" data-testid="servers-meta" />
        <p class="text-xs text-muted-foreground">
          Berichte bleiben auf deinen Servern und ändern nichts am Grundschutz.
        </p>
      </template>
      <template v-if="FEATURES.hostAgents" #tabs>
        <Tabs v-model="tabModel">
          <TabsList variant="line" aria-label="Ansicht">
            <TabsTrigger value="server">
              Befunde
            </TabsTrigger>
            <TabsTrigger value="agents" data-testid="tab-agents">
              {{ isGateway ? 'Agenten' : 'Agent' }}<span v-if="isGateway && pendingAgents.length" class="ml-1 tabular-nums">({{ pendingAgents.length }} {{ pendingAgents.length === 1 ? 'wartet' : 'warten' }})</span>
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </template>

      <!-- Server: detail of the selected host -->
      <template v-if="tab === 'server'">
        <div v-if="!detail && detailQ.isPending.value" class="space-y-3">
          <Skeleton class="h-6 w-2/3" />
          <Skeleton class="h-4 w-1/2" />
          <Skeleton class="h-28 w-full" />
        </div>
        <ErrorState
          v-else-if="!detail && detailQ.isError.value"
          title="Dieser Server lässt sich gerade nicht laden"
          :description="errorMessage(detailQ.error.value)"
          @retry="detailQ.refetch()"
        />
        <HostDetailPanel v-else-if="detail" :detail="detail" />
      </template>

      <!-- Agenten: enrolment, confirmation, revocation -->
      <template v-else>
        <div v-if="agentsQ.isPending.value" class="space-y-2">
          <Skeleton v-for="i in 3" :key="i" class="h-14 w-full" />
        </div>
        <ErrorState v-else-if="agentsQ.isError.value" title="Die Agenten lassen sich gerade nicht laden" :description="errorMessage(agentsQ.error.value)" @retry="agentsQ.refetch()" />
        <EmptyState
          v-else-if="!shownAgents.length"
          :icon="Server"
          title="Noch keine App-Server verbunden"
          description="Liegen deine Websites auf weiteren Servern hinter diesem Gateway? Dort kann ein Agent laufen: ein kleines eigenes Programm (schild-agent), das den Server nur liest und seinen Bericht signiert an dieses Gateway schickt. Der Bericht bleibt auf deinen Servern. Er nimmt keine Befehle an."
          data-testid="agents-empty"
        >
          <Button @click="addServer">
            <Plus aria-hidden="true" /> Server hinzufügen
          </Button>
        </EmptyState>
        <div v-else class="space-y-3 text-sm">
          <p class="text-muted-foreground">
            Ein <Term k="agent">Agent</Term> darf nur Berichte schicken, wenn du ihn bestätigt hast. Zurückziehen wirkt sofort und dauerhaft für diesen Schlüssel.
          </p>
          <ul class="divide-y rounded-xl border" aria-label="Agenten" data-testid="agents-list">
            <li v-for="a in shownAgents" :key="a.id" class="flex flex-wrap items-center gap-x-3 gap-y-2 p-3" data-testid="agent-row" :data-agent="a.id">
              <div class="min-w-0 flex-1 basis-64">
                <p class="flex flex-wrap items-center gap-2">
                  <span class="font-semibold break-all">{{ a.hostname }}</span>
                  <span v-if="a.label" class="text-muted-foreground">{{ a.label }}</span>
                  <StatusPill :tone="AGENT_STATUS[a.status].tone" size="sm">
                    {{ AGENT_STATUS[a.status].label }}
                  </StatusPill>
                  <StatusPill v-if="a.silent && a.status === 'enrolled'" tone="warning" size="sm">
                    Meldet sich nicht
                  </StatusPill>
                </p>
                <MetaLine
                  class="mt-0.5"
                  :items="[
                    { text: a.keyid, mono: true },
                    { text: `sha256: ${groupFingerprint(a.fingerprint).slice(0, 19)} …`, mono: true, title: a.fingerprint },
                    a.source === 'config' ? 'aus schild.yaml' : 'per Code',
                    a.status === 'revoked' && a.revoked_at ? `zurückgezogen ${formatRelative(a.revoked_at)}`
                    : a.status === 'pending' ? `gemeldet ${formatRelative(a.created_at)}`
                      : lastReportText(a),
                  ]"
                />
              </div>
              <div class="flex flex-wrap gap-2">
                <Button v-if="a.status === 'pending'" size="sm" data-testid="agent-confirm" @click="confirmPending(a)">
                  Vergleichen und bestätigen
                </Button>
                <Button v-if="a.status !== 'revoked' && a.source !== 'config'" variant="outline" size="sm" data-testid="agent-revoke" @click="revokeTarget = a">
                  {{ a.status === 'pending' ? 'Ablehnen' : 'Zurückziehen' }}
                </Button>
                <p v-else-if="a.status !== 'revoked'" class="max-w-56 text-xs text-muted-foreground">
                  Steht in schild.yaml. Zurückziehen geht dort mit <span class="font-mono">revoked: true</span>.
                </p>
              </div>
            </li>
          </ul>
        </div>
      </template>

      <template v-if="tab === 'server' && host && detail" #footer>
        <EffectFooter>
          <strong>{{ host.hostname }}:</strong>{{ ' ' }}<span data-testid="footer-summary">{{ footerText }}</span>
          <template v-if="host.last_report_at">
            Zuletzt geprüft {{ formatRelative(host.last_report_at) }}.
          </template>
          <span class="sr-only" aria-live="polite">{{ checkRunning ? 'Prüfung läuft.' : '' }}</span>
          <template #actions>
            <Button v-if="host.role === 'gateway'" size="sm" :disabled="checkRunning" data-testid="check-now" @click="checkNow">
              <LoaderCircle v-if="checkRunning" class="motion-safe:animate-spin" aria-hidden="true" />
              <RefreshCw v-else aria-hidden="true" />
              {{ checkRunning ? 'Prüfung läuft …' : 'Jetzt prüfen' }}
            </Button>
            <Button v-else-if="hostAgent && hostAgent.status !== 'revoked'" variant="outline" size="sm" @click="tabModel = 'agents'">
              Agent verwalten
            </Button>
          </template>
          <template #note>
            <template v-if="host.role === 'gateway'">
              Der Check liest nur: keine Updates, keine Paketlisten, keine Scans anderer Server. Was er nicht lesen darf, steht als „nicht lesbar“ mit Grund da.
            </template>
            <template v-else>
              App-Server prüfen sich selbst nach Plan. Schild schickt ihnen keine Befehle, darum gibt es hier kein „Jetzt prüfen“.
            </template>
          </template>
        </EffectFooter>
      </template>
    </SplitPane>

    <EnrolAgentDialog v-model:open="enrolOpen" :agent="enrolAgent" @enrolled="onEnrolled" />
    <ConfirmDialog
      v-model:open="revokeOpen"
      :title="revokeTarget?.status === 'pending' ? `${revokeTarget?.hostname} ablehnen?` : `Agent von ${revokeTarget?.hostname ?? ''} zurückziehen?`"
      :confirm-label="revokeTarget?.status === 'pending' ? 'Ablehnen' : 'Zurückziehen'"
      :pending="revoke.isPending.value"
      :error="revokeError"
      @confirm="doRevoke"
    >
      Schild nimmt von diesem Schlüssel keine Berichte mehr an, sofort und dauerhaft. Alte Berichte bleiben sichtbar, bis die Aufbewahrung sie löscht. Auf dem App-Server ändert sich nichts; für einen neuen Anfang erstellst du einen neuen Code.
    </ConfirmDialog>
  </div>
</template>
