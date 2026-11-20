<script setup lang="ts">
import type { UrlField } from '@/composables/useEventFilters'
import type { RuleExceptionInput } from '@/api/rules'
import type { EventSummary, LocalEvent, MatchedRule, WouldBlockReason } from '@/api/types'
import { Button, ErrorState, formatDateTime, formatNumber, IpAddress, JsonView, RelativeTime, Skeleton, StatusPill } from '@schild/ui'
import { Filter, History, ShieldCheck } from '@lucide/vue'
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { errorMessage } from '@/api/client'
import { useEvent, useIncident } from '@/api/queries'
import { useRequestRing, useWebsites } from '@/api/websites'
import { INCIDENT_STATE, incidentState } from '@/lib/behaviour'
import { HUB_LABEL, hubBaseId, hubRuleText } from '@/lib/crowdsec'
import { explainLocation, explainRule, explainScore, explainTarget, isEvaluationRule, ruleLinks, SCORE_HOW, SCORE_THRESHOLD, targetAnswer } from '@/lib/explain'
import { websitePath } from '@/lib/nav'
import { contextLink } from '@/lib/requests'
import { ATTRIBUTION, eventTypeLabel, letThroughText, NET_CLASS, OUTCOMES, SEVERITY, WOULD_BLOCK_REASON } from '@/lib/labels'
import { exceptionTargetOf, REPOSITORIES, rulesPath } from '@/lib/rules'
import IpActions from './blocks/IpActions.vue'
import CountryAsn from './CountryAsn.vue'
import OutcomePill from './OutcomePill.vue'
import RuleLinks from './RuleLinks.vue'
import RuleExceptionDialog from './rules/RuleExceptionDialog.vue'
import Term from './Term.vue'
import UnblockDialog from './UnblockDialog.vue'

/** Full detail of one local event: who, what, why, what left the server, the session timeline and actions. */
const props = defineProps<{ id: string }>()
const emit = defineEmits<{ filter: [field: UrlField, value: string], open: [id: string] }>()

const q = useEvent(() => props.id)
const route = useRoute()
const websitesQ = useWebsites()
/** Zugriffe of the request's website: the open one, on /events the one its Host belongs to. */
const siteId = computed(() => {
  const open = typeof route.params.site === 'string' ? route.params.site : ''
  const host = d.value?.host
  return open || (host ? websitesQ.data.value?.websites.find(w => w.hosts.includes(host))?.id : undefined)
})
const requestsPath = computed(() => siteId.value ? websitePath(siteId.value) : null)

/** A false positive: the form for an exception (D84), filled with what the finding says. */
const exceptionOpen = ref(false)
const exceptionPreset = ref<Partial<RuleExceptionInput>>({})
const canExcept = (r: MatchedRule) => r.repository === 'crs' || r.repository === 'crowdsec'
function exceptFor(r: MatchedRule) {
  if (r.repository !== 'crs' && r.repository !== 'crowdsec') return
  exceptionPreset.value = { website: siteId.value, path: d.value?.path, target: exceptionTargetOf(r.match_shape?.location), repository: r.repository, rules: [ruleLinkId(r)] }
  exceptionOpen.value = true
}
// MVP-22: "Kontext" (the visitor's requests around this one) while the request ring runs.
const ringQ = useRequestRing()
const ring = computed(() => ringQ.data.value === true)
const detail = computed(() => q.data.value)
const ev = computed(() => detail.value?.event as unknown as LocalEvent | undefined)
const d = computed(() => ev.value?.data)
const isRequest = computed(() => !!ev.value?.type.startsWith('schild.request.') && !!d.value?.client)
const incidentNo = computed(() => (d.value?.incident as string | undefined) ?? null)
const incident = useIncident(incidentNo)
/** blocked / ended (a timed block with ended_at, e.g. ended with a restart) / unblocked. */
const incState = computed(() => incident.data.value ? incidentState(incident.data.value) : null)
/** A behaviour block that ended or was lifted: no "Zu Eigene IPs hinzufügen" either, as on the incident page. */
const blockOver = computed(() => !!incident.data.value?.block && incState.value !== 'blocked')

const rules = computed<MatchedRule[]>(() => (d.value?.rules ?? []) as MatchedRule[])
/** A hub rule has one id in rule lists and filters, whichever of its groups matched. */
const ruleLinkId = (r: MatchedRule) => String(r.repository === 'crowdsec' ? hubBaseId(r.id) : r.id)
const matchText = (r: MatchedRule) => r.crowdsec ? hubRuleText(r.crowdsec) : explainRule(r.id, r.msg)
/** The rule page of the main finding: every rule can be switched off there (D73). */
const mainRulePath = computed(() => mainRule.value ? rulesPath(mainRule.value.repository, ruleLinkId(mainRule.value)) : '')
/** CRS 949110 and friends add up the points and decide; they are the decision, not a finding of their own. */
const isEvaluation = (r: MatchedRule) => r.repository === 'crs' && isEvaluationRule(r.id)
const findings = computed(() => rules.value.filter(r => !isEvaluation(r)))
const evaluation = computed(() => rules.value.find(isEvaluation) ?? null)
const mainRule = computed(() => findings.value[0] ?? rules.value[0])
/** OWASP page of the attack type, for CRS findings only (the CRS docs are on the rule page). */
const findingLinks = (r: MatchedRule) => r.repository === 'crs' ? ruleLinks(r.id, { docs: false }) : []
/** "/.git/HEAD" -> what the .git folder is; shown on the main finding. */
const target = computed(() => isRequest.value ? explainTarget(d.value?.path, d.value?.query) : null)

/**
 * Why a would_block came through: would_block_reason of the event (v0.5); older events without it fall
 * back to the gateway mode and the own-address flag of the client.
 */
const wouldReason = computed<WouldBlockReason | null>(() => {
  if (!d.value || d.value.outcome !== 'would_block') return null
  if (d.value.would_block_reason) return d.value.would_block_reason
  return d.value.mode === 'observe' ? 'gateway_observe' : d.value.client?.allowlisted ? 'allowlist' : null
})

const sentence = computed(() => {
  if (!d.value || !isRequest.value) return ''
  const target = `eine Anfrage an ${d.value.path}`
  const why = mainRule.value ? `, weil: ${matchText(mainRule.value).title}` : ''
  switch (d.value.outcome) {
    case 'blocked': return `Schild hat ${target} gesperrt${why}.`
    case 'would_block': {
      const t = letThroughText(wouldReason.value)
      return `Schild hat ${target} erkannt${why}. ${t.endsWith('.') ? t : `${t}.`}`
    }
    case 'logged': return `Schild hat ${target} durchgelassen und notiert${why}.`
    default: return `Schild hat ${target} geprüft und nichts Auffälliges gefunden.`
  }
})

/** How the score led to the outcome, after the general rule (SCORE_HOW). */
const decisionTail = computed(() => {
  if (!d.value) return ''
  const reached = (d.value.score ?? 0) >= SCORE_THRESHOLD
  const hub = rules.value.some(r => r.repository === 'crowdsec')
  switch (d.value.outcome) {
    case 'blocked':
      if (reached) return 'Darum hat Schild die Anfrage gesperrt.'
      return hub
        ? 'Gesperrt hat eine Regel aus dem CrowdSec Hub. Diese Regeln geben keine Punkte, sie sperren selbst, wenn der Schalter des CrowdSec Hub auf Sperren steht.'
        : 'Gesperrt hat Schild sie aus einem anderen Grund, zum Beispiel wegen des Verhaltens dieser IP.'
    case 'would_block':
      return wouldReason.value ? `Durchgelassen hat Schild sie trotzdem. Grund: ${WOULD_BLOCK_REASON[wouldReason.value]}.` : 'Durchgelassen hat Schild sie trotzdem, der Grund steht oben.'
    default:
      if (reached) return ''
      return hub ? 'Regeln aus dem CrowdSec Hub geben keine Punkte. Sie sperren nur, wenn der Schalter des CrowdSec Hub auf Sperren steht.' : 'Darunter sperrt Schild nicht.'
  }
})

const requestLine = computed(() => {
  if (!d.value) return ''
  const proto = d.value.protocol === 'h2' ? 'HTTP/2' : d.value.protocol === 'h3' ? 'HTTP/3' : (d.value.protocol ?? '').toUpperCase()
  return `${d.value.method} ${d.value.path}${d.value.query ? `?${d.value.query}` : ''} ${proto}`.trim()
})

const timeline = computed<EventSummary[]>(() => {
  if (!detail.value || !ev.value) return []
  const self: EventSummary = {
    id: ev.value.id,
    time: ev.value.time,
    type: ev.value.type,
    outcome: d.value?.outcome,
    path: d.value?.path,
    method: d.value?.method,
  }
  return [...(detail.value.related ?? []), self].sort((a, b) => Date.parse(a.time) - Date.parse(b.time))
})

/** The reason a block from this event gets (IpActions): the event and what it found. */
const blockReason = computed(() => {
  if (!ev.value || !d.value) return ''
  const what = mainRule.value ? matchText(mainRule.value).title : `Anfrage an ${d.value.path}`
  return `Ereignis ${ev.value.id}: ${what}`
})
const unblockOpen = ref(false)
function openUnblock() {
  unblockOpen.value = true
}
</script>

<template>
  <div>
    <div v-if="q.isPending.value" class="space-y-4" aria-busy="true">
      <Skeleton class="h-6 w-40" />
      <Skeleton class="h-16 w-full" />
      <Skeleton class="h-32 w-full" />
    </div>
    <ErrorState v-else-if="q.isError.value" title="Dieses Ereignis lässt sich nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />

    <div v-else-if="ev && d" class="space-y-6 text-sm">
      <!-- Summary -->
      <section class="space-y-2">
        <div class="flex flex-wrap items-center gap-2">
          <OutcomePill v-if="d.outcome" :outcome="d.outcome" :reason="wouldReason" size="md" />
          <StatusPill v-else tone="neutral" size="md">
            {{ eventTypeLabel(ev.type) }}
          </StatusPill>
          <span class="text-muted-foreground"><time :datetime="ev.time">{{ formatDateTime(ev.time) }}</time> · <RelativeTime :value="ev.time" /></span>
        </div>
        <p v-if="sentence" class="text-base text-pretty" data-testid="event-sentence">
          {{ sentence }}
        </p>
        <p v-if="d.outcome && !(d.outcome === 'would_block' && sentence)" class="text-muted-foreground" data-testid="outcome-explain">
          {{ d.outcome === 'would_block' ? letThroughText(wouldReason) : OUTCOMES[d.outcome].explain }}
        </p>
        <p v-if="incidentNo" class="flex flex-wrap items-center gap-2">
          <span class="text-muted-foreground"><Term k="incident" />:</span>
          <RouterLink :to="`/incidents/${incidentNo}`" class="font-mono font-medium underline underline-offset-4 hover:no-underline">
            {{ incidentNo }}
          </RouterLink>
          <StatusPill v-if="incState" :tone="INCIDENT_STATE[incState].tone" size="sm" :data-testid="incState === 'ended' ? 'event-incident-ended' : 'event-incident-state'">
            {{ INCIDENT_STATE[incState].label }}
          </StatusPill>
        </p>
      </section>

      <!-- Actions -->
      <section v-if="isRequest" class="flex flex-wrap gap-2" aria-label="Aktionen">
        <Button v-if="incState === 'blocked' || incState === 'stopped'" size="sm" data-testid="event-unblock" @click="openUnblock()">
          <ShieldCheck aria-hidden="true" />
          {{ incState === 'blocked' ? 'Sperre aufheben …' : 'Durchlassen …' }}
        </Button>
        <Button v-if="ring" as-child size="sm" variant="outline">
          <RouterLink :to="contextLink(route, ev.id)" data-testid="event-context">
            <History aria-hidden="true" />
            Kontext
          </RouterLink>
        </Button>
        <IpActions
          v-if="d.client?.ip"
          inline
          testid="event"
          :ip="d.client.ip"
          :net-class="d.client.geo?.net_class"
          :reason="blockReason"
          :can-block="incState !== 'blocked' && !d.client.allowlisted"
          :can-allow="!blockOver && !d.client.allowlisted"
          :allow-label="incidentNo ? `Vorfall ${incidentNo}` : ''"
        />
      </section>
      <p v-if="isRequest && d.outcome && d.outcome !== 'passed' && mainRule" class="text-xs text-muted-foreground" data-testid="event-fp-hint">
        Fehlalarm?
        <template v-if="canExcept(mainRule)">
          Leg unter „Warum“ eine Ausnahme für dieses Feld an. Die Regel
          <RouterLink :to="mainRulePath" class="underline underline-offset-4">auszuschalten</RouterLink>
          trifft sie auf allen Websites.
        </template>
        <template v-else>
          Unter <RouterLink :to="mainRulePath || '/settings/rules'" class="underline underline-offset-4">Regeln</RouterLink> kannst du die Regel ausschalten. Das gilt für alle Websites.
        </template>
      </p>

      <!-- Who -->
      <section v-if="isRequest && d.client" aria-labelledby="ev-who">
        <h3 id="ev-who" class="mb-2 font-medium">
          Wer
        </h3>
        <dl class="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 rounded-xl border p-3">
          <dt class="text-muted-foreground">
            IP-Adresse
          </dt>
          <dd class="min-w-0">
            <IpAddress :ip="d.client.ip" :country="d.client.geo.country" :asn="d.client.geo.asn" :asn-org="d.client.geo.as_org" />
            <span class="block text-xs text-muted-foreground">Im Klartext, nur hier lokal. Verlässt den Server nie.</span>
          </dd>
          <dt class="text-muted-foreground">
            Herkunft
          </dt>
          <dd class="min-w-0">
            <CountryAsn :geo="d.client.geo" />
          </dd>
          <dt class="text-muted-foreground">
            <Term k="asn">Netz</Term>
          </dt>
          <dd>{{ NET_CLASS[d.client.geo.net_class] ?? d.client.geo.net_class }}</dd>
          <dt class="text-muted-foreground">
            IP-Quelle
          </dt>
          <dd>{{ ATTRIBUTION[d.client.attribution] ?? d.client.attribution }}</dd>
          <template v-if="d.client.allowlisted">
            <dt class="text-muted-foreground">
              Eigene IP
            </dt>
            <dd>Ja, steht unter „Eigene IPs“. Schild sperrt sie nicht.</dd>
          </template>
        </dl>
        <div class="mt-2 flex flex-wrap gap-1.5">
          <Button v-if="requestsPath" size="xs" variant="outline" as-child>
            <RouterLink :to="{ path: requestsPath, query: { view: 'requests', ip: d.client.ip } }" data-testid="event-ip-requests">
              <Filter aria-hidden="true" /> Alle Anfragen dieser IP
            </RouterLink>
          </Button>
          <Button size="xs" variant="outline" @click="emit('filter', 'ip', d.client.ip)">
            <Filter aria-hidden="true" /> Nur diese IP
          </Button>
          <Button size="xs" variant="outline" @click="emit('filter', 'country', d.client.geo.country)">
            <Filter aria-hidden="true" /> Nur dieses Land
          </Button>
          <Button size="xs" variant="outline" @click="emit('filter', 'asn', String(d.client.geo.asn))">
            <Filter aria-hidden="true" /> Nur dieses Netz
          </Button>
          <Button v-if="d.session_id" size="xs" variant="outline" @click="emit('filter', 'session', d.session_id)">
            <Filter aria-hidden="true" /> Diese Sitzung
          </Button>
        </div>
      </section>

      <!-- What -->
      <section v-if="isRequest" aria-labelledby="ev-what">
        <h3 id="ev-what" class="mb-2 font-medium">
          Anfrage
        </h3>
        <div class="rounded-xl border">
          <p class="overflow-x-auto border-b bg-muted px-3 py-2 font-mono text-xs break-all whitespace-pre-wrap" data-testid="request-line">
            {{ requestLine }}
          </p>
          <dl class="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 p-3">
            <dt class="text-muted-foreground">
              Website
            </dt>
            <dd class="break-all">
              {{ d.host }}
            </dd>
            <template v-if="d.checked_paths?.length">
              <dt class="text-muted-foreground">
                Geprüfte Pfade
              </dt>
              <dd data-testid="checked-paths">
                <ol class="space-y-0.5">
                  <li v-for="(p, i) in d.checked_paths" :key="i" class="font-mono text-xs break-all">
                    {{ i + 1 }}. {{ p }}
                  </li>
                </ol>
                <span class="block text-xs text-muted-foreground">Schild hat diese Anfrage mehrmals geprüft, in dieser Reihenfolge. Sie zählt trotzdem nur einmal.</span>
              </dd>
            </template>
            <dt class="text-muted-foreground">
              Antwort
            </dt>
            <dd>HTTP {{ d.status }}</dd>
            <dt class="text-muted-foreground">
              Programm
            </dt>
            <dd class="font-mono text-xs break-all">
              {{ d.user_agent || '–' }}
            </dd>
            <dt class="text-muted-foreground">
              Dauer
            </dt>
            <dd>{{ formatNumber(d.duration_ms ?? 0) }} ms, davon {{ formatNumber(d.waf_ms ?? 0) }} ms für die Prüfung</dd>
          </dl>
        </div>
        <Button size="xs" variant="outline" class="mt-2" @click="emit('filter', 'path', d.path ?? '')">
          <Filter aria-hidden="true" /> Nur dieser Pfad
        </Button>
      </section>

      <!-- Why -->
      <section v-if="isRequest" aria-labelledby="ev-why">
        <h3 id="ev-why" class="mb-2 font-medium">
          Warum
        </h3>
        <ul v-if="findings.length" class="space-y-2">
          <li v-for="r in findings" :key="r.id" class="rounded-xl border p-3" data-testid="event-finding">
            <div class="flex flex-wrap items-baseline justify-between gap-2">
              <p class="font-medium">
                {{ matchText(r).title }}
              </p>
              <span class="text-xs text-muted-foreground">
                <template v-if="r.crowdsec">{{ HUB_LABEL }}<template v-if="r.crowdsec.cves?.length"> · {{ r.crowdsec.cves.join(', ') }}</template></template>
                <template v-else>{{ REPOSITORIES[r.repository]?.one ?? r.repository }} · {{ r.id }}</template><template v-if="r.severity"> · Schwere {{ SEVERITY[r.severity] }}</template>
              </span>
            </div>
            <p class="mt-1 text-muted-foreground">
              <span v-if="r.crowdsec" class="block font-mono text-xs" data-testid="event-hub-name">{{ r.crowdsec.name }}</span>
              {{ matchText(r).explain }}
              <template v-if="r.match_shape?.location">
                Gefunden {{ explainLocation(r.match_shape.location) }}.
              </template>
            </p>
            <p v-if="target && r === mainRule" class="mt-2 text-pretty" data-testid="event-target">
              {{ target }}
              <span class="text-muted-foreground">{{ targetAnswer(d.outcome, d.status) }}</span>
            </p>
            <RuleLinks :links="findingLinks(r)" class="mt-2 text-xs" />
            <div class="mt-2 flex flex-wrap gap-1.5">
              <Button size="xs" variant="outline" @click="emit('filter', 'rule', ruleLinkId(r))">
                <Filter aria-hidden="true" /> Alle Treffer dieser Regel
              </Button>
              <Button as-child size="xs" variant="ghost">
                <RouterLink :to="rulesPath(r.repository, ruleLinkId(r))">
                  Regel ansehen
                </RouterLink>
              </Button>
              <Button v-if="canExcept(r)" size="xs" variant="ghost" data-testid="event-exception-add" @click="exceptFor(r)">
                Ausnahme anlegen
              </Button>
            </div>
          </li>
        </ul>
        <p v-else-if="!rules.length" class="text-muted-foreground">
          Keine Regel hat angeschlagen.
        </p>
        <div v-if="rules.length && d.score !== undefined" class="mt-2 space-y-1 rounded-xl bg-muted p-3" data-testid="event-decision">
          <h4 class="font-medium">
            Entscheidung
          </h4>
          <p>
            <Term k="score" />: <span class="font-medium">{{ d.score }} von 100</span>, {{ explainScore(d.score) }}.
          </p>
          <p class="text-muted-foreground text-pretty">
            {{ SCORE_HOW }} {{ decisionTail }}
          </p>
          <div v-if="evaluation" class="space-y-1 pt-1 text-xs text-muted-foreground" data-testid="event-evaluation">
            <p>
              Zusammengezählt hat Regel {{ evaluation.id }} der Grundregeln (CRS). Sie sucht selbst nach nichts, sie entscheidet nur.
              <RouterLink :to="rulesPath('crs', String(evaluation.id))" class="underline underline-offset-4 hover:text-foreground hover:no-underline">
                Regel ansehen
              </RouterLink>
            </p>
            <RuleLinks :links="ruleLinks(evaluation.id)" />
          </div>
        </div>
      </section>

      <!-- Non-request events -->
      <section v-if="!isRequest" aria-labelledby="ev-data">
        <h3 id="ev-data" class="mb-2 font-medium">
          {{ eventTypeLabel(ev.type) }}
        </h3>
        <JsonView :value="ev.data" label="Daten des Ereignisses (lokal)" />
      </section>

      <!-- Timeline -->
      <section v-if="timeline.length > 1" aria-labelledby="ev-timeline">
        <h3 id="ev-timeline" class="mb-2 font-medium">
          Verlauf dieser <Term k="session">Sitzung</Term> und IP
        </h3>
        <ol class="relative space-y-1 border-l pl-4">
          <li v-for="t in timeline" :key="t.id" class="relative">
            <span :class="['absolute top-2.5 -left-[1.3rem] size-2 rounded-full', t.id === id ? 'bg-primary ring-4 ring-primary/20' : 'bg-border']" aria-hidden="true" />
            <button
              type="button"
              :disabled="t.id === id"
              :aria-current="t.id === id ? 'true' : undefined"
              class="flex w-full flex-wrap items-center gap-x-2 gap-y-0.5 rounded-md px-2 py-1.5 text-left hover:bg-muted disabled:cursor-default disabled:bg-muted/60"
              @click="emit('open', t.id)"
            >
              <time :datetime="t.time" class="font-mono text-xs text-muted-foreground tabular-nums">{{ formatDateTime(t.time).split(', ')[1] ?? formatDateTime(t.time) }}</time>
              <OutcomePill v-if="t.outcome" :outcome="t.outcome" :reason="t.would_block_reason" />
              <span class="min-w-0 truncate">{{ t.method }} {{ t.path ?? eventTypeLabel(t.type) }}</span>
              <span v-if="t.id === id" class="text-xs text-muted-foreground">(dieses Ereignis)</span>
            </button>
          </li>
        </ol>
      </section>
    </div>

    <RuleExceptionDialog v-model:open="exceptionOpen" :preset="exceptionPreset" />
    <UnblockDialog v-if="incident.data.value" v-model:open="unblockOpen" :incident="incident.data.value" />
  </div>
</template>
