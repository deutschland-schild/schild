<script setup lang="ts">
import { unwrap } from '@schild/app-kit'
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  ErrorState,
  formatDateTime,
  Input,
  IpAddress,
  Label,
  PageHeader,
  RelativeTime,
  Skeleton,
  StatusPill,
  toast,
} from '@schild/ui'
import { ArrowRight, Download, Search, ShieldCheck } from '@lucide/vue'
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, csrf, errorMessage, statusOf } from '@/api/client'
import { useEvents, useIncident } from '@/api/queries'
import { useRequestRing } from '@/api/websites'
import IpActions from '@/components/blocks/IpActions.vue'
import CountryAsn from '@/components/CountryAsn.vue'
import HubRuleLine from '@/components/HubRuleLine.vue'
import Term from '@/components/Term.vue'
import UnblockDialog from '@/components/UnblockDialog.vue'
import { blockSourceText, INCIDENT_STATE, incidentReason, incidentState } from '@/lib/behaviour'
import { isHubId } from '@/lib/crowdsec'
import { explainRule, isEvaluationRule } from '@/lib/explain'
import { AGGREGATE_EXPLAIN, aggregateText, normalizeIncident, validIncident } from '@/lib/incident'
import { contextLink } from '@/lib/requests'
import { incidentBlockText, WEBSITE_COPY } from '@/lib/websites'

const route = useRoute()
const router = useRouter()
// MVP-22: "Kontext" (the client's requests around the incident) while the request ring runs.
const ringQ = useRequestRing()
const ring = computed(() => ringQ.data.value === true)
const param = computed(() => typeof route.params.incident === 'string' ? normalizeIncident(route.params.incident) : null)
const number = computed(() => param.value && validIncident(param.value) ? param.value : null)
const q = useIncident(number)
const inc = computed(() => q.data.value)
const notFound = computed(() => q.isError.value && statusOf(q.error.value) === 404)

// Lookup form
const input = ref(param.value ?? '')
const touched = ref(false)
watch(param, v => (input.value = v ?? ''))
const inputError = computed(() => {
  if (!touched.value || !input.value) return null
  return validIncident(input.value) ? null : 'Eine Vorfallnummer hat 8 Zeichen, z. B. K7QM-4XWD. Sie enthält kein I, O, 0 oder 1.'
})
function onInput(v: string | number) {
  input.value = normalizeIncident(String(v))
}
function lookup() {
  touched.value = true
  if (!validIncident(input.value)) return
  void router.push(`/incidents/${input.value}`)
}
onMounted(() => {
  if (!param.value) document.getElementById('incident-input')?.focus()
})

// Recent blocks for quick access
const recent = useEvents(() => ({ outcome: 'blocked' as const }))
const recentItems = computed(() => (recent.data.value?.pages[0]?.items ?? []).filter(e => e.incident).slice(0, 8))

const reasons = computed(() => (inc.value?.request.rules ?? []).filter(r => !isEvaluationRule(r)).map(r => ({ id: r, ...explainRule(r) })))
/** A behaviour block (D29): who did what how often, how long the block lasts and why. */
const block = computed(() => inc.value?.block ?? null)
/** A block with ended_at (ran out, lifted, ended with a restart) is no longer "Gesperrt" and can't be released. */
const state = computed(() => inc.value ? incidentState(inc.value) : null)
/** The reason a block from this incident gets (IpActions). */
const blockReason = computed(() => inc.value ? `Vorfall ${inc.value.incident}: ${reasons.value[0]?.title ?? reasonText.value}` : '')
const blockCause = computed(() => {
  if (!block.value) return null
  return block.value.set_by ? `Agent ${block.value.set_by.token_label}` : blockSourceText(block.value.source)
})
const target = computed(() => {
  const r = inc.value?.request
  if (!r?.path) return ''
  return `${r.host ?? ''}${r.path}`
})
/** The stored reason of a behaviour block is technical English; show the scenario name instead. */
const reasonView = computed(() => incidentReason(inc.value?.reason))
const reasonText = computed(() => reasonView.value?.title ?? '–')
/** D38: several blocked requests of one client, rule and minute share this number. */
const aggregate = computed(() => inc.value ? aggregateText(inc.value) : null)
const unblockOpen = ref(false)

// D51: the incident as a file, for a case that outlives the retention.
const exporting = ref(false)
async function exportIncident() {
  if (!inc.value) return
  const incident = inc.value.incident
  exporting.value = true
  try {
    const data = await unwrap(api.POST('/incidents/{incident}/export', { params: { header: csrf(), path: { incident } } }))
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `schild-incident-${incident}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    toast.success('Vorfall gesichert', { description: 'Die Datei enthält volle IP-Adressen. Bewahre sie sicher auf.' })
  }
  catch (err) {
    toast.error('Sichern hat nicht geklappt', { description: errorMessage(err) })
  }
  finally {
    exporting.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="Vorfälle" description="Wen Schild stoppt, sieht eine Seite mit einer Vorfallnummer. Mit ihr findest du die Anfrage und lässt die Person wieder durch." />

    <Card class="mb-6">
      <CardContent>
        <form class="grid gap-2" novalidate @submit.prevent="lookup">
          <Label for="incident-input">Vorfallnummer</Label>
          <div class="flex flex-col gap-2 sm:flex-row">
            <Input
              id="incident-input"
              :model-value="input"
              placeholder="z. B. K7QM-4XWD"
              autocomplete="off"
              autocapitalize="characters"
              spellcheck="false"
              maxlength="9"
              class="font-mono text-base tracking-wider uppercase sm:max-w-56"
              :aria-invalid="!!inputError"
              aria-describedby="incident-hint"
              data-testid="incident-input"
              @update:model-value="onInput"
              @blur="touched = true"
            />
            <Button type="submit" data-testid="incident-search">
              <Search aria-hidden="true" />
              Vorfall suchen
            </Button>
          </div>
          <p id="incident-hint" :class="inputError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="inputError ? 'alert' : undefined">
            {{ inputError ?? 'Die Person, die gesperrt wurde, kann dir die Nummer von der Sperrseite nennen.' }}
          </p>
        </form>
      </CardContent>
    </Card>

    <!-- Result -->
    <section v-if="number" aria-live="polite" class="mb-6">
      <Card v-if="q.isPending.value">
        <CardContent class="space-y-3">
          <Skeleton class="h-6 w-48" />
          <Skeleton class="h-4 w-full" />
          <Skeleton class="h-4 w-2/3" />
        </CardContent>
      </Card>
      <Card v-else-if="notFound" data-testid="incident-not-found">
        <CardHeader>
          <CardTitle>Vorfall {{ number }} nicht gefunden</CardTitle>
          <CardDescription>
            Prüf die Nummer noch einmal. Ältere Vorfälle löscht Schild nach Ablauf der Aufbewahrungszeit (Einstellungen). Hat die Person sich vertippt, frag nach einem Foto der Sperrseite.
          </CardDescription>
        </CardHeader>
      </Card>
      <ErrorState v-else-if="q.isError.value" title="Der Vorfall lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
      <Card v-else-if="inc" data-testid="incident-card">
        <CardHeader>
          <div class="flex flex-wrap items-center gap-2">
            <CardTitle class="font-mono text-xl tracking-wider">
              {{ inc.incident }}
            </CardTitle>
            <StatusPill v-if="state" :tone="INCIDENT_STATE[state].tone" data-testid="incident-status">
              {{ INCIDENT_STATE[state].label }}
            </StatusPill>
          </div>
          <CardDescription>
            <time :datetime="inc.time">{{ formatDateTime(inc.time) }}</time> · <RelativeTime :value="inc.time" />
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-5 text-sm">
          <p v-if="block" class="text-base text-pretty" data-testid="incident-sentence">
            Schild hat diese Adresse gesperrt: {{ incidentBlockText(block) }}. Auslöser: {{ blockCause }}<template v-if="target">
              auf <span class="font-mono">{{ target }}</span>
            </template>.
          </p>
          <p v-else-if="target" class="text-base text-pretty" data-testid="incident-sentence">
            Schild hat eine Anfrage an <span class="font-mono">{{ target }}</span> gesperrt<template v-if="reasons[0]">, weil: {{ reasons[0].title }}</template>.
          </p>
          <p v-else class="text-base text-pretty" data-testid="incident-sentence">
            Schild hat eine Anfrage gesperrt<template v-if="reasons[0]">, weil: {{ reasons[0].title }}</template>.
          </p>

          <dl class="grid gap-x-4 gap-y-3 sm:grid-cols-[10rem_1fr]">
            <template v-if="aggregate">
              <dt class="text-muted-foreground">
                Anfragen
              </dt>
              <dd data-testid="incident-aggregate">
                {{ aggregate }}
                <span class="block text-muted-foreground">{{ AGGREGATE_EXPLAIN }}</span>
              </dd>
            </template>
            <dt class="text-muted-foreground">
              IP-Adresse
            </dt>
            <dd class="min-w-0">
              <IpAddress v-if="inc.request.ip" :ip="inc.request.ip" :country="inc.request.geo?.country" :asn="inc.request.geo?.asn" :asn-org="inc.request.geo?.as_org" />
              <template v-else>
                –
              </template>
            </dd>
            <dt class="text-muted-foreground">
              Herkunft
            </dt>
            <dd class="min-w-0">
              <CountryAsn :geo="inc.request.geo" />
            </dd>
            <template v-if="target">
              <dt class="text-muted-foreground">
                {{ block ? 'Seite' : 'Anfrage' }}
              </dt>
              <dd class="font-mono text-xs break-all">
                {{ inc.request.method }} {{ target }}
              </dd>
            </template>
            <template v-if="block">
              <dt class="text-muted-foreground">
                Dauer
              </dt>
              <dd data-testid="block-duration">
                {{ incidentBlockText(block) }}<template v-if="state === 'blocked'">
                  · bis <time :datetime="block.until">{{ formatDateTime(block.until) }}</time>
                </template><template v-else-if="state === 'ended'">
                  <template v-if="block.ended_at">
                    · beendet um <time :datetime="block.ended_at" data-testid="block-ended">{{ formatDateTime(block.ended_at) }}</time>
                  </template>
                </template>
                <span class="block text-muted-foreground">{{ WEBSITE_COPY.blockScope }} Jede Sperre endet von selbst.</span>
              </dd>
              <template v-if="block.set_by">
                <dt class="text-muted-foreground">
                  Gesetzt von
                </dt>
                <dd data-testid="block-set-by">
                  Von Agent {{ block.set_by.token_label }} gesetzt
                  <span v-if="block.agent_reason" class="block text-muted-foreground" data-testid="block-agent-reason">{{ block.agent_reason }}</span>
                </dd>
              </template>
            </template>
            <dt class="text-muted-foreground">
              Grund
            </dt>
            <dd>
              <ul class="space-y-1">
                <li v-for="r in reasons" :key="r.id">
                  <HubRuleLine v-if="isHubId(r.id)" :id="r.id" />
                  <template v-else>
                    <span class="font-medium">{{ r.title }}</span>
                    <span class="text-muted-foreground"> ({{ r.id }})</span>
                    <span class="block text-muted-foreground">{{ r.explain }}</span>
                  </template>
                </li>
                <li v-if="!reasons.length">
                  {{ reasonText }}<template v-if="block">
                    <span class="text-muted-foreground"> (Stufe {{ block.level }})</span>
                  </template>
                  <span v-if="reasonView?.detail" class="block text-xs text-muted-foreground" lang="en" data-testid="incident-reason-detail">{{ reasonView.detail }}</span>
                </li>
              </ul>
            </dd>
            <dt class="text-muted-foreground">
              {{ block ? 'Art der Sperre' : 'Art der Regel' }}
            </dt>
            <dd>{{ block ? 'Verhalten über mehrere Anfragen, erkannt auf deinem Server' : 'Regel auf deinem Server' }}</dd>
            <template v-if="inc.status === 'unblocked'">
              <dt class="text-muted-foreground">
                Aufgehoben
              </dt>
              <dd>
                <RelativeTime v-if="inc.unblocked_at" :value="inc.unblocked_at" />
                <template v-if="inc.allowlist_entry">
                  · IP steht auf der Liste <RouterLink to="/own-ips" class="underline underline-offset-4">eigener IPs</RouterLink>
                </template>
              </dd>
            </template>
          </dl>

          <div class="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
            <Button v-if="state === 'blocked' || state === 'stopped'" data-testid="incident-unblock" @click="unblockOpen = true">
              <ShieldCheck aria-hidden="true" />
              {{ state === 'blocked' ? 'Sperre aufheben …' : 'Durchlassen …' }}
            </Button>
            <IpActions
              v-if="inc.request.ip && state !== 'blocked'"
              inline
              testid="incident"
              :ip="inc.request.ip"
              :net-class="inc.request.geo?.net_class"
              :reason="blockReason"
              :allow-label="`Vorfall ${inc.incident}`"
            />
            <Button as-child variant="ghost">
              <RouterLink :to="`/events?event=${inc.request.id}`">
                Ereignis ansehen
                <ArrowRight aria-hidden="true" />
              </RouterLink>
            </Button>
            <Button v-if="ring" as-child variant="ghost">
              <RouterLink :to="contextLink(route, inc.request.id)" data-testid="incident-context">
                Kontext
              </RouterLink>
            </Button>
            <Button v-if="inc.request.ip" as-child variant="ghost">
              <RouterLink :to="`/events?ip=${encodeURIComponent(inc.request.ip)}&time=7d`">
                Alles von dieser IP
              </RouterLink>
            </Button>
            <Button variant="ghost" :disabled="exporting" data-testid="incident-export" @click="exportIncident">
              <Download aria-hidden="true" />
              Vorfall sichern
            </Button>
          </div>
          <p class="text-xs text-muted-foreground">
            „Vorfall sichern“ lädt den Vorfall mit Ereignissen und Kontext als Datei herunter, mit vollen IP-Adressen und Browserkennungen. Die Datei liegt dann bei dir: Fristen und Löschungen erreichen sie nicht mehr.
          </p>
        </CardContent>
      </Card>
      <UnblockDialog v-if="inc" v-model:open="unblockOpen" :incident="inc" />
    </section>

    <!-- Recent -->
    <Card>
      <CardHeader>
        <CardTitle>Letzte Sperren</CardTitle>
        <CardDescription>Die neuesten Vorfälle. Sperren laufen ohnehin von selbst ab.</CardDescription>
      </CardHeader>
      <CardContent>
        <div v-if="recent.isPending.value" class="space-y-2">
          <Skeleton v-for="i in 3" :key="i" class="h-10 w-full" />
        </div>
        <ul v-else-if="recentItems.length" class="divide-y rounded-xl border">
          <li v-for="e in recentItems" :key="e.id">
            <RouterLink :to="`/incidents/${e.incident}`" class="flex flex-wrap items-center gap-x-3 gap-y-1 p-3 text-sm hover:bg-muted/50 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring">
              <span class="font-mono font-medium tracking-wider">{{ e.incident }}</span>
              <span class="hidden min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground sm:block">{{ e.method }} {{ e.path }}</span>
              <span class="flex-1 sm:hidden" />
              <span class="font-mono text-xs">{{ e.ip }}</span>
              <RelativeTime :value="e.time" class="text-xs text-muted-foreground" />
            </RouterLink>
          </li>
        </ul>
        <p v-else class="text-sm text-muted-foreground">
          Keine Sperren in letzter Zeit. Steht keine Quelle auf „Sperren“, sperrt Schild nichts, und es gibt auch keine <Term k="incident">Vorfallnummern</Term>.
        </p>
      </CardContent>
    </Card>
  </div>
</template>
