<script setup lang="ts">
import type { SettingsPatch } from '@/api/types'
import { unwrap } from '@schild/app-kit'
import {
  BarList,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  ErrorState,
  formatBytes,
  formatNumber,
  formatPercent,
  Input,
  Label,
  PageHeader,
  RelativeTime,
  StatCard,
  StatusPill,
  Skeleton,
  toast,
} from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed, nextTick, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api, csrf, errorMessage, fieldErrors } from '@/api/client'
import { useBehaviourSettings } from '@/api/behaviour'
import { useServerSnapshot } from '@/api/monitoring'
import { useOverview, useSettings, useUpdateSettings } from '@/api/queries'
import { useRuleRepositories, useRules } from '@/api/rules'
import AgentApiCard from '@/components/AgentApiCard.vue'
import LastChange from '@/components/audit/LastChange.vue'
import ServersCard from '@/components/ServersCard.vue'
import { versionText } from '@/lib/labels'
import { BEHAVIOUR_RULES_PATH } from '@/lib/nav'
import { geoDbText } from '@/lib/requests'
import { REPOSITORIES, REPOSITORY_EFFECT, RULES_PATH, ruleText, rulesPath } from '@/lib/rules'
import { attentionItems, baselineView, partialView, plural } from '@/lib/summary'

const route = useRoute()
const q = useSettings()
const s = computed(() => q.data.value)
const update = useUpdateSettings()
// D89: no protection mode. The rule sources check single requests, the scenarios block whole addresses;
// each has its own switch, and this card only shows where they stand.
const repos = useRuleRepositories()
const behaviour = useBehaviourSettings()
const scenariosBlocking = computed(() => {
  const list = behaviour.data.value?.scenarios
  if (!list) return null
  const n = list.filter(x => x.effective_mode === 'block').length
  return n === 0 ? 'Gerade sperrt keins.' : `Gerade ${n === 1 ? 'sperrt' : 'sperren'} ${n} von ${list.length}.`
})

// ---------------------------------------------------------------- what schild does (the former Schutzstatus page, 2026-11-18)
// One page with the settings: no hero, no "nothing to do". Only when the Grundschutz is degraded or off
// does a box at the top name what needs a look.
const overview = useOverview()
const o = computed(() => overview.data.value)
const rules = useRules()
const gs = computed(() => o.value ? baselineView(o.value) : null)
const attention = computed(() => o.value && gs.value?.tone !== 'signal' ? attentionItems(o.value) : [])
const series = computed(() => o.value?.series_24h)

const topPatterns = computed(() => {
  const top = (rules.data.value?.pages.flatMap(p => p.items) ?? [])
    .filter(r => r.hits_24h > 0)
    .sort((a, b) => b.hits_24h - a.hits_24h)
    .slice(0, 6)
    .map(r => ({ r, title: ruleText(r).title }))
  // Several CRS rules share one plain-language title: name the rule then, so two bars never read the same.
  const count = new Map<string, number>()
  for (const t of top) count.set(t.title, (count.get(t.title) ?? 0) + 1)
  return top.map(({ r, title }) => ({ id: r.id, label: (count.get(title) ?? 0) > 1 ? `${title} · Regel ${r.id}` : title, value: r.hits_24h }))
})

/** p95 overhead in words: "unter 1 ms" or rounded up to whole milliseconds. */
const overheadHint = computed(() => {
  const ms = o.value?.counters_24h.p95_overhead_ms
  if (ms === undefined || ms === null) return undefined
  return `Schild braucht dafür meist unter ${ms <= 1 ? 1 : Math.ceil(ms)} ms`
})

/** D36 open items: the 24-hour counters began later (schild start) or have a gap. */
const countersPartial = computed(() => o.value ? partialView(o.value.counters_24h.partial, o.value.counters_24h.since, Date.now(), 'events') : null)

const blockedCard = computed(() => {
  const c = o.value?.counters_24h
  if (!c || !o.value) return null
  return o.value.profile === 'test'
    ? { label: 'Erkannt', value: c.would_block, trend: series.value?.would_block, hint: 'Im Testprofil kam alles durch.', to: '/events?outcome=would_block&time=24h' }
    : { label: 'Gesperrt', value: c.blocked, trend: series.value?.blocked, hint: c.would_block ? `${formatNumber(c.would_block)} weitere nur erkannt` : `${plural(c.incidents, 'Vorfall', 'Vorfälle')}`, to: '/events?outcome=blocked&time=24h' }
})
// MVP-22 (D35): "Geo-Daten: <Anbieter>, Stand <Datum>" from Overview.geo_db.
const geo = computed(() => geoDbText(o.value?.geo_db))

onMounted(() => {
  if (route.hash) void nextTick(() => setTimeout(() => document.querySelector(route.hash)?.scrollIntoView({ block: 'start' }), 150))
})

async function patch(p: SettingsPatch, success: string): Promise<boolean> {
  try {
    await update.mutateAsync(p)
    toast.success(success)
    return true
  }
  catch (err) {
    toast.error('Speichern hat nicht geklappt', { description: errorMessage(err) })
    return false
  }
}

// ---------------------------------------------------------------- retention
const ret = reactive({ raw_ip_days: 14, events_days: 14, summaries_days: 90 })
watch(s, (x) => {
  if (x) Object.assign(ret, { raw_ip_days: x.retention.raw_ip_days, events_days: x.retention.events_days, summaries_days: x.retention.summaries_days })
}, { immediate: true })
const retErrors = computed(() => ({
  raw_ip_days: ret.raw_ip_days < 1 || ret.raw_ip_days > 30 ? 'Zwischen 1 und 30 Tagen.' : null,
  events_days: ret.events_days < 1 || ret.events_days > 90 ? 'Zwischen 1 und 90 Tagen.' : null,
  summaries_days: ret.summaries_days < 1 || ret.summaries_days > 730 ? 'Zwischen 1 und 730 Tagen.' : null,
}))
const retDirty = computed(() => !!s.value && (ret.raw_ip_days !== s.value.retention.raw_ip_days || ret.events_days !== s.value.retention.events_days || ret.summaries_days !== s.value.retention.summaries_days))
/**
 * What schild keeps on its disk now (D38): event store against its cap, plus metrics.db, from the server
 * snapshot (monitoring on). The contract has no field yet for the disk budget and the space available on
 * storage.path (storage-bounds.md section 2), so the page shows what the API serves.
 */
const snapshot = useServerSnapshot()
const storage = computed(() => {
  const x = snapshot.data.value?.schild
  if (!x) return null
  return {
    used: x.store_bytes,
    cap: x.store_max_bytes,
    share: x.store_max_bytes ? Math.min(1, x.store_bytes / x.store_max_bytes) : null,
    over: x.store_max_bytes > 0 && x.store_bytes > x.store_max_bytes,
    metrics: x.metrics_store_bytes,
  }
})

async function saveRetention() {
  if (Object.values(retErrors.value).some(Boolean)) return
  await patch({ retention: { ...ret } }, 'Aufbewahrung gespeichert')
}

// ---------------------------------------------------------------- password
const pw = reactive({ current: '', next: '', repeat: '' })
const pwTouched = ref(false)
const pwSaving = ref(false)
const pwServer = ref<Record<string, string>>({})
const pwErrors = computed(() => ({
  current: pwServer.value.current_password ? 'Das aktuelle Passwort stimmt nicht.' : null,
  next: pwTouched.value && pw.next.length < 12 ? 'Mindestens 12 Zeichen.' : null,
  repeat: pwTouched.value && pw.repeat !== pw.next ? 'Die beiden Eingaben sind nicht gleich.' : null,
}))
async function changePassword() {
  pwTouched.value = true
  pwServer.value = {}
  if (pwErrors.value.next || pwErrors.value.repeat || !pw.current) return
  pwSaving.value = true
  try {
    await unwrap(api.POST('/auth/password', { params: { header: csrf() }, body: { current_password: pw.current, new_password: pw.next } }))
    Object.assign(pw, { current: '', next: '', repeat: '' })
    pwTouched.value = false
    toast.success('Passwort geändert', { description: 'Andere Sitzungen wurden abgemeldet.' })
  }
  catch (err) {
    pwServer.value = fieldErrors(err)
    if (!Object.keys(pwServer.value).length) toast.error('Ändern hat nicht geklappt', { description: errorMessage(err) })
  }
  finally {
    pwSaving.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="Einstellungen" description="Was Schild auf diesem Server tut und wie es eingestellt ist. Alles hier steht auch in schild.yaml und wird mit denselben Regeln geprüft." />

    <div class="space-y-6">
      <p v-if="o?.profile === 'test'" class="rounded-xl border border-status-warning/40 bg-status-warning-subtle p-3 text-sm" role="note">
        <strong>Testprofil:</strong> Schild sperrt nichts, egal wie die Schalter stehen.
        In Release-Versionen gibt es dieses Profil nicht.
      </p>

      <!-- Only when the Grundschutz is degraded or off: what needs a look -->
      <section v-if="gs && gs.tone !== 'signal'" aria-labelledby="gs-title" :class="['rounded-xl border p-4', gs.tone === 'danger' ? 'border-status-danger/40 bg-status-danger-subtle' : 'border-status-warning/40 bg-status-warning-subtle']" data-testid="baseline">
        <div class="flex flex-wrap items-center gap-2">
          <h2 id="gs-title" class="font-semibold">
            {{ gs.title }}
          </h2>
          <StatusPill :tone="gs.tone" size="sm">
            {{ gs.pill }}
          </StatusPill>
        </div>
        <p class="text-sm text-muted-foreground">
          {{ gs.subtitle }}
        </p>
        <ul v-if="attention.length" class="mt-3 grid gap-2" data-testid="attention">
          <li v-for="a in attention" :key="a.id" class="flex flex-col gap-2 rounded-lg border bg-card p-3 sm:flex-row sm:items-center">
            <div class="min-w-0 flex-1">
              <p class="font-medium">
                {{ a.title }}
              </p>
              <p class="text-sm text-muted-foreground">
                {{ a.next }}
              </p>
            </div>
            <Button v-if="a.to" as-child variant="outline" size="sm" class="self-start sm:self-center">
              <RouterLink :to="a.to">
                {{ a.action }}
                <ArrowRight aria-hidden="true" />
              </RouterLink>
            </Button>
          </li>
        </ul>
      </section>

      <!-- 24 h numbers -->
      <section aria-labelledby="numbers-title">
        <h2 id="numbers-title" class="mb-3 text-sm font-medium text-muted-foreground">
          Letzte 24 Stunden<span v-if="countersPartial" :title="countersPartial.text" data-testid="counters-partial"> · {{ countersPartial.short }}<span class="sr-only">. {{ countersPartial.text }}</span></span>
        </h2>
        <ErrorState
          v-if="overview.isError.value && !o"
          title="Die Zahlen lassen sich gerade nicht laden"
          :description="errorMessage(overview.error.value)"
          :retrying="overview.isFetching.value"
          @retry="overview.refetch()"
        />
        <div v-else class="grid gap-4 sm:grid-cols-3">
          <StatCard
            label="Anfragen geprüft"
            :value="o?.counters_24h.requests ?? null"
            :loading="!o"
            :trend="series?.requests"
            trend-label="Anfragen pro Stunde, letzte 24 Stunden"
            :hint="overheadHint"
          />
          <RouterLink v-if="blockedCard" :to="blockedCard.to" class="rounded-xl focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">
            <StatCard :label="blockedCard.label" :value="blockedCard.value" :trend="blockedCard.trend" :trend-label="`${blockedCard.label} pro Stunde`" :hint="blockedCard.hint" class="h-full transition-colors hover:bg-muted" />
          </RouterLink>
          <StatCard v-else label="Gesperrt" :value="null" loading />
          <RouterLink to="/incidents" class="rounded-xl focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">
            <StatCard
              label="Vorfälle"
              :value="o?.counters_24h.incidents ?? null"
              :loading="!o"
              hint="Jede gestoppte Anfrage hat eine Vorfallnummer"
              class="h-full transition-colors hover:bg-muted"
            />
          </RouterLink>
        </div>
      </section>

      <div class="grid gap-4 lg:grid-cols-2">
        <!-- What blocks (D89: each source has its own switch, there is no mode above them) -->
        <Card id="protection" class="min-w-0 scroll-mt-20">
          <CardHeader>
            <CardTitle>Was Schild sperrt</CardTitle>
            <CardDescription>Jede Quelle hat ihren eigenen Schalter.</CardDescription>
          </CardHeader>
          <CardContent class="space-y-4 text-sm">
            <div class="space-y-2">
              <p class="text-muted-foreground">
                Die Regeln prüfen jede Anfrage einzeln. Jede Regelquelle steht auf Aus, Erkennen oder Sperren.
              </p>
              <Skeleton v-if="repos.isPending.value" class="h-24 w-full" />
              <ul v-else class="divide-y rounded-xl border" data-testid="protection-sources">
                <li v-for="r in repos.data.value?.items ?? []" :key="r.id" class="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                  <RouterLink :to="rulesPath(r.id)" class="underline-offset-4 hover:underline">
                    {{ REPOSITORIES[r.id]?.name ?? r.name }}
                  </RouterLink>
                  <span class="flex items-center gap-2 text-xs text-muted-foreground">
                    <template v-if="r.crs">Version {{ r.crs.version }}</template>
                    <StatusPill :tone="REPOSITORY_EFFECT[r.effect].tone" size="sm">
                      {{ REPOSITORY_EFFECT[r.effect].label }}
                    </StatusPill>
                  </span>
                </li>
              </ul>
            </div>
            <p class="text-muted-foreground" data-testid="protection-scenarios">
              Die Szenarien sperren eine Adresse für eine Weile, jedes mit eigenem Schalter.
              <template v-if="scenariosBlocking">
                {{ scenariosBlocking }}
              </template>
              <RouterLink :to="BEHAVIOUR_RULES_PATH" class="font-medium text-foreground underline-offset-4 hover:underline">
                Szenarien einstellen
              </RouterLink>
            </p>
            <p class="text-muted-foreground">
              Willst du erst nur zusehen, stell die Regelquellen auf „Erkennen“ und die Szenarien auf „Beobachten“.
              <RouterLink :to="RULES_PATH" class="font-medium text-foreground underline-offset-4 hover:underline">
                Regeln einstellen
              </RouterLink>
            </p>
          </CardContent>
        </Card>

        <!-- Top patterns -->
        <Card class="min-w-0">
          <CardHeader>
            <CardTitle>Häufigste Muster</CardTitle>
            <CardDescription>Welche Regeln in den letzten 24 Stunden am häufigsten angeschlagen haben.</CardDescription>
          </CardHeader>
          <CardContent>
            <div v-if="rules.isPending.value" class="space-y-3">
              <Skeleton v-for="i in 4" :key="i" class="h-6 w-full" />
            </div>
            <BarList v-else-if="topPatterns.length" :items="topPatterns" label="Häufigste Muster, Treffer in 24 Stunden" />
            <p v-else class="text-sm text-muted-foreground">
              Noch keine Treffer. Sobald eine Regel anschlägt, siehst du hier, welche Muster am häufigsten anschlagen.
            </p>
            <Button as-child variant="link" size="sm" class="mt-3 h-auto p-0">
              <RouterLink :to="RULES_PATH">
                Alle Regeln ansehen
              </RouterLink>
            </Button>
          </CardContent>
        </Card>

        <!-- v0.3: server check (only when host_check is configured) -->
        <ServersCard v-if="o?.servers" :servers="o.servers" class="lg:col-span-2" />
      </div>

      <!-- D103: the switch of the agent API -->
      <AgentApiCard />

      <ErrorState v-if="q.isError.value" title="Die Einstellungen lassen sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
      <div v-else-if="!s" class="space-y-4">
        <Skeleton v-for="i in 2" :key="i" class="h-48 w-full" />
      </div>

      <template v-else>
        <!-- Retention -->
        <Card id="retention" class="scroll-mt-20">
          <CardHeader>
            <CardTitle>Aufbewahrung</CardTitle>
            <CardDescription>Wie lange Schild Daten auf deinem Server behält. Kürzer ist datensparsamer, länger hilft beim Nachvollziehen.</CardDescription>
            <LastChange :query="{ action: 'settings.set' }" setting />
          </CardHeader>
          <CardContent>
            <form class="grid items-start gap-4 sm:grid-cols-3" novalidate @submit.prevent="saveRetention">
              <div class="grid gap-1.5">
                <Label for="ret-ip">Volle IP-Adressen (Tage)</Label>
                <Input id="ret-ip" v-model.number="ret.raw_ip_days" type="number" min="1" max="30" :aria-invalid="!!retErrors.raw_ip_days" />
                <p :class="retErrors.raw_ip_days ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'">
                  {{ retErrors.raw_ip_days ?? 'Danach gekürzt. 1 bis 30.' }}
                </p>
              </div>
              <div class="grid gap-1.5">
                <Label for="ret-ev">Ereignisse (Tage)</Label>
                <Input id="ret-ev" v-model.number="ret.events_days" type="number" min="1" max="90" :aria-invalid="!!retErrors.events_days" />
                <p :class="retErrors.events_days ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'">
                  {{ retErrors.events_days ?? `Höchstens ${formatNumber(s.retention.max_size_mb)} MB. 1 bis 90.` }}
                </p>
              </div>
              <div class="grid gap-1.5">
                <Label for="ret-sum">Zusammenfassungen (Tage)</Label>
                <Input id="ret-sum" v-model.number="ret.summaries_days" type="number" min="1" max="730" :aria-invalid="!!retErrors.summaries_days" />
                <p :class="retErrors.summaries_days ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'">
                  {{ retErrors.summaries_days ?? 'Ohne IP-Adressen. 1 bis 730.' }}
                </p>
              </div>
              <div v-if="storage" class="grid gap-1 rounded-lg border bg-muted/40 p-3 text-sm sm:col-span-3" data-testid="storage-figures">
                <p>
                  <span class="font-medium">Ereignisspeicher:</span>
                  {{ formatBytes(storage.used) }} von {{ formatBytes(storage.cap) }} belegt<template v-if="storage.share !== null">
                    ({{ formatPercent(storage.share) }})
                  </template>
                </p>
                <p v-if="storage.over" class="text-muted-foreground" data-testid="storage-over">
                  Gerade über der Grenze. Die neuesten Einträge jeder Art löscht Schild nicht.
                </p>
                <p class="text-muted-foreground">
                  Messwerte (metrics.db): {{ formatBytes(storage.metrics) }}. Diese Datei hat eine feste Größe, sobald sie einmal gefüllt ist. Wird der Ereignisspeicher voll, löscht Schild zuerst unauffällige Anfragen und erst zuletzt Sperren und Vorfälle.
                </p>
              </div>
              <div v-if="retDirty" class="flex justify-end gap-2 sm:col-span-3">
                <Button type="button" variant="ghost" @click="Object.assign(ret, { raw_ip_days: s.retention.raw_ip_days, events_days: s.retention.events_days, summaries_days: s.retention.summaries_days })">
                  Verwerfen
                </Button>
                <Button type="submit" :disabled="update.isPending.value">
                  Speichern
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        <!-- Password -->
        <Card id="password" class="scroll-mt-20">
          <CardHeader>
            <CardTitle>Passwort ändern</CardTitle>
            <CardDescription>Andere angemeldete Sitzungen werden danach abgemeldet.</CardDescription>
          </CardHeader>
          <CardContent>
            <form class="grid items-start gap-4 sm:grid-cols-3" novalidate @submit.prevent="changePassword">
              <div class="grid gap-1.5">
                <Label for="pw-current">Aktuelles Passwort</Label>
                <Input id="pw-current" v-model="pw.current" type="password" autocomplete="current-password" :aria-invalid="!!pwErrors.current" />
                <p v-if="pwErrors.current" class="text-xs text-destructive" role="alert">
                  {{ pwErrors.current }}
                </p>
              </div>
              <div class="grid gap-1.5">
                <Label for="pw-new">Neues Passwort</Label>
                <Input id="pw-new" v-model="pw.next" type="password" autocomplete="new-password" :aria-invalid="!!pwErrors.next" />
                <p :class="pwErrors.next ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'">
                  {{ pwErrors.next ?? 'Mindestens 12 Zeichen.' }}
                </p>
              </div>
              <div class="grid gap-1.5">
                <Label for="pw-repeat">Wiederholen</Label>
                <Input id="pw-repeat" v-model="pw.repeat" type="password" autocomplete="new-password" :aria-invalid="!!pwErrors.repeat" />
                <p v-if="pwErrors.repeat" class="text-xs text-destructive" role="alert">
                  {{ pwErrors.repeat }}
                </p>
              </div>
              <div class="flex justify-end sm:col-span-3">
                <Button type="submit" variant="outline" :disabled="pwSaving || !pw.current || !pw.next">
                  Passwort ändern
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </template>

      <p v-if="o" class="text-xs text-muted-foreground">
        <template v-if="o.counters_24h.requests">
          {{ formatPercent((o.counters_24h.blocked + o.counters_24h.would_block) / o.counters_24h.requests) }} der Anfragen in 24 Stunden auffällig ·
        </template>
        Stand <RelativeTime :value="o.generated_at" />, aktualisiert sich alle 30 Sekunden<template v-if="o.version"> · Version <span data-testid="version">{{ versionText(o.version) }}</span></template><template v-if="geo"> · <span data-testid="geo-db">{{ geo.line }}</span></template>
      </p>
      <p v-if="geo?.error" class="-mt-5 text-xs text-muted-foreground" data-testid="geo-db-error">
        {{ geo.error }}
      </p>
    </div>
  </div>
</template>
