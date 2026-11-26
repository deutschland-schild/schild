<script setup lang="ts">
import { unwrap } from '@schild/app-kit'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  EmptyState,
  ErrorState,
  formatDateTime,
  formatNumber,
  Input,
  Label,
  PageHeader,
  RelativeTime,
  Skeleton,
  StatusPill,
  toast,
} from '@schild/ui'
import { Check, Download, Search, Trash2, UserSearch } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, csrf, errorMessage } from '@/api/client'
import { useGroupStatus } from '@/api/group'
import { keys, usePrivacySearch, useSettings } from '@/api/queries'
import { erasureNodesText } from '@/lib/group'
import { isIP } from '@/lib/ip'

const route = useRoute()
const router = useRouter()
const qc = useQueryClient()
const ip = computed(() => typeof route.query.ip === 'string' && isIP(route.query.ip) ? route.query.ip : null)
const input = ref(ip.value ?? '')
const touched = ref(false)
watch(ip, v => (input.value = v ?? ''))
const inputError = computed(() => touched.value && input.value && !isIP(input.value.trim()) ? 'Das ist keine gültige IP-Adresse, z. B. 203.0.113.42 oder 2001:db8::1.' : null)
function search() {
  touched.value = true
  const v = input.value.trim()
  if (!isIP(v)) return
  exported.value = false
  void router.replace({ query: { ip: v } })
}

const q = usePrivacySearch(ip)
const s = computed(() => q.data.value)
const settings = useSettings()
const r = computed(() => settings.data.value?.retention)
const groupQ = useGroupStatus()
// Nothing is said about where addresses go before the mode is known.
const inGroup = computed(() => groupQ.data.value ? groupQ.data.value.mode === 'group' : undefined)

// Export
const exporting = ref(false)
const exported = ref(false)
async function doExport() {
  if (!ip.value) return
  exporting.value = true
  try {
    const data = await unwrap(api.POST('/privacy/export', { params: { header: csrf() }, body: { ip: ip.value } }))
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `schild-export-${ip.value.replace(/[:.]/g, '-')}-${new Date().toISOString().slice(0, 10)}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
    exported.value = true
    toast.success('Export heruntergeladen', { description: `${formatNumber(data.events.length)} Ereignisse als JSON-Datei. Gib sie der Person, die gefragt hat.` })
  }
  catch (err) {
    toast.error('Export hat nicht geklappt', { description: errorMessage(err) })
  }
  finally {
    exporting.value = false
  }
}

// Delete
const deleteOpen = ref(false)
const typed = ref('')
const keepIncidents = ref(false)
const deleting = ref(false)
watch(deleteOpen, (v) => {
  if (!v) {
    typed.value = ''
    keepIncidents.value = false
  }
})
async function doDelete() {
  if (!ip.value || typed.value.trim() !== ip.value) return
  deleting.value = true
  try {
    const res = await unwrap(api.POST('/privacy/delete', { params: { header: csrf() }, body: { ip: ip.value, confirm: true, keep_incidents: keepIncidents.value } }))
    deleteOpen.value = false
    toast.success('Gelöscht', {
      description: `${formatNumber(res.deleted_events)} Ereignisse, ${formatNumber(res.deleted_sessions)} Sitzungen${res.deleted_allowlist_entries ? ` und ${formatNumber(res.deleted_allowlist_entries)} Freischaltungen` : ''} zu ${res.ip}${res.erased_requests ? `, in ${formatNumber(res.erased_requests)} Anfragen ist die Adresse gelöscht` : ''}. Das lässt sich nicht rückgängig machen.${res.nodes ? ` ${erasureNodesText(res.nodes)}` : ''}`,
    })
    void qc.invalidateQueries({ queryKey: keys.privacy(ip.value) })
    void qc.invalidateQueries({ queryKey: ['events'] })
    void qc.invalidateQueries({ queryKey: keys.allowlist })
  }
  catch (err) {
    toast.error('Löschen hat nicht geklappt', { description: errorMessage(err) })
  }
  finally {
    deleting.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="Datenschutz" description="Auskunft geben und löschen, wenn jemand fragt, was über seine IP-Adresse gespeichert ist." />

    <div class="grid items-start gap-6 lg:grid-cols-3">
      <div class="space-y-6 lg:col-span-2">
        <Card>
          <CardContent>
            <form class="grid gap-2" novalidate @submit.prevent="search">
              <Label for="privacy-ip">IP-Adresse</Label>
              <div class="flex flex-col gap-2 sm:flex-row">
                <Input
                  id="privacy-ip"
                  v-model="input"
                  placeholder="z. B. 203.0.113.42"
                  autocomplete="off"
                  spellcheck="false"
                  class="font-mono sm:max-w-72"
                  :aria-invalid="!!inputError"
                  aria-describedby="privacy-ip-hint"
                  data-testid="privacy-ip"
                  @blur="touched = !!input"
                />
                <Button type="submit" data-testid="privacy-search">
                  <Search aria-hidden="true" />
                  Suchen
                </Button>
              </div>
              <p id="privacy-ip-hint" :class="inputError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="inputError ? 'alert' : undefined">
                {{ inputError ?? 'Die Person nennt dir ihre IP-Adresse, z. B. von einer Seite wie „Wie ist meine IP?“.' }}
              </p>
            </form>
          </CardContent>
        </Card>

        <EmptyState v-if="!ip" :icon="UserSearch" title="Nach einer IP-Adresse suchen" description="Du siehst dann alles, was Schild zu ihr gespeichert hat, und kannst es exportieren oder löschen." />
        <Card v-else-if="q.isPending.value">
          <CardContent class="space-y-3">
            <Skeleton class="h-6 w-56" />
            <Skeleton class="h-24 w-full" />
          </CardContent>
        </Card>
        <ErrorState v-else-if="q.isError.value" title="Die Suche hat nicht geklappt" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
        <Card v-else-if="s" data-testid="privacy-result">
          <CardHeader>
            <CardTitle>Gespeichert zu <span class="font-mono">{{ s.ip }}</span></CardTitle>
            <CardDescription v-if="s.events === 0">
              Zu dieser IP ist nichts gespeichert. Entweder war sie nie hier, oder die Daten sind schon gelöscht oder gekürzt.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-5 text-sm">
            <dl class="grid gap-x-4 gap-y-3 sm:grid-cols-[14rem_1fr]">
              <dt class="text-muted-foreground">
                Ereignisse
              </dt>
              <dd class="font-medium" data-testid="privacy-events">
                {{ formatNumber(s.events) }}
                <RouterLink v-if="s.events" :to="`/events?ip=${encodeURIComponent(s.ip)}&time=all`" class="ml-2 font-normal underline underline-offset-4">
                  ansehen
                </RouterLink>
              </dd>
              <dt class="text-muted-foreground">
                Sitzungen
              </dt>
              <dd>{{ formatNumber(s.sessions ?? 0) }}</dd>
              <dt class="text-muted-foreground">
                Vorfälle
              </dt>
              <dd>
                <span v-if="s.incidents?.length" class="flex flex-wrap gap-2">
                  <RouterLink v-for="n in s.incidents" :key="n" :to="`/incidents/${n}`" class="inline-flex min-h-6 items-center rounded border px-2 font-mono text-xs hover:bg-muted">{{ n }}</RouterLink>
                </span>
                <template v-else>
                  keine
                </template>
              </dd>
              <dt class="text-muted-foreground">
                Zuerst / zuletzt gesehen
              </dt>
              <dd>
                <template v-if="s.first_seen">
                  {{ formatDateTime(s.first_seen) }} / {{ s.last_seen ? formatDateTime(s.last_seen) : '–' }}
                </template>
                <template v-else>
                  –
                </template>
              </dd>
              <dt class="text-muted-foreground">
                Volle IP wird gekürzt
              </dt>
              <dd>
                <template v-if="s.ip_truncated_after">
                  <RelativeTime :value="s.ip_truncated_after" />, danach bleibt nur ein gekürzter Teil.
                </template>
                <template v-else>
                  –
                </template>
              </dd>
              <dt class="text-muted-foreground">
                Freigeschaltet
              </dt>
              <dd>{{ s.allowlisted ? 'ja, steht auf der Liste eigener IPs' : 'nein' }}</dd>
              <dt class="text-muted-foreground">
                Weitergegeben
              </dt>
              <dd>
                <template v-if="inGroup !== undefined">
                  <StatusPill tone="signal" size="sm">
                    {{ inGroup ? 'Nur im Cluster' : 'Nie' }}
                  </StatusPill>
                  <span class="ml-2 text-muted-foreground">{{ inGroup ? 'IP-Adressen gehen nur an die anderen Server deines Clusters, nicht an Dritte.' : 'IP-Adressen verlassen den Server nicht.' }}</span>
                </template>
                <template v-else>
                  –
                </template>
              </dd>
            </dl>

            <div v-if="s.events > 0 || s.allowlisted" class="flex flex-col gap-2 border-t pt-4 sm:flex-row">
              <Button variant="outline" :disabled="exporting" data-testid="privacy-export" @click="doExport">
                <Check v-if="exported" class="text-status-success" aria-hidden="true" />
                <Download v-else aria-hidden="true" />
                {{ exporting ? 'Wird exportiert …' : exported ? 'Exportiert, noch einmal' : 'Alles exportieren (JSON)' }}
              </Button>
              <Button variant="destructive" data-testid="privacy-delete" @click="deleteOpen = true">
                <Trash2 aria-hidden="true" />
                Alles löschen
              </Button>
            </div>
            <p v-if="s.events > 0 && !exported" class="text-xs text-muted-foreground">
              Tipp: Erst exportieren, dann löschen. Gelöschtes lässt sich nicht wiederherstellen.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>So lange speichert Schild</CardTitle>
          <CardDescription>{{ inGroup === undefined ? '' : inGroup ? 'Alles bleibt auf den Servern deines Clusters.' : 'Alles bleibt auf deinem Server.' }} Einstellen kannst du das unter Einstellungen.</CardDescription>
        </CardHeader>
        <CardContent>
          <div v-if="!r" class="space-y-2">
            <Skeleton v-for="i in 4" :key="i" class="h-8 w-full" />
          </div>
          <dl v-else class="space-y-3 text-sm" data-testid="retention">
            <div>
              <dt class="font-medium">
                Volle IP-Adressen: {{ r.raw_ip_days }} {{ r.raw_ip_days === 1 ? 'Tag' : 'Tage' }}
              </dt>
              <dd class="text-muted-foreground">
                Danach kürzt Schild sie, damit sie keiner Person mehr zuzuordnen sind.
              </dd>
            </div>
            <div>
              <dt class="font-medium">
                Ereignisse: {{ r.events_days }} Tage
              </dt>
              <dd class="text-muted-foreground">
                Danach werden sie gelöscht, höchstens {{ formatNumber(r.max_size_mb) }} MB. Ist der Platz voll, gehen die ältesten zuerst.
              </dd>
            </div>
            <div>
              <dt class="font-medium">
                Zusammenfassungen: {{ r.summaries_days }} Tage
              </dt>
              <dd class="text-muted-foreground">
                Zahlen pro Tag, ohne IP-Adressen. Für Statistiken wie im Überblick.
              </dd>
            </div>
          </dl>
          <Button as-child variant="link" size="sm" class="mt-3 h-auto p-0">
            <RouterLink to="/settings#retention">
              Aufbewahrung ändern
            </RouterLink>
          </Button>
        </CardContent>
      </Card>
    </div>

    <AlertDialog v-model:open="deleteOpen">
      <AlertDialogContent>
        <form class="grid gap-4" @submit.prevent="doDelete">
          <AlertDialogHeader>
            <AlertDialogTitle>Alles zu {{ ip }} löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Schild löscht alle Ereignisse und Sitzungen zu dieser IP und entfernt sie von der Liste eigener IPs. Das lässt sich nicht rückgängig machen.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Label class="flex items-start gap-2 leading-snug font-normal">
            <Checkbox v-model="keepIncidents" class="mt-0.5" />
            <span>
              Vorfälle behalten
              <span class="block text-sm text-muted-foreground">Nur, wenn du sie noch brauchst, z. B. für eine laufende Klärung.</span>
            </span>
          </Label>
          <div class="grid gap-2">
            <Label for="privacy-confirm" class="leading-normal font-normal">
              Tippe <strong class="font-mono font-semibold select-all">{{ ip }}</strong> ein, um zu bestätigen.
            </Label>
            <Input id="privacy-confirm" v-model="typed" autocomplete="off" spellcheck="false" class="font-mono" data-testid="privacy-confirm" />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel type="button">
              Abbrechen
            </AlertDialogCancel>
            <Button type="submit" variant="destructive" :disabled="deleting || typed.trim() !== ip" data-testid="privacy-confirm-delete">
              {{ deleting ? 'Wird gelöscht …' : 'Endgültig löschen' }}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  </div>
</template>
