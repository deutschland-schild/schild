<script setup lang="ts">
import type { LabSettings, LabSettingsPatch } from '@/api/types'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, formatDateTime, Input, PageHeader, StatusPill, toast } from '@schild/ui'
import { computed, reactive, ref, watch } from 'vue'
import { useSettings, useUpdateSettings } from '@/api/queries'
import FormField from '@/components/FormField.vue'
import PasswordConfirmDialog from '@/components/PasswordConfirmDialog.vue'
import QueryState from '@/components/QueryState.vue'
import { useLogout, useSession } from '@/composables/useSession'
import { fieldErrors } from '@/lib/problem'

const settings = useSettings()
const update = useUpdateSettings()
const { session, canEdit } = useSession()
const logout = useLogout()

/** Editable fields as strings (inputs), share in percent. */
const form = reactive({ min_issuers: '', max_share_pct: '', window_minutes: '', min_score: '', rate: '', retry_ms: '', signals_days: '' })
function load(s: LabSettings) {
  form.min_issuers = String(s.scoring.min_issuers)
  form.max_share_pct = String(Math.round(s.scoring.max_issuer_share * 100))
  form.window_minutes = String(s.scoring.window_minutes)
  form.min_score = String(s.scoring.min_score)
  form.rate = String(s.ingest.rate_per_client_per_min)
  form.retry_ms = String(s.ingest.retry_after_ms)
  form.signals_days = String(s.retention.signals_days)
}
watch(() => settings.data.value, s => s && load(s), { immediate: true })

const int = (v: string | number) => (/^\d+$/.test(String(v).trim()) ? Number(v) : Number.NaN)
const local = computed(() => {
  const e: Record<string, string> = {}
  if (!(int(form.min_issuers) >= 3)) e['scoring.min_issuers'] = 'Mindestens 3 Bürgen.'
  const pct = int(form.max_share_pct)
  if (!(pct >= 1 && pct <= 34)) e['scoring.max_issuer_share'] = 'Zwischen 1 und 34 %.'
  if (!(int(form.window_minutes) >= 5)) e['scoring.window_minutes'] = 'Mindestens 5 Minuten.'
  const sc = int(form.min_score)
  if (!(sc >= 0 && sc <= 100)) e['scoring.min_score'] = 'Zwischen 0 und 100.'
  if (!(int(form.rate) >= 1)) e['ingest.rate_per_client_per_min'] = 'Mindestens 1.'
  if (!(int(form.retry_ms) >= 1)) e['ingest.retry_after_ms'] = 'Mindestens 1 ms.'
  const d = int(form.signals_days)
  if (!(d >= 1 && d <= 30)) e['retention.signals_days'] = 'Zwischen 1 und 30 Tagen.'
  return e
})
const errs = computed(() => ({ ...fieldErrors(update.error.value), ...local.value }))

const patch = computed<LabSettingsPatch>(() => {
  const s = settings.data.value
  if (!s) return {}
  const p: LabSettingsPatch = {}
  const scoring: NonNullable<LabSettingsPatch['scoring']> = {}
  if (int(form.min_issuers) !== s.scoring.min_issuers) scoring.min_issuers = int(form.min_issuers)
  if (int(form.max_share_pct) !== Math.round(s.scoring.max_issuer_share * 100)) scoring.max_issuer_share = int(form.max_share_pct) / 100
  if (int(form.window_minutes) !== s.scoring.window_minutes) scoring.window_minutes = int(form.window_minutes)
  if (int(form.min_score) !== s.scoring.min_score) scoring.min_score = int(form.min_score)
  if (Object.keys(scoring).length) p.scoring = scoring
  const ingest: NonNullable<LabSettingsPatch['ingest']> = {}
  if (int(form.rate) !== s.ingest.rate_per_client_per_min) ingest.rate_per_client_per_min = int(form.rate)
  if (int(form.retry_ms) !== s.ingest.retry_after_ms) ingest.retry_after_ms = int(form.retry_ms)
  if (Object.keys(ingest).length) p.ingest = ingest
  if (int(form.signals_days) !== s.retention.signals_days) p.retention = { signals_days: int(form.signals_days) }
  return p
})
const dirty = computed(() => Object.keys(patch.value).length > 0)
const changes = computed(() => {
  const out: string[] = []
  const p = patch.value
  if (p.scoring?.min_issuers !== undefined) out.push(`Mindestens Bürgen: ${p.scoring.min_issuers}`)
  if (p.scoring?.max_issuer_share !== undefined) out.push(`Größter Anteil eines Bürgen: ${Math.round(p.scoring.max_issuer_share * 100)} %`)
  if (p.scoring?.window_minutes !== undefined) out.push(`Zeitfenster: ${p.scoring.window_minutes} min`)
  if (p.scoring?.min_score !== undefined) out.push(`Mindest-Score: ${p.scoring.min_score}`)
  if (p.ingest?.rate_per_client_per_min !== undefined) out.push(`Hinweise pro Client und Minute: ${p.ingest.rate_per_client_per_min}`)
  if (p.ingest?.retry_after_ms !== undefined) out.push(`Wartezeit bei voller Schlange: ${p.ingest.retry_after_ms} ms`)
  if (p.retention?.signals_days !== undefined) out.push(`Signale aufbewahren: ${p.retention.signals_days} Tage`)
  return out
})

const confirmOpen = ref(false)
function startSave() {
  if (!dirty.value || Object.keys(local.value).length) return
  update.reset()
  confirmOpen.value = true
}
function onConfirm(v: { password: string }) {
  update.mutate({ ...patch.value, confirm: { password: v.password } }, {
    onSuccess: (s) => {
      confirmOpen.value = false
      load(s)
      toast.success('Einstellungen gespeichert', { description: 'In lab.yaml geschrieben und geprüft.' })
    },
    onError: () => {
      // Field errors stay visible in the form; only password problems keep the dialog open.
      if (!Object.keys(fieldErrors(update.error.value)).some(k => k.startsWith('confirm'))) confirmOpen.value = false
    },
  })
}
function reset() {
  if (settings.data.value) load(settings.data.value)
  update.reset()
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader title="Einstellungen" description="Schwellen, Eingang und Aufbewahrung dieses Labs. Änderungen landen in lab.yaml und werden dort geprüft." />
    <QueryState :pending="settings.isPending.value" :error="settings.error.value" @retry="settings.refetch()">
      <template v-if="settings.data.value">
        <Card>
          <CardHeader>
            <CardTitle>Identität</CardTitle>
            <CardDescription>Aus lab.yaml, hier nicht änderbar.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl class="grid gap-4 text-sm sm:grid-cols-4">
              <div>
                <dt class="text-muted-foreground">
                  Betreiber
                </dt><dd class="font-mono">
                  {{ settings.data.value.identity.operator }}
                </dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Lab
                </dt><dd class="font-mono">
                  {{ settings.data.value.identity.lab }}
                </dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Kanal
                </dt><dd class="font-mono">
                  {{ settings.data.value.channel ?? '–' }}
                </dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Profil
                </dt>
                <dd>
                  <StatusPill :tone="settings.data.value.profile === 'test' ? 'info' : 'neutral'" size="sm">
                    {{ settings.data.value.profile === 'test' ? 'Test' : 'Produktion' }}
                  </StatusPill>
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <form class="space-y-6" @submit.prevent="startSave">
          <fieldset :disabled="!canEdit" class="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Schwellen</CardTitle>
                <CardDescription>Wann aus Hinweisen ein Muster für die Prüfung wird. Mindestwerte sind fest: 3 Bürgen, höchstens 34 % von einem Bürgen.</CardDescription>
              </CardHeader>
              <CardContent class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <FormField v-slot="{ id, aria }" label="Mindestens Bürgen" hint="Ab 3." :error="errs['scoring.min_issuers']">
                  <Input :id="id" v-model="form.min_issuers" v-bind="aria" type="number" min="3" step="1" />
                </FormField>
                <FormField v-slot="{ id, aria }" label="Größter Anteil eines Bürgen (%)" hint="Höchstens 34 %." :error="errs['scoring.max_issuer_share']">
                  <Input :id="id" v-model="form.max_share_pct" v-bind="aria" type="number" min="1" max="34" step="1" />
                </FormField>
                <FormField v-slot="{ id, aria }" label="Zeitfenster (Minuten)" hint="Ab 5." :error="errs['scoring.window_minutes']">
                  <Input :id="id" v-model="form.window_minutes" v-bind="aria" type="number" min="5" step="1" />
                </FormField>
                <FormField v-slot="{ id, aria }" label="Mindest-Score" hint="0 bis 100." :error="errs['scoring.min_score']">
                  <Input :id="id" v-model="form.min_score" v-bind="aria" type="number" min="0" max="100" step="1" />
                </FormField>
              </CardContent>
            </Card>

            <div class="grid gap-6 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Eingang</CardTitle>
                  <CardDescription>Grenzen pro Client. Die Schlangengröße steht in lab.yaml.</CardDescription>
                </CardHeader>
                <CardContent class="grid gap-4 sm:grid-cols-2">
                  <FormField v-slot="{ id, aria }" label="Hinweise pro Client und Minute" :error="errs['ingest.rate_per_client_per_min']">
                    <Input :id="id" v-model="form.rate" v-bind="aria" type="number" min="1" step="1" />
                  </FormField>
                  <FormField v-slot="{ id, aria }" label="Wartezeit bei voller Schlange (ms)" :error="errs['ingest.retry_after_ms']">
                    <Input :id="id" v-model="form.retry_ms" v-bind="aria" type="number" min="1" step="1" />
                  </FormField>
                  <p class="text-sm text-muted-foreground sm:col-span-2">
                    Schlange höchstens {{ settings.data.value.ingest.queue_max_depth.toLocaleString('de-DE') }} Einträge.
                  </p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Aufbewahrung</CardTitle>
                  <CardDescription>Einzelne Signale höchstens 30 Tage, danach nur Summen.</CardDescription>
                </CardHeader>
                <CardContent class="grid gap-4 sm:grid-cols-2">
                  <FormField v-slot="{ id, aria }" label="Signale (Tage)" hint="1 bis 30." :error="errs['retention.signals_days']">
                    <Input :id="id" v-model="form.signals_days" v-bind="aria" type="number" min="1" max="30" step="1" />
                  </FormField>
                  <div class="grid gap-1.5 text-sm">
                    <p class="font-medium">
                      Summen (Tage)
                    </p>
                    <p class="flex h-9 items-center text-muted-foreground">
                      {{ settings.data.value.retention.aggregates_days }}, aus lab.yaml
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </fieldset>

          <div v-if="canEdit" class="sticky bottom-0 z-10 -mx-4 flex flex-wrap items-center justify-end gap-2 border-t bg-background/95 px-4 py-3 backdrop-blur sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8">
            <p class="mr-auto text-sm text-muted-foreground" aria-live="polite">
              {{ dirty ? `${changes.length} ${changes.length === 1 ? 'Änderung' : 'Änderungen'} nicht gespeichert` : 'Alles gespeichert' }}
            </p>
            <Button type="button" variant="outline" :disabled="!dirty" @click="reset">
              Verwerfen
            </Button>
            <Button type="submit" :disabled="!dirty || Object.keys(local).length > 0">
              Speichern …
            </Button>
          </div>
        </form>

        <Card>
          <CardHeader>
            <CardTitle>Veröffentlichen</CardTitle>
            <CardDescription>Fest in lab.yaml.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl class="grid gap-4 text-sm sm:grid-cols-4">
              <div>
                <dt class="text-muted-foreground">
                  Bündel gültig
                </dt><dd>{{ settings.data.value.publish.bundle_validity_hours }} h</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Checkpoint alle
                </dt><dd>{{ settings.data.value.publish.checkpoint_interval_s }} s</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Checkpoint gültig
                </dt><dd>{{ settings.data.value.publish.checkpoint_ttl_s }} s</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Menschliche Freigabe
                </dt>
                <dd>
                  <StatusPill tone="neutral" size="sm">
                    Immer nötig
                  </StatusPill>
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Dein Konto</CardTitle>
          </CardHeader>
          <CardContent class="flex flex-wrap items-center gap-4 text-sm">
            <dl class="grid flex-1 gap-4 sm:grid-cols-3">
              <div>
                <dt class="text-muted-foreground">
                  Benutzer
                </dt><dd>{{ session?.user ?? 'admin' }}</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Rolle
                </dt><dd>{{ session?.role === 'readonly' ? 'Nur lesen' : 'Admin' }}</dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Sitzung bis
                </dt><dd>{{ session?.expires_at ? formatDateTime(session.expires_at) : '–' }}</dd>
              </div>
            </dl>
            <Button variant="outline" @click="logout.mutate()">
              Abmelden
            </Button>
          </CardContent>
        </Card>
      </template>
    </QueryState>

    <PasswordConfirmDialog
      v-model:open="confirmOpen"
      title="Einstellungen speichern?"
      description="Das Lab schreibt die Werte in lab.yaml und prüft sie mit demselben Validator wie beim Start."
      :consequences="changes"
      confirm-label="Speichern"
      :pending="update.isPending.value"
      :error="update.error.value"
      @confirm="onConfirm"
    />
  </div>
</template>
