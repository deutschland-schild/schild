<script setup lang="ts">
import type { SegmentOption } from '@schild/ui'
import type { HttpMethod, LimitMode, RateLimit, RateLimitDraft, RateLimitDryRun, RateLimitInput } from '@/api/behaviour'
import {
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  NativeSelect,
  NativeSelectOption,
  SegmentedControl,
  toast,
} from '@schild/ui'
import { FlaskConical } from '@lucide/vue'
import { computed, ref, useId, watch } from 'vue'
import { errorMessage, fieldErrors, problemOf } from '@/api/client'
import { useDryRunRateLimit, useSaveRateLimit } from '@/api/behaviour'
import { dryRunText, isSiteWide, LIMIT_MODES, limitText, validPer } from '@/lib/behaviour'

/** Add or change an own rate limit, with a Probelauf over the last 24 h. */
const props = withDefaults(defineProps<{ limit?: RateLimit | null }>(), { limit: null })
const open = defineModel<boolean>('open', { default: false })

const METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const UNITS = [
  { value: 's', label: 'Sekunden', max: 59 },
  { value: 'm', label: 'Minuten', max: 59 },
  { value: 'h', label: 'Stunden', max: 24 },
] as const
type Unit = typeof UNITS[number]['value']

const uid = useId()
const label = ref('')
const route = ref('')
const methods = ref<HttpMethod[]>([])
const count = ref<number>(10)
const perN = ref<number>(1)
const perUnit = ref<Unit>('m')
const burst = ref<number | ''>('')
const mode = ref<LimitMode>('observe')
const site = ref('')
const siteWide = ref(false)
const touched = ref(false)
const server = ref<Record<string, string>>({})
const dry = ref<RateLimitDryRun | null>(null)

watch(open, (v) => {
  if (!v) return
  const l = props.limit
  const m = l ? /^(\d+)([smh])$/.exec(l.per) : null
  label.value = l?.label ?? ''
  route.value = l?.route ?? ''
  methods.value = (l?.methods ?? []).filter((x): x is HttpMethod => (METHODS as string[]).includes(x))
  count.value = l?.limit ?? 10
  perN.value = m ? Number(m[1]) : 1
  perUnit.value = (m?.[2] as Unit | undefined) ?? 'm'
  burst.value = l && l.burst !== l.limit ? l.burst : ''
  mode.value = l?.mode ?? 'observe'
  site.value = l?.site ?? ''
  siteWide.value = !!l?.confirm_site_wide
  touched.value = false
  server.value = {}
  dry.value = null
}, { immediate: true })

const per = computed(() => `${perN.value}${perUnit.value}`)
const wholeSite = computed(() => isSiteWide(route.value))
const modeOptions: SegmentOption<LimitMode>[] = (['off', 'observe', 'block'] as const).map(m => ({ value: m, label: LIMIT_MODES[m].label, tone: m === 'block' ? 'ink' : m === 'off' ? 'neutral' : 'signal', testid: `limit-mode-${m}` }))

const errors = computed(() => {
  const e: Record<string, string | null> = {}
  const r = route.value.trim()
  e.route = server.value.route ? 'Das hat der Server nicht akzeptiert. Eine Route beginnt mit „/“.' : (touched.value && (!r || !r.startsWith('/')) ? 'Gib eine Route an, die mit „/“ beginnt, z. B. /wp-login.php.' : null)
  e.limit = server.value.limit || (touched.value && (!Number.isInteger(count.value) || count.value < 1 || count.value > 100000)) ? 'Eine ganze Zahl zwischen 1 und 100.000.' : null
  e.per = server.value.per || (touched.value && !validPer(per.value)) ? 'Höchstens 59 Sekunden oder Minuten oder 24 Stunden.' : null
  e.burst = server.value.burst || (touched.value && burst.value !== '' && (!Number.isInteger(burst.value) || burst.value < 1 || burst.value > 100000)) ? 'Leer lassen oder eine ganze Zahl zwischen 1 und 100.000.' : null
  e.label = server.value.label || (touched.value && label.value.length > 64) ? 'Höchstens 64 Zeichen.' : null
  e.siteWide = server.value.confirm_site_wide || (touched.value && wholeSite.value && !siteWide.value) ? 'Bitte bestätige, dass das Limit für die ganze Website gelten soll.' : null
  return e
})
const draftErrors = computed(() => !!(errors.value.route || errors.value.limit || errors.value.per || errors.value.burst))

function draft(): RateLimitDraft {
  return {
    route: route.value.trim(),
    ...(methods.value.length ? { methods: [...methods.value] } : {}),
    limit: count.value,
    per: per.value,
    ...(burst.value !== '' ? { burst: burst.value } : {}),
    ...(site.value.trim() ? { site: site.value.trim() } : {}),
  }
}

const dryRun = useDryRunRateLimit()
async function runDry() {
  touched.value = true
  server.value = {}
  if (draftErrors.value) return
  try {
    dry.value = await dryRun.mutateAsync(draft())
  }
  catch (err) {
    server.value = fieldErrors(err)
    if (!Object.keys(server.value).length) toast.error('Der Probelauf hat nicht geklappt', { description: errorMessage(err) })
  }
}
// The result belongs to the draft it was run for.
watch([route, methods, count, perN, perUnit, burst, site], () => {
  dry.value = null
}, { deep: true })

const save = useSaveRateLimit()
async function submit() {
  touched.value = true
  server.value = {}
  if (Object.values(errors.value).some(Boolean)) return
  const body: RateLimitInput = {
    ...draft(),
    mode: mode.value,
    ...(label.value.trim() ? { label: label.value.trim() } : {}),
    ...(wholeSite.value ? { confirm_site_wide: true } : {}),
  }
  try {
    const saved = await save.mutateAsync({ id: props.limit?.id, body })
    open.value = false
    toast.success(props.limit ? 'Limit geändert' : 'Limit hinzugefügt', { description: `${saved.label ?? saved.route}: ${limitText(saved)}, ${LIMIT_MODES[saved.mode].label}.` })
  }
  catch (err) {
    server.value = fieldErrors(err)
    if (!Object.keys(server.value).length) {
      toast.error('Speichern hat nicht geklappt', { description: problemOf(err)?.code === 'config_limit' ? 'Dieses Limit steht in schild.yaml oder ist voreingestellt. Ändere es dort.' : errorMessage(err) })
    }
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <form class="grid gap-5" novalidate data-testid="limit-form" @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>{{ limit ? 'Limit ändern' : 'Limit hinzufügen' }}</DialogTitle>
          <DialogDescription>
            Wie viele Anfragen eine Adresse an diese Route schicken darf. Darüber antwortet Schild kurz mit „zu viele Anfragen“. Eigene Adressen sind ausgenommen.
          </DialogDescription>
        </DialogHeader>

        <div class="grid gap-2">
          <Label :for="`${uid}-label`">Bezeichnung <span class="font-normal text-muted-foreground">(optional)</span></Label>
          <Input :id="`${uid}-label`" v-model="label" maxlength="64" placeholder="z. B. Kontaktformular" data-testid="limit-label" />
          <p v-if="errors.label" class="text-sm text-destructive" role="alert">
            {{ errors.label }}
          </p>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-route`">Route</Label>
          <Input
            :id="`${uid}-route`"
            v-model="route"
            placeholder="/wp-login.php"
            autocomplete="off"
            spellcheck="false"
            class="font-mono"
            :aria-invalid="!!errors.route"
            :aria-describedby="`${uid}-route-hint`"
            data-testid="limit-route"
          />
          <p :id="`${uid}-route-hint`" :class="errors.route ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="errors.route ? 'alert' : undefined">
            {{ errors.route ?? '„*“ steht für einen Abschnitt, „**“ für beliebig viele. Beispiel: /wp-json/**' }}
          </p>
          <div v-if="wholeSite" class="grid gap-1 rounded-md border border-status-warning/40 bg-status-warning-subtle p-3" data-testid="limit-site-wide-box">
            <Label class="flex items-start gap-2 leading-snug font-normal">
              <Checkbox v-model="siteWide" class="mt-0.5" data-testid="limit-site-wide" />
              Dieses Limit gilt für die ganze Website auf einmal. Ich habe es mit dem Probelauf geprüft.
            </Label>
            <p v-if="errors.siteWide" class="text-sm text-destructive" role="alert">
              {{ errors.siteWide }}
            </p>
          </div>
        </div>

        <fieldset class="grid gap-2">
          <legend class="mb-1 text-sm font-medium">
            Methoden <span class="font-normal text-muted-foreground">(keine Auswahl: alle)</span>
          </legend>
          <div class="flex flex-wrap gap-x-4 gap-y-2">
            <Label v-for="m in METHODS" :key="m" class="flex items-center gap-2 font-mono text-[13px] font-normal">
              <Checkbox
                :model-value="methods.includes(m)"
                :data-testid="`limit-method-${m}`"
                @update:model-value="(v: boolean | 'indeterminate') => methods = v === true ? [...methods, m] : methods.filter(x => x !== m)"
              />
              {{ m }}
            </Label>
          </div>
        </fieldset>

        <div class="grid gap-2">
          <span class="text-sm font-medium">Limit</span>
          <div class="flex flex-wrap items-center gap-2">
            <Input v-model.number="count" type="number" min="1" max="100000" class="w-24" aria-label="Anfragen" :aria-invalid="!!errors.limit" data-testid="limit-count" />
            <span class="text-sm">Anfragen pro</span>
            <Input v-model.number="perN" type="number" min="1" :max="perUnit === 'h' ? 24 : 59" class="w-20" aria-label="Zeitspanne" :aria-invalid="!!errors.per" data-testid="limit-per-n" />
            <NativeSelect v-model="perUnit" aria-label="Einheit" data-testid="limit-per-unit">
              <NativeSelectOption v-for="u in UNITS" :key="u.value" :value="u.value">
                {{ u.label }}
              </NativeSelectOption>
            </NativeSelect>
          </div>
          <p v-if="errors.limit || errors.per" class="text-sm text-destructive" role="alert">
            {{ errors.limit ?? errors.per }}
          </p>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <div class="grid gap-2">
            <Label :for="`${uid}-burst`">Kurzzeitig erlaubt <span class="font-normal text-muted-foreground">(optional)</span></Label>
            <Input :id="`${uid}-burst`" v-model.number="burst" type="number" min="1" max="100000" :placeholder="String(count || '')" :aria-invalid="!!errors.burst" data-testid="limit-burst" />
            <p :class="errors.burst ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'">
              {{ errors.burst ?? 'So viele Anfragen dürfen auf einmal kommen. Leer: wie das Limit.' }}
            </p>
          </div>
          <div class="grid gap-2">
            <Label :for="`${uid}-site`">Nur für Website <span class="font-normal text-muted-foreground">(optional)</span></Label>
            <Input :id="`${uid}-site`" v-model="site" maxlength="253" placeholder="verein.example" autocomplete="off" spellcheck="false" data-testid="limit-site" />
          </div>
        </div>

        <div class="grid gap-2">
          <span class="text-sm font-medium">Was soll passieren?</span>
          <SegmentedControl v-model="mode" :options="modeOptions" label="Schalter des Limits" />
          <p class="text-xs text-muted-foreground">
            Mit „Beobachten“ zählt Schild nur mit und zeigt, was es begrenzt hätte. Ein guter Start für jedes neue Limit.
          </p>
        </div>

        <div class="grid gap-2 rounded-xl border bg-muted p-3 text-sm">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <span class="font-medium">Probelauf mit den letzten 24 Stunden</span>
            <Button type="button" variant="outline" size="sm" :disabled="dryRun.isPending.value" data-testid="limit-dry-run" @click="runDry">
              <FlaskConical aria-hidden="true" />
              {{ dryRun.isPending.value ? 'Läuft …' : 'Probelauf' }}
            </Button>
          </div>
          <p v-if="dry" aria-live="polite" data-testid="limit-dry-run-result">
            {{ dryRunText(dry) }}
            <span v-if="dry.sampled" class="block text-xs text-muted-foreground">
              „Mindestens“, weil Schild von unauffälligen Anfragen nur eine Stichprobe speichert.
            </span>
          </p>
          <p v-else class="text-xs text-muted-foreground">
            Zeigt, wen dieses Limit gestern getroffen hätte. Es ändert nichts.
          </p>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="save.isPending.value" data-testid="limit-submit">
            {{ save.isPending.value ? 'Wird gespeichert …' : limit ? 'Speichern' : 'Hinzufügen' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
