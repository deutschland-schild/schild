<script setup lang="ts">
import type { RuleExceptionInput } from '@/api/rules'
import {
  Button,
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
  toast,
} from '@schild/ui'
import { computed, ref, useId, watch } from 'vue'
import { fieldErrors } from '@/api/client'
import { exceptionError, useCreateRuleException } from '@/api/rules'
import { useWebsites } from '@/api/websites'
import { EXCEPTION_KINDS, exceptionTarget, parseExceptionRules, parseExceptionTarget, REPOSITORIES } from '@/lib/rules'
import { websiteName } from '@/lib/websites'

/**
 * Set a rule exception in the dashboard (D84): named rules left out for one field on one page of one
 * website. The same checks as the agent API; the gateway says what it refuses. No password (D74).
 */
const props = defineProps<{ preset?: Partial<RuleExceptionInput> }>()
const open = defineModel<boolean>('open', { default: false })

const websites = useWebsites()
const sites = computed(() => websites.data.value?.websites ?? [])

const website = ref('')
const path = ref('')
const kind = ref<keyof typeof EXCEPTION_KINDS>('form')
const name = ref('')
const repository = ref<RuleExceptionInput['repository']>('crs')
const rulesText = ref('')
const reason = ref('')
const touched = ref(false)
const serverErrors = ref<Record<string, string>>({})
const refused = ref<string | null>(null)
const uid = useId()

watch(open, (v) => {
  if (!v) return
  const p = props.preset ?? {}
  const t = parseExceptionTarget(p.target ?? '')
  website.value = p.website ?? (sites.value.length === 1 ? sites.value[0]!.id : '')
  path.value = p.path ?? ''
  kind.value = t.kind
  name.value = t.name
  repository.value = p.repository ?? 'crs'
  rulesText.value = (p.rules ?? []).join(', ')
  reason.value = ''
  touched.value = false
  serverErrors.value = {}
  refused.value = null
})

const rules = computed(() => parseExceptionRules(rulesText.value))

const errors = computed(() => {
  const s = serverErrors.value
  const t = touched.value
  return {
    website: s.website || (t && !website.value) ? 'Wähl die Website, für die die Ausnahme gilt.' : null,
    path: s.path || (t && !/^\/\S*$/.test(path.value.trim())) ? 'Der Pfad beginnt mit / und nennt genau eine Seite, zum Beispiel /kontakt. {name} steht für einen Abschnitt.' : null,
    target: s.target || (t && !name.value.trim()) ? 'Nenn genau einen Namen. Ein Stern steht für einen Teil des Namens zwischen Punkten, aber nicht für alles.' : null,
    rules: s.rules || s.repository || (t && (!rules.value.length || rules.value.length > 16 || rules.value.some(r => !/^[1-9]\d{0,8}$/.test(r)))) ? '1 bis 16 Regelnummern dieser Quelle, jede nur einmal. Die Nummer steht im Ereignis und unter Regeln.' : null,
    reason: s.reason || (t && (!reason.value.trim() || reason.value.trim().length > 300)) ? 'Schreib in einer Zeile, wofür die Ausnahme da ist. Höchstens 300 Zeichen.' : null,
  }
})

const create = useCreateRuleException()

async function submit() {
  touched.value = true
  serverErrors.value = {}
  refused.value = null
  if (Object.values(errors.value).some(Boolean)) return
  const body: RuleExceptionInput = {
    website: website.value,
    path: path.value.trim(),
    target: exceptionTarget(kind.value, name.value),
    repository: repository.value,
    rules: rules.value,
    reason: reason.value.trim(),
  }
  try {
    await create.mutateAsync(body)
    open.value = false
    toast.success('Die Ausnahme gilt', { description: `${body.path}, ${EXCEPTION_KINDS[kind.value].label} ${name.value.trim()}: ${rules.value.length === 1 ? 'Regel' : 'Regeln'} ${rules.value.join(', ')} ausgenommen.` })
  }
  catch (err) {
    serverErrors.value = fieldErrors(err)
    if (!Object.keys(serverErrors.value).length) refused.value = exceptionError(err)
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg" data-testid="exception-dialog">
      <form class="grid gap-5" novalidate @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>Ausnahme anlegen</DialogTitle>
          <DialogDescription>
            Schild lässt die genannten Regeln für ein Feld auf einer Seite aus. Alle anderen Regeln, Felder und Seiten prüft es weiter. Die Ausnahme gilt sofort, ohne Neustart.
          </DialogDescription>
        </DialogHeader>

        <div class="grid gap-2">
          <Label :for="`${uid}-website`">Website</Label>
          <NativeSelect :id="`${uid}-website`" v-model="website" class="w-full" :aria-invalid="!!errors.website" data-testid="exception-website">
            <NativeSelectOption value="" disabled>
              Website wählen
            </NativeSelectOption>
            <NativeSelectOption v-for="w in sites" :key="w.id" :value="w.id">
              {{ websiteName(w) }}
            </NativeSelectOption>
          </NativeSelect>
          <p v-if="errors.website" class="text-sm text-destructive" role="alert">
            {{ errors.website }}
          </p>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-path`">Pfad der Seite</Label>
          <Input :id="`${uid}-path`" v-model="path" placeholder="/kontakt" autocomplete="off" spellcheck="false" class="font-mono" :aria-invalid="!!errors.path" data-testid="exception-path" />
          <p :class="errors.path ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="errors.path ? 'alert' : undefined">
            {{ errors.path ?? 'Der genaue Pfad ohne Adresse und ohne ?-Teil. {name} steht für einen Abschnitt, etwa /artikel/{name}/kommentar.' }}
          </p>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-name`">Was soll ausgenommen sein?</Label>
          <div class="grid gap-2 sm:grid-cols-[11rem_1fr]">
            <NativeSelect v-model="kind" class="w-full" aria-label="Art des Werts" data-testid="exception-kind">
              <NativeSelectOption v-for="(k, key) in EXCEPTION_KINDS" :key="key" :value="key">
                {{ k.label }}
              </NativeSelectOption>
            </NativeSelect>
            <Input :id="`${uid}-name`" v-model="name" :placeholder="EXCEPTION_KINDS[kind].placeholder" autocomplete="off" spellcheck="false" class="font-mono" :aria-invalid="!!errors.target" data-testid="exception-name" />
          </div>
          <p :class="errors.target ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="errors.target ? 'alert' : undefined">
            {{ errors.target ?? EXCEPTION_KINDS[kind].hint }}
          </p>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-rules`">Regeln</Label>
          <div class="grid gap-2 sm:grid-cols-[11rem_1fr]">
            <NativeSelect v-model="repository" class="w-full" aria-label="Regelquelle" data-testid="exception-repository">
              <NativeSelectOption value="crs">
                {{ REPOSITORIES.crs.name }}
              </NativeSelectOption>
              <NativeSelectOption value="crowdsec">
                {{ REPOSITORIES.crowdsec.name }}
              </NativeSelectOption>
            </NativeSelect>
            <Input :id="`${uid}-rules`" v-model="rulesText" placeholder="942100, 942110" autocomplete="off" spellcheck="false" inputmode="numeric" class="font-mono" :aria-invalid="!!errors.rules" data-testid="exception-rules" />
          </div>
          <p :class="errors.rules ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="errors.rules ? 'alert' : undefined">
            {{ errors.rules ?? 'Die Nummern der Regeln, die hier fälschlich anschlagen, mit Komma getrennt. Nimm nur die, die du im Ereignis siehst.' }}
          </p>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-reason`">Begründung</Label>
          <Input :id="`${uid}-reason`" v-model="reason" maxlength="300" placeholder="z. B. Das Kontaktformular nimmt freien Text an" :aria-invalid="!!errors.reason" data-testid="exception-reason" />
          <p :class="errors.reason ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="errors.reason ? 'alert' : undefined">
            {{ errors.reason ?? 'Für alle, die die Liste später lesen. Steht bei der Ausnahme und im Ereignis.' }}
          </p>
        </div>

        <p v-if="refused" class="text-sm text-destructive" role="alert" data-testid="exception-refused">
          {{ refused }}
        </p>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="create.isPending.value" data-testid="exception-submit">
            {{ create.isPending.value ? 'Wird gespeichert …' : 'Ausnahme anlegen' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
