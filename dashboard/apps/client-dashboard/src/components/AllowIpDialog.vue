<script setup lang="ts">
import type { AllowlistInput, Ttl } from '@/api/types'
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
  RadioGroup,
  RadioGroupItem,
  toast,
} from '@schild/ui'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, useId, watch } from 'vue'
import { errorMessage, fieldErrors } from '@/api/client'
import { deleteAllowlistEntry, keys, useAddAllowlist } from '@/api/queries'
import { isCidr, isHostName, isIP } from '@/lib/ip'
import { ALLOW_LEVELS, TTLS } from '@/lib/labels'

/** Add an IP, range or DynDNS name to the local allowlist (never sent anywhere). */
const props = withDefaults(defineProps<{ ip?: string, label?: string, ttl?: Ttl }>(), { ip: '', label: '', ttl: '7d' })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ done: [] }>()

type Kind = 'ip' | 'cidr' | 'host'
const kind = ref<Kind>('ip')
const value = ref('')
const labelText = ref('')
const level = ref<'no_block' | 'bypass_waf'>('no_block')
const ttlValue = ref<Ttl>('7d')
const confirmBypass = ref(false)
const touched = ref(false)
const serverErrors = ref<Record<string, string>>({})
const uid = useId()

watch(open, (v) => {
  if (!v) return
  kind.value = props.ip.includes('/') ? 'cidr' : 'ip'
  value.value = props.ip
  labelText.value = props.label
  ttlValue.value = props.ttl
  level.value = 'no_block'
  confirmBypass.value = false
  touched.value = false
  serverErrors.value = {}
})

const KINDS: { value: Kind, label: string, placeholder: string, hint: string }[] = [
  { value: 'ip', label: 'Einzelne IP', placeholder: '203.0.113.7 oder 2001:db8::1', hint: 'Eine IPv4- oder IPv6-Adresse.' },
  { value: 'cidr', label: 'Bereich', placeholder: '198.51.100.0/24', hint: 'Ein ganzes Netz in CIDR-Schreibweise, z. B. das Büro.' },
  { value: 'host', label: 'DynDNS-Name', placeholder: 'zuhause.example.net', hint: 'Ein Name, dessen Adresse sich ändert. Schild prüft ihn regelmäßig neu.' },
]
const current = computed(() => KINDS.find(k => k.value === kind.value)!)

const valueError = computed(() => {
  if (serverErrors.value[kind.value]) return 'Das hat der Server nicht akzeptiert. Prüf die Schreibweise.'
  const v = value.value.trim()
  if (!touched.value) return null
  if (!v) return 'Bitte ausfüllen.'
  if (kind.value === 'ip' && !isIP(v)) return 'Das ist keine gültige IP-Adresse.'
  if (kind.value === 'cidr' && !isCidr(v)) return 'Das ist kein gültiger Bereich. Beispiel: 198.51.100.0/24'
  if (kind.value === 'host' && !isHostName(v)) return 'Das ist kein gültiger Name. Beispiel: zuhause.example.net'
  return null
})
const labelError = computed(() => serverErrors.value.label ? 'Bitte gib eine Bezeichnung mit höchstens 64 Zeichen an.' : touched.value && !labelText.value.trim() ? 'Gib dem Eintrag einen Namen, damit du ihn später wiedererkennst.' : null)
const bypassError = computed(() => level.value === 'bypass_waf' && touched.value && !confirmBypass.value ? 'Bitte bestätige, dass der Filter für diese Absender komplett aus sein soll.' : null)

const add = useAddAllowlist()
const qc = useQueryClient()

async function submit() {
  touched.value = true
  serverErrors.value = {}
  if (valueError.value || labelError.value || bypassError.value) return
  const v = value.value.trim()
  const body: AllowlistInput = {
    [kind.value]: v,
    label: labelText.value.trim(),
    level: level.value,
    ttl: ttlValue.value,
    ...(level.value === 'bypass_waf' ? { confirm_bypass: true } : {}),
  } as AllowlistInput
  try {
    const entry = await add.mutateAsync(body)
    open.value = false
    emit('done')
    toast.success(`${v} ist freigeschaltet`, {
      description: ttlValue.value === 'never' ? 'Dauerhaft, bis du den Eintrag löschst.' : `Für ${TTLS.find(t => t.value === ttlValue.value)?.label}.`,
      action: {
        label: 'Rückgängig',
        onClick: async () => {
          await deleteAllowlistEntry(entry.id)
          void qc.invalidateQueries({ queryKey: keys.allowlist })
          void qc.invalidateQueries({ queryKey: keys.myip })
          toast(`Freischaltung für ${v} zurückgenommen`)
        },
      },
    })
  }
  catch (err) {
    serverErrors.value = fieldErrors(err)
    if (!Object.keys(serverErrors.value).length) toast.error(errorMessage(err))
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <form class="grid gap-5" novalidate @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>IP freischalten</DialogTitle>
          <DialogDescription>
            Freigeschaltete Absender sperrt Schild nicht. Die Liste bleibt auf deinem Server und wird nie verschickt.
          </DialogDescription>
        </DialogHeader>

        <fieldset class="grid gap-2">
          <legend class="mb-2 text-sm font-medium">
            Was möchtest du freischalten?
          </legend>
          <RadioGroup v-model="kind" class="grid grid-cols-1 gap-2 sm:grid-cols-3" aria-label="Art des Eintrags">
            <Label v-for="k in KINDS" :key="k.value" :for="`${uid}-${k.value}`" class="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 font-normal has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-accent">
              <RadioGroupItem :id="`${uid}-${k.value}`" :value="k.value" />
              {{ k.label }}
            </Label>
          </RadioGroup>
        </fieldset>

        <div class="grid gap-2">
          <Label :for="`${uid}-value`">{{ current.label }}</Label>
          <Input
            :id="`${uid}-value`"
            v-model="value"
            :placeholder="current.placeholder"
            autocomplete="off"
            spellcheck="false"
            class="font-mono"
            :aria-invalid="!!valueError"
            :aria-describedby="`${uid}-value-hint`"
            data-testid="allow-value"
            @blur="touched = touched || !!value"
          />
          <p :id="`${uid}-value-hint`" :class="valueError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="valueError ? 'alert' : undefined">
            {{ valueError ?? current.hint }}
          </p>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-label`">Bezeichnung</Label>
          <Input :id="`${uid}-label`" v-model="labelText" maxlength="64" placeholder="z. B. Büro, Agentur, Monitoring" :aria-invalid="!!labelError" :aria-describedby="labelError ? `${uid}-label-err` : undefined" data-testid="allow-label" />
          <p v-if="labelError" :id="`${uid}-label-err`" class="text-sm text-destructive" role="alert">
            {{ labelError }}
          </p>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-ttl`">Wie lange?</Label>
          <NativeSelect :id="`${uid}-ttl`" v-model="ttlValue" class="w-full" data-testid="allow-ttl">
            <NativeSelectOption v-for="t in TTLS" :key="t.value" :value="t.value">
              {{ t.label }}
            </NativeSelectOption>
          </NativeSelect>
        </div>

        <fieldset class="grid gap-2">
          <legend class="mb-2 text-sm font-medium">
            Wie weit?
          </legend>
          <RadioGroup v-model="level" class="grid gap-2" aria-label="Umfang der Freischaltung">
            <Label v-for="(meta, key) in ALLOW_LEVELS" :key="key" :for="`${uid}-${key}`" class="flex cursor-pointer items-start gap-3 rounded-md border p-3 font-normal has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-accent">
              <RadioGroupItem :id="`${uid}-${key}`" :value="key" class="mt-0.5" />
              <span class="grid gap-0.5">
                <span class="font-medium">{{ meta.label }}</span>
                <span class="text-sm text-muted-foreground">{{ meta.explain }}</span>
              </span>
            </Label>
          </RadioGroup>
          <div v-if="level === 'bypass_waf'" class="mt-1 grid gap-1 rounded-md border border-status-warning/40 bg-status-warning-subtle p-3">
            <Label class="flex items-start gap-2 leading-snug font-normal">
              <Checkbox v-model="confirmBypass" class="mt-0.5" data-testid="allow-bypass-confirm" />
              Ich verstehe: Für diese Absender prüft Schild gar nichts mehr. Wird so ein Rechner übernommen, kommt jeder Angriff von dort durch.
            </Label>
            <p v-if="bypassError" class="text-sm text-destructive" role="alert">
              {{ bypassError }}
            </p>
          </div>
        </fieldset>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="add.isPending.value" data-testid="allow-submit">
            {{ add.isPending.value ? 'Wird gespeichert …' : 'Freischalten' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
