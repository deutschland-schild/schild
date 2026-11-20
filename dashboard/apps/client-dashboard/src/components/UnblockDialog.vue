<script setup lang="ts">
import type { Incident, Ttl } from '@/api/types'
import {
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Label,
  NativeSelect,
  NativeSelectOption,
  RadioGroup,
  RadioGroupItem,
  Textarea,
  toast,
} from '@schild/ui'
import { computed, ref, useId, watch } from 'vue'
import { errorMessage } from '@/api/client'
import { useUnblock } from '@/api/queries'
import { incidentState } from '@/lib/behaviour'
import { TTLS } from '@/lib/labels'

/**
 * Unblock flow for one incident: false positive or not, optionally add the IP to Eigene IPs.
 * What the gateway does (review 2026-11-19, the dialog said "nur für deine Website"): a running block ends on
 * every website of this server, and for 24 hours the sources that stopped the client let it pass (limits
 * excepted). A stopped request without a block only gets that exception: "Durchlassen".
 * Eigene IPs is off by default: the exception already lets the person in, the list is a separate decision.
 * Nothing is preselected for the false-positive question unless the caller passes an explicit
 * intent (presetFalsePositive): a reflex "Ja, echter Besuch" would record false positives the
 * operator never decided on.
 */
const props = withDefaults(defineProps<{ incident: Incident, presetFalsePositive?: boolean }>(), { presetFalsePositive: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ done: [incident: Incident] }>()

const fp = ref<'yes' | 'no' | ''>('')
const fpMissing = ref(false)
const allowIp = ref(false)
const stopped = computed(() => incidentState(props.incident) === 'stopped')
const ttl = ref<Ttl>('7d')
const note = ref('')
const uid = useId()

watch(open, (v) => {
  if (!v) return
  fp.value = props.presetFalsePositive === undefined ? '' : props.presetFalsePositive ? 'yes' : 'no'
  fpMissing.value = false
  allowIp.value = false
  ttl.value = '7d'
  note.value = ''
})

const unblock = useUnblock()

watch(fp, (v) => {
  if (v) fpMissing.value = false
})

async function submit() {
  if (!fp.value) {
    fpMissing.value = true
    return
  }
  try {
    const inc = await unblock.mutateAsync({
      incident: props.incident.incident,
      body: {
        false_positive: fp.value === 'yes',
        allow_ip: allowIp.value,
        allow_ttl: ttl.value,
        ...(note.value.trim() ? { note: note.value.trim() } : {}),
      },
    })
    open.value = false
    emit('done', inc)
    const parts = ['Die Person kann die Websites wieder nutzen.']
    if (inc.allowlist_entry) parts.push(`Ihre IP steht ${ttl.value === 'never' ? 'dauerhaft' : `für ${TTLS.find(t => t.value === ttl.value)?.label}`} unter „Eigene IPs“.`)
    toast.success(stopped.value ? `Vorfall ${inc.incident}: wird durchgelassen` : `Sperre von Vorfall ${inc.incident} aufgehoben`, { description: parts.join(' ') })
  }
  catch (err) {
    toast.error(stopped.value ? 'Durchlassen hat nicht geklappt' : 'Aufheben hat nicht geklappt', { description: errorMessage(err) })
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <form class="grid gap-5" @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>{{ stopped ? `Vorfall ${incident.incident}: durchlassen` : `Sperre von Vorfall ${incident.incident} aufheben` }}</DialogTitle>
          <DialogDescription data-testid="unblock-scope">
            <template v-if="stopped">
              24 Stunden lang lassen die Regeln, die diese Anfrage gestoppt haben, die Adresse durch, auf allen Websites dieses Servers. Alle anderen Regeln prüfen weiter.
            </template>
            <template v-else>
              Die Sperre endet sofort, auf allen Websites dieses Servers. 24 Stunden lang lassen die Regeln, die sie ausgelöst haben, die Adresse durch.
            </template>
          </DialogDescription>
        </DialogHeader>

        <fieldset class="grid gap-2" data-testid="unblock-fp" :aria-describedby="fpMissing ? `${uid}-fp-missing` : undefined">
          <legend class="mb-2 text-sm font-medium">
            War das ein Fehlalarm?
          </legend>
          <RadioGroup v-model="fp" class="grid gap-2" :aria-invalid="fpMissing || undefined">
            <Label :for="`${uid}-yes`" class="flex cursor-pointer items-start gap-3 rounded-md border p-3 font-normal has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-accent">
              <RadioGroupItem :id="`${uid}-yes`" value="yes" class="mt-0.5" data-testid="unblock-fp-yes" />
              <span class="grid gap-0.5">
                <span class="font-medium">Ja, das war ein echter Besuch</span>
                <span class="text-sm text-muted-foreground">Schild notiert den Fehlalarm. An der Regel ändert sich nichts. Damit es nicht wieder passiert, leg im Ereignis eine Ausnahme an.</span>
              </span>
            </Label>
            <Label :for="`${uid}-no`" class="flex cursor-pointer items-start gap-3 rounded-md border p-3 font-normal has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-accent">
              <RadioGroupItem :id="`${uid}-no`" value="no" class="mt-0.5" data-testid="unblock-fp-no" />
              <span class="grid gap-0.5">
                <span class="font-medium">Nein oder unklar</span>
                <span class="text-sm text-muted-foreground">Nur diesmal durchlassen.</span>
              </span>
            </Label>
          </RadioGroup>
          <p v-if="fpMissing" :id="`${uid}-fp-missing`" role="alert" class="text-sm text-destructive" data-testid="unblock-fp-missing">
            Wähl bitte zuerst, ob das ein Fehlalarm war.
          </p>
        </fieldset>

        <div class="grid gap-3 rounded-md border p-3">
          <Label class="flex items-start gap-2 leading-snug font-normal">
            <Checkbox v-model="allowIp" class="mt-0.5" data-testid="unblock-allow-ip" />
            <span>
              <span class="font-mono">{{ incident.request.ip }}</span> außerdem zu „Eigene IPs“ hinzufügen
              <span class="block text-sm text-muted-foreground">Dann sperrt Schild sie für diese Zeit gar nicht mehr, egal welche Regel anschlägt.</span>
            </span>
          </Label>
          <div v-if="allowIp" class="grid gap-1.5 pl-6">
            <Label :for="`${uid}-ttl`" class="text-sm">Wie lange?</Label>
            <NativeSelect :id="`${uid}-ttl`" v-model="ttl" class="w-full" data-testid="unblock-ttl">
              <NativeSelectOption v-for="t in TTLS" :key="t.value" :value="t.value">
                {{ t.label }}
              </NativeSelectOption>
            </NativeSelect>
          </div>
        </div>

        <div class="grid gap-2">
          <Label :for="`${uid}-note`">Notiz (optional, bleibt lokal)</Label>
          <Textarea :id="`${uid}-note`" v-model="note" maxlength="500" rows="2" placeholder="z. B. Kundin hat angerufen" />
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="unblock.isPending.value" data-testid="unblock-submit">
            {{ stopped ? 'Durchlassen' : 'Sperre aufheben' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
