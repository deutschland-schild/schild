<script setup lang="ts">
import type { Agent, Enrolment } from '@/api/hosts'
import {
  Button,
  CommandBlock,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  formatRelative,
  Input,
  Label,
  MetaLine,
  toast,
} from '@schild/ui'
import { CircleCheck, CircleX, LoaderCircle } from '@lucide/vue'
import { computed, onBeforeUnmount, ref, useId, watch } from 'vue'
import { errorMessage, problemOf } from '@/api/client'
import { useAgents, useConfirmAgent, useCreateEnrolment, useRevokeAgent } from '@/api/hosts'
import Term from '@/components/Term.vue'
import { groupFingerprint, normalizeFingerprint, toApiFingerprint } from '@/lib/hosts'

/**
 * "Server hinzufügen": one-time code, the one line for the app VM, wait for the agent's enrolment
 * request, compare the key fingerprint and confirm. With `agent` set the dialog starts at the
 * comparison (a pending agent from the list).
 */
const props = withDefaults(defineProps<{ agent?: Agent | null }>(), { agent: null })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ enrolled: [agent: Agent] }>()

type Step = 'start' | 'code' | 'confirm'
const step = ref<Step>('start')
const label = ref('')
const labelError = ref<string | null>(null)
const busy = ref(false)
const enrolment = ref<Enrolment | null>(null)
const knownPending = ref<Set<string>>(new Set())
const found = ref<Agent | null>(null)
const pasted = ref('')
const confirmError = ref<string | null>(null)
const now = ref(Date.now())
const uid = useId()

let clock: ReturnType<typeof setInterval> | undefined
watch(open, (v) => {
  clearInterval(clock)
  if (!v) return
  step.value = props.agent ? 'confirm' : 'start'
  found.value = props.agent
  label.value = ''
  labelError.value = null
  enrolment.value = null
  pasted.value = ''
  confirmError.value = null
  now.value = Date.now()
  clock = setInterval(() => (now.value = Date.now()), 1000)
}, { immediate: true })
onBeforeUnmount(() => clearInterval(clock))

// While the code is shown, look for the new pending agent every 3 s.
const waiting = computed(() => open.value && step.value === 'code')
const agentsQ = useAgents(() => waiting.value ? 3000 : false)
const expired = computed(() => !!enrolment.value && Date.parse(enrolment.value.expires_at) <= now.value)
watch(() => agentsQ.data.value, (page) => {
  if (!waiting.value || !page) return
  const fresh = page.items.find(a => a.status === 'pending' && !knownPending.value.has(a.id) && (!enrolment.value?.label || a.label === enrolment.value.label))
  if (fresh) {
    found.value = fresh
    step.value = 'confirm'
  }
})

const create = useCreateEnrolment()

async function start() {
  labelError.value = null
  const l = label.value.trim()
  if (l.length > 64) {
    labelError.value = 'Höchstens 64 Zeichen.'
    return
  }
  busy.value = true
  try {
    const before = await agentsQ.refetch()
    knownPending.value = new Set((before.data?.items ?? []).filter(a => a.status === 'pending').map(a => a.id))
    enrolment.value = await create.mutateAsync({ ...(l ? { label: l } : {}) })
    step.value = 'code'
  }
  catch (err) {
    if (problemOf(err)?.errors?.some(e => e.pointer === '/label')) labelError.value = 'Höchstens 64 Zeichen.'
    else toast.error('Der Code ließ sich nicht erstellen', { description: errorMessage(err) })
  }
  finally {
    busy.value = false
  }
}

const expected = computed(() => found.value ? normalizeFingerprint(found.value.fingerprint) : '')
const typed = computed(() => normalizeFingerprint(pasted.value))
const match = computed<'empty' | 'partial' | 'match' | 'mismatch'>(() => {
  if (!typed.value) return 'empty'
  if (typed.value === expected.value) return 'match'
  if (typed.value.length < 64 && expected.value.startsWith(typed.value)) return 'partial'
  return 'mismatch'
})

const confirm = useConfirmAgent()
const revoke = useRevokeAgent()
async function confirmAgent() {
  const a = found.value
  const fp = toApiFingerprint(pasted.value)
  if (!a || !fp || match.value !== 'match') return
  confirmError.value = null
  try {
    const done = await confirm.mutateAsync({ id: a.id, fingerprint: fp })
    open.value = false
    emit('enrolled', done)
    toast.success(`${done.hostname} ist bestätigt`, { description: 'Sein erster Bericht erscheint nach dem nächsten Lauf des Agents.' })
  }
  catch (err) {
    const code = problemOf(err)?.code
    confirmError.value = code === 'fingerprint_mismatch'
      ? 'Der Fingerabdruck passt nicht zum Schlüssel, den Schild bekommen hat. Bestätige nicht und erstelle lieber einen neuen Code.'
      : errorMessage(err)
  }
}
async function rejectAgent() {
  const a = found.value
  if (!a) return
  try {
    await revoke.mutateAsync({ id: a.id, note: 'rejected during enrolment' })
    open.value = false
    toast(`${a.hostname} abgelehnt`, { description: 'Sein Schlüssel steht auf der Sperrliste. Für einen neuen Versuch erstellst du einen neuen Code.' })
  }
  catch (err) {
    toast.error('Ablehnen hat nicht geklappt', { description: errorMessage(err) })
  }
}
const expiresText = computed(() => enrolment.value ? new Date(enrolment.value.expires_at).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) : '')
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-xl" data-testid="enrol-dialog">
      <!-- 1: what an agent is, label -->
      <form v-if="step === 'start'" class="grid gap-5" novalidate @submit.prevent="start">
        <DialogHeader>
          <DialogTitle>Server hinzufügen</DialogTitle>
          <DialogDescription>
            Für App-Server hinter diesem Gateway. Dort läuft dann ein <Term k="agent">Agent</Term>: ein kleines eigenes Programm (<span class="font-mono">schild-agent</span>), das den Server nur liest und seinen Bericht signiert an dieses Gateway schickt. Der Bericht bleibt auf deinen Servern. Er nimmt keine Befehle an und ändert nichts.
          </DialogDescription>
        </DialogHeader>
        <ol class="grid gap-1.5 text-sm text-muted-foreground">
          <li><strong class="text-foreground">1.</strong> Du erstellst hier einen Code, der nur einmal und nur kurz gilt (ab Werk 30 Minuten).</li>
          <li><strong class="text-foreground">2.</strong> Auf dem App-Server führst du eine Zeile aus. Sie erzeugt dort einen eigenen Schlüssel.</li>
          <li><strong class="text-foreground">3.</strong> Du vergleichst den <Term k="fingerabdruck">Fingerabdruck</Term> und bestätigst den Server.</li>
        </ol>
        <div class="grid gap-2">
          <Label :for="`${uid}-label`">Name für den Server (freiwillig)</Label>
          <Input
            :id="`${uid}-label`"
            v-model="label"
            maxlength="64"
            autocomplete="off"
            placeholder="z. B. Shop oder Nextcloud"
            :aria-invalid="!!labelError"
            :aria-describedby="labelError ? `${uid}-label-err` : undefined"
            data-testid="enrol-label"
          />
          <p v-if="labelError" :id="`${uid}-label-err`" class="text-sm text-destructive" role="alert">
            {{ labelError }}
          </p>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="busy" data-testid="enrol-create">
            <LoaderCircle v-if="busy" class="motion-safe:animate-spin" aria-hidden="true" />
            {{ busy ? 'Wird erstellt …' : 'Code erstellen' }}
          </Button>
        </DialogFooter>
      </form>

      <!-- 2: the command for the app VM, wait for the agent -->
      <div v-else-if="step === 'code' && enrolment" class="grid gap-5">
        <DialogHeader>
          <DialogTitle>Auf dem App-Server ausführen</DialogTitle>
          <DialogDescription>
            Melde dich auf dem App-Server an und führe diese Zeile aus. Sie legt dort einen eigenen Schlüssel an, der den Server nie verlässt, und zeigt dessen Fingerabdruck.
          </DialogDescription>
        </DialogHeader>
        <CommandBlock :command="enrolment.command" copy-label="Befehl für den App-Server kopieren" data-testid="enrol-command" />
        <MetaLine
          :items="[
            { text: enrolment.code, mono: true },
            expired ? { text: 'abgelaufen', tone: 'danger' } : `gilt einmal, bis ${expiresText} Uhr (${formatRelative(enrolment.expires_at, new Date(now))})`,
            enrolment.label ? `Name: ${enrolment.label}` : '',
          ]"
        />
        <p class="text-xs text-muted-foreground">
          Der App-Server muss das Gateway unter <span class="font-mono">{{ enrolment.gateway_url }}</span> erreichen. Der Befehl prüft dessen Zertifikat über die Prüfsumme hinter <span class="font-mono">--pin</span>.
        </p>
        <div class="flex items-center gap-2 rounded-xl border bg-muted p-3 text-sm" role="status" data-testid="enrol-waiting">
          <template v-if="expired">
            <CircleX class="size-4 shrink-0 text-status-danger" aria-hidden="true" />
            Der Code ist abgelaufen, ohne dass sich ein Server gemeldet hat.
          </template>
          <template v-else>
            <LoaderCircle class="size-4 shrink-0 text-muted-foreground motion-safe:animate-spin" aria-hidden="true" />
            Warte auf den neuen Server … Lass dieses Fenster offen.
          </template>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Schließen
          </Button>
          <Button v-if="expired" type="button" @click="step = 'start'">
            Neuen Code erstellen
          </Button>
        </DialogFooter>
      </div>

      <!-- 3: compare the fingerprint and confirm -->
      <form v-else-if="step === 'confirm' && found" class="grid gap-5" novalidate @submit.prevent="confirmAgent">
        <DialogHeader>
          <DialogTitle>{{ found.hostname }} bestätigen</DialogTitle>
          <DialogDescription>
            Ein Server hat sich mit dem Code gemeldet. Vergleiche den <Term k="fingerabdruck">Fingerabdruck</Term> mit dem, den der Befehl auf dem App-Server angezeigt hat. Erst nach deiner Bestätigung nimmt Schild seine Berichte an.
          </DialogDescription>
        </DialogHeader>
        <div class="grid gap-1.5 text-sm">
          <p class="text-xs font-semibold text-muted-foreground">
            Fingerabdruck, den Schild bekommen hat
          </p>
          <p class="rounded-lg border bg-muted px-3 py-2 font-mono text-[13px] leading-relaxed break-all" data-testid="enrol-fingerprint">
            sha256: {{ groupFingerprint(found.fingerprint) }}
          </p>
          <MetaLine :items="[found.label ? `Name: ${found.label}` : '', { text: found.keyid, mono: true }, `gemeldet ${formatRelative(found.created_at)}`]" />
        </div>
        <div class="grid gap-2">
          <Label :for="`${uid}-fp`">Fingerabdruck vom App-Server einfügen</Label>
          <Input
            :id="`${uid}-fp`"
            v-model="pasted"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            class="font-mono text-xs"
            placeholder="sha256:…"
            :aria-invalid="match === 'mismatch' || !!confirmError"
            :aria-describedby="`${uid}-fp-state`"
            data-testid="enrol-fingerprint-input"
          />
          <p :id="`${uid}-fp-state`" class="text-sm" aria-live="polite" data-testid="enrol-match">
            <template v-if="confirmError">
              <span class="text-destructive">{{ confirmError }}</span>
            </template>
            <template v-else-if="match === 'match'">
              <CircleCheck class="mr-1 inline size-4 -translate-y-px text-status-success" aria-hidden="true" />Stimmt überein.
            </template>
            <template v-else-if="match === 'mismatch'">
              <CircleX class="mr-1 inline size-4 -translate-y-px text-status-danger" aria-hidden="true" /><span class="text-destructive">Stimmt nicht überein. Bestätige diesen Server nicht.</span>
            </template>
            <span v-else class="text-xs text-muted-foreground">Groß- und Kleinschreibung, Leerzeichen und „sha256:“ spielen keine Rolle.</span>
          </p>
        </div>
        <DialogFooter class="gap-2">
          <Button type="button" variant="outline" :disabled="revoke.isPending.value" data-testid="enrol-reject" @click="rejectAgent">
            Ablehnen
          </Button>
          <Button type="submit" :disabled="match !== 'match' || confirm.isPending.value" data-testid="enrol-confirm">
            {{ confirm.isPending.value ? 'Wird bestätigt …' : 'Server bestätigen' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
