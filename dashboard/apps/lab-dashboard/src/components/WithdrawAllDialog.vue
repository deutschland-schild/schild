<script setup lang="ts">
import type { EmergencyStopInput } from '@/api/types'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Button,
  Input,
  NativeSelect,
  NativeSelectOption,
  Textarea,
} from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { fieldErrors, problemMessage } from '@/lib/problem'
import { WITHDRAW_ALL_PHRASE as PHRASE, WITHDRAW_ALL_WIRE_CONFIRM } from '@/lib/labels'
import FormField from './FormField.vue'

/**
 * Withdraw all network rules (wire: POST /emergency-stop): typed phrase, reason, password.
 * Never reachable by a single key press. The typed phrase is German and calm; the wire value stays until contracts v0.4.
 */

const props = withDefaults(defineProps<{ threshold: number, rulesActive?: number, pending?: boolean, error?: unknown }>(), { rulesActive: undefined, pending: false, error: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [body: EmergencyStopInput] }>()

const typed = ref('')
const password = ref('')
const reason = ref<EmergencyStopInput['reason']>('emergency_stop')
const note = ref('')
watch(open, (v) => {
  if (!v) {
    typed.value = ''
    password.value = ''
    note.value = ''
    reason.value = 'emergency_stop'
  }
})
const errs = computed(() => (props.error ? fieldErrors(props.error) : {}))
const phraseOk = computed(() => typed.value === PHRASE)
const canConfirm = computed(() => !props.pending && phraseOk.value && password.value.length > 0)
function submit() {
  if (!canConfirm.value) return
  emit('confirm', { confirm_text: WITHDRAW_ALL_WIRE_CONFIRM, password: password.value, reason: reason.value, ...(note.value.trim() ? { note: note.value.trim() } : {}) })
}
</script>

<template>
  <AlertDialog v-model:open="open">
    <AlertDialogContent class="sm:max-w-lg">
      <form class="grid gap-4" data-testid="withdraw-all-form" @submit.prevent="submit">
        <AlertDialogHeader>
          <AlertDialogTitle>Alle Netzregeln zurückziehen?</AlertDialogTitle>
          <AlertDialogDescription>
            Rückzug aller Netzregeln dieses Kanals. Lies kurz, was passiert.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <ul class="list-disc space-y-1 rounded-xl border bg-muted p-3 pl-8 text-sm">
          <li>Alle Netzregeln<template v-if="rulesActive !== undefined"> ({{ rulesActive }} aktiv)</template> werden auf allen Servern entfernt, sobald der Rückzug wirksam ist.</li>
          <li>Der Grundschutz läuft auf jedem Server weiter, ebenso die lokalen Regeln.</li>
          <li>Wirksam erst mit Signaturen von {{ threshold }} unabhängigen Betreibern. Dieses Lab signiert jetzt als erstes.</li>
          <li>Der Rückzug ist ein neuer, mitgezeichneter Regelstand im öffentlichen Log. Netzregeln kommen erst mit einem neuen Bündel wieder.</li>
        </ul>
        <FormField v-slot="{ id, aria }" label="Grund" required :error="errs.reason">
          <NativeSelect :id="id" v-model="reason" v-bind="aria" class="w-full">
            <NativeSelectOption value="emergency_stop">
              Unklare Lage (Fehlalarme, Ursache offen)
            </NativeSelectOption>
            <NativeSelectOption value="compromised_key">
              Schlüssel kompromittiert
            </NativeSelectOption>
          </NativeSelect>
        </FormField>
        <FormField v-slot="{ id, aria }" label="Notiz für die anderen Labs (optional)" hint="Steht im öffentlichen Log. Höchstens 280 Zeichen." :error="errs.note">
          <Textarea :id="id" v-model="note" v-bind="aria" rows="2" maxlength="280" />
        </FormField>
        <FormField v-slot="{ id, aria }" :label="`Tippe ${PHRASE} zur Bestätigung`" required :error="errs.confirm_text">
          <Input :id="id" v-model="typed" v-bind="aria" autocomplete="off" autocapitalize="characters" spellcheck="false" class="font-mono" data-testid="withdraw-all-phrase" />
        </FormField>
        <FormField v-slot="{ id, aria }" label="Dein Passwort" required :error="errs.password">
          <Input :id="id" v-model="password" v-bind="aria" type="password" autocomplete="current-password" data-testid="withdraw-all-password" />
        </FormField>
        <p v-if="error && !errs.password && !errs.confirm_text && !errs.reason" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(error) }}
        </p>
        <AlertDialogFooter>
          <AlertDialogCancel type="button">
            Abbrechen
          </AlertDialogCancel>
          <Button type="submit" variant="destructive" :disabled="!canConfirm" data-testid="withdraw-all-submit">
            {{ pending ? 'Wird signiert …' : 'Rückzug signieren' }}
          </Button>
        </AlertDialogFooter>
      </form>
    </AlertDialogContent>
  </AlertDialog>
</template>
