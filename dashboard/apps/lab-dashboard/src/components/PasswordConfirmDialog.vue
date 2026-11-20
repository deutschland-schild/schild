<script setup lang="ts">
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
  Textarea,
} from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { fieldErrors, problemMessage } from '@/lib/problem'
import FormField from './FormField.vue'

/**
 * Confirmation for consequential actions: lists the consequences, asks for the password
 * (and optionally a typed phrase and a note). Stays open on errors and shows them in place.
 */
const props = withDefaults(defineProps<{
  title: string
  description?: string
  consequences?: string[]
  confirmLabel: string
  /** Exact text the user must type, e.g. the issuer id. */
  confirmPhrase?: string
  withNote?: boolean
  noteLabel?: string
  destructive?: boolean
  pending?: boolean
  /** Extra condition from slot content (e.g. nothing selected yet). */
  disabled?: boolean
  error?: unknown
}>(), { disabled: false, description: undefined, consequences: () => [], confirmPhrase: undefined, withNote: false, noteLabel: 'Notiz (optional)', destructive: false, pending: false, error: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [value: { password: string, note?: string }] }>()

const password = ref('')
const note = ref('')
const typed = ref('')
watch(open, (v) => {
  if (!v) {
    password.value = ''
    note.value = ''
    typed.value = ''
  }
})
const errs = computed(() => (props.error ? fieldErrors(props.error) : {}))
const phraseOk = computed(() => !props.confirmPhrase || typed.value.trim() === props.confirmPhrase)
const canConfirm = computed(() => !props.pending && !props.disabled && phraseOk.value && password.value.length > 0)
function submit() {
  if (!canConfirm.value) return
  emit('confirm', { password: password.value, ...(props.withNote && note.value.trim() ? { note: note.value.trim() } : {}) })
}
</script>

<template>
  <AlertDialog v-model:open="open">
    <AlertDialogContent class="sm:max-w-lg">
      <form class="grid gap-4" @submit.prevent="submit">
        <AlertDialogHeader>
          <AlertDialogTitle>{{ title }}</AlertDialogTitle>
          <AlertDialogDescription v-if="description">
            {{ description }}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div v-if="consequences.length" class="rounded-xl border bg-muted p-3 text-sm">
          <p class="mb-1 font-medium">
            Was dann passiert
          </p>
          <ul class="list-disc space-y-1 pl-5 text-muted-foreground">
            <li v-for="c in consequences" :key="c">
              {{ c }}
            </li>
          </ul>
        </div>
        <slot />
        <FormField v-if="confirmPhrase" v-slot="{ id, aria }" :label="`Tippe ${confirmPhrase} zur Bestätigung`" required>
          <Input :id="id" v-model="typed" v-bind="aria" autocomplete="off" autocapitalize="off" spellcheck="false" class="font-mono" data-testid="confirm-phrase" />
        </FormField>
        <FormField v-if="withNote" v-slot="{ id, aria }" :label="noteLabel" :error="errs.note">
          <Textarea :id="id" v-model="note" v-bind="aria" rows="2" maxlength="280" />
        </FormField>
        <FormField v-slot="{ id, aria }" label="Dein Passwort" :error="errs.password ?? errs['confirm.password']" required>
          <Input :id="id" v-model="password" v-bind="aria" type="password" autocomplete="current-password" data-testid="confirm-password" />
        </FormField>
        <p v-if="error && !errs.password && !errs['confirm.password']" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(error) }}
        </p>
        <AlertDialogFooter>
          <AlertDialogCancel type="button">
            Abbrechen
          </AlertDialogCancel>
          <Button type="submit" :variant="destructive ? 'destructive' : 'default'" :disabled="!canConfirm" data-testid="confirm-submit">
            {{ pending ? 'Wird gesendet …' : confirmLabel }}
          </Button>
        </AlertDialogFooter>
      </form>
    </AlertDialogContent>
  </AlertDialog>
</template>
