<script setup lang="ts">
import type { Proposal } from '@/api/types'
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Textarea,
} from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { fieldErrors, problemMessage } from '@/lib/problem'
import FormField from '../FormField.vue'

/** Reject with a mandatory reason. */
const props = withDefaults(defineProps<{ proposal: Proposal, pending?: boolean, error?: unknown }>(), { pending: false, error: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [reason: string] }>()
const reason = ref('')
const touched = ref(false)
watch(open, (v) => {
  if (v) {
    reason.value = ''
    touched.value = false
  }
})
const errs = computed(() => fieldErrors(props.error))
const localError = computed(() => (touched.value && !reason.value.trim() ? 'Bitte nenne einen Grund.' : undefined))
function submit() {
  touched.value = true
  if (!reason.value.trim() || props.pending) return
  emit('confirm', reason.value.trim())
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>{{ proposal.rule_id }} ablehnen</DialogTitle>
        <DialogDescription>Der Grund wird beim Vorschlag gespeichert, damit andere ihn nachvollziehen können.</DialogDescription>
      </DialogHeader>
      <form id="reject-form" class="grid gap-4" @submit.prevent="submit">
        <FormField v-slot="{ id, aria }" label="Grund" required :error="errs.reason ?? localError">
          <Textarea :id="id" v-model="reason" v-bind="aria" rows="3" maxlength="1000" placeholder="z. B. Trifft auch normale Suchanfragen" data-testid="reject-reason" />
        </FormField>
        <p v-if="error && !errs.reason" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(error) }}
        </p>
      </form>
      <DialogFooter>
        <Button variant="outline" type="button" @click="open = false">
          Abbrechen
        </Button>
        <Button type="submit" form="reject-form" variant="destructive" :disabled="pending" data-testid="reject-submit">
          {{ pending ? 'Wird gespeichert …' : 'Ablehnen' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
