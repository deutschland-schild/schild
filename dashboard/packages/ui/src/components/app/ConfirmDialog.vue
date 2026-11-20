<script setup lang="ts">
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@schild/ui/components/ui/alert-dialog'
import { Button } from '@schild/ui/components/ui/button'
import { Input } from '@schild/ui/components/ui/input'
import { Label } from '@schild/ui/components/ui/label'
import { computed, ref, useId, watch } from 'vue'

/**
 * Confirmation for consequential actions. With `confirmPhrase`, the user must type the phrase
 * (type-to-confirm) before the action button is enabled, e.g. for withdrawing all network rules or a single rule.
 */
const props = withDefaults(defineProps<{
  title: string
  description?: string
  confirmLabel?: string
  cancelLabel?: string
  /** If set, the confirm button stays disabled until this exact text is typed. */
  confirmPhrase?: string
  destructive?: boolean
  pending?: boolean
}>(), {
  description: undefined,
  confirmLabel: 'Bestätigen',
  cancelLabel: 'Abbrechen',
  confirmPhrase: undefined,
  destructive: false,
  pending: false,
})
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [] }>()

const typed = ref('')
const inputId = useId()
watch(open, (v) => {
  if (!v) typed.value = ''
})
const canConfirm = computed(() => !props.pending && (!props.confirmPhrase || typed.value.trim() === props.confirmPhrase))

function onConfirm() {
  if (!canConfirm.value) return
  emit('confirm')
}
</script>

<template>
  <AlertDialog v-model:open="open">
    <AlertDialogContent>
      <form class="contents" @submit.prevent="onConfirm">
        <AlertDialogHeader>
          <AlertDialogTitle>{{ title }}</AlertDialogTitle>
          <AlertDialogDescription v-if="description || $slots.default">
            <slot>{{ description }}</slot>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div v-if="confirmPhrase" class="space-y-2">
          <Label :for="inputId" class="leading-normal font-normal">
            Tippe <strong class="font-mono font-semibold select-all">{{ confirmPhrase }}</strong> ein, um zu bestätigen.
          </Label>
          <Input :id="inputId" v-model="typed" autocomplete="off" autocapitalize="off" spellcheck="false" data-testid="confirm-input" />
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel type="button">
            {{ cancelLabel }}
          </AlertDialogCancel>
          <Button type="submit" :variant="destructive ? 'destructive' : 'default'" :disabled="!canConfirm" data-testid="confirm-action">
            {{ confirmLabel }}
          </Button>
        </AlertDialogFooter>
      </form>
    </AlertDialogContent>
  </AlertDialog>
</template>
