<script setup lang="ts">
import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@schild/ui'

/** Confirmation of a consequential change. No password: the session is enough (D74). */
const props = withDefaults(defineProps<{ title: string, description?: string, confirmLabel?: string, pending?: boolean, error?: string | null }>(), {
  description: undefined,
  confirmLabel: 'Bestätigen',
  pending: false,
  error: null,
})
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [] }>()
function submit() {
  if (props.pending) return
  emit('confirm')
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <form class="grid gap-4" @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>{{ title }}</DialogTitle>
          <DialogDescription>
            <slot>{{ description }}</slot>
          </DialogDescription>
        </DialogHeader>
        <slot name="details" />
        <p v-if="error" class="text-sm text-destructive" role="alert">
          {{ error }}
        </p>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="pending" data-testid="confirm-submit">
            {{ pending ? 'Wird gespeichert …' : confirmLabel }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
