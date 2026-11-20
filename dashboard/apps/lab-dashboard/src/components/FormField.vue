<script setup lang="ts">
import { Label } from '@schild/ui'
import { computed, useId } from 'vue'

/** Label, hint and error for one control. The slot receives the id and aria attributes to bind. */
const props = defineProps<{ label: string, hint?: string, error?: string, required?: boolean }>()
const id = useId()
const hintId = `${id}-hint`
const errorId = `${id}-error`
const describedBy = computed(() => [props.hint && hintId, props.error && errorId].filter(Boolean).join(' ') || undefined)
</script>

<template>
  <div class="grid gap-1.5" :data-invalid="!!error || undefined">
    <div class="flex items-baseline gap-1">
      <Label :for="id" class="text-sm font-medium">
        {{ label }}
      </Label>
      <!-- Required is announced via aria-required on the control; the star is visual only. -->
      <span v-if="required" class="text-sm text-muted-foreground" aria-hidden="true">*</span>
    </div>
    <slot :id="id" :aria="{ 'aria-describedby': describedBy, 'aria-invalid': error ? 'true' : undefined, 'aria-required': required ? 'true' : undefined }" />
    <p v-if="hint" :id="hintId" class="text-xs text-muted-foreground">
      {{ hint }}
    </p>
    <p v-if="error" :id="errorId" class="text-xs font-medium text-status-danger" role="alert">
      {{ error }}
    </p>
  </div>
</template>
