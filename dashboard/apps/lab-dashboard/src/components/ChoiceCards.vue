<script setup lang="ts" generic="T extends string">
import { useId } from 'vue'

/** Native radio group as cards: arrow keys work, each option can explain itself; disabled options say why. */
defineProps<{
  legend: string
  options: { value: T, label: string, hint?: string, disabled?: boolean, disabledReason?: string }[]
  error?: string
  columns?: 1 | 2 | 3
}>()
const model = defineModel<T>({ required: true })
const name = useId()
</script>

<template>
  <fieldset class="grid gap-1.5" :aria-invalid="error ? 'true' : undefined">
    <legend class="mb-1.5 text-sm font-medium">
      {{ legend }}
    </legend>
    <div class="grid gap-2" :class="columns === 3 ? 'sm:grid-cols-3' : columns === 2 ? 'sm:grid-cols-2' : ''">
      <label
        v-for="o in options"
        :key="o.value"
        class="flex cursor-pointer items-start gap-2.5 rounded-xl border p-3 text-sm transition-colors hover:bg-muted has-[:checked]:border-status-signal-text has-[:checked]:bg-status-signal-subtle has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-60 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ring"
      >
        <input v-model="model" type="radio" :name="name" :value="o.value" :disabled="o.disabled" class="mt-0.5 size-4 accent-[var(--signal-text)]" :data-value="o.value">
        <span class="grid gap-0.5">
          <span class="font-semibold">{{ o.label }}</span>
          <span v-if="o.hint" class="text-xs text-muted-foreground">{{ o.hint }}</span>
          <span v-if="o.disabled && o.disabledReason" class="text-xs text-status-warning">{{ o.disabledReason }}</span>
        </span>
      </label>
    </div>
    <p v-if="error" class="text-xs font-medium text-status-danger" role="alert">
      {{ error }}
    </p>
  </fieldset>
</template>
