<script setup lang="ts">
import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, formatNumber, Input } from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { fieldErrors, problemMessage } from '@/lib/problem'
import FormField from './FormField.vue'

const props = withDefaults(defineProps<{ title: string, current: number, used?: number, pending?: boolean, error?: unknown }>(), { used: undefined, pending: false, error: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [quota: number] }>()
const value = ref<number | string>(0)
watch(open, v => v && (value.value = props.current))
const n = computed(() => Number(value.value))
const localError = computed(() => (Number.isInteger(n.value) && n.value >= 0 && n.value <= 100_000_000 ? undefined : 'Bitte eine ganze Zahl zwischen 0 und 100 000 000.'))
const errs = computed(() => fieldErrors(props.error))
function submit() {
  if (!localError.value && !props.pending) emit('confirm', n.value)
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-md">
      <DialogHeader>
        <DialogTitle>{{ title }}</DialogTitle>
        <DialogDescription>
          Hinweise pro Tag. 0 heißt: nichts mehr annehmen.<template v-if="used !== undefined">
            Genutzt in 24 h: {{ formatNumber(used) }}.
          </template>
        </DialogDescription>
      </DialogHeader>
      <form id="quota-form" class="grid gap-4" @submit.prevent="submit">
        <FormField v-slot="{ id, aria }" label="Kontingent pro Tag" required :error="errs.quota_per_day ?? localError">
          <Input :id="id" v-model="value" v-bind="aria" type="number" min="0" step="1" class="w-48" />
        </FormField>
        <p v-if="error && !errs.quota_per_day" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(error) }}
        </p>
      </form>
      <DialogFooter>
        <Button variant="outline" type="button" @click="open = false">
          Abbrechen
        </Button>
        <Button type="submit" form="quota-form" :disabled="!!localError || pending">
          Speichern
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
