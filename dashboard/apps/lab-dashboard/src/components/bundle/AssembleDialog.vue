<script setup lang="ts">
import type { AssembleBundle, Bundle, Proposal } from '@/api/types'
import {
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
} from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { ACTION_LABEL, CLASS_LABEL } from '@/lib/labels'
import { fieldErrors, problemMessage } from '@/lib/problem'
import FormField from '../FormField.vue'

/** Assemble the next bundle from the current rules plus approved proposals. This lab signs first; k operators publish. */
const props = withDefaults(defineProps<{ approved: Proposal[], current?: Bundle, defaultHours: number, pending?: boolean, error?: unknown }>(), { current: undefined, pending: false, error: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [body: AssembleBundle] }>()

const add = ref<string[]>([])
const remove = ref<string[]>([])
const hours = ref<number | string>(168)
watch(open, (v) => {
  if (!v) return
  add.value = props.approved.map(p => p.id)
  remove.value = []
  hours.value = props.defaultHours
})
function toggled(list: string[], id: string, on: boolean | 'indeterminate'): string[] {
  return on === true ? [...new Set([...list, id])] : list.filter(x => x !== id)
}
const errs = computed(() => fieldErrors(props.error))
const hoursError = computed(() => {
  const n = Number(hours.value)
  return Number.isInteger(n) && n >= 1 && n <= 744 ? undefined : 'Zwischen 1 und 744 Stunden.'
})
const canSubmit = computed(() => !props.pending && !hoursError.value && (add.value.length > 0 || remove.value.length > 0))
function submit() {
  if (canSubmit.value) emit('confirm', { add: add.value, remove: remove.value, validity_hours: Number(hours.value) })
}
const lastAction = (p: Proposal) => p.approvals.at(-1)?.max_action
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[92svh] overflow-y-auto sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>Neues Bündel zusammenstellen</DialogTitle>
        <DialogDescription>
          Dieses Lab signiert zuerst. Veröffentlicht wird, sobald genug unabhängige Betreiber mitsignieren.
        </DialogDescription>
      </DialogHeader>
      <form id="assemble-form" class="grid gap-5" @submit.prevent="submit">
        <fieldset class="grid gap-2">
          <legend class="mb-1 text-sm font-medium">
            Freigegebene Vorschläge aufnehmen
          </legend>
          <p v-if="!approved.length" class="text-sm text-muted-foreground">
            Gerade ist nichts freigegeben.
          </p>
          <label v-for="p in approved" :key="p.id" class="flex items-start gap-2.5 rounded-md border p-3 text-sm">
            <Checkbox :model-value="add.includes(p.id)" :aria-label="`${p.rule_id} aufnehmen`" @update:model-value="(v) => (add = toggled(add, p.id, v))" />
            <span class="grid gap-0.5">
              <span class="font-mono font-medium">{{ p.rule_id }}</span>
              <span class="text-xs text-muted-foreground">{{ CLASS_LABEL[p.class] }} · {{ p.target.software }} {{ p.target.versions }}<template v-if="lastAction(p)"> · höchstens {{ ACTION_LABEL[lastAction(p)!] }}</template></span>
            </span>
          </label>
          <p v-if="errs.add" class="text-xs font-medium text-status-danger" role="alert">
            {{ errs.add }}
          </p>
        </fieldset>
        <fieldset v-if="current?.rules.length" class="grid gap-2">
          <legend class="mb-1 text-sm font-medium">
            Aus Version {{ current.version }} entfernen (optional)
          </legend>
          <label v-for="r in current.rules" :key="r.rule_id" class="flex items-center gap-2.5 text-sm">
            <Checkbox :model-value="remove.includes(r.rule_id)" :aria-label="`${r.rule_id} entfernen`" @update:model-value="(v) => (remove = toggled(remove, r.rule_id, v))" />
            <span class="font-mono">{{ r.rule_id }}</span>
            <span class="text-xs text-muted-foreground">{{ ACTION_LABEL[r.max_action] }}</span>
          </label>
        </fieldset>
        <FormField v-slot="{ id, aria }" label="Gültig für (Stunden)" hint="Danach verwerfen Clients das Bündel. Höchstens 744 Stunden (31 Tage)." :error="errs.validity_hours ?? hoursError">
          <Input :id="id" v-model="hours" v-bind="aria" type="number" min="1" max="744" step="1" class="w-40" />
        </FormField>
        <p v-if="error && !Object.keys(errs).length" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(error) }}
        </p>
      </form>
      <DialogFooter>
        <Button variant="outline" type="button" @click="open = false">
          Abbrechen
        </Button>
        <Button type="submit" form="assemble-form" :disabled="!canSubmit">
          {{ pending ? 'Wird signiert …' : 'Zusammenstellen und signieren' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
