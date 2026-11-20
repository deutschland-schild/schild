<script setup lang="ts">
import type { MaxAction, Proposal } from '@/api/types'
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Textarea,
} from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { actionRank, ACTIONS, labCapReasons, levelWithApproval, minAction, missingFor } from '@/lib/evidence'
import { ACTION_HINT, ACTION_LABEL } from '@/lib/labels'
import { fieldErrors, problemMessage } from '@/lib/problem'
import ChoiceCards from '../ChoiceCards.vue'
import FormField from '../FormField.vue'

/**
 * Human approval: names the person (from the session) and the organisation.
 * Only actions up to what the evidence allows can be chosen (G2); the lab checks again.
 */
const props = withDefaults(defineProps<{ proposal: Proposal, user: string, defaultOrg?: string, pending?: boolean, error?: unknown }>(), { defaultOrg: '', pending: false, error: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [body: { max_action: MaxAction, org: string, max_action_until?: string, note?: string }] }>()

const org = ref('')
const action = ref<MaxAction>('observe')
const until = ref('')
const note = ref('')
const DAY = 24 * 3600_000

function localInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

const isNewOrg = computed(() => !!org.value.trim() && !props.proposal.approvals.some(x => x.org === org.value.trim()))
const level = computed(() => levelWithApproval(props.proposal.class, props.proposal.evidence, org.value.trim(), props.proposal.approvals.map(a => a.org), props.proposal.allowed_max_action))
const options = computed(() => ACTIONS.map((a) => {
  const allowed = actionRank(a) <= actionRank(level.value)
  return {
    value: a,
    label: ACTION_LABEL[a],
    hint: ACTION_HINT[a],
    disabled: !allowed,
    disabledReason: allowed ? undefined : (missingFor(a, props.proposal.class, { ...props.proposal.evidence, human_approval_orgs: props.proposal.evidence.human_approval_orgs + (isNewOrg.value ? 1 : 0) }, { withOwnApproval: isNewOrg.value }).join(' ') || labCapReasons(props.proposal.class, props.proposal.evidence, props.proposal.allowed_max_action).join(' ') || 'Die Belege reichen nicht.'),
  }
}))

watch(open, (v) => {
  if (!v) return
  org.value = props.defaultOrg
  note.value = ''
  touched.value = false
  action.value = minAction(props.proposal.requested_max_action, level.value) ?? 'observe'
  until.value = localInput(new Date(Date.now() + 7 * DAY))
})
watch(level, (l) => {
  if (actionRank(action.value) > actionRank(l)) action.value = l ?? 'observe'
})

const needsUntil = computed(() => action.value !== 'observe')
const localErrors = computed(() => {
  const e: Record<string, string> = {}
  if (!org.value.trim()) e.org = 'Bitte nenne deine Organisation.'
  if (!note.value.trim()) e.note = 'Bitte begründe die Freigabe kurz.'
  if (needsUntil.value) {
    const t = Date.parse(until.value)
    if (Number.isNaN(t)) e.max_action_until = 'Bitte gib ein Enddatum an.'
    else if (t <= Date.now()) e.max_action_until = 'Das Enddatum muss in der Zukunft liegen.'
    else if (action.value === 'challenge' && t - Date.now() > 7 * DAY + 60_000) e.max_action_until = 'Challenge gilt höchstens 7 Tage.'
  }
  return e
})
const errs = computed(() => ({ ...fieldErrors(props.error) }))
const nothingAllowed = computed(() => level.value === null)
const touched = ref(false)
const canSubmit = computed(() => !props.pending && !nothingAllowed.value && !Object.keys(localErrors.value).length)
const otherOrgs = computed(() => [...new Set(props.proposal.approvals.map(a => a.org))])

function submit() {
  touched.value = true
  if (!canSubmit.value) return
  emit('confirm', {
    max_action: action.value,
    org: org.value.trim(),
    ...(needsUntil.value ? { max_action_until: new Date(until.value).toISOString() } : {}),
    note: note.value.trim(),
  })
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[92svh] overflow-y-auto sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>{{ proposal.rule_id }} freigeben</DialogTitle>
        <DialogDescription>
          Deine Freigabe ist eine von mehreren. Veröffentlicht wird erst, wenn genug Betreiber das Bündel signieren.
        </DialogDescription>
      </DialogHeader>
      <form id="approve-form" class="grid gap-4" @submit.prevent="submit">
        <div class="grid gap-4 sm:grid-cols-2">
          <div class="grid gap-1.5">
            <p class="text-sm font-medium">
              Person
            </p>
            <p class="flex h-9 items-center rounded-md border bg-muted px-3 text-sm" data-testid="approve-person">
              {{ user }}
            </p>
          </div>
          <FormField v-slot="{ id, aria }" label="Organisation" required :error="errs.org ?? (org ? undefined : localErrors.org)">
            <Input :id="id" v-model="org" v-bind="aria" maxlength="64" autocomplete="organization" />
          </FormField>
        </div>
        <div class="rounded-xl border bg-muted p-3 text-sm" data-testid="four-eyes">
          <p class="font-medium">
            Vier Augen
          </p>
          <p class="text-muted-foreground">
            <template v-if="otherOrgs.length">
              Bisher freigegeben von: {{ otherOrgs.join(', ') }}.
            </template>
            <template v-else>
              Noch keine Freigabe.
            </template>
            Sperren braucht Freigaben aus mindestens 2 Organisationen; eine zweite Freigabe aus derselben Organisation zählt nicht extra.
          </p>
        </div>
        <p v-if="nothingAllowed" class="rounded-md bg-status-warning-subtle p-3 text-sm" role="alert">
          Die Belege erlauben noch nicht einmal Beobachten. Häng zuerst Belege an.
        </p>
        <ChoiceCards v-else v-model="action" legend="Höchstaktion für diese Freigabe" :options="options" :error="errs.max_action" />
        <FormField v-if="needsUntil" v-slot="{ id, aria }" label="Gilt bis" required :hint="action === 'challenge' ? 'Höchstens 7 Tage.' : 'Danach fällt die Regel zurück.'" :error="errs.max_action_until ?? localErrors.max_action_until">
          <Input :id="id" v-model="until" v-bind="aria" type="datetime-local" />
        </FormField>
        <FormField v-slot="{ id, aria }" label="Begründung" required hint="Was hast du geprüft? Steht bei der Freigabe." :error="errs.note ?? (touched ? localErrors.note : undefined)">
          <Textarea :id="id" v-model="note" v-bind="aria" rows="2" maxlength="1000" data-testid="approve-note" />
        </FormField>
        <p v-if="error && !Object.keys(errs).length" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(error) }}
        </p>
      </form>
      <DialogFooter>
        <Button variant="outline" type="button" @click="open = false">
          Abbrechen
        </Button>
        <Button type="submit" form="approve-form" :disabled="pending || nothingAllowed" data-testid="approve-submit">
          {{ pending ? 'Wird gespeichert …' : `Als ${user} freigeben` }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
