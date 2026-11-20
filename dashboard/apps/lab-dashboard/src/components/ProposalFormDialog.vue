<script setup lang="ts">
import type { MaxAction, PatternSummary, Proposal, ProposalClass } from '@/api/types'
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
import { useCreateProposal } from '@/api/queries'
import { ACTION_HINT, ACTION_LABEL, CLASS_LABEL, STAGE_LABEL } from '@/lib/labels'
import { fieldErrors, problemMessage } from '@/lib/problem'
import ChoiceCards from './ChoiceCards.vue'
import FormField from './FormField.vue'

/** Draft a rule proposal from a pattern. The lab checks the SecLang subset at once; the evidence decides the max action. */
const props = defineProps<{ pattern?: PatternSummary }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ created: [p: Proposal] }>()

const cls = ref<ProposalClass>('virtual_patch')
const software = ref('')
const versions = ref('')
const cve = ref('')
const seclang = ref('')
const requested = ref<MaxAction>('observe')
const stage = ref<'shadow' | 'canary' | 'general'>('shadow')
const create = useCreateProposal()

function template(p?: PatternSummary): string {
  const msg = p ? `${p.action_sig}` : 'Beschreibung'
  return `SecRule ARGS "@detectSQLi" "id:7700100,phase:2,pass,log,msg:'${msg}',tag:'schild-remote',t:none,t:urlDecodeUni"`
}

watch(open, (v) => {
  if (v) {
    create.reset()
    const behavioral = /burst|stuffing|flood|scan/.test(props.pattern?.action_sig ?? '')
    cls.value = behavioral ? 'behavioral' : 'virtual_patch'
    software.value = ''
    versions.value = ''
    cve.value = ''
    seclang.value = template(props.pattern)
    requested.value = 'observe'
    stage.value = 'shadow'
  }
})

const errs = computed(() => fieldErrors(create.error.value))
const classOptions = (Object.keys(CLASS_LABEL) as ProposalClass[]).map(k => ({
  value: k,
  label: CLASS_LABEL[k],
  hint: k === 'virtual_patch' ? 'Schließt eine benannte Lücke. Nur diese Klasse kann sperren.' : k === 'heuristic' ? 'Allgemeines Angriffsmuster ohne feste Lücke.' : 'Verhalten wie Login-Wellen. Höchstens Challenge.',
}))
const actionOptions = computed(() => (['observe', 'challenge', 'block'] as MaxAction[]).map(a => ({
  value: a,
  label: ACTION_LABEL[a],
  hint: ACTION_HINT[a],
  disabled: a === 'block' && cls.value !== 'virtual_patch',
  disabledReason: 'Nur virtuelle Patches dürfen sperren.',
})))
watch(cls, (c) => {
  if (c !== 'virtual_patch' && requested.value === 'block') requested.value = 'challenge'
})

function submit() {
  create.mutate({
    ...(props.pattern ? { pattern_id: props.pattern.pattern_id } : {}),
    class: cls.value,
    seclang: seclang.value,
    // The spec types `target` as a free object; the lab validates software/versions/cve.
    target: { software: software.value.trim(), versions: versions.value.trim() || '*', ...(cve.value.trim() ? { cve: cve.value.split(/[\s,]+/).filter(Boolean) } : {}) },
    requested_max_action: requested.value,
    stage: stage.value,
  }, {
    onSuccess: (p) => {
      open.value = false
      emit('created', p)
    },
  })
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[92svh] overflow-y-auto sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>Vorschlag anlegen</DialogTitle>
        <DialogDescription>
          <template v-if="pattern">
            Aus dem Muster <span class="font-mono">{{ pattern.action_sig }}</span>.
          </template>
          Der Vorschlag geht in die Prüfung. Veröffentlicht wird nur nach menschlicher Freigabe.
        </DialogDescription>
      </DialogHeader>
      <form id="proposal-form" class="grid gap-5" @submit.prevent="submit">
        <ChoiceCards v-model="cls" legend="Klasse" :options="classOptions" :columns="3" :error="errs.class" />
        <div class="grid gap-4 sm:grid-cols-3">
          <FormField v-slot="{ id, aria }" label="Software" required hint="z. B. wp-plugin/gallery" :error="errs['target.software'] ?? errs.target">
            <Input :id="id" v-model="software" v-bind="aria" autocomplete="off" />
          </FormField>
          <FormField v-slot="{ id, aria }" label="Versionen" hint="z. B. <2.4.1, leer = alle" :error="errs['target.versions']">
            <Input :id="id" v-model="versions" v-bind="aria" autocomplete="off" />
          </FormField>
          <FormField v-slot="{ id, aria }" label="CVE (optional)" hint="Mehrere mit Komma" :error="errs['target.cve']">
            <Input :id="id" v-model="cve" v-bind="aria" autocomplete="off" />
          </FormField>
        </div>
        <FormField v-slot="{ id, aria }" label="Regel (SecLang)" required hint="Erlaubte Teilmenge: eine SecRule plus bis zu 3 Ketten, IDs 7700000–7799999. Beobachten braucht „pass“." :error="errs.seclang">
          <Textarea :id="id" v-model="seclang" v-bind="aria" rows="5" spellcheck="false" class="font-mono text-xs" />
        </FormField>
        <ChoiceCards v-model="requested" legend="Gewünschte Höchstaktion" :options="actionOptions" :columns="3" :error="errs.requested_max_action" />
        <p class="-mt-3 text-xs text-muted-foreground">
          Was tatsächlich erlaubt ist, entscheiden die Belege. Das Dashboard zeigt dir danach, was noch fehlt.
        </p>
        <ChoiceCards
          v-model="stage"
          legend="Start"
          :columns="3"
          :options="[
            { value: 'shadow', label: STAGE_LABEL.shadow!, hint: 'Zählt nur mit, mindestens 24 h.' },
            { value: 'canary', label: STAGE_LABEL.canary!, hint: 'Bis 5 % der Clients.' },
            { value: 'general', label: STAGE_LABEL.general!, hint: 'Alle Clients.' },
          ]"
        />
        <p v-if="create.isError.value && !Object.keys(errs).length" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(create.error.value) }}
        </p>
      </form>
      <DialogFooter>
        <Button variant="outline" type="button" @click="open = false">
          Abbrechen
        </Button>
        <Button type="submit" form="proposal-form" :disabled="create.isPending.value">
          {{ create.isPending.value ? 'Wird angelegt …' : 'Vorschlag anlegen' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
