<script setup lang="ts">
import type { EvidenceInput, Proposal } from '@/api/types'
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
import { fieldErrors, problemMessage } from '@/lib/problem'
import ChoiceCards from '../ChoiceCards.vue'
import FormField from '../FormField.vue'

/** Attach a reproduction (request + named target version, MVP-03), a sensor observation or a negative-corpus run. */
const props = withDefaults(defineProps<{ proposal: Proposal, pending?: boolean, error?: unknown }>(), { pending: false, error: undefined })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ confirm: [body: EvidenceInput] }>()

const kind = ref<EvidenceInput['kind']>('reproduction')
const image = ref('')
const version = ref('')
const request = ref('')
const result = ref<'reproduced' | 'not_reproduced'>('reproduced')
const corpusVersion = ref('')
const corpusMatches = ref<number | string>(0)
const local = ref<Record<string, string>>({})

watch(open, (v) => {
  if (!v) return
  kind.value = 'reproduction'
  const own = props.proposal.evidence.reproductions[0]
  image.value = own?.image ?? ''
  version.value = own?.version ?? ''
  request.value = ''
  result.value = 'reproduced'
  corpusVersion.value = props.proposal.evidence.negative_corpus?.version ?? ''
  corpusMatches.value = 0
  local.value = {}
})
const errs = computed(() => ({ ...fieldErrors(props.error), ...local.value }))

function submit() {
  if (props.pending) return
  local.value = {}
  if (kind.value === 'reproduction') {
    if (!image.value.trim()) local.value.image = 'Bitte nenne das Container-Image.'
    if (!version.value.trim()) local.value.version = 'Bitte nenne die Version.'
    if (!request.value.trim()) local.value.request = 'Bitte füge die reproduzierende Anfrage ein.'
    if (Object.keys(local.value).length) return
    emit('confirm', { kind: 'reproduction', image: image.value.trim(), version: version.value.trim(), request: request.value, result: result.value })
  }
  else if (kind.value === 'sensor') {
    emit('confirm', { kind: 'sensor' })
  }
  else {
    const n = Number(corpusMatches.value)
    if (!corpusVersion.value.trim()) local.value.corpus_version = 'Bitte nenne die Korpus-Version.'
    if (!Number.isInteger(n) || n < 0) local.value.corpus_matches = 'Bitte eine ganze Zahl ab 0.'
    if (Object.keys(local.value).length) return
    emit('confirm', { kind: 'negative_corpus', corpus_version: corpusVersion.value.trim(), corpus_matches: n })
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[92svh] overflow-y-auto sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>Beleg anhängen</DialogTitle>
        <DialogDescription>Für {{ proposal.rule_id }}. Die erlaubte Höchstaktion wird danach neu berechnet.</DialogDescription>
      </DialogHeader>
      <form id="evidence-form" class="grid gap-4" @submit.prevent="submit">
        <ChoiceCards
          v-model="kind"
          legend="Art des Belegs"
          :columns="3"
          :options="[
            { value: 'reproduction', label: 'Reproduktion', hint: 'Angriff gegen eine benannte Version nachgestellt.' },
            { value: 'sensor', label: 'Eigene Sensoren', hint: 'Honeypot oder Lab-Range hat es gesehen.' },
            { value: 'negative_corpus', label: 'Negativ-Korpus', hint: 'Regel gegen normalen Verkehr geprüft.' },
          ]"
        />
        <template v-if="kind === 'reproduction'">
          <div class="grid gap-4 sm:grid-cols-2">
            <FormField v-slot="{ id, aria }" label="Container-Image" required hint="z. B. wordpress:6.6.2-gallery-2.4.0" :error="errs.image">
              <Input :id="id" v-model="image" v-bind="aria" autocomplete="off" class="font-mono" />
            </FormField>
            <FormField v-slot="{ id, aria }" label="Verwundbare Version" required hint="z. B. 2.4.0" :error="errs.version">
              <Input :id="id" v-model="version" v-bind="aria" autocomplete="off" />
            </FormField>
          </div>
          <FormField v-slot="{ id, aria }" label="Reproduzierende Anfrage (roh)" required hint="Bleibt im Lab. Öffentlich steht nur ihr Hash." :error="errs.request">
            <Textarea :id="id" v-model="request" v-bind="aria" rows="6" spellcheck="false" class="font-mono text-xs" placeholder="POST /wp-json/gallery/v1/items HTTP/1.1&#10;Host: target.test&#10;…" />
          </FormField>
          <ChoiceCards
            v-model="result"
            legend="Ergebnis"
            :columns="2"
            :error="errs.result"
            :options="[
              { value: 'reproduced', label: 'Reproduziert', hint: 'Der Angriff wirkt gegen diese Version.' },
              { value: 'not_reproduced', label: 'Nicht reproduziert', hint: 'Zählt nicht als Beleg, wird aber vermerkt.' },
            ]"
          />
        </template>
        <p v-else-if="kind === 'sensor'" class="rounded-xl border bg-muted p-3 text-sm text-muted-foreground">
          Du bestätigst, dass Sensoren dieses Labs das Muster selbst gesehen haben. Sensoren zählen je Betreiber einmal.
        </p>
        <div v-else class="grid gap-4 sm:grid-cols-2">
          <FormField v-slot="{ id, aria }" label="Korpus-Version" required :error="errs.corpus_version">
            <Input :id="id" v-model="corpusVersion" v-bind="aria" autocomplete="off" />
          </FormField>
          <FormField v-slot="{ id, aria }" label="Treffer im normalen Verkehr" required hint="0 heißt: keine Fehlalarme gefunden." :error="errs.corpus_matches">
            <Input :id="id" v-model="corpusMatches" v-bind="aria" type="number" min="0" step="1" />
          </FormField>
        </div>
        <p v-if="error && !Object.keys(fieldErrors(error)).length" class="text-sm font-medium text-status-danger" role="alert">
          {{ problemMessage(error) }}
        </p>
      </form>
      <DialogFooter>
        <Button variant="outline" type="button" @click="open = false">
          Abbrechen
        </Button>
        <Button type="submit" form="evidence-form" :disabled="pending" data-testid="evidence-submit">
          {{ pending ? 'Wird angehängt …' : 'Beleg anhängen' }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
