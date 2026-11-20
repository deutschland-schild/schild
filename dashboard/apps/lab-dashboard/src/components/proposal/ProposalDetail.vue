<script setup lang="ts">
import type { Proposal } from '@/api/types'
import { Button, EffectFooter, formatRelative, MetaLine, RelativeTime, StatusPill } from '@schild/ui'
import { CircleCheck, CircleX, FlaskConical, Info } from '@lucide/vue'
import { computed } from 'vue'
import { ACTION_LABEL, CLASS_LABEL, PROPOSAL_STATUS, REPRO_STATUS, STAGE_LABEL } from '@/lib/labels'
import ActionPill from '../ActionPill.vue'
import Kbd from '../Kbd.vue'
import EvidenceLadder from './EvidenceLadder.vue'
import MaxActionPanel from './MaxActionPanel.vue'

const props = defineProps<{ proposal: Proposal, user: string, canEdit: boolean }>()
const emit = defineEmits<{ approve: [], reject: [], evidence: [] }>()
const p = computed(() => props.proposal)
const open = computed(() => ['draft', 'review', 'approved'].includes(p.value.status))
/** Four eyes (contracts v0.1): whoever drafted a proposal never approves it. */
const isAuthor = computed(() => !!p.value.created_by && p.value.created_by === props.user)
const canApprove = computed(() => props.canEdit && ['review', 'approved'].includes(p.value.status) && p.value.seclang_check.valid && !isAuthor.value && !p.value.approvals.some(a => a.by === props.user))
const alreadyApproved = computed(() => p.value.approvals.some(a => a.by === props.user))
const orgs = computed(() => new Set(p.value.approvals.map(a => a.org)).size)
const reproduced = computed(() => p.value.evidence.reproductions.filter(r => r.status === 'reproduced').length)
const shortDigest = (d?: string) => (d ? `${d.slice(0, 15)}…` : '–')
</script>

<template>
  <article class="space-y-5" :aria-labelledby="`p-${p.id}`" data-testid="proposal-detail">
    <header class="space-y-1.5">
      <div class="flex flex-wrap items-center gap-2">
        <h2 :id="`p-${p.id}`" class="font-mono text-lg font-bold">
          {{ p.rule_id }}
        </h2>
        <StatusPill :tone="PROPOSAL_STATUS[p.status].tone" size="sm">
          {{ PROPOSAL_STATUS[p.status].text }}
        </StatusPill>
      </div>
      <MetaLine
        class="text-sm"
        :items="[
          CLASS_LABEL[p.class],
          `${p.target.software} ${p.target.versions}`,
          p.target.cve?.length ? p.target.cve.join(', ') : '',
          p.stage ? `Start: ${STAGE_LABEL[p.stage]}` : '',
        ]"
      />
      <MetaLine
        :items="[
          { text: p.id, mono: true },
          `angelegt ${formatRelative(p.created_at)}${p.created_by ? ` von ${p.created_by}` : ''}`,
          reproduced ? { text: `${reproduced} von ${p.evidence.reproductions.length} Labs reproduziert`, tone: 'signal' } : 'noch nicht reproduziert',
        ]"
      >
        <template v-if="p.pattern_id">
          · aus <RouterLink :to="`/signals/${p.pattern_id}`" class="underline underline-offset-4">
            Muster {{ p.pattern_id }}
          </RouterLink>
        </template>
        <template v-if="p.bundle_version">
          · in <RouterLink :to="`/published/${p.bundle_version}`" class="underline underline-offset-4">
            Bündel {{ p.bundle_version }}
          </RouterLink>
        </template>
      </MetaLine>
    </header>

    <p v-if="isAuthor && open" class="flex items-start gap-2 text-sm text-muted-foreground" data-testid="author-hint">
      <Info class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      Diesen Vorschlag hast du selbst eingereicht. Freigeben muss ihn eine andere Person (Vier-Augen-Prinzip).
    </p>
    <p v-if="alreadyApproved && open" class="flex items-start gap-2 text-sm text-muted-foreground">
      <Info class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      Du hast schon freigegeben. Die nächste Freigabe muss von einer anderen Person kommen, für Sperren aus einer anderen Organisation.
    </p>
    <p v-if="!p.seclang_check.valid && open" class="flex items-start gap-2 text-sm text-status-danger">
      <Info class="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      Freigabe erst möglich, wenn die Regel in der erlaubten SecLang-Teilmenge liegt.
    </p>
    <p v-if="p.status === 'rejected' && p.rejected_reason" class="rounded-xl border bg-muted p-3 text-sm">
      <span class="font-semibold">Abgelehnt:</span> {{ p.rejected_reason }}
    </p>

    <section class="space-y-2" aria-label="Höchstaktion">
      <h3 class="text-sm font-bold">
        Höchstaktion
      </h3>
      <MaxActionPanel :proposal="p" />
    </section>

    <section class="space-y-2">
      <h3 class="text-sm font-bold">
        Belegstufen
      </h3>
      <EvidenceLadder :cls="p.class" :evidence="p.evidence" :requested="p.requested_max_action" :allowed="p.allowed_max_action" />
      <p class="text-xs text-muted-foreground">
        Hinweise kommen von {{ p.evidence.tip_issuers }} Bürgen (größter Anteil {{ Math.round(p.evidence.max_issuer_share * 100) }} %) · eigene Sensoren bei {{ p.evidence.sensor_operators }} Betreibern<template v-if="p.evidence.negative_corpus">
          · Negativ-Korpus {{ p.evidence.negative_corpus.version }}: {{ p.evidence.negative_corpus.matches ?? 0 }} Treffer
        </template>
      </p>
    </section>

    <section class="space-y-2">
      <h3 class="text-sm font-bold">
        Reproduktion je Lab
      </h3>
      <div class="overflow-x-auto rounded-xl border">
        <table class="w-full text-sm" aria-label="Reproduktion je Lab">
          <thead class="bg-muted text-xs text-muted-foreground">
            <tr>
              <th scope="col" class="px-3 py-2 text-left font-medium">
                Lab
              </th>
              <th scope="col" class="px-3 py-2 text-left font-medium">
                Status
              </th>
              <th scope="col" class="px-3 py-2 text-left font-medium">
                Ziel
              </th>
              <th scope="col" class="hidden px-3 py-2 text-left font-medium md:table-cell">
                Anfrage (Hash)
              </th>
              <th scope="col" class="px-3 py-2 text-left font-medium">
                Wann
              </th>
            </tr>
          </thead>
          <tbody class="divide-y">
            <tr v-for="r in p.evidence.reproductions" :key="r.lab">
              <td class="px-3 py-2">
                <span class="font-medium">{{ r.lab }}</span>
                <span class="block text-xs text-muted-foreground">{{ r.operator }}</span>
              </td>
              <td class="px-3 py-2">
                <StatusPill :tone="REPRO_STATUS[r.status].tone" size="sm">
                  {{ REPRO_STATUS[r.status].text }}
                </StatusPill>
              </td>
              <td class="px-3 py-2 font-mono text-xs">
                {{ r.image }}<span class="block text-muted-foreground">Version {{ r.version }}</span>
              </td>
              <td class="hidden px-3 py-2 font-mono text-xs md:table-cell" :title="r.request_digest">
                {{ shortDigest(r.request_digest) }}
              </td>
              <td class="px-3 py-2 text-xs">
                <RelativeTime v-if="r.at" :value="r.at" />
                <span v-else class="text-muted-foreground">läuft</span>
              </td>
            </tr>
            <tr v-if="!p.evidence.reproductions.length">
              <td colspan="5" class="px-3 py-4 text-center text-sm text-muted-foreground">
                Noch keine Reproduktion. Ohne Reproduktion bleibt es höchstens bei Beobachten.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="space-y-2">
      <div class="flex flex-wrap items-center gap-2">
        <h3 class="text-sm font-bold">
          Regel
        </h3>
        <StatusPill :tone="p.seclang_check.valid ? 'success' : 'danger'" size="sm">
          {{ p.seclang_check.valid ? 'SecLang-Teilmenge eingehalten' : 'Außerhalb der Teilmenge' }}
        </StatusPill>
      </div>
      <pre class="overflow-x-auto rounded-xl border bg-muted p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">{{ p.seclang }}</pre>
      <p v-if="p.seclang_check.error" class="text-sm text-status-danger">
        {{ p.seclang_check.error }}
      </p>
    </section>

    <section class="space-y-2">
      <h3 class="text-sm font-bold">
        Freigaben <span class="font-normal text-muted-foreground">({{ orgs }} {{ orgs === 1 ? 'Organisation' : 'Organisationen' }})</span>
      </h3>
      <ul v-if="p.approvals.length" class="divide-y rounded-xl border text-sm">
        <li v-for="a in p.approvals" :key="`${a.by}-${a.at}`" class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
          <span class="font-medium">{{ a.by }}</span>
          <span class="text-muted-foreground">{{ a.org }}</span>
          <ActionPill v-if="a.max_action" :action="a.max_action" />
          <RelativeTime :value="a.at" class="ml-auto text-xs text-muted-foreground" />
        </li>
      </ul>
      <p v-else class="text-sm text-muted-foreground">
        Noch keine Freigabe. Nichts wird ohne Menschen veröffentlicht.
      </p>
    </section>

    <!-- Sticky so the decision stays at hand while reading the evidence (website footer band). -->
    <EffectFooter class="sticky bottom-0 -mx-4 -mb-4 sm:-mx-5 sm:-mb-5" data-testid="proposal-effect">
      <span>
        <strong>Belege erlauben: {{ p.allowed_max_action ? ACTION_LABEL[p.allowed_max_action] : 'noch nichts' }}.</strong>
        Gewünscht: {{ ACTION_LABEL[p.requested_max_action] }} ·
        {{ p.approvals.length === 1 ? '1 Freigabe' : `${p.approvals.length} Freigaben` }} aus {{ orgs }} {{ orgs === 1 ? 'Organisation' : 'Organisationen' }}.
      </span>
      <template v-if="canEdit && open" #actions>
        <div class="flex flex-wrap gap-2" role="toolbar" aria-label="Aktionen zum Vorschlag">
          <Button variant="outline" size="sm" aria-keyshortcuts="r" data-testid="action-reject" @click="emit('reject')">
            <CircleX aria-hidden="true" /> Ablehnen … <span class="hidden md:contents"><Kbd class="ml-1">R</Kbd></span>
          </Button>
          <Button variant="outline" size="sm" aria-keyshortcuts="e" data-testid="action-evidence" @click="emit('evidence')">
            <FlaskConical aria-hidden="true" /> Beleg anhängen … <span class="hidden md:contents"><Kbd class="ml-1">E</Kbd></span>
          </Button>
          <Button size="sm" :disabled="!canApprove" aria-keyshortcuts="a" data-testid="action-approve" @click="emit('approve')">
            <CircleCheck aria-hidden="true" /> Freigeben … <span class="hidden md:contents"><Kbd class="ml-1 bg-primary-foreground/15 text-primary-foreground">A</Kbd></span>
          </Button>
        </div>
      </template>
    </EffectFooter>
  </article>
</template>
