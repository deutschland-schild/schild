<script setup lang="ts">
import type { AuditEntry } from '@/api/audit'
import { formatDateTime, formatNumber, IpAddress, RelativeTime, StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { useAgentTokens } from '@/api/agentapi'
import { statusOf } from '@/api/client'
import { useAllowlist, useEvent, useIncident } from '@/api/queries'
import { useRuleExceptions } from '@/api/rules'
import { useWebsites } from '@/api/websites'
import {
  actorId,
  actorKind,
  actorName,
  actorSession,
  AUDIT_COPY as COPY,
  auditLink,
  CLASSES,
  countText,
  entryTitle,
  FIELD_CHANGE,
  hiddenText,
  historyFilters,
  moreFieldsText,
  objectLink,
  splitOperation,
  subjectLabel,
  valueText,
  wayLabel,
} from '@/lib/audit'
import { websitePath } from '@/lib/nav'
import { websiteName } from '@/lib/websites'

/**
 * One entry of the audit log in full: who, when, through which way, where from, what, and before and
 * after for every changed field. Every name leads on: to the object while it exists, to every entry of
 * that object, to the cause, to what the session or the token did. Something that is gone says so.
 *
 * Reasons, labels, names and values are text from outside. They are only ever interpolated as text and
 * never become a link target. The parent keys this component by the id of the entry, so the lookups
 * below are set up once per entry.
 */
const props = defineProps<{ entry: AuditEntry }>()
const e = props.entry

const op = splitOperation(e.operation)
const session = actorSession(e.actor)
const token = actorId(e.actor)
const fields = e.change?.fields ?? []

// ---------------------------------------------------------------- website
const websites = useWebsites()
const site = computed(() => e.website ? websites.data.value?.websites.find(w => w.id === e.website) : undefined)
const siteKnown = computed(() => !!site.value)

// ---------------------------------------------------------------- the object: does it still exist?
type Presence = 'exists' | 'gone' | 'unknown'
const kind = e.subject.kind
const id = e.subject.id
const link = objectLink(e)

function lookup(): () => Presence {
  if (!id) return () => kind === 'setting' || kind === 'agent_api' ? 'exists' : 'unknown'
  switch (kind) {
    case 'allowlist_entry': {
      const q = useAllowlist()
      return () => {
        if (!q.data.value) return 'unknown'
        if (q.data.value.pages.some(p => p.items.some(a => a.id === id))) return 'exists'
        return q.hasNextPage.value ? 'unknown' : 'gone'
      }
    }
    case 'rule_exception': {
      const q = useRuleExceptions()
      return () => !q.data.value ? 'unknown' : q.data.value.items.some(x => String(x.id) === id) ? 'exists' : 'gone'
    }
    case 'token': {
      const q = useAgentTokens()
      return () => !q.data.value ? 'unknown' : q.data.value.some(t => t.id === id) ? 'exists' : 'gone'
    }
    case 'website':
      return () => !websites.data.value ? 'unknown' : websites.data.value.websites.some(w => w.id === id) ? 'exists' : 'gone'
    case 'block':
    case 'incident': {
      const q = useIncident(link ? id : null)
      return () => q.data.value ? 'exists' : statusOf(q.error.value) === 404 ? 'gone' : 'unknown'
    }
    case 'setting':
      return () => 'exists'
    default:
      return () => 'unknown'
  }
}
const presenceOf = lookup()
const presence = computed(presenceOf)

// ---------------------------------------------------------------- the cause: an event or an incident
const causeEvent = e.cause && 'event' in e.cause ? e.cause.event : null
const causeIncident = e.cause && 'incident' in e.cause ? e.cause.incident : null
const eventQ = useEvent(causeEvent)
const incidentQ = useIncident(causeIncident)
const causeGone = computed(() => statusOf((causeEvent ? eventQ.error.value : incidentQ.error.value)) === 404)
</script>

<template>
  <div class="space-y-6 text-sm" data-testid="audit-entry" :data-entry="e.id">
    <section class="space-y-2">
      <div class="flex flex-wrap items-center gap-2">
        <StatusPill :tone="CLASSES[e.class]?.tone ?? 'neutral'" size="md">
          {{ CLASSES[e.class]?.label ?? e.class }}
        </StatusPill>
        <span class="text-muted-foreground"><time :datetime="e.time">{{ formatDateTime(e.time) }}</time> · <RelativeTime :value="e.time" /></span>
      </div>
      <p class="text-base font-medium text-pretty" data-testid="audit-title">
        {{ entryTitle(e) }}
      </p>
      <p v-if="e.count" class="text-muted-foreground" data-testid="audit-count">
        {{ countText(e.count) }} in einer Minute<template v-if="e.last">, zuletzt um <time :datetime="e.last">{{ formatDateTime(e.last) }}</time></template>. Schild fasst abgelehnte Aufrufe je Absender und Minute in einem Eintrag zusammen.
      </p>
    </section>

    <dl class="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-3">
      <dt class="text-muted-foreground">
        Wer
      </dt>
      <dd class="min-w-0 space-y-1" data-testid="audit-actor" :data-actor-kind="e.actor.kind">
        <p>
          <template v-if="e.actor.kind === 'dashboard' && !e.actor.user">
            <span class="text-muted-foreground">{{ COPY.noName }}</span>
          </template>
          <template v-else>
            <span class="font-medium break-words">{{ actorName(e.actor) }}</span>
            <span class="text-muted-foreground"> · {{ actorKind(e.actor) }}</span>
          </template>
        </p>
        <p v-if="e.actor.kind === 'agent' && e.actor.id && e.actor.label" class="font-mono text-xs text-muted-foreground">
          {{ e.actor.id }}
        </p>
        <p v-if="e.actor.kind === 'integration' && e.actor.on_behalf_of" class="text-muted-foreground">
          Laut Portal für: <span class="break-words text-foreground">{{ e.actor.on_behalf_of }}</span>
        </p>
        <p v-if="e.actor.kind === 'cli'" class="text-xs text-muted-foreground">
          {{ COPY.cliHint }}
        </p>
        <p v-if="session">
          <span class="text-muted-foreground">Sitzung </span><span class="font-mono text-xs">{{ session }}</span>
          ·
          <RouterLink :to="auditLink({ session })" class="underline underline-offset-4 hover:no-underline" data-testid="audit-session-link">
            {{ e.action === 'session.start' ? 'Was diese Anmeldung getan hat' : 'Alles aus dieser Sitzung' }}
          </RouterLink>
        </p>
        <p v-if="token">
          <RouterLink :to="auditLink({ actor: token })" class="underline underline-offset-4 hover:no-underline" data-testid="audit-token-link">
            Alle Einträge dieses Tokens
          </RouterLink>
        </p>
      </dd>

      <dt class="text-muted-foreground">
        Weg
      </dt>
      <dd class="min-w-0" data-testid="audit-way">
        {{ wayLabel(op.way) }}
        <span v-if="op.name" class="font-mono text-xs break-all text-muted-foreground"> · {{ op.name }}</span>
      </dd>

      <dt class="text-muted-foreground">
        Woher
      </dt>
      <dd class="min-w-0" data-testid="audit-address">
        <IpAddress v-if="e.address" :ip="e.address" />
        <span v-else class="text-muted-foreground">{{ COPY.onHost }}</span>
      </dd>

      <dt class="text-muted-foreground">
        Was
      </dt>
      <dd class="min-w-0 space-y-1" data-testid="audit-subject">
        <p>
          {{ subjectLabel(kind) }}
          <span v-if="id" class="font-mono text-xs break-all">{{ id }}</span>
        </p>
        <p v-if="presence === 'gone'" class="text-muted-foreground" data-testid="audit-object-gone">
          {{ COPY.objectGone }}
        </p>
        <p v-else-if="link">
          <RouterLink :to="link.to" class="underline underline-offset-4 hover:no-underline" data-testid="audit-object-link">
            {{ link.label }}
          </RouterLink>
        </p>
        <p>
          <RouterLink :to="auditLink(historyFilters(e))" class="underline underline-offset-4 hover:no-underline" data-testid="audit-history-link">
            {{ id ? COPY.history : `Alle Einträge zu „${subjectLabel(kind)}“` }}
          </RouterLink>
        </p>
        <p v-if="kind === 'token' && id">
          <RouterLink :to="auditLink({ actor: id })" class="underline underline-offset-4 hover:no-underline" data-testid="audit-token-did-link">
            Was dieses Token getan hat
          </RouterLink>
        </p>
      </dd>

      <template v-if="e.website">
        <dt class="text-muted-foreground">
          Website
        </dt>
        <dd class="min-w-0 space-y-1" data-testid="audit-website">
          <p>
            <RouterLink v-if="siteKnown" :to="websitePath(e.website)" class="underline underline-offset-4 hover:no-underline" data-testid="audit-website-link">
              {{ websiteName(site, e.website) }}
            </RouterLink>
            <template v-else>
              <span class="font-mono text-xs break-all">{{ e.website }}</span>
              <span v-if="websites.data.value" class="text-muted-foreground" data-testid="audit-website-gone"> · Diese Website gibt es hier nicht mehr.</span>
            </template>
          </p>
          <p>
            <RouterLink :to="auditLink({ website: e.website })" class="underline underline-offset-4 hover:no-underline" data-testid="audit-website-entries">
              Alle Einträge dieser Website
            </RouterLink>
          </p>
        </dd>
      </template>

      <template v-if="causeEvent || causeIncident">
        <dt class="text-muted-foreground">
          Anlass
        </dt>
        <dd class="min-w-0 space-y-1" data-testid="audit-cause">
          <p>
            {{ causeEvent ? 'Ereignis' : 'Vorfall' }}
            <span class="font-mono text-xs break-all">{{ causeEvent ?? causeIncident }}</span>
          </p>
          <p v-if="causeGone" class="text-muted-foreground" data-testid="audit-cause-gone">
            {{ causeEvent ? COPY.eventGone : COPY.incidentGone }}
          </p>
          <p v-else>
            <RouterLink
              :to="causeEvent ? { path: '/events', query: { event: causeEvent, time: 'all' } } : `/incidents/${causeIncident}`"
              class="underline underline-offset-4 hover:no-underline"
              data-testid="audit-cause-link"
            >
              {{ causeEvent ? 'Ereignis ansehen' : 'Zum Vorfall' }}
            </RouterLink>
          </p>
          <p>
            <RouterLink :to="auditLink(causeEvent ? { event: causeEvent } : { incident: causeIncident! })" class="underline underline-offset-4 hover:no-underline" data-testid="audit-cause-entries">
              {{ causeEvent ? 'Alles, was wegen dieses Ereignisses geändert wurde' : 'Alles, was wegen dieses Vorfalls geändert wurde' }}
            </RouterLink>
          </p>
        </dd>
      </template>

      <template v-if="e.reason">
        <dt class="text-muted-foreground">
          Begründung
        </dt>
        <dd class="min-w-0 break-words whitespace-pre-wrap" data-testid="audit-reason">
          {{ e.reason }}
        </dd>
      </template>
    </dl>

    <section v-if="fields.length || e.change?.more_fields" aria-labelledby="audit-fields-title" class="space-y-2">
      <h3 id="audit-fields-title" class="font-medium">
        Vorher und nachher
      </h3>
      <ul class="divide-y rounded-xl border" data-testid="audit-fields">
        <li v-for="f in fields" :key="f.field" class="space-y-1 px-3 py-2" data-testid="audit-field" :data-field="f.field">
          <p class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-xs break-all">{{ f.field }}</span>
            <span class="text-xs text-muted-foreground">{{ FIELD_CHANGE[f.change] ?? f.change }}</span>
          </p>
          <p v-if="f.hidden" class="text-muted-foreground" data-testid="audit-hidden" :data-hidden="f.hidden">
            {{ hiddenText(f.hidden) }}
          </p>
          <template v-else>
            <dl v-if="f.before !== undefined || f.after !== undefined" class="grid grid-cols-[4.5rem_1fr] gap-x-2 gap-y-0.5">
              <template v-if="f.before !== undefined">
                <dt class="text-muted-foreground">
                  Vorher
                </dt>
                <dd class="min-w-0 font-mono text-[13px] break-all whitespace-pre-wrap" data-testid="audit-before">
                  {{ valueText(f.before) }}
                </dd>
              </template>
              <template v-if="f.after !== undefined">
                <dt class="text-muted-foreground">
                  Nachher
                </dt>
                <dd class="min-w-0 font-mono text-[13px] break-all whitespace-pre-wrap" data-testid="audit-after">
                  {{ valueText(f.after) }}
                </dd>
              </template>
            </dl>
            <p v-if="f.added?.length" data-testid="audit-added">
              <span class="text-muted-foreground">Dazu: </span>
              <span v-for="(x, i) in f.added" :key="x" class="font-mono text-[13px] break-all">{{ i ? ', ' : '' }}{{ x }}</span>
            </p>
            <p v-if="f.removed?.length" data-testid="audit-removed">
              <span class="text-muted-foreground">Weg: </span>
              <span v-for="(x, i) in f.removed" :key="x" class="font-mono text-[13px] break-all">{{ i ? ', ' : '' }}{{ x }}</span>
            </p>
            <p v-if="f.more" class="text-xs text-muted-foreground" data-testid="audit-more">
              und {{ formatNumber(f.more) }} weitere, die der Eintrag nicht nennt
            </p>
            <p v-if="f.cut" class="text-xs text-muted-foreground" data-testid="audit-cut">
              Der Wert war länger. Der Eintrag hält nur den Anfang fest.
            </p>
          </template>
        </li>
        <li v-if="e.change?.more_fields" class="px-3 py-2 text-muted-foreground" data-testid="audit-more-fields">
          {{ moreFieldsText(e.change.more_fields) }}
        </li>
      </ul>
    </section>

    <p class="text-xs text-muted-foreground">
      Server <span class="font-mono">{{ e.node }}</span> · Eintrag <span class="font-mono break-all" data-testid="audit-id">{{ e.id }}</span>
    </p>
  </div>
</template>
