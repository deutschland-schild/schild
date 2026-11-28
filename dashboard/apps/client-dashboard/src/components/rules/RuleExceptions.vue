<script setup lang="ts">
import type { RuleExceptionInput } from '@/api/rules'
import type { RuleException } from '@/api/types'
import type { ExceptionGroup } from '@/lib/rules'
import { Plus, Trash2, X } from '@lucide/vue'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, formatDateTime, formatNumber, MetaLine, Skeleton, toast } from '@schild/ui'
import { computed, ref } from 'vue'
import { problemOf } from '@/api/client'
import { exceptionError, useRemoveRuleException, useRemoveRuleExceptionRule, useRuleExceptions } from '@/api/rules'
import { useWebsites } from '@/api/websites'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import { explainRule } from '@/lib/explain'
import { websitePath } from '@/lib/nav'
import { exceptionField, exceptionRuleFamilies, groupExceptions, REPOSITORIES, rulesPath } from '@/lib/rules'
import { websiteName } from '@/lib/websites'
import RuleExceptionDialog from './RuleExceptionDialog.vue'

/**
 * The rule exceptions in force (D83): where schild leaves named rules out, why, and who set it. Set and
 * removed here (D84) or through the agent API. Exceptions for the same field are one entry: an exception
 * holds 16 rules, so more rules arrive in parts. A single rule comes out with its ×, the rest stays (D86).
 * Without `always` the card hides while there are none.
 */
const props = defineProps<{ repository?: RuleException['repository'], always?: boolean }>()
const q = useRuleExceptions()
const items = computed(() => groupExceptions((q.data.value?.items ?? []).filter(x => !props.repository || x.repository === props.repository)))
const websites = useWebsites()
const siteName = (id: string) => websiteName(websites.data.value?.websites.find(w => w.id === id), id)
const countText = (n: number) => n === 1 ? '1 Regel ausgenommen' : `${formatNumber(n)} Regeln ausgenommen`
/** Up to this many rules are listed open; more fold behind their kinds. */
const OPEN_RULES = 16
/** Who set the parts: one text when all agree. */
const setByAll = (g: ExceptionGroup) => [...new Set(g.parts.map(setBy))]
const setBy = (x: RuleException) => x.set_by === 'dashboard' ? 'im Dashboard gesetzt' : x.token_label ? `gesetzt von Agent „${x.token_label}“` : 'von einem Agenten gesetzt'

const createOpen = ref(false)
const preset = ref<Partial<RuleExceptionInput>>({})
/** Open the form, with what the page already knows; a hint or a rule passes the rest. */
function create(with_: Partial<RuleExceptionInput> = {}) {
  preset.value = { ...(props.repository ? { repository: props.repository } : {}), ...with_ }
  createOpen.value = true
}
defineExpose({ create })

const removing = ref<ExceptionGroup | null>(null)
const removeOpen = computed({ get: () => !!removing.value, set: (v) => { if (!v) removing.value = null } })
const remove = useRemoveRuleException()
const removeError = ref<string | null>(null)
function askRemove(x: ExceptionGroup) {
  removeError.value = null
  removing.value = x
}
async function doRemove() {
  const x = removing.value
  if (!x) return
  try {
    // Every part, one after the other: each answer is the list that is left. A part someone else removed is fine.
    for (const part of x.parts) {
      await remove.mutateAsync(part.id).catch((err) => {
        if (problemOf(err)?.code !== 'not_found') throw err
      })
    }
    removing.value = null
    toast.success('Ausnahme entfernt', { description: `${x.first.path}: Schild prüft ${exceptionField(x.first.target).kind} ${exceptionField(x.first.target).name} wieder mit allen Regeln.` })
  }
  catch (err) {
    removeError.value = exceptionError(err)
  }
}

/** One rule out (D86): from the part that holds it; the entry stays for the others. */
const takingOut = ref<{ g: ExceptionGroup, rule: string } | null>(null)
const takeOutOpen = computed({ get: () => !!takingOut.value, set: (v) => { if (!v) takingOut.value = null } })
const takeOut = useRemoveRuleExceptionRule()
const takeOutError = ref<string | null>(null)
function askTakeOut(g: ExceptionGroup, rule: string) {
  takeOutError.value = null
  takingOut.value = { g, rule }
}
async function doTakeOut() {
  const t = takingOut.value
  const part = t?.g.parts.find(p => p.rules.includes(t.rule))
  if (!t || !part) return
  try {
    await takeOut.mutateAsync({ id: part.id, rule: t.rule })
    takingOut.value = null
    toast.success(`Regel ${t.rule} herausgenommen`, { description: `${t.g.first.path}: Schild prüft ${exceptionField(t.g.first.target).kind} ${exceptionField(t.g.first.target).name} wieder mit dieser Regel.` })
  }
  catch (err) {
    takeOutError.value = exceptionError(err)
  }
}
</script>

<template>
  <Card v-if="always || items.length" data-testid="rule-exceptions">
    <CardHeader>
      <div class="flex flex-wrap items-start justify-between gap-2">
        <CardTitle>Aktive Ausnahmen</CardTitle>
        <Button size="sm" data-testid="rule-exception-add" @click="create()">
          <Plus aria-hidden="true" />
          Ausnahme anlegen
        </Button>
      </div>
      <CardDescription>
        Hier lässt Schild einzelne Regeln aus: je Ausnahme nur für ein Feld auf einer Seite einer Website. Alle anderen Regeln, Felder und Seiten prüft es weiter. Du legst Ausnahmen hier an, ein Agent über die Agent-API.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <Skeleton v-if="q.isPending.value" class="h-20 w-full" />
      <p v-else-if="q.isError.value && !items.length" class="text-sm text-muted-foreground">
        Die Ausnahmen lassen sich gerade nicht laden.
      </p>
      <p v-else-if="!items.length" class="text-sm text-muted-foreground" data-testid="rule-exceptions-empty">
        Gerade keine. Jede Regel prüft jede Anfrage.
      </p>
      <ul v-else class="divide-y">
        <li v-for="g in items" :key="g.key" class="relative space-y-1.5 py-4 pr-10 first:pt-0 last:pb-0" data-testid="rule-exception" :data-exception="g.first.id">
          <Button variant="ghost" size="icon-sm" class="absolute top-3 right-0" :class="{ 'top-0': g === items[0] }" :aria-label="`Ausnahme für ${g.first.path} entfernen`" title="Ausnahme entfernen" data-testid="rule-exception-remove" @click="askRemove(g)">
            <Trash2 aria-hidden="true" />
          </Button>
          <p class="font-medium">
            <RouterLink :to="websitePath(g.first.website, 'events')" class="underline-offset-4 hover:underline">{{ siteName(g.first.website) }}</RouterLink>
            <span class="text-muted-foreground"> · </span>
            <span class="font-mono text-sm break-all">{{ g.first.path }}</span>
            <span class="text-muted-foreground"> · {{ exceptionField(g.first.target).kind }}</span>
            {{ ' ' }}<span class="font-mono text-sm break-all">{{ exceptionField(g.first.target).name }}</span>
          </p>
          <MetaLine
            :items="[
              REPOSITORIES[g.first.repository].name,
              countText(g.rules.length),
              `seit ${formatDateTime(g.first.created)}`,
              ...setByAll(g),
            ]"
          />
          <p v-if="g.reasons.length" class="text-sm text-pretty" data-testid="rule-exception-reason">
            <span class="text-muted-foreground">Begründung:</span> {{ g.reasons[0] }}
          </p>
          <details v-if="g.reasons.length > 1" class="text-sm" data-testid="rule-exception-more-reasons">
            <summary class="cursor-pointer text-xs text-muted-foreground underline-offset-4 hover:underline">
              {{ g.reasons.length === 2 ? 'Eine weitere Begründung' : `${g.reasons.length - 1} weitere Begründungen` }}
            </summary>
            <p v-for="r in g.reasons.slice(1)" :key="r" class="mt-1 text-pretty">
              {{ r }}
            </p>
          </details>
          <p v-if="g.rules.length <= OPEN_RULES" class="flex flex-wrap gap-x-2 gap-y-1 text-xs">
            <span class="text-muted-foreground">Regeln:</span>
            <span v-for="id in g.rules" :key="id" class="inline-flex items-center" data-testid="rule-exception-rule" :data-rule="id">
              <RouterLink :to="rulesPath(g.first.repository, id)" class="font-mono underline-offset-4 hover:underline">{{ id }}</RouterLink>
              <button type="button" class="inline-flex size-6 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-2" :aria-label="`Regel ${id} aus der Ausnahme nehmen`" title="Aus der Ausnahme nehmen" data-testid="rule-exception-rule-remove" @click="askTakeOut(g, id)">
                <X class="size-3" aria-hidden="true" />
              </button>
            </span>
          </p>
          <details v-else class="text-xs" data-testid="rule-exception-families">
            <summary class="cursor-pointer text-pretty underline-offset-4 hover:underline">
              <span class="text-muted-foreground">Regeln:</span>
              {{ exceptionRuleFamilies(g).map(f => `${f.title} (${f.rules.length})`).join(' · ') }}
            </summary>
            <div v-for="f in exceptionRuleFamilies(g)" :key="f.title" class="mt-2">
              <p class="text-muted-foreground">
                {{ f.title }}
              </p>
              <p class="flex flex-wrap gap-x-2 gap-y-1">
                <span v-for="id in f.rules" :key="id" class="inline-flex items-center" data-testid="rule-exception-rule" :data-rule="id">
                  <RouterLink :to="rulesPath(g.first.repository, id)" class="font-mono underline-offset-4 hover:underline">{{ id }}</RouterLink>
                  <button type="button" class="inline-flex size-6 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-2" :aria-label="`Regel ${id} aus der Ausnahme nehmen`" title="Aus der Ausnahme nehmen" data-testid="rule-exception-rule-remove" @click="askTakeOut(g, id)">
                    <X class="size-3" aria-hidden="true" />
                  </button>
                </span>
              </p>
            </div>
          </details>
        </li>
      </ul>
    </CardContent>

    <RuleExceptionDialog v-model:open="createOpen" :preset="preset" />
    <ConfirmDialog
      v-model:open="removeOpen"
      title="Ausnahme entfernen?"
      confirm-label="Entfernen"
      :pending="remove.isPending.value"
      :error="removeError"
      @confirm="doRemove"
    >
      <template v-if="removing">
        Schild prüft {{ exceptionField(removing.first.target).kind }} <span class="font-mono text-sm break-all">{{ exceptionField(removing.first.target).name }}</span> auf <span class="font-mono text-sm break-all">{{ removing.first.path }}</span> dann wieder mit {{ removing.rules.length === 1 ? `der Regel ${removing.rules[0]}` : removing.rules.length <= OPEN_RULES ? `den Regeln ${removing.rules.join(', ')}` : `allen ${formatNumber(removing.rules.length)} Regeln, die hier ausgenommen sind` }}. Das gilt sofort. Anfragen, die bisher durchkamen, kann Schild danach wieder sperren.
      </template>
    </ConfirmDialog>
    <ConfirmDialog
      v-model:open="takeOutOpen"
      :title="takingOut && takingOut.g.rules.length === 1 ? 'Ausnahme entfernen?' : 'Regel aus der Ausnahme nehmen?'"
      :confirm-label="takingOut && takingOut.g.rules.length === 1 ? 'Entfernen' : 'Herausnehmen'"
      :pending="takeOut.isPending.value"
      :error="takeOutError"
      @confirm="doTakeOut"
    >
      <template v-if="takingOut">
        Schild prüft {{ exceptionField(takingOut.g.first.target).kind }} <span class="font-mono text-sm break-all">{{ exceptionField(takingOut.g.first.target).name }}</span> auf <span class="font-mono text-sm break-all">{{ takingOut.g.first.path }}</span> dann wieder mit Regel {{ takingOut.rule }} ({{ explainRule(takingOut.rule).title }}).
        {{ takingOut.g.rules.length === 1 ? 'Es war die letzte Regel, damit ist die Ausnahme weg.' : takingOut.g.rules.length === 2 ? 'Die andere Regel bleibt ausgenommen.' : `Die anderen ${formatNumber(takingOut.g.rules.length - 1)} Regeln bleiben ausgenommen.` }}
        Das gilt sofort.
      </template>
    </ConfirmDialog>
  </Card>
</template>
