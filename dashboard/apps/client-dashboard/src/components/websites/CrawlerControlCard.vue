<script setup lang="ts">
import type { CrawlerAction, CrawlerCatalogueEntry, CrawlerCategory, CrawlerPolicy, CrawlerPolicyInput } from '@/api/crawlers'
import type { BotStats, CrawlerRule } from '@/lib/crawlers'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, formatNumber, Label, RelativeTime, SegmentedControl, Skeleton, Switch, toast } from '@schild/ui'
import { ChevronRight, Eye } from '@lucide/vue'
import { computed, ref } from 'vue'
import { errorMessage, statusOf } from '@/api/client'
import { useCrawlerPolicy, useSetCrawlerPolicy } from '@/api/crawlers'
import { useOverview } from '@/api/queries'
import { useBotOverview } from '@/api/requests'
import {
  ACTION_LABEL,
  applyPreset,
  blockedText,
  categoryAction,
  categorySummary,
  changeText,
  CRAWLER_CATEGORIES,
  CRAWLERS_COPY as C,
  effectiveAction,
  emptyPolicy,
  isPresetApplied,
  ownRule,
  policyInput,
  presetInput,
  rangesNote,
  withBot,
  withCategory,
  withImpersonators,
} from '@/lib/crawlers'
import { botCategoryLabel, robotsText } from '@/lib/requests'

/**
 * KI-Crawler of a website (D57, MVP-29): one button for the preset, a switch for impersonators, the eleven
 * catalogue categories with Erlauben/Blocken, each expandable to its crawlers with an own rule. Every change
 * is saved at once with the whole policy (no save button, no password prompt). Per crawler the numbers of the
 * last 24 hours come from the bot overview of this website.
 */
const props = defineProps<{ site: string, siteName: string }>()
const q = useCrawlerPolicy(() => props.site)
const set = useSetCrawlerPolicy(() => props.site)
const overview = useOverview()
const observe = computed(() => overview.data.value?.profile === 'test')
const bots = useBotOverview(() => ({ site: props.site, range: '24h' }))
const rangesHint = computed(() => rangesNote(bots.data.value))

/** While a change is on its way, show it already (the answer replaces it). */
const pending = ref<CrawlerPolicy | null>(null)
const stored = computed(() => q.data.value?.policy ?? emptyPolicy())
const policy = computed(() => pending.value ?? stored.value)
const presetOn = computed(() => isPresetApplied(policy.value))
/** The button undoes itself: with KI-Training blocked it allows the category again (other rules stay). */
const aiBlocked = computed(() => categoryAction(policy.value, 'ai_training') === 'block')

const byCategory = computed(() => {
  const m = new Map<CrawlerCategory, CrawlerCatalogueEntry[]>()
  for (const c of CRAWLER_CATEGORIES) m.set(c, [])
  for (const c of q.data.value?.crawlers ?? []) m.get(c.category)?.push(c)
  for (const list of m.values()) list.sort((a, b) => (stats.value.get(b.id)?.requests ?? 0) - (stats.value.get(a.id)?.requests ?? 0) || a.name.localeCompare(b.name, 'de'))
  return m
})
const stats = computed(() => new Map<string, BotStats>((bots.data.value?.bots ?? []).map(b => [b.id, b])))
const categoryRequests = computed(() => new Map((bots.data.value?.categories ?? []).map(c => [c.category, c.requests])))
const open = ref<Set<CrawlerCategory>>(new Set())
function toggle(c: CrawlerCategory) {
  const s = new Set(open.value)
  if (s.has(c)) s.delete(c)
  else s.add(c)
  open.value = s
}

async function save(body: CrawlerPolicyInput, optimistic: CrawlerPolicy, done: string) {
  pending.value = optimistic
  try {
    await set.mutateAsync(body)
    toast.success(C.saved, { description: done })
  }
  catch (err) {
    toast.error(C.failed, { description: statusOf(err) === 409 ? C.notBehindSchild : errorMessage(err) })
  }
  finally {
    pending.value = null
  }
}

function setCategory(c: CrawlerCategory, a: CrawlerAction) {
  if (categoryAction(policy.value, c) === a) return
  const next = withCategory(policy.value, c, a)
  void save(policyInput(next), next, changeText({ category: c }, a))
}
function setBot(c: CrawlerCatalogueEntry, r: CrawlerRule) {
  if (ownRule(policy.value, c.id) === r) return
  const next = withBot(policy.value, c.id, r)
  void save(policyInput(next), next, changeText({ bot: c.id, name: c.name }, r))
}
function setImpersonators(on: boolean) {
  const a: CrawlerAction = on ? 'block' : 'allow'
  const next = withImpersonators(policy.value, a)
  void save(policyInput(next), next, changeText({ impersonators: a }, a))
}
function doPreset() {
  if (aiBlocked.value) setCategory('ai_training', 'allow')
  else void save(presetInput(), applyPreset(policy.value), `${C.preset}: ${props.siteName}`)
}

const categoryOptions = [{ value: 'allow' as const, label: C.allow }, { value: 'block' as const, label: C.block }]
const ruleOptions = [{ value: 'inherit' as const, label: C.inherit }, { value: 'allow' as const, label: C.allow }, { value: 'block' as const, label: C.block }]
</script>

<template>
  <div class="space-y-4" data-testid="crawlers">
    <div v-if="observe" class="flex items-center gap-3 rounded-xl border border-status-info/30 bg-status-info-subtle px-4 py-2.5 text-sm" role="note" data-testid="crawlers-observe">
      <Eye class="size-4 shrink-0 text-status-info" aria-hidden="true" />
      <p>{{ C.observe }}</p>
    </div>

    <Card class="min-w-0">
      <CardHeader>
        <CardTitle>{{ C.title }}</CardTitle>
        <CardDescription>{{ C.lead }} {{ C.scope }}</CardDescription>
      </CardHeader>
      <CardContent class="space-y-5 text-sm">
        <Skeleton v-if="q.isPending.value" class="h-24 w-full" />
        <ErrorState v-else-if="q.isError.value" title="Die Crawler-Regeln lassen sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
        <template v-else>
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div class="grid max-w-prose gap-0.5">
              <p class="font-medium">
                {{ C.preset }}
              </p>
              <p class="text-muted-foreground" data-testid="crawlers-preset-text">
                {{ presetOn ? C.presetActive : aiBlocked ? C.presetBlocked : C.presetExplain }}
              </p>
            </div>
            <Button :variant="aiBlocked ? 'outline' : 'default'" :disabled="set.isPending.value" data-testid="crawlers-preset" @click="doPreset">
              {{ aiBlocked ? C.presetUndo : C.preset }}
            </Button>
          </div>
          <Label class="flex items-center justify-between gap-3 leading-snug font-normal">
            <span>
              <span class="block font-medium">{{ C.impersonators }}</span>
              <span class="block text-muted-foreground">{{ C.impersonatorsExplain }}</span>
              <span v-if="rangesHint" class="mt-1 block text-status-warning" data-testid="crawlers-ranges">{{ rangesHint }}</span>
            </span>
            <Switch
              :model-value="policy.impersonators === 'block'"
              :disabled="set.isPending.value"
              data-testid="crawlers-impersonators"
              @update:model-value="(v: boolean) => setImpersonators(v)"
            />
          </Label>
          <p v-if="q.data.value?.updated_at" class="text-xs text-muted-foreground" data-testid="crawlers-updated">
            Zuletzt geändert <RelativeTime :value="q.data.value.updated_at" />{{ q.data.value.actor === 'agent' ? ' von einem Agenten' : ' im Dashboard' }}
          </p>
        </template>
      </CardContent>
    </Card>

    <Card v-if="q.data.value" class="min-w-0">
      <CardHeader>
        <CardTitle>{{ C.categories }}</CardTitle>
        <CardDescription>{{ C.categoriesLead }} {{ C.ownIps }}</CardDescription>
      </CardHeader>
      <CardContent class="text-sm">
        <ul class="divide-y" data-testid="crawlers-categories">
          <li v-for="cat in CRAWLER_CATEGORIES" :key="cat" class="py-2.5" :data-crawler-category="cat">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <button
                type="button"
                class="flex min-w-0 items-center gap-2 rounded-sm text-left focus-visible:outline-2 focus-visible:outline-ring"
                :aria-expanded="open.has(cat)"
                :aria-controls="`crawlers-${cat}`"
                :data-testid="`crawlers-open-${cat}`"
                @click="toggle(cat)"
              >
                <ChevronRight class="size-4 shrink-0 transition-transform" :class="open.has(cat) ? 'rotate-90' : ''" aria-hidden="true" />
                <span class="grid">
                  <span class="font-medium">{{ botCategoryLabel(cat) }}</span>
                  <span class="text-xs text-muted-foreground">
                    {{ categorySummary(policy, byCategory.get(cat) ?? []) }}<template v-if="categoryRequests.get(cat)"> · {{ formatNumber(categoryRequests.get(cat)!) }} Anfragen</template>
                  </span>
                </span>
              </button>
              <SegmentedControl
                :model-value="categoryAction(policy, cat)"
                :options="categoryOptions"
                :label="`${botCategoryLabel(cat)}: erlauben oder blocken`"
                :disabled="set.isPending.value"
                :data-testid="`crawlers-category-${cat}`"
                @update:model-value="(v: CrawlerAction) => setCategory(cat, v)"
              />
            </div>
            <div v-if="open.has(cat)" :id="`crawlers-${cat}`" class="mt-2 pl-6">
              <p v-if="!(byCategory.get(cat) ?? []).length" class="text-muted-foreground">
                {{ C.noCrawlers }}
              </p>
              <div v-else class="overflow-x-auto">
                <table class="w-full min-w-[720px] tabular-nums">
                  <caption class="sr-only">
                    Crawler der Kategorie {{ botCategoryLabel(cat) }} mit Anfragen, Blockiert, robots.txt und Regel
                  </caption>
                  <thead class="text-xs text-muted-foreground">
                    <tr>
                      <th scope="col" class="pb-1.5 text-left font-medium">
                        Crawler
                      </th>
                      <th scope="col" class="w-20 pb-1.5 text-right font-medium">
                        Anfragen
                      </th>
                      <th scope="col" class="w-32 pb-1.5 pl-3 text-left font-medium">
                        Blockiert
                      </th>
                      <th scope="col" class="w-40 pb-1.5 text-left font-medium" title="Beachtet der Crawler deine robots.txt?">
                        robots.txt: hält sich daran?
                      </th>
                      <th scope="col" class="pb-1.5 text-left font-medium">
                        Regel
                      </th>
                    </tr>
                  </thead>
                  <tbody class="divide-y">
                    <tr v-for="c in byCategory.get(cat)" :key="c.id" :data-crawler="c.id" :data-effective="effectiveAction(policy, c)">
                      <th scope="row" class="py-1.5 pr-2 text-left font-normal">
                        <span class="font-medium">{{ c.name }}</span>
                        <span class="block text-xs text-muted-foreground">{{ c.operator }} · {{ ACTION_LABEL[effectiveAction(policy, c)] }}</span>
                      </th>
                      <td class="py-1.5 text-right">
                        {{ stats.get(c.id) ? formatNumber(stats.get(c.id)!.requests) : '–' }}
                      </td>
                      <td class="py-1.5 pl-3" :data-blocked="c.id">
                        {{ blockedText(stats.get(c.id)) }}
                      </td>
                      <td class="py-1.5 text-xs">
                        <span v-if="stats.get(c.id)?.robots" :data-robots="stats.get(c.id)!.robots!.respects">{{ robotsText(stats.get(c.id)!.robots!) }}</span>
                        <span v-else class="text-muted-foreground">–</span>
                      </td>
                      <td class="py-1.5">
                        <SegmentedControl
                          :model-value="ownRule(policy, c.id)"
                          :options="ruleOptions"
                          :label="`Regel für ${c.name}`"
                          :disabled="set.isPending.value"
                          :data-testid="`crawlers-bot-${c.id}`"
                          @update:model-value="(v: CrawlerRule) => setBot(c, v)"
                        />
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </li>
        </ul>
        <p class="mt-3 text-xs text-muted-foreground" data-testid="crawlers-window">
          {{ bots.isError.value ? C.statsMissing : C.window }}
          <template v-if="q.data.value.catalogue_version">
            Bot-Liste Version {{ q.data.value.catalogue_version }}.
          </template>
        </p>
      </CardContent>
    </Card>
  </div>
</template>
