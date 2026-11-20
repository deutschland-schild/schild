<script setup lang="ts">
import type { WebsiteSummary } from '@/api/websites'
import { StatusDot } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed } from 'vue'
import { useOverview } from '@/api/queries'
import { useRunningBlocks } from '@/composables/useRunningBlocks'
import { websitePath } from '@/lib/nav'
import { baselineView } from '@/lib/summary'
import { WEBSITE_COPY } from '@/lib/websites'

/**
 * One calm line at the top of Zugriffe (D68) so security is not hidden on the start page of a website:
 * the Grundschutz of the server, whether part of the website runs without schild, and the running blocks
 * of this website with a link to its Ereignisse. Data the dashboard loads anyway (getOverview, the website,
 * listBehaviourHits).
 */
const props = defineProps<{ site: string, website?: WebsiteSummary }>()

const overview = useOverview()
const gs = computed(() => overview.data.value ? baselineView(overview.data.value) : null)
const { count } = useRunningBlocks(() => props.site)
const eventsPath = computed(() => websitePath(props.site, 'events'))
</script>

<template>
  <p v-if="gs" class="mb-4 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-xl border bg-card px-4 py-2 text-sm" data-testid="website-status-line">
    <span class="inline-flex items-center gap-2" data-testid="status-baseline">
      <StatusDot :tone="gs.tone" />
      <span class="font-medium">{{ gs.tone === 'warning' ? WEBSITE_COPY.statusDegraded : gs.title }}</span>
    </span>
    <template v-if="gs.tone !== 'signal'">
      <span aria-hidden="true" class="text-muted-foreground">·</span>
      <RouterLink to="/settings" class="underline-offset-4 hover:underline">
        Details ansehen
      </RouterLink>
    </template>
    <template v-if="website?.protection === 'partial'">
      <span aria-hidden="true" class="text-muted-foreground">·</span>
      <span class="text-muted-foreground" data-testid="status-partial">{{ WEBSITE_COPY.statusPartial }}</span>
    </template>
    <template v-if="count === 0">
      <span aria-hidden="true" class="text-muted-foreground">·</span>
      <span class="text-muted-foreground">{{ WEBSITE_COPY.statusNoBlocks }}</span>
    </template>
    <span aria-hidden="true" class="text-muted-foreground">·</span>
    <RouterLink :to="eventsPath" class="inline-flex items-center gap-1 font-medium underline-offset-4 hover:underline" data-testid="status-to-events">
      {{ count ? WEBSITE_COPY.statusBlocks(count) : WEBSITE_COPY.statusToEvents }}
      <ArrowRight class="size-3.5" aria-hidden="true" />
    </RouterLink>
  </p>
</template>
