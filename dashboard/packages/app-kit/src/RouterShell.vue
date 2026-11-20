<script setup lang="ts">
import type { BreadcrumbEntry, CommandEntry, NavGroup } from '@schild/ui'
import { AppShell } from '@schild/ui'
import { computed, nextTick, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { breadcrumbsFor } from './routes'

/** AppShell wired to vue-router: active nav, breadcrumbs, palette navigation, focus to <main> after navigation. */
const props = withDefaults(defineProps<{
  appName: string
  appSubtitle?: string
  nav: NavGroup[]
  commands?: CommandEntry[]
  /** Replaces the breadcrumb built from the route (e.g. with the website's name). */
  breadcrumbs?: BreadcrumbEntry[]
}>(), {
  appSubtitle: undefined,
  commands: () => [],
  breadcrumbs: undefined,
})
const route = useRoute()
const router = useRouter()
const crumbs = computed(() => props.breadcrumbs ?? breadcrumbsFor(route, props.appName))

// Move focus to the main landmark after route changes so screen readers start at the new content.
watch(() => route.path, (_n, old) => {
  if (old === undefined) return
  nextTick(() => document.getElementById('main')?.focus({ preventScroll: true }))
})
</script>

<template>
  <AppShell
    :app-name="appName"
    :app-subtitle="appSubtitle"
    :nav="nav"
    :current-path="route.path"
    :breadcrumbs="crumbs"
    :commands="commands"
    @navigate="(to) => router.push(to)"
  >
    <template v-if="$slots.context" #context>
      <slot name="context" />
    </template>
    <template v-if="$slots.status" #status>
      <slot name="status" />
    </template>
    <template v-if="$slots.actions" #actions>
      <slot name="actions" />
    </template>
    <template v-if="$slots['sidebar-header']" #sidebar-header>
      <slot name="sidebar-header" />
    </template>
    <template v-if="$slots['sidebar-footer']" #sidebar-footer>
      <slot name="sidebar-footer" />
    </template>
    <slot />
  </AppShell>
</template>
