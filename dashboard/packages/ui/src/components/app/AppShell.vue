<script setup lang="ts">
import type { Component } from 'vue'
import type { BreadcrumbEntry, CommandEntry, NavGroup } from './types'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@schild/ui/components/ui/breadcrumb'
import { Button } from '@schild/ui/components/ui/button'
import { Separator } from '@schild/ui/components/ui/separator'
import { SidebarInset, SidebarProvider, SidebarTrigger } from '@schild/ui/components/ui/sidebar'
import { Toaster } from '@schild/ui/components/ui/sonner'
import { Search } from '@lucide/vue'
import { computed, ref } from 'vue'
import AppSidebar from './AppSidebar.vue'
import BrandMark from './BrandMark.vue'
import CommandPalette from './CommandPalette.vue'
import { useLinkComponent } from './link'
import ThemeToggle from './ThemeToggle.vue'

/**
 * Application frame: collapsible sidebar (icon rail on desktop, sheet on mobile),
 * top bar with breadcrumb, cmd+k palette, theme switch and an actions slot.
 * Router-agnostic: pass `currentPath` and listen to `navigate` (RouterLink is used when registered).
 */
const props = withDefaults(defineProps<{
  appName: string
  appSubtitle?: string
  nav: NavGroup[]
  currentPath: string
  breadcrumbs?: BreadcrumbEntry[]
  /** Extra palette entries; all nav items are added automatically. */
  commands?: CommandEntry[]
  homePath?: string
  linkComponent?: Component | string
}>(), {
  appSubtitle: undefined,
  breadcrumbs: () => [],
  commands: () => [],
  homePath: '/',
  linkComponent: undefined,
})
const emit = defineEmits<{ navigate: [to: string] }>()

const paletteOpen = ref(false)
const { is: linkIs, props: linkProps } = useLinkComponent(props.linkComponent)
/** Groups that lead the palette, before the pages (the server and its websites). */
const LEADING = new Set(['Server', 'Websites'])
const allCommands = computed<CommandEntry[]>(() => [
  ...props.commands.filter(c => LEADING.has(c.group ?? '')),
  ...props.nav.flatMap(g => g.items.flatMap(i => [i, ...(i.children ?? [])])).filter(i => !i.hideInPalette).map(i => ({
    id: `nav:${i.to}`,
    label: i.label,
    group: 'Seiten',
    icon: i.icon,
    to: i.to,
    keywords: i.keywords,
  })),
  ...props.commands.filter(c => !LEADING.has(c.group ?? '')),
])
</script>

<template>
  <SidebarProvider>
    <a
      href="#main"
      class="sr-only z-50 rounded-md bg-background px-3 py-2 text-sm font-medium shadow focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
    >Zum Inhalt springen</a>
    <AppSidebar
      :app-name="appName"
      :app-subtitle="appSubtitle"
      :nav="nav"
      :current-path="currentPath"
      :home-path="homePath"
      :link-component="linkComponent"
    >
      <template v-if="$slots['sidebar-header']" #header>
        <slot name="sidebar-header" />
      </template>
      <template v-if="$slots['sidebar-footer']" #footer>
        <slot name="sidebar-footer" />
      </template>
    </AppSidebar>
    <SidebarInset class="min-w-0">
      <header class="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 border-b bg-card/95 px-3 backdrop-blur supports-[backdrop-filter]:bg-card/85 sm:px-4">
        <SidebarTrigger class="-ml-1" />
        <Separator orientation="vertical" class="mr-1 data-[orientation=vertical]:h-4" />
        <BrandMark :size="20" class="md:hidden" />
        <!--
          Breadcrumb keeps its natural width and only shrinks (truncates) when space runs out; no fixed minimum,
          so the header fits at 360 px. The context line takes leftover space only (basis 0), so on desktop it
          never squeezes the breadcrumb.
        -->
        <Breadcrumb class="min-w-0 shrink overflow-hidden text-[13px]" data-slot="shell-breadcrumb">
          <BreadcrumbList class="flex-nowrap">
            <template v-for="(b, i) in breadcrumbs" :key="`${i}-${b.label}`">
              <BreadcrumbItem :class="i < breadcrumbs.length - 1 ? 'hidden sm:inline-flex' : 'min-w-0'">
                <BreadcrumbLink v-if="b.to && i < breadcrumbs.length - 1" as-child>
                  <component :is="linkIs" v-bind="linkProps(b.to)">
                    {{ b.label }}
                  </component>
                </BreadcrumbLink>
                <BreadcrumbPage v-else class="truncate">
                  {{ b.label }}
                </BreadcrumbPage>
              </BreadcrumbItem>
              <BreadcrumbSeparator v-if="i < breadcrumbs.length - 1" class="hidden sm:inline-flex" />
            </template>
          </BreadcrumbList>
        </Breadcrumb>
        <p v-if="$slots.context" class="hidden min-w-0 flex-1 basis-0 truncate text-xs text-muted-foreground xl:block" data-slot="shell-context">
          <slot name="context" />
        </p>
        <div class="ml-auto flex shrink-0 items-center gap-1 sm:gap-2" data-slot="shell-actions">
          <slot name="status" />
          <Button
            variant="outline"
            size="sm"
            class="border-border font-medium text-muted-foreground hover:bg-muted"
            aria-keyshortcuts="Meta+K Control+K"
            @click="paletteOpen = true"
          >
            <Search aria-hidden="true" />
            <span class="hidden md:inline">Suchen</span>
            <span class="sr-only md:hidden">Suchen</span>
          </Button>
          <slot name="actions" />
          <ThemeToggle />
        </div>
      </header>
      <main id="main" tabindex="-1" class="mx-auto w-full max-w-7xl flex-1 px-4 py-5 focus:outline-none sm:px-6 sm:py-6 lg:px-8">
        <slot />
      </main>
    </SidebarInset>
    <CommandPalette v-model:open="paletteOpen" :commands="allCommands" @navigate="(to) => emit('navigate', to)" />
    <Toaster position="bottom-right" rich-colors close-button />
  </SidebarProvider>
</template>
