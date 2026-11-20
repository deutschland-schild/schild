<script setup lang="ts">
import type { Component } from 'vue'
import type { NavGroup, NavItem } from './types'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInput,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  SidebarRail,
  useSidebar,
} from '@schild/ui/components/ui/sidebar'
import { reactive } from 'vue'
import BrandMark from './BrandMark.vue'
import { isActivePath, useLinkComponent } from './link'
import StatusDot from './StatusDot.vue'

const props = defineProps<{
  appName: string
  appSubtitle?: string
  nav: NavGroup[]
  currentPath: string
  homePath?: string
  linkComponent?: Component | string
}>()
const { is: linkIs, props: linkProps } = useLinkComponent(props.linkComponent)
const { isMobile, setOpenMobile } = useSidebar()

function active(item: NavItem): boolean {
  if (item.selected) return false
  if (item.exact ? props.currentPath === item.to : isActivePath(props.currentPath, item.to)) return true
  return (item.activeOn ?? []).some(p => isActivePath(props.currentPath, p))
}

/** Text of the filter field per group (groups with `filter` only). */
const query = reactive<Record<string, string>>({})
const groupKey = (group: NavGroup, gi: number) => group.label ?? String(gi)
function visible(group: NavGroup, gi: number): NavItem[] {
  const q = (query[groupKey(group, gi)] ?? '').trim().toLowerCase()
  if (!group.filter || !q) return group.items
  return group.items.filter(i => [i.label, ...(i.keywords ?? [])].some(t => t.toLowerCase().includes(q)))
}

function onNavigate() {
  if (isMobile.value) setOpenMobile(false)
}
</script>

<template>
  <Sidebar collapsible="icon">
    <SidebarHeader>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton size="lg" as-child :tooltip="appName">
            <component :is="linkIs" v-bind="linkProps(homePath ?? '/')" @click="onNavigate">
              <span class="flex aspect-square size-8 items-center justify-center">
                <BrandMark :size="28" />
              </span>
              <span class="grid flex-1 text-left leading-tight">
                <span class="truncate font-bold">{{ appName }}</span>
                <span v-if="appSubtitle" class="truncate text-xs text-muted-foreground">{{ appSubtitle }}</span>
              </span>
            </component>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
      <!-- e.g. a website switcher below the brand -->
      <slot name="header" />
    </SidebarHeader>
    <SidebarContent>
      <nav aria-label="Hauptnavigation" class="contents">
        <SidebarGroup v-for="(group, gi) in nav" :key="groupKey(group, gi)">
          <SidebarGroupLabel v-if="group.label">
            {{ group.label }}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <div v-if="group.filter" class="px-0.5 pb-1.5 group-data-[collapsible=icon]:hidden">
              <SidebarInput
                v-model="query[groupKey(group, gi)]"
                type="search"
                :placeholder="group.filter.placeholder"
                :aria-label="group.filter.label"
                data-testid="nav-filter"
              />
            </div>
            <SidebarMenu>
              <SidebarMenuItem v-for="item in visible(group, gi)" :key="item.to" :data-nav-item="item.to">
                <SidebarMenuButton
                  as-child
                  :is-active="active(item)"
                  :tooltip="item.label"
                  :class="item.selected ? 'font-medium' : undefined"
                >
                  <component
                    :is="linkIs"
                    v-bind="linkProps(item.to)"
                    :aria-current="active(item) ? 'page' : undefined"
                    :data-selected="item.selected ? '' : undefined"
                    @click="onNavigate"
                  >
                    <component :is="item.icon" v-if="item.icon" aria-hidden="true" />
                    <span v-else-if="item.dot" class="flex size-4 shrink-0 items-center justify-center">
                      <StatusDot :tone="item.dot" :label="item.dotLabel" />
                    </span>
                    <span class="min-w-0 flex-1 truncate">{{ item.label }}</span>
                    <span v-if="item.meta" class="ml-auto shrink-0 text-xs font-normal text-muted-foreground tabular-nums" data-slot="nav-meta">{{ item.meta }}</span>
                    <StatusDot v-if="item.dot && item.icon" :tone="item.dot" :label="item.dotLabel" class="ml-auto" />
                  </component>
                </SidebarMenuButton>
                <SidebarMenuSub v-if="item.children?.length">
                  <SidebarMenuSubItem v-for="sub in item.children" :key="sub.to">
                    <SidebarMenuSubButton as-child :is-active="active(sub)">
                      <component
                        :is="linkIs"
                        v-bind="linkProps(sub.to)"
                        :aria-current="active(sub) ? 'page' : undefined"
                        @click="onNavigate"
                      >
                        <span class="flex-1">{{ sub.label }}</span>
                        <span v-if="sub.badge !== undefined && sub.badge !== 0" class="ml-auto inline-flex h-5 min-w-5 items-center justify-center rounded-md bg-secondary px-1.5 text-xs font-semibold text-secondary-foreground tabular-nums">{{ sub.badge }}</span>
                      </component>
                    </SidebarMenuSubButton>
                  </SidebarMenuSubItem>
                </SidebarMenuSub>
                <!-- A count of open items: a small sand badge, so it reads as a count and not as a plain number next to the label. -->
                <SidebarMenuBadge v-if="item.badge !== undefined && item.badge !== 0" class="rounded-md bg-secondary px-1.5 font-semibold text-secondary-foreground tabular-nums peer-hover/menu-button:text-secondary-foreground peer-data-[active=true]/menu-button:text-secondary-foreground">
                  {{ item.badge }}
                </SidebarMenuBadge>
              </SidebarMenuItem>
            </SidebarMenu>
            <p v-if="group.filter && !visible(group, gi).length" class="px-2 py-1.5 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">
              {{ group.filter.empty }}
            </p>
          </SidebarGroupContent>
        </SidebarGroup>
      </nav>
    </SidebarContent>
    <SidebarFooter v-if="$slots.footer">
      <slot name="footer" />
    </SidebarFooter>
    <SidebarRail />
  </Sidebar>
</template>
