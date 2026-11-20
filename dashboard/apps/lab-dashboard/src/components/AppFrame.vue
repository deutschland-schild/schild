<script setup lang="ts">
import type { CommandEntry, NavGroup } from '@schild/ui'
import { navFromRoutes, RouterShell } from '@schild/app-kit'
import { Button, StatusPill, toast } from '@schild/ui'
import { Keyboard, LogOut, Pause, Undo2 } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { apiUrl } from '@/api/client'
import { useHealth, useProposals, useWithdrawals } from '@/api/queries'
import { useLogout, useSession } from '@/composables/useSession'
import { useShortcuts } from '@/composables/useShortcuts'
import { live, setPaused, startLive } from '@/lib/live'
import { APP_NAME, routes } from '@/router'
import LiveControl from './LiveControl.vue'
import ShortcutsDialog from './ShortcutsDialog.vue'

const isMock = import.meta.env.VITE_MOCK === 'true'
const router = useRouter()
const qc = useQueryClient()
const { session, user } = useSession()
const logout = useLogout()

// Badges: proposals waiting for review, withdrawals waiting for this lab's co-signature.
const review = useProposals('review')
const withdrawals = useWithdrawals()
const health = useHealth()
const needsCosign = computed(() => {
  const lab = health.data.value?.lab
  if (!lab) return 0
  return withdrawals.items.value.filter(w => w.status === 'collecting' && !w.signatures.some(s => s.lab === lab)).length
})
const nav = computed<NavGroup[]>(() => navFromRoutes(routes).map(g => ({
  ...g,
  items: g.items.map((i) => {
    if (i.to === '/proposals' && review.items.value.length) return { ...i, badge: review.items.value.length }
    if (i.to === '/published' && needsCosign.value) return { ...i, badge: needsCosign.value }
    return i
  }),
})))

const shortcutsOpen = ref(false)
const commands = computed<CommandEntry[]>(() => [
  { id: 'shortcuts', label: 'Tastenkürzel anzeigen', group: 'Aktionen', icon: Keyboard, shortcut: '?', run: () => (shortcutsOpen.value = true) },
  { id: 'pause', label: live.paused ? 'Aktualisierung fortsetzen' : 'Aktualisierung pausieren', group: 'Aktionen', icon: Pause, run: () => setPaused(qc, !live.paused) },
  { id: 'logout', label: 'Abmelden', group: 'Aktionen', icon: LogOut, run: () => logout.mutate() },
  // Opens only the page; withdrawing needs the dialog there.
  { id: 'withdrawals', label: 'Netzregeln zurückziehen', group: 'Aktionen', icon: Undo2, keywords: ['rückzug', 'rückzüge', 'alle netzregeln zurückziehen', 'mitzeichnen', 'withdraw'], to: '/published/withdrawals' },
  ...review.items.value.map(p => ({ id: `proposal:${p.id}`, label: `Vorschlag prüfen: ${p.rule_id}`, group: 'Vorschläge in Prüfung', keywords: [p.id, p.target.software], to: `/proposals/${p.id}` })),
])

const NAV_KEYS: [string, string, string][] = [
  ['g o', '/', 'Überblick'],
  ['g s', '/signals', 'Signale & Muster'],
  ['g v', '/proposals', 'Vorschläge'],
  ['g b', '/published', 'Veröffentlicht'],
  ['g r', '/relays', 'Relays & Peers'],
  ['g c', '/clients', 'Clients & Bürgen'],
  ['g l', '/log', 'Öffentliches Log'],
  ['g e', '/settings', 'Einstellungen'],
]
useShortcuts([
  { keys: '?', description: 'Tastenkürzel anzeigen', run: () => (shortcutsOpen.value = true) },
  ...NAV_KEYS.map(([keys, to, label]) => ({ keys, description: `Gehe zu ${label}`, group: 'Navigation', run: () => void router.push(to) })),
])

let stop: (() => void) | undefined
onMounted(() => {
  stop = startLive(qc, { url: apiUrl('/events/stream') })
})
onUnmounted(() => stop?.())

function doLogout() {
  logout.mutate(undefined, { onSuccess: () => toast.success('Abgemeldet') })
}
</script>

<template>
  <RouterShell :app-name="APP_NAME" app-subtitle="Lab-Dashboard" :nav="nav" :commands="commands">
    <template v-if="health.data.value" #context>
      Lab <span class="text-foreground">{{ health.data.value.lab }}</span> · Betreiber <span class="text-foreground">{{ health.data.value.operator }}</span><template v-if="health.data.value.profile === 'test'">
        · Testprofil
      </template>
    </template>
    <template #status>
      <StatusPill v-if="isMock" tone="info" size="sm" class="hidden sm:inline-flex">
        Testdaten
      </StatusPill>
      <LiveControl />
    </template>
    <template #sidebar-footer>
      <div class="flex items-center gap-2 px-2 py-1 text-sm group-data-[collapsible=icon]:hidden">
        <div class="min-w-0 flex-1">
          <p class="truncate font-medium">
            {{ user }}
          </p>
          <p class="truncate text-xs text-muted-foreground">
            {{ session?.role === 'readonly' ? 'Nur lesen' : 'Admin' }} · {{ session?.via === 'localhost' ? 'localhost' : 'Passwort' }}
          </p>
        </div>
        <Button variant="ghost" size="icon-sm" aria-label="Abmelden" @click="doLogout">
          <LogOut aria-hidden="true" />
        </Button>
      </div>
    </template>
    <RouterView />
    <ShortcutsDialog v-model:open="shortcutsOpen" />
  </RouterShell>
</template>
