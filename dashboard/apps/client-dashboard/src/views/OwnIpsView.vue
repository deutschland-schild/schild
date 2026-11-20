<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { AllowlistEntry, Ttl } from '@/api/types'
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataTable,
  ErrorState,
  Input,
  Label,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  RelativeTime,
  Skeleton,
  StatusPill,
  toast,
} from '@schild/ui'
import { Plus, Trash2, UserCheck } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, h, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage } from '@/api/client'
import { deleteAllowlistEntry, hideAllowlistEntry, keys, useAllowlist, useAllowMyIp, useMyIp } from '@/api/queries'
import AllowIpDialog from '@/components/AllowIpDialog.vue'
import { useShortcuts } from '@/composables/useShortcuts'
import { ALLOW_LEVELS, ATTRIBUTION, TTLS } from '@/lib/labels'

const route = useRoute()
const router = useRouter()
const qc = useQueryClient()
const my = useMyIp()
const list = useAllowlist()
const items = computed(() => list.data.value?.pages.flatMap(p => p.items) ?? [])

// "Meine IP freischalten"
const ttl = ref<Ttl>('7d')
const label = ref('Meine IP')
const allowMine = useAllowMyIp()
async function allowMe() {
  try {
    const entry = await allowMine.mutateAsync({ label: label.value.trim() || 'Meine IP', ttl: ttl.value })
    toast.success(`Deine IP ${entry.ip ?? ''} ist freigeschaltet`, {
      description: ttl.value === 'never' ? 'Dauerhaft.' : `Für ${TTLS.find(t => t.value === ttl.value)?.label}.`,
      action: { label: 'Rückgängig', onClick: () => remove(entry, true) },
    })
  }
  catch (err) {
    toast.error('Freischalten hat nicht geklappt', { description: errorMessage(err) })
  }
}

// Add dialog, also via ?new=1 (command palette)
const addOpen = ref(false)
watch(() => route.query.new, (v) => {
  if (v === '1') {
    addOpen.value = true
    const query = { ...route.query }
    delete query.new
    void router.replace({ query })
  }
}, { immediate: true })
useShortcuts([
  { keys: 'n', label: 'Neuen Eintrag anlegen', group: 'Eigene IPs', run: () => (addOpen.value = true) },
])

/**
 * Delete with undo: the entry disappears at once, the DELETE is sent after 6 s unless undone.
 * If the tab closes before that, the entry simply stays (the safe direction).
 */
function remove(entry: AllowlistEntry, immediate = false) {
  const restore = hideAllowlistEntry(qc, entry.id)
  const commit = async () => {
    try {
      await deleteAllowlistEntry(entry.id)
    }
    catch (err) {
      restore()
      toast.error('Löschen hat nicht geklappt', { description: errorMessage(err) })
    }
    finally {
      void qc.invalidateQueries({ queryKey: keys.allowlist })
      void qc.invalidateQueries({ queryKey: keys.myip })
    }
  }
  if (immediate) {
    void commit().then(() => toast('Freischaltung zurückgenommen'))
    return
  }
  const timer = setTimeout(commit, 6000)
  toast(`${target(entry)} entfernt`, {
    description: 'Schild prüft diese Absender wieder wie alle anderen.',
    duration: 6000,
    action: {
      label: 'Rückgängig',
      onClick: () => {
        clearTimeout(timer)
        restore()
      },
    },
  })
}

function target(e: AllowlistEntry) {
  return e.ip ?? e.cidr ?? e.host ?? e.id
}
function kind(e: AllowlistEntry) {
  return e.ip ? 'IP' : e.cidr ? 'Bereich' : 'DynDNS'
}

const columns: ColumnDef<AllowlistEntry, unknown>[] = [
  {
    id: 'target',
    header: 'Eintrag',
    accessorFn: e => target(e),
    enableHiding: false,
    meta: { label: 'Eintrag', class: 'min-w-48' },
    cell: ({ row }) => h('div', { class: 'min-w-0' }, [
      h('p', { class: 'font-mono text-[13px] break-all' }, target(row.original)),
      h('p', { class: 'text-xs text-muted-foreground' }, [
        kind(row.original),
        row.original.resolved?.length ? ` · gerade: ${row.original.resolved.join(', ')}` : '',
      ]),
    ]),
  },
  { id: 'label', header: 'Bezeichnung', accessorKey: 'label', meta: { label: 'Bezeichnung' } },
  {
    id: 'level',
    header: 'Umfang',
    accessorKey: 'level',
    meta: { label: 'Umfang', hideOnMobile: true },
    cell: ({ row }) => h(StatusPill, { tone: row.original.level === 'bypass_waf' ? 'warning' : 'neutral', size: 'sm', title: ALLOW_LEVELS[row.original.level].explain }, () => ALLOW_LEVELS[row.original.level].label),
  },
  {
    id: 'expires',
    header: 'Gültig',
    accessorFn: e => e.expires === 'never' ? '9999' : e.expires,
    meta: { label: 'Gültig' },
    cell: ({ row }) => {
      const e = row.original
      if (e.expired) return h(StatusPill, { tone: 'neutral', size: 'sm' }, () => 'Abgelaufen')
      if (e.expires === 'never') return h('span', {}, 'Dauerhaft')
      return h('span', {}, ['bis ', h(RelativeTime, { value: e.expires })])
    },
  },
  {
    id: 'source',
    header: 'Angelegt',
    accessorKey: 'source',
    meta: { label: 'Angelegt', hideOnMobile: true },
    cell: ({ row }) => h('span', { class: 'text-muted-foreground' }, [
      row.original.source === 'config' ? 'schild.yaml' : row.original.source === 'cli' ? 'Kommandozeile' : 'Dashboard',
      ', ',
      h(RelativeTime, { value: row.original.created_at }),
    ]),
  },
  {
    id: 'actions',
    header: () => h('span', { class: 'sr-only' }, 'Aktionen'),
    enableSorting: false,
    enableHiding: false,
    meta: { class: 'w-12 text-right' },
    cell: ({ row }) => row.original.source === 'config'
      ? h('span', { class: 'text-xs text-muted-foreground', title: 'Steht in schild.yaml. Dort ändern.' }, 'yaml')
      : h(Button, { 'variant': 'ghost', 'size': 'icon-sm', 'aria-label': `${target(row.original)} entfernen`, 'data-testid': 'allow-delete', 'onClick': () => remove(row.original) }, () => h(Trash2, { 'aria-hidden': 'true' })),
  },
]
</script>

<template>
  <div>
    <PageHeader title="Eigene IPs" description="Absender, die Schild nie sperrt: du selbst, dein Büro, deine Agentur. Die Liste bleibt auf deinem Server.">
      <template #actions>
        <Button data-testid="allow-add" @click="addOpen = true">
          <Plus aria-hidden="true" />
          Hinzufügen
        </Button>
      </template>
    </PageHeader>

    <Card class="mb-6" data-testid="my-ip-card">
      <CardHeader>
        <CardTitle>Meine IP freischalten</CardTitle>
        <CardDescription>Damit du dich beim Arbeiten an deiner Website nicht selbst aussperrst.</CardDescription>
      </CardHeader>
      <CardContent>
        <div v-if="my.isPending.value" class="space-y-2">
          <Skeleton class="h-6 w-56" />
          <Skeleton class="h-9 w-full max-w-md" />
        </div>
        <p v-else-if="my.isError.value" class="text-sm text-muted-foreground">
          Deine IP lässt sich gerade nicht ermitteln. {{ errorMessage(my.error.value) }}
        </p>
        <div v-else-if="my.data.value" class="space-y-4">
          <p class="flex flex-wrap items-center gap-2 text-sm">
            So sieht Schild dich:
            <span class="font-mono text-base font-medium" data-testid="my-ip">{{ my.data.value.ip }}</span>
            <span class="text-muted-foreground">({{ ATTRIBUTION[my.data.value.attribution] ?? my.data.value.attribution }})</span>
            <StatusPill v-if="my.data.value.allowlisted" tone="success" size="sm" data-testid="my-ip-allowed">
              Freigeschaltet
            </StatusPill>
          </p>
          <form v-if="!my.data.value.allowlisted" class="flex flex-col gap-3 sm:flex-row sm:items-end" @submit.prevent="allowMe">
            <div class="grid gap-1.5">
              <Label for="mine-label">Bezeichnung</Label>
              <Input id="mine-label" v-model="label" maxlength="64" class="sm:w-48" />
            </div>
            <div class="grid gap-1.5">
              <Label for="mine-ttl">Wie lange?</Label>
              <NativeSelect id="mine-ttl" v-model="ttl" class="sm:w-40" data-testid="mine-ttl">
                <NativeSelectOption v-for="t in TTLS" :key="t.value" :value="t.value">
                  {{ t.label }}
                </NativeSelectOption>
              </NativeSelect>
            </div>
            <Button type="submit" :disabled="allowMine.isPending.value" data-testid="allow-mine">
              <UserCheck aria-hidden="true" />
              Meine IP freischalten
            </Button>
          </form>
          <p v-else class="text-sm text-muted-foreground">
            Ändert sich deine Adresse oft (z. B. zu Hause)? Dann trag lieber einen DynDNS-Namen ein.
          </p>
        </div>
      </CardContent>
    </Card>

    <ErrorState v-if="list.isError.value && !items.length" title="Die Liste lässt sich gerade nicht laden" :description="errorMessage(list.error.value)" @retry="list.refetch()" />
    <DataTable
      v-else
      :columns="columns"
      :data="items"
      label="Freigeschaltete Absender"
      :loading="list.isPending.value"
      :get-row-id="(e: AllowlistEntry) => e.id"
      cursor
      :has-more="list.hasNextPage.value"
      :loading-more="list.isFetchingNextPage.value"
      empty-title="Noch niemand freigeschaltet"
      empty-description="Trag hier deine eigene IP, dein Büro oder Monitoring-Dienste ein. Schild sperrt sie dann nie."
      hide-column-menu
      @load-more="list.fetchNextPage()"
    />

    <div class="mt-6 grid gap-4 text-sm md:grid-cols-2">
      <div v-for="(meta, key) in ALLOW_LEVELS" :key="key" class="rounded-xl border p-4">
        <p class="font-medium">
          {{ meta.label }}
        </p>
        <p class="mt-1 text-muted-foreground">
          {{ meta.explain }}
        </p>
      </div>
    </div>

    <AllowIpDialog v-model:open="addOpen" />
  </div>
</template>
