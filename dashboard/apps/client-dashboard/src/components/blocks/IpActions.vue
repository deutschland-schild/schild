<script setup lang="ts">
import { Button, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger, toast } from '@schild/ui'
import { Ban, Clock, Ellipsis, UserCheck } from '@lucide/vue'
import { computed, nextTick, ref } from 'vue'
import { useCreateBlock } from '@/api/blocks'
import { errorMessage, problemOf } from '@/api/client'
import { useUnblock } from '@/api/queries'
import AllowIpDialog from '../AllowIpDialog.vue'
import BlockAddressDialog from './BlockAddressDialog.vue'

/**
 * What can be done with one address, in the event panel and in the lists of events and requests
 * (initiator 2026-11-18). One click blocks with the given reason and offers "Rückgängig" in the toast:
 * data-centre addresses for 7 days (scanners on rented servers keep them), every other address for 24 hours
 * (a home address often belongs to someone else the next day). A shared address (mobile, CGNAT, Tor) still
 * needs the confirmation of the dialog. The rare actions sit in the "…" menu: another duration and Eigene IPs.
 *
 * inline: the block button stands beside the menu (event panel); else everything is in the menu (a list row).
 */
const props = withDefaults(defineProps<{
  ip: string
  reason: string
  netClass?: string
  canBlock?: boolean
  canAllow?: boolean
  inline?: boolean
  /** Label of the allowlist entry, e.g. "Vorfall K7QM-4XWD". */
  allowLabel?: string
  testid?: string
}>(), { netClass: '', canBlock: true, canAllow: true, inline: false, allowLabel: '', testid: 'ip' })

const quick = computed(() => props.netClass === 'hosting'
  ? { s: 604800 as const, label: '7 Tage' }
  : { s: 86400 as const, label: '24 Stunden' })
const reasonText = computed(() => props.reason.slice(0, 300))

const blockOpen = ref(false)
const blockShared = ref(false)
const allowOpen = ref(false)
// A list has a menu per row: the dialogs mount at their first use, then open (they reset on open).
const blockMounted = ref(false)
const allowMounted = ref(false)
async function show(mounted: typeof blockMounted, open: typeof blockOpen) {
  mounted.value = true
  await nextTick()
  open.value = true
}

const createBlock = useCreateBlock()
const unblock = useUnblock()
function openBlock(shared = false) {
  blockShared.value = shared
  void show(blockMounted, blockOpen)
}
function openAllow() {
  void show(allowMounted, allowOpen)
}
async function quickBlock() {
  try {
    const b = await createBlock.mutateAsync({ address: props.ip, duration_s: quick.value.s, reason: reasonText.value, shared_ok: false })
    toast.success(`${b.client} ist für ${quick.value.label} gesperrt`, {
      description: `Vorfall ${b.incident}. ${b.firewall === 'off' ? 'Die Sperre gilt in Schild.' : 'Die Firewall übernimmt sie gleich.'}`,
      action: {
        label: 'Rückgängig',
        onClick: () => void unblock.mutateAsync({ incident: b.incident, body: { false_positive: false, allow_ip: false, allow_ttl: '24h', note: 'Gleich wieder zurückgenommen' } })
          .then(() => toast.success(`Sperre von ${b.client} zurückgenommen`))
          .catch(err => toast.error('Zurücknehmen hat nicht geklappt', { description: errorMessage(err) })),
      },
    })
  }
  catch (err) {
    if (problemOf(err)?.code === 'shared_address') return openBlock(true)
    toast.error('Sperren hat nicht geklappt', { description: errorMessage(err) })
  }
}
</script>

<template>
  <Button v-if="inline && canBlock" size="sm" variant="outline" :disabled="createBlock.isPending.value" :data-testid="`${testid}-block-ip`" @click="quickBlock">
    <Ban aria-hidden="true" />
    IP für {{ quick.label }} sperren
  </Button>
  <DropdownMenu v-if="canBlock || canAllow">
    <DropdownMenuTrigger as-child>
      <Button :size="inline ? 'sm' : 'icon-sm'" variant="ghost" :aria-label="`Weitere Aktionen für ${ip}`" :data-testid="`${testid}-more`">
        <Ellipsis aria-hidden="true" />
      </Button>
    </DropdownMenuTrigger>
    <DropdownMenuContent :align="inline ? 'start' : 'end'">
      <DropdownMenuItem v-if="!inline && canBlock" :disabled="createBlock.isPending.value" :data-testid="`${testid}-block-ip`" @select="quickBlock">
        <Ban aria-hidden="true" />
        IP für {{ quick.label }} sperren
      </DropdownMenuItem>
      <DropdownMenuItem v-if="canBlock" :data-testid="`${testid}-block-other`" @select="openBlock()">
        <Clock aria-hidden="true" />
        Andere Dauer …
      </DropdownMenuItem>
      <DropdownMenuSeparator v-if="canBlock && canAllow" />
      <DropdownMenuItem v-if="canAllow" :data-testid="`${testid}-allow-ip`" @select="openAllow">
        <UserCheck aria-hidden="true" />
        Zu Eigene IPs hinzufügen …
      </DropdownMenuItem>
    </DropdownMenuContent>
  </DropdownMenu>
  <BlockAddressDialog v-if="blockMounted" v-model:open="blockOpen" :address="ip" :preset-reason="reasonText" :preset-shared="blockShared" />
  <AllowIpDialog v-if="allowMounted" v-model:open="allowOpen" :ip="ip" :label="allowLabel" />
</template>
