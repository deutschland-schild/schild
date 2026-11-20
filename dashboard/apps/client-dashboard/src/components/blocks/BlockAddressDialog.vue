<script setup lang="ts">
import type { BlockRequest } from '@/api/blocks'
import {
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  RadioGroup,
  RadioGroupItem,
  toast,
} from '@schild/ui'
import { computed, ref, useId, watch } from 'vue'
import { useCreateBlock } from '@/api/blocks'
import { errorMessage, fieldErrors, problemOf } from '@/api/client'
import { isIP } from '@/lib/ip'

/**
 * Block one address by hand (D88): for every website of this server, for 1 hour, 24 hours or 7 days, with a reason.
 * The firewall gets it within a second when `schild firewall run` is connected. Own, private and shared addresses
 * are refused by the gateway; a shared one (mobile, CGNAT, Tor) can be blocked after a confirmation.
 */
const props = withDefaults(defineProps<{ address?: string, presetReason?: string, presetShared?: boolean }>(), { address: '', presetReason: '', presetShared: false })
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ done: [] }>()

const DURATIONS = [
  { value: 3600, label: '1 Stunde' },
  { value: 86400, label: '24 Stunden' },
  { value: 604800, label: '7 Tage' },
] as const
const addr = ref('')
const duration = ref('86400')
const reason = ref('')
const sharedAsk = ref(false)
const sharedOk = ref(false)
const refused = ref<string | null>(null)
const touched = ref(false)
const serverErrors = ref<Record<string, string>>({})
const uid = useId()

watch(open, (v) => {
  if (!v) return
  addr.value = props.address
  duration.value = '86400'
  reason.value = props.presetReason
  sharedAsk.value = props.presetShared
  sharedOk.value = false
  refused.value = null
  touched.value = false
  serverErrors.value = {}
})

const addressError = computed(() => {
  if (serverErrors.value.address) return 'Eine einzelne IPv4- oder IPv6-Adresse, kein Netz und kein Name.'
  if (!touched.value) return null
  const v = addr.value.trim()
  if (!v) return 'Bitte ausfüllen.'
  return isIP(v) ? null : 'Das ist keine einzelne IP-Adresse. Netze wie 198.51.100.0/24 gehen hier nicht.'
})
const reasonError = computed(() => serverErrors.value.reason ? 'Eine Zeile, höchstens 300 Zeichen.' : touched.value && !reason.value.trim() ? 'Schreib kurz dazu, warum. Das steht später beim Vorfall.' : null)

const create = useCreateBlock()
async function submit() {
  touched.value = true
  serverErrors.value = {}
  refused.value = null
  if (addressError.value || reasonError.value) return
  const v = addr.value.trim()
  const body: BlockRequest = { address: v, duration_s: Number(duration.value) as BlockRequest['duration_s'], reason: reason.value.trim(), shared_ok: sharedOk.value }
  try {
    const b = await create.mutateAsync(body)
    open.value = false
    emit('done')
    toast.success(`${b.client} ist gesperrt`, {
      description: `${DURATIONS.find(d => d.value === b.duration_s)?.label ?? ''}, Vorfall ${b.incident}. ${b.firewall === 'off' ? 'Die Sperre gilt in Schild.' : 'Die Firewall übernimmt sie gleich.'}`,
    })
  }
  catch (err) {
    const p = problemOf(err)
    if (p?.code === 'shared_address') {
      sharedAsk.value = true
      refused.value = p.detail ?? null
      return
    }
    serverErrors.value = fieldErrors(err)
    if (!Object.keys(serverErrors.value).length) refused.value = p?.detail ?? errorMessage(err)
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg" data-testid="block-dialog">
      <form class="grid gap-5" novalidate @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>Adresse sperren</DialogTitle>
          <DialogDescription>
            Die Adresse bekommt auf allen Websites dieses Servers die Sperrseite. Ist die Firewall angebunden, kommt sie auch nicht mehr an die Ports 80 und 443. Die Sperre endet von selbst, aufheben kannst du sie jederzeit unter „Sperren“.
          </DialogDescription>
        </DialogHeader>

        <div class="grid gap-2">
          <Label :for="`${uid}-address`">IP-Adresse</Label>
          <Input :id="`${uid}-address`" v-model="addr" placeholder="203.0.113.7 oder 2001:db8::1" autocomplete="off" spellcheck="false" class="font-mono" :aria-invalid="!!addressError" data-testid="block-address" />
          <p :class="addressError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="addressError ? 'alert' : undefined">
            {{ addressError ?? 'Bei IPv6 sperrt Schild das ganze /64-Netz, das ist der Anschluss eines Haushalts.' }}
          </p>
        </div>

        <fieldset class="grid gap-2">
          <legend class="mb-2 text-sm font-medium">
            Wie lange?
          </legend>
          <RadioGroup v-model="duration" class="grid grid-cols-3 gap-2" aria-label="Dauer der Sperre">
            <Label v-for="d in DURATIONS" :key="d.value" :for="`${uid}-${d.value}`" class="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 font-normal has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-accent">
              <RadioGroupItem :id="`${uid}-${d.value}`" :value="String(d.value)" :data-testid="`block-duration-${d.value}`" />
              {{ d.label }}
            </Label>
          </RadioGroup>
        </fieldset>

        <div class="grid gap-2">
          <Label :for="`${uid}-reason`">Grund</Label>
          <Input :id="`${uid}-reason`" v-model="reason" maxlength="300" placeholder="z. B. Scanner, viele Aufrufe von /wp-login.php" :aria-invalid="!!reasonError" data-testid="block-reason" />
          <p v-if="reasonError" class="text-sm text-destructive" role="alert">
            {{ reasonError }}
          </p>
        </div>

        <Label v-if="sharedAsk" class="flex items-start gap-2 rounded-lg border border-status-warning/40 bg-status-warning-subtle p-3 font-normal" data-testid="block-shared">
          <Checkbox v-model="sharedOk" class="mt-0.5" data-testid="block-shared-ok" />
          <span>Ich weiß, dass ich damit alle sperre, die sich diese Adresse teilen.</span>
        </Label>
        <p v-if="refused" class="text-sm" :class="sharedAsk ? 'text-muted-foreground' : 'text-destructive'" role="alert" data-testid="block-refused">
          {{ refused }}
        </p>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="create.isPending.value || (sharedAsk && !sharedOk)" data-testid="block-submit">
            Sperren
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
