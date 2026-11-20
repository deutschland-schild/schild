<script setup lang="ts">
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Label,
  Switch,
  Textarea,
  toast,
} from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { useAccessProtection, useSetMaintenance } from '@/api/access'
import { errorMessage } from '@/api/client'
import { useAllowlist } from '@/api/queries'
import { ACCESS_COPY, MAINTENANCE_COPY as C } from '@/lib/access'

/**
 * The maintenance switch of a website (D98): the whole website closed with Eigene IPs as the only way in. A switch
 * of its own: it works with a Zugriffsschutz set, which stays as it is and still holds for whoever gets through.
 */
const props = defineProps<{ site: string, siteName: string }>()
const q = useAccessProtection(() => props.site)
const m = computed(() => q.data.value?.maintenance ?? null)
const on = computed(() => !!m.value?.on)
const hasProtection = computed(() => !!q.data.value?.protection)
const allow = useAllowlist()
const ownIps = computed(() => allow.data.value?.pages.reduce((n, pg) => n + pg.items.length, 0))
const set = useSetMaintenance(() => props.site)
const pending = computed(() => set.isPending.value)

const message = ref('')
watch(() => m.value?.message, v => (message.value = v ?? ''), { immediate: true })
const messageDirty = computed(() => on.value && message.value.trim() !== (m.value?.message ?? ''))

// The dialog closes before its action's click runs: the intent stays in `asking`, `askOpen` only shows it.
const asking = ref<'on' | 'off'>('on')
const askOpen = ref(false)
function ask(v: boolean) {
  asking.value = v ? 'on' : 'off'
  askOpen.value = true
}

async function turnOn() {
  try {
    await set.mutateAsync({ on: true, ...(message.value.trim() ? { message: message.value.trim() } : {}) })
    toast.success(`${props.siteName} ist im Wartungsmodus`)
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}
async function turnOff() {
  try {
    await set.mutateAsync({ on: false })
    toast.success(hasProtection.value ? `Wartungsmodus von ${props.siteName} ist aus, der Zugriffsschutz gilt weiter` : `${props.siteName} ist wieder für alle offen`)
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}
async function saveMessage() {
  try {
    await set.mutateAsync({ on: true, message: message.value.trim() })
    toast.success('Text der Wartungsseite gespeichert')
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}
async function confirm() {
  askOpen.value = false
  if (asking.value === 'on') await turnOn()
  else await turnOff()
}
</script>

<template>
  <Card class="mb-4 min-w-0" data-testid="maintenance-card">
    <CardHeader>
      <div class="flex items-start justify-between gap-4">
        <div class="grid gap-1.5">
          <CardTitle>{{ C.title }}</CardTitle>
          <CardDescription>{{ C.lead }}</CardDescription>
        </div>
        <Switch
          :model-value="on"
          :disabled="pending || q.isPending.value"
          :aria-label="C.switchLabel"
          data-testid="maintenance-switch"
          @update:model-value="ask"
        />
      </div>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <p v-if="on" class="font-medium" data-testid="maintenance-on">
        {{ C.on }}
      </p>
      <p v-if="ownIps !== undefined" :class="ownIps ? 'text-muted-foreground' : 'text-status-warning'" data-testid="maintenance-own-ips">
        {{ ownIps ? C.ownIps(ownIps) : C.noOwnIps }}
        <RouterLink to="/own-ips" class="font-medium text-foreground underline-offset-4 hover:underline">
          Eigene IPs
        </RouterLink>
      </p>
      <p v-if="hasProtection" class="text-muted-foreground" data-testid="maintenance-with-protection">
        {{ C.withProtection }}
      </p>
      <div class="grid gap-1.5">
        <Label for="maintenance-message">{{ C.message }}</Label>
        <Textarea id="maintenance-message" v-model="message" :maxlength="500" rows="2" :placeholder="ACCESS_COPY.messagePlaceholder" data-testid="maintenance-message" />
      </div>
      <Button v-if="messageDirty" size="sm" variant="outline" :disabled="pending" data-testid="maintenance-save-message" @click="saveMessage">
        {{ C.saveMessage }}
      </Button>
    </CardContent>
  </Card>

  <AlertDialog v-model:open="askOpen">
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>{{ asking === 'off' ? C.confirmOff : C.confirmOn }}</AlertDialogTitle>
        <AlertDialogDescription>
          <template v-if="asking === 'off'">
            {{ C.confirmOffText }}
          </template>
          <template v-else>
            {{ C.confirmOnText }} {{ ownIps ? C.ownIps(ownIps) : C.noOwnIps }}
          </template>
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>Abbrechen</AlertDialogCancel>
        <AlertDialogAction data-testid="maintenance-confirm" @click="confirm">
          {{ asking === 'off' ? 'Ausschalten' : 'Einschalten' }}
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
