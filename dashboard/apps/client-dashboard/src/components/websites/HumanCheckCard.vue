<script setup lang="ts">
import type { HumanCheckMode, UnderAttackScope } from '@/api/humancheck'
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Label,
  toast,
} from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { errorMessage } from '@/api/client'
import { useHumanCheck, useSetHumanCheck } from '@/api/humancheck'

/**
 * Browser verification ("Kurze Prüfung") and Under Attack mode per website
 * (MVP-12 v1_cut): local SHA-256 PoW, no third-party service, no fingerprinting.
 */
const props = defineProps<{ site: string, siteName: string }>()
const q = useHumanCheck(() => props.site)
const set = useSetHumanCheck(() => props.site)
const policy = computed(() => q.data.value?.policy)
const counts = computed(() => q.data.value?.counts)

const mode = ref<HumanCheckMode>('off')
const uaScope = ref<UnderAttackScope>('admin')
const uaHours = ref<number>(1)

watch(policy, (p) => {
  if (!p) return
  mode.value = p.mode
  if (p.under_attack_active && p.under_attack.scope !== 'off') {
    uaScope.value = p.under_attack.scope
  }
}, { immediate: true })

const uaActive = computed(() => !!policy.value?.under_attack_active)
const uaUntilText = computed(() => {
  const raw = policy.value?.under_attack.until
  if (!raw || !uaActive.value) return ''
  const d = new Date(raw)
  return Number.isNaN(d.getTime()) ? raw : d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' })
})

async function saveMode(next: HumanCheckMode) {
  mode.value = next
  const cur = policy.value
  try {
    await set.mutateAsync({
      mode: next,
      ...(cur?.under_attack_active ? { under_attack: cur.under_attack } : { under_attack: { scope: 'off' } }),
      ...(cur?.except?.length ? { except: cur.except } : {}),
    })
    const label = next === 'off' ? 'ausgeschaltet' : next === 'findings' ? 'auf „Bei Auffälligkeiten“ gestellt' : 'auf „Immer“ gestellt'
    toast.success(`Browser-Prüfung für ${props.siteName} ${label}`)
  }
  catch (err) {
    if (cur) mode.value = cur.mode
    toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}

async function enableUnderAttack() {
  const until = new Date(Date.now() + uaHours.value * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
  const cur = policy.value
  try {
    await set.mutateAsync({
      mode: mode.value,
      under_attack: { scope: uaScope.value === 'off' ? 'admin' : uaScope.value, until },
      ...(cur?.except?.length ? { except: cur.except } : {}),
    })
    toast.success(`Under-Attack-Modus für ${props.siteName} aktiviert`)
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}

async function disableUnderAttack() {
  const cur = policy.value
  try {
    await set.mutateAsync({
      mode: mode.value,
      under_attack: { scope: 'off' },
      ...(cur?.except?.length ? { except: cur.except } : {}),
    })
    toast.success(`Under-Attack-Modus für ${props.siteName} beendet`)
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}
</script>

<template>
  <Card class="mb-4 min-w-0" data-testid="human-check-card">
    <CardHeader>
      <CardTitle>Browser-Prüfung &amp; Under Attack</CardTitle>
      <CardDescription>
        Kurze Rechenaufgabe direkt im Browser (SHA-256, ohne Drittanbieter und ohne Tracking) mit Button für Browser ohne JavaScript.
      </CardDescription>
    </CardHeader>
    <CardContent class="space-y-5 text-sm">
      <div class="space-y-2">
        <Label>Regulärer Modus</Label>
        <div class="flex flex-wrap gap-2" role="group" aria-label="Modus der Browser-Prüfung">
          <Button
            size="sm"
            :variant="mode === 'off' ? 'default' : 'outline'"
            :disabled="set.isPending.value || q.isPending.value"
            data-testid="human-check-mode-off"
            @click="saveMode('off')"
          >
            Aus
          </Button>
          <Button
            size="sm"
            :variant="mode === 'findings' ? 'default' : 'outline'"
            :disabled="set.isPending.value || q.isPending.value"
            data-testid="human-check-mode-findings"
            @click="saveMode('findings')"
          >
            Bei Auffälligkeiten
          </Button>
          <Button
            size="sm"
            :variant="mode === 'always' ? 'default' : 'outline'"
            :disabled="set.isPending.value || q.isPending.value"
            data-testid="human-check-mode-always"
            @click="saveMode('always')"
          >
            Immer
          </Button>
        </div>
        <p class="text-xs text-muted-foreground">
          „Bei Auffälligkeiten“ prüft CGNAT-, Mobilfunk- und Tor-Adressen bei Szenario-Treffern sowie aggressives Abrufen. „Immer“ prüft jeden neuen Seitenaufruf (z. B. gegen KI-Crawler). APIs, Webhooks und eigene IPs bleiben immer frei.
        </p>
      </div>

      <div class="space-y-2 border-t pt-4">
        <Label>Under Attack (zeitlich begrenzt, max. 24 Stunden)</Label>
        <p v-if="uaActive" class="font-medium text-status-warning" data-testid="under-attack-active">
          Aktiv ({{ policy?.under_attack.scope === 'all' ? 'ganze Website' : 'Admin- und Login-Seiten' }}) bis {{ uaUntilText }}.
        </p>
        <div class="flex flex-wrap items-center gap-2">
          <select
            v-model="uaScope"
            aria-label="Bereich für Under Attack"
            class="h-9 rounded-md border bg-background px-2.5 text-sm"
            :disabled="set.isPending.value"
          >
            <option value="admin">
              Nur Admin- &amp; Login-Seiten
            </option>
            <option value="all">
              Ganze Website
            </option>
          </select>
          <select
            v-model.number="uaHours"
            aria-label="Dauer für Under Attack"
            class="h-9 rounded-md border bg-background px-2.5 text-sm"
            :disabled="set.isPending.value"
          >
            <option :value="1">
              1 Stunde
            </option>
            <option :value="4">
              4 Stunden
            </option>
            <option :value="12">
              12 Stunden
            </option>
            <option :value="24">
              24 Stunden
            </option>
          </select>
          <Button
            size="sm"
            variant="destructive"
            :disabled="set.isPending.value || q.isPending.value"
            data-testid="under-attack-enable"
            @click="enableUnderAttack"
          >
            {{ uaActive ? 'Verlängern' : 'Under Attack aktivieren' }}
          </Button>
          <Button
            v-if="uaActive"
            size="sm"
            variant="outline"
            :disabled="set.isPending.value"
            data-testid="under-attack-disable"
            @click="disableUnderAttack"
          >
            Jetzt beenden
          </Button>
        </div>
      </div>

      <p v-if="counts" class="border-t pt-3 text-xs text-muted-foreground" data-testid="human-check-counts">
        Seit Start (alle Websites): {{ counts.served }} gezeigt · {{ counts.passed }} bestanden · {{ counts.nojs }} ohne JS · {{ counts.invalid }} ungültig
      </p>
    </CardContent>
  </Card>
</template>
