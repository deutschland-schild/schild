<script setup lang="ts">
import type { RuleRepository } from '@/api/types'
import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, Input, NativeSelect, NativeSelectOption, toast } from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { fieldErrors } from '@/api/client'
import { ruleError, useUpdateRuleRepositorySettings } from '@/api/rules'
import { CRS_LEVELS, CRS_SINGLE_HIT, crsSettingsText } from '@/lib/rules'

/**
 * Paranoia level and blocking threshold of the CRS (D101). A value equal to the one of schild.yaml is not
 * sent, so the file keeps deciding it; saving both as they stand there removes what the dashboard set.
 */
const props = defineProps<{ repo: RuleRepository }>()
const open = defineModel<boolean>('open', { default: false })

const level = ref(1)
const threshold = ref(5)
const touched = ref(false)
const server = ref<Record<string, string>>({})
const failed = ref<string | null>(null)

const crs = computed(() => props.repo.crs)
const config = computed(() => ({ level: crs.value?.config_paranoia_level ?? 1, threshold: crs.value?.config_inbound_anomaly_threshold ?? 5 }))

watch(open, (v) => {
  if (!v || !crs.value) return
  level.value = crs.value.paranoia_level
  threshold.value = crs.value.inbound_anomaly_threshold
  touched.value = false
  server.value = {}
  failed.value = null
}, { immediate: true })

const atConfig = computed(() => level.value === config.value.level && threshold.value === config.value.threshold)
function fillConfig() {
  level.value = config.value.level
  threshold.value = config.value.threshold
}

const errors = computed(() => ({
  level: server.value.paranoia_level ? 'Eine Stufe von 1 bis 4.' : null,
  threshold: server.value.inbound_anomaly_threshold || (touched.value && !(Number.isInteger(threshold.value) && threshold.value >= 1 && threshold.value <= 100))
    ? 'Eine ganze Zahl zwischen 1 und 100.'
    : null,
}))

const update = useUpdateRuleRepositorySettings()
async function submit() {
  touched.value = true
  server.value = {}
  failed.value = null
  if (Object.values(errors.value).some(Boolean)) return
  const body = {
    ...(level.value !== config.value.level ? { paranoia_level: level.value } : {}),
    ...(threshold.value !== config.value.threshold ? { inbound_anomaly_threshold: threshold.value } : {}),
  }
  try {
    const r = await update.mutateAsync({ id: props.repo.id, body })
    open.value = false
    toast.success(atConfig.value ? 'OWASP CRS: wieder wie in schild.yaml' : 'OWASP CRS: Werte geändert', { description: r.crs ? `${crsSettingsText(r.crs.paranoia_level, r.crs.inbound_anomaly_threshold)}.` : undefined })
  }
  catch (err) {
    server.value = fieldErrors(err)
    if (!Object.keys(server.value).length) failed.value = ruleError(err)
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <form class="grid gap-5" novalidate data-testid="crs-settings-form" @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>Strenge und Schwelle von OWASP CRS</DialogTitle>
          <DialogDescription>
            Beide Werte gelten für alle Websites auf diesem Server. Schild lädt die Regeln nach dem Speichern neu, ohne Neustart.
          </DialogDescription>
        </DialogHeader>

        <div class="grid gap-2">
          <label for="crs-settings-level" class="text-sm font-medium">Strenge (Paranoia-Level)</label>
          <NativeSelect id="crs-settings-level" v-model.number="level" :aria-invalid="!!errors.level" data-testid="crs-settings-level">
            <NativeSelectOption v-for="l in CRS_LEVELS" :key="l.value" :value="l.value">
              {{ l.label }}
            </NativeSelectOption>
          </NativeSelect>
          <p v-if="errors.level" class="text-sm text-destructive" role="alert">
            {{ errors.level }}
          </p>
          <p class="text-sm text-muted-foreground" data-testid="crs-settings-level-hint">
            <template v-if="level > 1">
              Ab Stufe 2 laufen zusätzliche Regeln. Sie finden mehr und schlagen öfter bei normalen Anfragen an. Stell OWASP CRS vorher für ein paar Tage auf „Erkennen“ und sieh dir die Treffer an.
            </template>
            <template v-else>
              Stufe 1 ist der Stand ab Werk. Jede höhere Stufe lädt zusätzliche Regeln.
            </template>
          </p>
        </div>

        <div class="grid gap-2">
          <span class="text-sm font-medium">Schwelle</span>
          <div class="flex flex-wrap items-center gap-2 text-sm">
            <span>Sperrt ab</span>
            <Input v-model.number="threshold" type="number" min="1" max="100" class="w-24" aria-label="Punkte, ab denen gesperrt wird" :aria-invalid="!!errors.threshold" data-testid="crs-settings-threshold" />
            <span>Punkten</span>
          </div>
          <p v-if="errors.threshold" class="text-sm text-destructive" role="alert">
            {{ errors.threshold }}
          </p>
          <p class="text-sm text-muted-foreground">
            Ein kritischer Treffer zählt 5 Punkte, ein leichterer 2 bis 4.
          </p>
          <p v-if="threshold > CRS_SINGLE_HIT" class="rounded-xl border border-status-warning/40 bg-status-warning-subtle p-3 text-sm" role="status" data-testid="crs-settings-threshold-hint">
            Über 5 Punkten kommt eine Anfrage mit einem einzelnen kritischen Treffer durch.
          </p>
        </div>

        <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl border bg-muted p-3 text-sm">
          <p data-testid="crs-settings-config">
            <span class="font-medium">In schild.yaml:</span> {{ crsSettingsText(config.level, config.threshold) }}
          </p>
          <Button v-if="!atConfig" type="button" variant="outline" size="sm" data-testid="crs-settings-reset" @click="fillConfig">
            Werte aus schild.yaml einsetzen
          </Button>
        </div>

        <p v-if="failed" class="text-sm text-destructive" role="alert">
          {{ failed }}
        </p>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="update.isPending.value" data-testid="crs-settings-submit">
            {{ update.isPending.value ? 'Wird gespeichert …' : 'Speichern' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
