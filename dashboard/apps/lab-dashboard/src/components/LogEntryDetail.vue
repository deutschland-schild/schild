<script setup lang="ts">
import type { LogEntry } from '@/api/types'
import type { EntryCheck } from '@/lib/logverify'
import { formatDateTime, JsonView, Skeleton } from '@schild/ui'
import { ref, watch } from 'vue'
import { useLogEntry } from '@/api/queries'
import { checkEntry } from '@/lib/logverify'
import CheckBadge from './CheckBadge.vue'

const props = defineProps<{ entry: LogEntry }>()
const q = useLogEntry(() => props.entry.index)
const result = ref<EntryCheck | null>(null)
watch(() => q.data.value, async (e) => {
  result.value = e ? await checkEntry(e) : null
}, { immediate: true })
</script>

<template>
  <div class="space-y-4 text-sm">
    <dl class="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2">
      <dt class="text-muted-foreground">
        Index
      </dt>
      <dd class="tabular-nums">
        {{ entry.index }}
      </dd>
      <dt class="text-muted-foreground">
        Zeit
      </dt>
      <dd>{{ formatDateTime(entry.time) }}</dd>
      <dt class="text-muted-foreground">
        Bezug
      </dt>
      <dd class="font-mono">
        {{ entry.ref }}
      </dd>
      <dt class="text-muted-foreground">
        Zusammenfassung
      </dt>
      <dd>{{ entry.summary }}</dd>
      <dt class="text-muted-foreground">
        Prüfsumme
      </dt>
      <dd class="font-mono text-xs break-all">
        {{ entry.digest }}
      </dd>
      <dt class="text-muted-foreground">
        Prüfung
      </dt>
      <dd>
        <Skeleton v-if="q.isPending.value" class="h-5 w-32" />
        <CheckBadge v-else :result="result" />
      </dd>
    </dl>
    <JsonView v-if="q.data.value?.envelope" :value="q.data.value.envelope" label="Signierter Umschlag" :expand-depth="1" />
    <p v-else-if="!q.isPending.value" class="text-muted-foreground">
      Zu diesem Eintrag liefert das Lab keinen Umschlag.
    </p>
  </div>
</template>
