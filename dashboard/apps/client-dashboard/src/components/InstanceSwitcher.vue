<script setup lang="ts">
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@schild/ui'
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { DRAFT_HOME } from '@/lib/draft-nav'

/**
 * DRAFT (initiator, 2026-11-03): a plain select box for the instance at the top of the sidebar. Choosing
 * an instance opens its overview. Several instances exist only in the central dashboard (MVP-20); the two
 * others here are examples and disabled.
 */
const props = defineProps<{ name: string }>()
const router = useRouter()
const examples = ['kunde-mueller', 'staging']
const model = computed({
  get: () => props.name,
  set: () => void router.push(DRAFT_HOME),
})
</script>

<template>
  <div class="px-2 group-data-[collapsible=icon]:hidden">
    <Select v-model="model">
      <SelectTrigger class="w-full bg-card" aria-label="Instanz">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem :value="props.name">
          {{ props.name }}
        </SelectItem>
        <SelectItem v-for="e in examples" :key="e" :value="e" disabled>
          {{ e }} (Beispiel)
        </SelectItem>
      </SelectContent>
    </Select>
  </div>
</template>
