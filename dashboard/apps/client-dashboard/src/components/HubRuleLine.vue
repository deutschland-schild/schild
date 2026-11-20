<script setup lang="ts">
import { computed } from 'vue'
import { useRule } from '@/api/rules'
import { HUB_LABEL, hubBaseId, hubRuleText } from '@/lib/crowdsec'

/**
 * A hub rule in an incident: label, rule name and CVE. An incident only keeps the id of the group that
 * matched, so the rule is looked up by its base id; a rule that left the hub since then keeps the label.
 */
const props = defineProps<{ id: string }>()
const q = useRule('crowdsec', () => String(hubBaseId(Number(props.id))))
const hub = computed(() => q.data.value?.crowdsec)
const text = computed(() => hub.value ? hubRuleText(hub.value) : null)
</script>

<template>
  <span class="font-medium">{{ text?.title ?? HUB_LABEL }}</span>
  <span class="text-muted-foreground"> ({{ id }})</span>
  <span v-if="hub" class="block text-muted-foreground" data-testid="hub-rule-line">
    {{ HUB_LABEL }}<template v-if="hub.cves?.length"> · {{ hub.cves.join(', ') }}</template>
  </span>
  <span v-if="text" class="block text-muted-foreground">{{ text.explain }}</span>
</template>
