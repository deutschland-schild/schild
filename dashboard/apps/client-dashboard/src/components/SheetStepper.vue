<script setup lang="ts">
import { ChevronDown, ChevronUp } from '@lucide/vue'
import { Button } from '@schild/ui'
import { computed, onBeforeUnmount, onMounted } from 'vue'

/**
 * Previous and next entry of the list behind a side panel, with buttons and the keys K and J.
 * Hidden when the open entry is not in the loaded list (opened by a link, filtered away).
 */
const props = defineProps<{ ids: string[], current: string | null }>()
const emit = defineEmits<{ select: [id: string] }>()

const index = computed(() => props.current ? props.ids.indexOf(props.current) : -1)
const prev = computed(() => index.value > 0 ? props.ids[index.value - 1] : undefined)
const next = computed(() => index.value >= 0 ? props.ids[index.value + 1] : undefined)

function isTyping(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null
  if (!el?.tagName) return false
  return el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName)
}

/** The panel is a dialog itself; a second one (a confirmation) on top keeps the keys. */
function dialogOnTop(): boolean {
  return document.querySelectorAll('[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]').length > 1
}

function onKeydown(e: KeyboardEvent) {
  if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target) || dialogOnTop()) return
  const id = e.key === 'j' ? next.value : e.key === 'k' ? prev.value : undefined
  if (!id) return
  e.preventDefault()
  emit('select', id)
}

onMounted(() => document.addEventListener('keydown', onKeydown))
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown))
</script>

<template>
  <div v-if="index >= 0 && ids.length > 1" class="absolute top-2.5 right-12 flex items-center gap-1" data-testid="sheet-stepper">
    <span class="mr-1 text-xs text-muted-foreground tabular-nums" data-testid="sheet-stepper-position">{{ index + 1 }} von {{ ids.length }}</span>
    <Button variant="ghost" size="icon-sm" :disabled="!prev" aria-label="Vorheriger Eintrag (Taste K)" title="Vorheriger Eintrag (K)" data-testid="sheet-stepper-prev" @click="prev && emit('select', prev)">
      <ChevronUp class="size-4" aria-hidden="true" />
    </Button>
    <Button variant="ghost" size="icon-sm" :disabled="!next" aria-label="Nächster Eintrag (Taste J)" title="Nächster Eintrag (J)" data-testid="sheet-stepper-next" @click="next && emit('select', next)">
      <ChevronDown class="size-4" aria-hidden="true" />
    </Button>
  </div>
</template>
