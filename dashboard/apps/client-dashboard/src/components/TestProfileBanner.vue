<script setup lang="ts">
import { Eye } from '@lucide/vue'

/**
 * Slim note on every screen while the gateway runs the test profile (D89): nothing is blocked, whatever the
 * switches of the rule sources, scenarios and limits say. The profile is set in schild.yaml only.
 */
</script>

<template>
  <div class="mb-6 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-status-info/30 bg-status-info-subtle px-4 py-2.5 text-sm" role="note" data-testid="test-profile-banner">
    <Eye class="size-4 shrink-0 text-status-info" aria-hidden="true" />
    <p class="min-w-0 flex-1">
      <strong class="font-medium">Testprofil:</strong>
      Schild sperrt gerade nichts. Es zeigt nur, was es gesperrt hätte.
    </p>
  </div>
</template>
