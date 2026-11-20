<script setup lang="ts">
import { Button, EmptyState, PageHeader } from '@schild/ui'
import { MapPinOff } from '@lucide/vue'
</script>

<template>
  <div>
    <PageHeader title="Seite nicht gefunden" />
    <EmptyState :icon="MapPinOff" title="Diese Seite gibt es nicht" description="Vielleicht hat sich die Adresse geändert.">
      <Button as-child variant="outline">
        <RouterLink to="/">
          Zum Überblick
        </RouterLink>
      </Button>
    </EmptyState>
  </div>
</template>
