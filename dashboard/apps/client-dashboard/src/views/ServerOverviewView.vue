<script setup lang="ts">
import { computed } from 'vue'
import { useOverview } from '@/api/queries'
import GroupCard from '@/components/GroupCard.vue'
import NowSection from '@/components/monitoring/NowSection.vue'
import ServerHeader from '@/components/ServerHeader.vue'

/**
 * Server overview (/server): "Gerade jetzt" with the totals of all websites, CPU, memory, disk, network
 * and hints, then the card "Gruppe" (MVP-27): alone or a node of a group. Auslastung and Server-Check are tabs
 * of the same header.
 */
const overview = useOverview()
const o = computed(() => overview.data.value)
</script>

<template>
  <div>
    <ServerHeader description="Was dieser Server gerade tut und was du dir ansehen solltest." />
    <NowSection :overview="o" />
    <GroupCard class="mt-6" />
  </div>
</template>
