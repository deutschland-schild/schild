<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useWebsite } from '@/api/websites'
import AccessProtectionCard from '@/components/websites/AccessProtectionCard.vue'
import HumanCheckCard from '@/components/websites/HumanCheckCard.vue'
import MaintenanceCard from '@/components/websites/MaintenanceCard.vue'
import WebsiteHeader from '@/components/websites/WebsiteHeader.vue'
import { websiteName } from '@/lib/websites'

/** Zugriffsschutz of a website (D56, MVP-14 step 1), with the maintenance switch on top. */
const route = useRoute()
const site = computed(() => typeof route.params.site === 'string' ? route.params.site : '')
const websiteQ = useWebsite(site)
const name = computed(() => websiteQ.data.value?.website ? websiteName(websiteQ.data.value.website) : site.value)
</script>

<template>
  <div>
    <WebsiteHeader :id="site" :website="websiteQ.data.value?.website" title="Zugriffsschutz" />
    <MaintenanceCard :site="site" :site-name="name" />
    <HumanCheckCard :site="site" :site-name="name" />
    <AccessProtectionCard :site="site" :site-name="name" />
  </div>
</template>
