<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useWebsite } from '@/api/websites'
import CrawlerControlCard from '@/components/websites/CrawlerControlCard.vue'
import WebsiteHeader from '@/components/websites/WebsiteHeader.vue'
import { websiteName } from '@/lib/websites'

/** KI-Crawler of a website (D57, MVP-29). */
const route = useRoute()
const site = computed(() => typeof route.params.site === 'string' ? route.params.site : '')
const websiteQ = useWebsite(site)
const name = computed(() => websiteQ.data.value?.website ? websiteName(websiteQ.data.value.website) : site.value)
</script>

<template>
  <div>
    <WebsiteHeader :id="site" :website="websiteQ.data.value?.website" title="KI-Crawler" />
    <CrawlerControlCard :site="site" :site-name="name" />
  </div>
</template>
