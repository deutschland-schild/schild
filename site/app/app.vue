<script setup lang="ts">
import '@fontsource-variable/inter'
import '@fontsource-variable/archivo/wdth.css'
import '@fontsource-variable/jetbrains-mono'

// Canonical link and og:url per route (static site, so the path is the page).
const route = useRoute()
const pageUrl = computed(() => `${SITE_URL}${route.path === '/' ? '/' : route.path.replace(/\/$/, '')}`)
useHead({ link: [{ rel: 'canonical', href: pageUrl }] })
useSeoMeta({ ogUrl: pageUrl })

// og:title and og:description follow the title and description of the page, so a shared link describes the page it
// points to. Pages only set title and description; the defaults live in nuxt.config.ts.
injectHead().hooks.hook('tags:resolve', (ctx) => {
  const title = ctx.tags.find(t => t.tag === 'title')?.textContent
  const description = ctx.tags.find(t => t.tag === 'meta' && t.props.name === 'description')?.props.content
  for (const t of ctx.tags) {
    if (t.tag !== 'meta') continue
    if (t.props.property === 'og:title' && title) t.props.content = title
    if (t.props.property === 'og:description' && description) t.props.content = description
  }
})
</script>

<template>
  <NuxtLayout>
    <NuxtPage />
  </NuxtLayout>
</template>
