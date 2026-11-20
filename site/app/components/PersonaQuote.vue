<script setup lang="ts">
// Wish of a made-up persona from docs/stories as a speech bubble (an assumed need, never a testimonial; the label
// above the bubble says so): the bubble "speaks" from the avatar below
// (tail above it). On large screens it sits slightly outdented to the left of the content column and pops in /
// fades out with the scroll position (CSS scroll timeline; without support or with reduced motion it simply stays).
// Source of truth: frontmatter `role` and `quote` of the persona file.
// Avatars: DiceBear "Notionists" by Zoish (CC0), drawn on purpose – the personas are made up.
export type Persona = { path: string, role?: string, quote?: string }
// Boolean props default to false in Vue, so `link` and `outdent` need explicit defaults.
const props = withDefaults(defineProps<{ persona?: Persona | null, link?: boolean, outdent?: boolean }>(), { link: true, outdent: true })
const name = computed(() => props.persona?.role?.split(',')[0] ?? '')
const role = computed(() => props.persona?.role?.split(',').slice(1).join(',').trim() ?? '')
const avatar = computed(() => `/img/personas/${props.persona?.path.split('/').pop()}.svg`)
</script>

<template>
  <figure v-if="persona?.quote" class="bubble" :class="outdent ? 'lg:-ml-10 xl:-ml-20' : ''">
    <p class="mb-3 text-xs font-semibold tracking-wide text-slate uppercase">Erfundene Persona · angenommener Bedarf, kein Kundenzitat</p>
    <blockquote class="relative rounded-2xl bg-white px-6 py-6 shadow-[0_18px_40px_-14px_rgb(10_26_51/0.28)] ring-1 ring-line sm:px-8 sm:py-7">
      <p class="text-xl/8 font-semibold tracking-tight text-balance text-ink sm:text-2xl/9">{{ persona.quote }}</p>
      <!-- Tail pointing down to the avatar -->
      <span class="absolute -bottom-[9px] left-9 size-4 rotate-45 border-r border-b border-line bg-white sm:left-11" aria-hidden="true" />
    </blockquote>
    <figcaption class="mt-5 flex items-center gap-x-4 pl-5 sm:pl-7">
      <img :src="avatar" alt="" width="56" height="56" loading="lazy" class="size-14 shrink-0 rounded-full bg-signal-tint ring-1 ring-line">
      <div class="text-sm/6">
        <p class="font-semibold text-ink">
          <NuxtLink v-if="link" :to="persona.path" class="hover:underline">{{ name }}</NuxtLink>
          <template v-else>{{ name }}</template>
        </p>
        <p class="text-slate">{{ role }}</p>
      </div>
    </figcaption>
  </figure>
</template>
