import { defineCollection, defineContentConfig, z } from '@nuxt/content'
import { fileURLToPath } from 'node:url'
import { COLLECTIONS, UNPUBLISHED_CONCEPT } from './app/utils/hub'

// The site renders the Markdown in ../docs directly, docs/ stays the single source of truth.
// Documentation hub (/doku): gateway docs, concept, brand, personas & user stories. docs/internal/ is a separate private repo and is never built.
const chapterSchema = z.object({
  // Brand docs have no frontmatter; their navigation data comes from BRAND_META in app/utils/hub.ts.
  short: z.string().optional(),
  group: z.string().optional(),
  // Personas only: who is speaking and one quote in their voice (shown on the landing page and the persona page).
  role: z.string().optional(),
  quote: z.string().optional(),
})

const src = (dir: string) => fileURLToPath(new URL(`../${dir}`, import.meta.url))

export default defineContentConfig({
  collections: {
    gateway: defineCollection({
      type: 'page',
      source: {
        cwd: src(COLLECTIONS.gateway.dir),
        include: '*.md',
        exclude: ['README.md'],
        prefix: COLLECTIONS.gateway.base,
      },
      schema: chapterSchema,
    }),
    concept: defineCollection({
      type: 'page',
      source: {
        cwd: src(COLLECTIONS.concept.dir),
        include: '*.md',
        exclude: ['README.md', ...UNPUBLISHED_CONCEPT.map(s => `${s}.md`)],
        prefix: COLLECTIONS.concept.base,
      },
      schema: chapterSchema,
    }),
    brand: defineCollection({
      type: 'page',
      source: {
        cwd: src(COLLECTIONS.brand.dir),
        include: '*.md',
        // bildnachweise.md is a repo document only (the site shows no third-party photos).
        exclude: ['README.md', 'bildnachweise.md'],
        prefix: COLLECTIONS.brand.base,
      },
      schema: chapterSchema,
    }),
    stories: defineCollection({
      type: 'page',
      source: {
        cwd: src(COLLECTIONS.stories.dir),
        include: '*.md',
        exclude: ['README.md'],
        prefix: COLLECTIONS.stories.base,
      },
      schema: chapterSchema,
    }),
  },
})
