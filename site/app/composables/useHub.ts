import { BRAND_META, HUB_SECTIONS, type DocCollection, type HubSectionDef } from '~/utils/hub'

export type HubChapter = {
  path: string
  slug: string
  title: string
  short: string
  description?: string
  section: string
}

export type HubSection = HubSectionDef & { chapters: HubChapter[] }

const slugOf = (path: string) => path.split('/').pop()!

// All chapters of the documentation hub, grouped by the parts of Deutschland-Schild and the project (HUB_SECTIONS).
export function useHub() {
  const { data } = useAsyncData('hub-chapters', async () => {
    const fields = ['path', 'title', 'short', 'description', 'meta'] as const
    const load = (c: DocCollection) => queryCollection(c).select(...fields).order('stem', 'ASC').all()
    const [gateway, concept, brand, stories] = await Promise.all([load('gateway'), load('concept'), load('brand'), load('stories')])
    const map = (d: any): Omit<HubChapter, 'section'> => {
      const slug = slugOf(d.path)
      const brandMeta = BRAND_META[slug]
      return {
        path: d.path,
        slug,
        title: d.title,
        short: d.short ?? brandMeta?.short ?? d.title,
        description: brandMeta?.description ?? d.description,
      }
    }
    return { gateway: gateway.map(map), concept: concept.map(map), brand: brand.map(map), stories: stories.map(map) } as Record<DocCollection, Omit<HubChapter, 'section'>[]>
  })

  const sections = computed<HubSection[]>(() => {
    if (!data.value) return HUB_SECTIONS.map(s => ({ ...s, chapters: [] }))
    const find = (ref: string) => {
      const [collection, slug] = ref.split('/') as [DocCollection, string]
      return data.value![collection]?.find(c => c.slug === slug)
    }
    const listed = new Set(HUB_SECTIONS.flatMap(s => s.docs ?? []))
    return HUB_SECTIONS.map((s) => {
      let chapters = s.docs ? s.docs.map(find).filter(c => !!c) : s.collection ? data.value![s.collection] : []
      // Gateway and concept files not mapped to any section still show up (under the system section) – nothing gets lost.
      if (s.id === 'system') {
        const rest = (['gateway', 'concept'] as const).flatMap(c => data.value![c].filter(d => !listed.has(`${c}/${d.slug}`)))
        chapters = [...chapters, ...rest]
      }
      return { ...s, chapters: chapters.map(c => ({ ...c, section: s.id })) }
    })
  })

  const chapters = computed(() => sections.value.flatMap(s => s.chapters))

  // Prev/next follow the reading order across all sections.
  function neighbours(path: string) {
    const list = chapters.value
    const i = list.findIndex(c => c.path === path)
    const chapter = list[i]
    return {
      chapter,
      section: sections.value.find(s => s.id === chapter?.section),
      prev: i > 0 ? list[i - 1] : undefined,
      next: i >= 0 ? list[i + 1] : undefined,
    }
  }

  return { sections, chapters, neighbours }
}
