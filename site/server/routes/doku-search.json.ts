// Search index for DokuSearch.vue: titles, headings and text of all /doku pages, prerendered as one static JSON file.
// Querying in the browser instead would load the SQLite WASM and the SQL dumps of all collections (~750 KB).
// Diagram source is indexed as text by Nuxt Content; it is noise in results and dropped here.
const MERMAID = /\b(?:flowchart|graph|sequenceDiagram)\b[\s\S]*$/

export default defineEventHandler(async (event) => {
  const cols = ['gateway', 'concept', 'brand', 'stories'] as const
  const all = await Promise.all(cols.map(c => queryCollectionSearchSections(event, c)))
  return all.flat().map(s => ({ id: s.id, title: s.title, titles: s.titles, content: s.content.replace(MERMAID, '').trim() }))
})
