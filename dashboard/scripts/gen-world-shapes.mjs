// Converts world-atlas countries-110m.json (Natural Earth 1:110m, public domain) into a TS module of
// simplified SVG paths in the Equal Earth projection, keyed by ISO 3166-1 alpha-2.
// Usage: node dashboard/scripts/gen-world-shapes.mjs <countries-110m.json> apps/client-dashboard/src/assets/world-110m.ts
import { readFileSync, writeFileSync } from 'node:fs'

const [, , input, output] = process.argv
const topo = JSON.parse(readFileSync(input, 'utf8'))
const N2A = {
  '004': 'AF', '008': 'AL', '010': 'AQ', '012': 'DZ', '024': 'AO', '031': 'AZ', '032': 'AR', '036': 'AU', '040': 'AT', '044': 'BS', '050': 'BD', '051': 'AM', '056': 'BE', '064': 'BT', '068': 'BO', '070': 'BA', '072': 'BW', '076': 'BR', '084': 'BZ', '090': 'SB', '096': 'BN', '100': 'BG', '104': 'MM', '108': 'BI', '112': 'BY', '116': 'KH', '120': 'CM', '124': 'CA', '140': 'CF', '144': 'LK', '148': 'TD', '152': 'CL', '156': 'CN', '158': 'TW', '170': 'CO', '178': 'CG', '180': 'CD', '188': 'CR', '191': 'HR', '192': 'CU', '196': 'CY', '203': 'CZ', '204': 'BJ', '208': 'DK', '214': 'DO', '218': 'EC', '222': 'SV', '226': 'GQ', '231': 'ET', '232': 'ER', '233': 'EE', '238': 'FK', '242': 'FJ', '246': 'FI', '250': 'FR', '260': 'TF', '262': 'DJ', '266': 'GA', '268': 'GE', '270': 'GM', '275': 'PS', '276': 'DE', '288': 'GH', '300': 'GR', '304': 'GL', '320': 'GT', '324': 'GN', '328': 'GY', '332': 'HT', '340': 'HN', '348': 'HU', '352': 'IS', '356': 'IN', '360': 'ID', '364': 'IR', '368': 'IQ', '372': 'IE', '376': 'IL', '380': 'IT', '384': 'CI', '388': 'JM', '392': 'JP', '398': 'KZ', '400': 'JO', '404': 'KE', '408': 'KP', '410': 'KR', '414': 'KW', '417': 'KG', '418': 'LA', '422': 'LB', '426': 'LS', '428': 'LV', '430': 'LR', '434': 'LY', '440': 'LT', '442': 'LU', '450': 'MG', '454': 'MW', '458': 'MY', '466': 'ML', '478': 'MR', '484': 'MX', '496': 'MN', '498': 'MD', '499': 'ME', '504': 'MA', '508': 'MZ', '512': 'OM', '516': 'NA', '524': 'NP', '528': 'NL', '540': 'NC', '548': 'VU', '554': 'NZ', '558': 'NI', '562': 'NE', '566': 'NG', '578': 'NO', '586': 'PK', '591': 'PA', '598': 'PG', '600': 'PY', '604': 'PE', '608': 'PH', '616': 'PL', '620': 'PT', '624': 'GW', '626': 'TL', '630': 'PR', '634': 'QA', '642': 'RO', '643': 'RU', '646': 'RW', '682': 'SA', '686': 'SN', '688': 'RS', '694': 'SL', '703': 'SK', '704': 'VN', '705': 'SI', '706': 'SO', '710': 'ZA', '716': 'ZW', '724': 'ES', '728': 'SS', '729': 'SD', '732': 'EH', '740': 'SR', '748': 'SZ', '752': 'SE', '756': 'CH', '760': 'SY', '762': 'TJ', '764': 'TH', '768': 'TG', '780': 'TT', '784': 'AE', '788': 'TN', '792': 'TR', '795': 'TM', '800': 'UG', '804': 'UA', '807': 'MK', '818': 'EG', '826': 'GB', '834': 'TZ', '840': 'US', '854': 'BF', '858': 'UY', '860': 'UZ', '862': 'VE', '887': 'YE', '894': 'ZM',
}
// Without a numeric id in Natural Earth: Kosovo has the user-assigned XK (DB-IP, MaxMind); the other two
// are drawn under the country the geo databases report for them.
const BY_NAME = { 'Kosovo': 'XK', 'N. Cyprus': 'CY', 'Somaliland': 'SO' }

const [sx, sy] = topo.transform.scale
const [tx, ty] = topo.transform.translate
const arcs = topo.arcs.map((arc) => {
  let x = 0
  let y = 0
  return arc.map(([dx, dy]) => {
    x += dx
    y += dy
    return [x * sx + tx, y * sy + ty]
  })
})
const arcPts = i => i >= 0 ? arcs[i] : [...arcs[~i]].reverse()
function ring(ix) {
  const out = []
  for (const i of ix) {
    const p = arcPts(i)
    out.push(...(out.length ? p.slice(1) : p))
  }
  return out
}

// Equal Earth (Savric, Patterson, Jenny 2018).
const A1 = 1.340264
const A2 = -0.081106
const A3 = 0.000893
const A4 = 0.003796
const M = Math.sqrt(3) / 2
function project(lon, lat) {
  const l = lon * Math.PI / 180
  const p = lat * Math.PI / 180
  const t = Math.asin(M * Math.sin(p))
  const t2 = t * t
  const t6 = t2 * t2 * t2
  const x = (2 * Math.sqrt(3) * l * Math.cos(t)) / (3 * (9 * A4 * t6 * t2 + 7 * A3 * t6 + 3 * A2 * t2 + A1))
  const y = t * (A4 * t6 * t2 + A3 * t6 + A2 * t2 + A1)
  return [x, -y]
}
const XMAX = project(180, 0)[0]
const W = 1000
const S = W / (2 * XMAX)

const rings = []
for (const g of topo.objects.countries.geometries) {
  const id = g.id ? N2A[g.id] : BY_NAME[g.properties.name]
  if (!id) throw new Error(`no code for ${g.id} ${g.properties.name}`)
  if (id === 'AQ') continue
  const polys = g.type === 'Polygon' ? [g.arcs] : g.arcs
  for (const poly of polys) {
    for (const r of poly) {
      // Unwrap longitudes so a ring crossing the antimeridian stays continuous; draw it twice when it does.
      const pts = ring(r)
      let prev = pts[0][0]
      let off = 0
      const un = pts.map(([lon, lat]) => {
        if (lon - prev > 180) off -= 360
        else if (prev - lon > 180) off += 360
        prev = lon
        return [lon + off, lat]
      })
      const lons = un.map(p => p[0])
      const copies = [0]
      if (Math.max(...lons) > 180) copies.push(-360)
      if (Math.min(...lons) < -180) copies.push(360)
      for (const c of copies) rings.push({ id, pts: un.map(([lon, lat]) => project(lon + c, lat)) })
    }
  }
}
let minY = Infinity
let maxY = -Infinity
for (const r of rings) {
  for (const [, y] of r.pts) {
    minY = Math.min(minY, y)
    maxY = Math.max(maxY, y)
  }
}
const H = Math.ceil((maxY - minY) * S)
const r1 = v => Math.round(v * 10) / 10
const fmt = (v) => {
  const s = r1(v).toFixed(1)
  return s.endsWith('.0') ? s.slice(0, -2) : s
}
const shapes = new Map()
for (const r of rings) {
  let d = ''
  let px = 0
  let py = 0
  let n = 0
  for (const [x0, y0] of r.pts) {
    const x = r1((x0 + XMAX) * S)
    const y = r1((y0 - minY) * S)
    if (!d) {
      d = `M${fmt(x)} ${fmt(y)}`
      px = x
      py = y
      n = 1
      continue
    }
    const dx = r1(x - px)
    const dy = r1(y - py)
    if (Math.abs(dx) < 0.25 && Math.abs(dy) < 0.25) continue
    d += `l${fmt(dx)}${dy < 0 ? '' : ' '}${fmt(dy)}`
    px = r1(px + dx)
    py = r1(py + dy)
    n++
  }
  if (n < 3) continue
  shapes.set(r.id, `${shapes.get(r.id) ?? ''}${d}z`)
}
// Outline of the projection (meridians -180 and 180): copies of rings across the antimeridian are
// clipped to it, so they never show beside the curved edge of the map.
const edge = []
for (let lat = 90; lat >= -90; lat -= 2) edge.push(project(180, lat))
for (let lat = -90; lat <= 90; lat += 2) edge.push(project(-180, lat))
const outline = `M${edge.map(([x, y]) => `${fmt(r1((x + XMAX) * S))} ${fmt(r1((y - minY) * S))}`).join('L')}z`
const entries = [...shapes.entries()].sort(([a], [b]) => a.localeCompare(b))
const body = entries.map(([id, d]) => `  ${id}: '${d}',`).join('\n')
writeFileSync(output, `/**
 * Simplified country shapes for the Länder map (MVP-22): Natural Earth 1:110m Admin 0 countries
 * (public domain, naturalearthdata.com), version 4.1.0 as redistributed by world-atlas 2.0.2 (ISC),
 * projected with Equal Earth into a ${W} x ${H} box, coordinates rounded to 0.1, Antarctica left out.
 * Generated once (no build step); keyed by ISO 3166-1 alpha-2 (Kosovo XK; Northern Cyprus under CY and
 * Somaliland under SO, as the geo databases report them). Countries below the 1:110m scale (Malta,
 * Singapore, ...) have no shape and appear in the list only. Loaded on demand, no tile server, no
 * external request.
 */
export const WORLD_VIEWBOX = '0 0 ${W} ${H}'
/** Edge of the projection; the map clips to it (rings across the antimeridian are drawn twice). */
export const WORLD_OUTLINE = '${outline}'
export const WORLD_SHAPES: Record<string, string> = {
${body}
}
`)
console.log('countries', entries.length, 'height', H, 'bytes', body.length)
