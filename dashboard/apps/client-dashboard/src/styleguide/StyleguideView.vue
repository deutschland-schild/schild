<script setup lang="ts">
import type { ColumnDef, FilterChip, SegmentOption } from '@schild/ui'
import type { DateRange } from 'reka-ui'
import type { DemoEvent } from './demo-data'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
  AreaChart,
  Badge,
  BarList,
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
  Button,
  Calendar,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  CommandBlock,
  ConfirmDialog,
  DataTable,
  DateRangePicker,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
  EffectFooter,
  EmptyState,
  ErrorState,
  FilterBar,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  Input,
  IpAddress,
  JsonView,
  Label,
  LiveIndicator,
  MetaLine,
  PageHeader,
  PaneItem,
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
  Popover,
  PopoverContent,
  PopoverTrigger,
  RadioGroup,
  RadioGroupItem,
  RelativeTime,
  ScrollArea,
  SegmentedControl,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Separator,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
  Skeleton,
  Sparkline,
  SplitPane,
  StatCard,
  StatusPill,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tag,
  Textarea,
  toast,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@schild/ui'
import { getLocalTimeZone, today } from '@internationalized/date'
import { Download, Info, MoreHorizontal, ShieldCheck, Trash2 } from '@lucide/vue'
import { useForm } from 'vee-validate'
import { computed, h, reactive, ref, shallowRef } from 'vue'
import RequestOutcomeBadge from '@/components/requests/RequestOutcomeBadge.vue'
import SiteStrip from '@/components/requests/SiteStrip.vue'
import VerificationBadge from '@/components/requests/VerificationBadge.vue'
import WorldMap from '@/components/requests/WorldMap.vue'
import { REQUEST_OUTCOME_KEYS, VERIFICATION_KEYS } from '@/lib/requests'
import { demoCountries, demoEventData, demoEvents, demoSeries, demoStrip } from './demo-data'
import StyleguideSection from './StyleguideSection.vue'

const sections = [
  ['colors', 'Farben und Status'],
  ['typo', 'Schrift'],
  ['buttons', 'Buttons und Badges'],
  ['panel', 'Panel wie auf der Website'],
  ['forms', 'Formulare'],
  ['metrics', 'Kennzahlen und Diagramme'],
  ['table', 'Tabelle mit Filtern'],
  ['data', 'Datenbausteine'],
  ['dialogs', 'Dialoge und Seitenblätter'],
  ['menus', 'Menüs, Popover, Tooltips'],
  ['navigation', 'Navigation'],
  ['states', 'Leer, Fehler, Laden'],
  ['traffic', 'Zugriffe und Bots'],
] as const

const swatches = [
  ['bg-status-signal', 'Signal (Grundschutz aktiv)'],
  ['bg-status-success', 'Erfolg'],
  ['bg-status-warning', 'Hinweis'],
  ['bg-status-danger', 'Problem'],
  ['bg-status-info', 'Info'],
  ['bg-status-neutral', 'Neutral'],
  ['bg-primary', 'Primär'],
  ['bg-muted', 'Fläche'],
  ['bg-chart-1', 'Diagramm 1'],
  ['bg-chart-2', 'Diagramm 2'],
  ['bg-chart-3', 'Diagramm 3'],
  ['bg-chart-4', 'Diagramm 4'],
  ['bg-chart-5', 'Diagramm 5'],
] as const

// Charts
const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`)
const passed = demoSeries(24, 3, 600, 300)
const blocked = demoSeries(24, 9, 40, 60)
const categories = [
  { id: 'sqli', label: 'SQL-Injection-Versuch', value: 412 },
  { id: 'xss', label: 'Cross-Site-Scripting', value: 268 },
  { id: 'scanner', label: 'Scanner', value: 190 },
  { id: 'lfi', label: 'Dateizugriff', value: 77 },
  { id: 'rce', label: 'Code-Ausführung', value: 21 },
]

// Table
const events = demoEvents(120)
const typeLabel: Record<DemoEvent['type'], string> = {
  'schild.request.blocked.v1': 'Abgewehrt',
  'schild.request.evaluated.v1': 'Geprüft',
  'schild.session.flagged.v1': 'Auffällige Sitzung',
}
const typeTone = { 'schild.request.blocked.v1': 'danger', 'schild.request.evaluated.v1': 'neutral', 'schild.session.flagged.v1': 'warning' } as const
const columns: ColumnDef<DemoEvent, any>[] = [
  { accessorKey: 'time', header: 'Zeit', meta: { label: 'Zeit' }, cell: ({ row }) => h(RelativeTime, { value: row.original.time }), enableHiding: false },
  { accessorKey: 'type', header: 'Art', meta: { label: 'Art' }, cell: ({ row }) => h(StatusPill, { tone: typeTone[row.original.type], size: 'sm' }, () => typeLabel[row.original.type]) },
  { accessorKey: 'ip', header: 'IP-Adresse', meta: { label: 'IP-Adresse' }, cell: ({ row }) => h(IpAddress, { ip: row.original.ip, country: row.original.country, asn: row.original.asn, asnOrg: row.original.asnOrg }) },
  { id: 'request', accessorFn: r => `${r.method} ${r.path}`, header: 'Anfrage', meta: { label: 'Anfrage', hideOnMobile: true }, cell: ({ getValue }) => h('span', { class: 'font-mono text-xs' }, getValue() as string) },
  { accessorKey: 'rule', header: 'Regel', meta: { label: 'Regel', hideOnMobile: true }, cell: ({ getValue }) => getValue() ?? '–' },
  { accessorKey: 'score', header: 'Score', meta: { label: 'Score', class: 'text-right tabular-nums' } },
]
const search = ref('')
const chips = ref<FilterChip[]>([{ key: 'type', label: 'Art', value: 'Abgewehrt' }])
const range = shallowRef<DateRange>({ start: today(getLocalTimeZone()).subtract({ days: 7 }), end: today(getLocalTimeZone()) })
const filtered = computed(() => events.filter((e) => {
  const q = search.value.trim().toLowerCase()
  if (q && !`${e.ip} ${e.path} ${e.rule ?? ''}`.toLowerCase().includes(q)) return false
  return chips.value.every(c => c.key !== 'type' || typeLabel[e.type] === c.value)
}))
function addTypeFilter(value: string) {
  if (!chips.value.some(c => c.key === 'type' && c.value === value)) chips.value = [...chips.value.filter(c => c.key !== 'type'), { key: 'type', label: 'Art', value }]
}

// Form
// Plain rule functions, no schema library (zod 3 had an open advisory, 2026-11-19).
const schema = {
  name: (v?: string) => !v ? 'Bitte gib einen Namen ein.' : v.length < 2 ? 'Mindestens 2 Zeichen.' : true,
  cidr: (v?: string) => !v ? 'Bitte gib eine Adresse ein.' : /^[\d.:a-f/]+$/i.test(v) ? true : 'Das sieht nicht nach einer IP-Adresse aus.',
}
const form = useForm({ validationSchema: schema })
const onSubmit = form.handleSubmit((values) => {
  toast.success('Gespeichert', { description: `${values.name} (${values.cidr}) wird nie gesperrt.` })
  form.resetForm()
})
const mode = ref('detect')

// Website-style panel demo (sample data only).
const panelItems = [
  { id: 'hub', label: 'CrowdSec Hub', sub: 'Öffentliche Regeln gegen bekannte Lücken', on: true },
  { id: 'crs', label: 'Grundregeln (CRS)', sub: 'laufen immer', on: true },
  { id: 'own', label: 'Eigene Regeln', sub: 'aus schild.yaml', on: false },
]
const panelSelected = ref('hub')
const panelSwitch = reactive<Record<string, boolean>>({ hub: true, crs: true, own: false })
const strength = ref<'block' | 'observe' | 'off'>('block')
const strengthOptions: SegmentOption<'block' | 'observe' | 'off'>[] = [
  { value: 'block', label: 'Sperren', tone: 'ink', mark: 'empfohlen' },
  { value: 'observe', label: 'Beobachten' },
  { value: 'off', label: 'Aus', tone: 'neutral' },
]
const autoUpdates = ref(true)
const share = ref(false)

// Dialogs
const confirmOpen = ref(false)
const confirmPending = ref(false)
function onConfirm() {
  confirmPending.value = true
  setTimeout(() => {
    confirmPending.value = false
    confirmOpen.value = false
    toast('Daten gelöscht', { description: 'Das steht im lokalen Ereignisprotokoll.' })
  }, 600)
}
const calendarDate = shallowRef(today(getLocalTimeZone()))
const page = ref(3)

// Hash routing owns the URL fragment, so section links scroll programmatically.
function jump(id: string) {
  const el = document.getElementById(id)
  if (!el) return
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' })
  el.querySelector<HTMLElement>('h2')?.setAttribute('tabindex', '-1')
  el.querySelector<HTMLElement>('h2')?.focus({ preventScroll: true })
}
const showError = ref(true)
</script>

<template>
  <div class="space-y-10">
    <PageHeader title="Styleguide" description="Alle gemeinsamen Bausteine der Schild-Dashboards an einem Ort. Die Seite dient auch als visueller Test.">
      <template #eyebrow>
        Entwicklung
      </template>
      <template #meta>
        <StatusPill tone="signal" pulse>
          Grundschutz aktiv
        </StatusPill>
        <LiveIndicator state="live" />
      </template>
    </PageHeader>

    <nav aria-label="Abschnitte" class="flex flex-wrap gap-2">
      <a v-for="[id, title] in sections" :key="id" :href="`#/styleguide`" class="rounded-full border px-3 py-1 text-xs hover:bg-accent" @click.prevent="jump(id)">{{ title }}</a>
    </nav>

    <StyleguideSection id="colors" title="Farben und Status" description="Ruhig und hell. Grün nur für „Grundschutz aktiv“ und Signal-Zustände. Statusfarben immer mit Text, nie allein.">
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        <div v-for="[cls, label] in swatches" :key="cls" class="space-y-1.5">
          <div :class="cls" class="h-12 rounded-lg border" />
          <p class="text-xs text-muted-foreground">
            {{ label }}
          </p>
        </div>
      </div>
      <div class="flex flex-wrap gap-2">
        <StatusPill tone="signal">
          Grundschutz aktiv
        </StatusPill>
        <StatusPill tone="success">
          Übernommen
        </StatusPill>
        <StatusPill tone="warning">
          Ausgesetzt
        </StatusPill>
        <StatusPill tone="danger">
          Abgewehrt
        </StatusPill>
        <StatusPill tone="info">
          Probelauf
        </StatusPill>
        <StatusPill tone="neutral">
          Beobachten
        </StatusPill>
        <LiveIndicator state="connecting" />
        <LiveIndicator state="paused" />
        <LiveIndicator state="offline" />
      </div>
    </StyleguideSection>

    <StyleguideSection id="typo" title="Schrift" description="Inter, lokal ausgeliefert. Zahlen in Tabellen mit gleicher Breite.">
      <div class="space-y-2">
        <p class="text-2xl font-semibold tracking-tight">
          Überschrift Seite (2xl)
        </p>
        <p class="text-lg font-semibold">
          Überschrift Abschnitt (lg)
        </p>
        <p class="max-w-prose text-sm">
          Fließtext: Schild prüft jede Anfrage auf deinem Server. Was auffällt, landet als Ereignis im Protokoll. Die IP-Adresse im Klartext verlässt deinen Server nie.
        </p>
        <p class="text-sm text-muted-foreground">
          Sekundärtext für Hinweise und Beschreibungen.
        </p>
        <p class="font-mono text-sm">
          GET /wp-login.php · 942100 · 2001:db8::1
        </p>
        <p class="text-sm tabular-nums">
          1.234.567 · 89,5 %
        </p>
      </div>
    </StyleguideSection>

    <StyleguideSection id="buttons" title="Buttons und Badges">
      <div class="flex flex-wrap items-center gap-2">
        <Button>Speichern</Button>
        <Button variant="secondary">
          Abbrechen
        </Button>
        <Button variant="outline">
          <Download aria-hidden="true" /> Exportieren
        </Button>
        <Button variant="ghost">
          Mehr
        </Button>
        <Button variant="link">
          Zur Doku
        </Button>
        <Button variant="destructive">
          <Trash2 aria-hidden="true" /> Löschen
        </Button>
        <Button disabled>
          Deaktiviert
        </Button>
        <Button size="sm">
          Klein
        </Button>
        <Button size="icon" variant="outline" aria-label="Weitere Aktionen">
          <MoreHorizontal aria-hidden="true" />
        </Button>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <Badge>Standard</Badge>
        <Badge variant="secondary">
          Sekundär
        </Badge>
        <Badge variant="outline">
          Umriss
        </Badge>
        <Badge variant="destructive">
          Kritisch
        </Badge>
      </div>
    </StyleguideSection>

    <StyleguideSection id="panel" title="Panel wie auf der Website" description="Liste auf Papier links, aktiver Eintrag als weiße Karte, Details rechts, grünes Band mit der Wirkung unten. Beispieldaten.">
      <SplitPane list-label="Beispiel-Liste" list-title="Herkunft">
        <template #header>
          <p class="flex items-center gap-2 text-sm font-bold">
            Schild-Dashboard <span class="font-normal text-muted-foreground">· Beispiel</span>
          </p>
          <p class="text-xs text-muted-foreground">
            Läuft: <span class="text-foreground">Grundregeln (CRS) 4.8 · CrowdSec Hub</span>
          </p>
        </template>
        <template #tabs>
          <Tabs default-value="rules">
            <TabsList variant="line" aria-label="Beispiel-Tabs">
              <TabsTrigger value="rules">
                Regeln
              </TabsTrigger>
              <TabsTrigger value="exceptions">
                Ausnahmen
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </template>
        <template #list>
          <ul class="grid gap-1.5">
            <li v-for="it in panelItems" :key="it.id" class="flex items-center gap-2">
              <Switch v-model="panelSwitch[it.id]" :aria-label="`${it.label} an`" />
              <PaneItem :active="panelSelected === it.id" class="min-w-0 flex-1" @click="panelSelected = it.id">
                <span class="block truncate font-semibold">{{ it.label }}</span>
                <span class="block text-xs text-muted-foreground">{{ it.sub }}</span>
              </PaneItem>
            </li>
          </ul>
        </template>
        <ul class="divide-y">
          <li class="flex flex-wrap items-start justify-between gap-3 pb-3">
            <div class="min-w-0 flex-1 basis-64">
              <p class="text-sm font-semibold">
                Benutzernamen nicht verraten <Tag tone="warning" class="ml-1">
                  Probelauf
                </Tag>
              </p>
              <p class="mt-0.5 text-sm text-muted-foreground">
                Abrufe wie ?author=1 verraten Login-Namen.
              </p>
              <MetaLine class="mt-1" :items="['Quelle: CrowdSec Hub', { text: 'CVE-2026-1207', tone: 'signal' }, '24 h: 97 Treffer']" />
            </div>
            <SegmentedControl v-model="strength" :options="strengthOptions" label="Wirkung für Benutzernamen nicht verraten" />
          </li>
        </ul>
        <template #footer>
          <EffectFooter live>
            <strong>Probelauf mit den letzten 24 Stunden:</strong> Diese Einstellung hätte <strong>97 Anfragen</strong> getroffen.
            <template #actions>
              <Button variant="outline" size="sm">
                Verwerfen
              </Button>
              <Button size="sm">
                Anwenden
              </Button>
            </template>
            <template #note>
              Fußnote: klein, grau, für Herkunft und Rücknehmbarkeit.
            </template>
          </EffectFooter>
        </template>
      </SplitPane>
    </StyleguideSection>

    <StyleguideSection id="forms" title="Formulare" description="Labels immer sichtbar, Fehlermeldungen direkt am Feld.">
      <div class="grid gap-8 lg:grid-cols-2">
        <form class="space-y-4" novalidate @submit="onSubmit">
          <FormField v-slot="{ componentField }" name="name">
            <FormItem>
              <FormLabel>Name</FormLabel>
              <FormControl>
                <Input placeholder="z. B. Backup-Server" v-bind="componentField" />
              </FormControl>
              <FormDescription>Nur für dich, damit du die Adresse wiedererkennst.</FormDescription>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="cidr">
            <FormItem>
              <FormLabel>IP-Adresse oder Netz</FormLabel>
              <FormControl>
                <Input placeholder="192.0.2.10 oder 2001:db8::/48" class="font-mono" v-bind="componentField" />
              </FormControl>
              <FormMessage />
            </FormItem>
          </FormField>
          <Button type="submit">
            Eigene IP hinzufügen
          </Button>
        </form>
        <div class="space-y-5">
          <div class="space-y-2">
            <Label for="sg-mode">Regelquelle</Label>
            <Select v-model="mode">
              <SelectTrigger id="sg-mode" class="w-full sm:w-64">
                <SelectValue placeholder="Schalter wählen" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="off">
                  Aus
                </SelectItem>
                <SelectItem value="detect">
                  Erkennen
                </SelectItem>
                <SelectItem value="block">
                  Sperren
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          <fieldset class="space-y-2">
            <legend class="text-sm font-medium">
              Aufbewahrung der IP-Adressen
            </legend>
            <RadioGroup default-value="7" class="gap-2">
              <div class="flex items-center gap-2">
                <RadioGroupItem id="sg-r1" value="1" /><Label for="sg-r1" class="font-normal">1 Tag</Label>
              </div>
              <div class="flex items-center gap-2">
                <RadioGroupItem id="sg-r7" value="7" /><Label for="sg-r7" class="font-normal">7 Tage (Standard)</Label>
              </div>
              <div class="flex items-center gap-2">
                <RadioGroupItem id="sg-r30" value="30" /><Label for="sg-r30" class="font-normal">30 Tage</Label>
              </div>
            </RadioGroup>
          </fieldset>
          <div class="flex items-center justify-between gap-4 rounded-lg border p-3">
            <div>
              <Label for="sg-auto">Regeln automatisch übernehmen</Label>
              <p class="text-xs text-muted-foreground">
                Neue Regeln erkennen zuerst nur.
              </p>
            </div>
            <Switch id="sg-auto" v-model="autoUpdates" />
          </div>
          <div class="flex items-start gap-2">
            <Checkbox id="sg-share" v-model="share" />
            <Label for="sg-share" class="leading-snug font-normal">Vorfallnummer auf der Sperrseite zeigen</Label>
          </div>
          <div class="space-y-2">
            <Label for="sg-note">Notiz</Label>
            <Textarea id="sg-note" placeholder="Warum hast du diese Regel freigeschaltet?" />
          </div>
        </div>
      </div>
    </StyleguideSection>

    <StyleguideSection id="metrics" title="Kennzahlen und Diagramme" description="Eine Achse, dünne Linien, Werte per Maus oder Pfeiltasten. Für Screenreader steht eine Tabelle dahinter.">
      <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Anfragen heute" :value="48213" :delta="0.08" :trend="passed" tone="neutral" hint="gegenüber gestern" />
        <StatCard label="Abgewehrt" :value="1287" :delta="-0.12" delta-positive="neutral" :trend="blocked" tone="danger" hint="gegenüber gestern" />
        <StatCard label="Grundschutz" value="aktiv" tone="signal" hint="seit 14 Tagen ohne Unterbrechung">
          <template #icon>
            <ShieldCheck class="size-4 text-status-signal-text" aria-hidden="true" />
          </template>
        </StatCard>
        <StatCard label="Vorfälle" :value="null" loading />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Anfragen pro Stunde</CardTitle>
          <CardDescription>Letzte 24 Stunden</CardDescription>
        </CardHeader>
        <CardContent>
          <AreaChart
            label="Anfragen pro Stunde, letzte 24 Stunden"
            :labels="hours"
            :series="[{ id: 'passed', label: 'Durchgelassen', values: passed, slot: 2 }, { id: 'blocked', label: 'Abgewehrt', values: blocked, slot: 3 }]"
          />
        </CardContent>
      </Card>
      <div class="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Angriffsarten</CardTitle>
          </CardHeader>
          <CardContent>
            <BarList :items="categories" label="Abgewehrte Anfragen nach Angriffsart" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Sparklines</CardTitle>
          </CardHeader>
          <CardContent class="flex flex-wrap items-center gap-6">
            <Sparkline :values="passed" label="Anfragen" />
            <Sparkline :values="blocked" label="Abgewehrt" color="var(--chart-3)" />
            <Sparkline :values="[3, 3, 4, 3, 5, 4, 6]" label="Vorfälle" color="var(--chart-2)" :area="false" />
          </CardContent>
        </Card>
      </div>
    </StyleguideSection>

    <StyleguideSection id="table" title="Tabelle mit Filtern" description="Sortierbar, Spalten ein- und ausblendbar, Kopfzeile bleibt stehen. Pfeiltasten wechseln die Zeile, Enter öffnet die Details.">
      <DataTable
        :columns="columns"
        :data="filtered"
        label="Ereignisse (Beispieldaten)"
        :get-row-id="(r: DemoEvent) => r.id"
        max-height="28rem"
        :detail-title="(r: DemoEvent) => `Ereignis ${r.id}`"
      >
        <template #toolbar>
          <FilterBar v-model:search="search" v-model:chips="chips" search-placeholder="IP, Pfad oder Regel suchen …">
            <DropdownMenu>
              <DropdownMenuTrigger as-child>
                <Button variant="outline" size="sm">
                  Art
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem v-for="label in Object.values(typeLabel)" :key="label" @select="addTypeFilter(label)">
                  {{ label }}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <DateRangePicker v-model="range" />
          </FilterBar>
        </template>
        <template #detail="{ row }">
          <dl class="mb-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt class="text-muted-foreground">
              Zeit
            </dt><dd><RelativeTime :value="row.time" /></dd>
            <dt class="text-muted-foreground">
              IP-Adresse
            </dt><dd><IpAddress :ip="row.ip" :country="row.country" :asn="row.asn" :asn-org="row.asnOrg" /></dd>
            <dt class="text-muted-foreground">
              Anfrage
            </dt><dd class="font-mono text-xs">
              {{ row.method }} {{ row.path }}
            </dd>
          </dl>
          <JsonView :value="row" label="Ereignis (lokal, verlässt den Server nie)" />
        </template>
      </DataTable>
    </StyleguideSection>

    <StyleguideSection id="data" title="Datenbausteine">
      <div class="grid gap-6 lg:grid-cols-2">
        <div class="space-y-3 text-sm">
          <p class="flex items-center gap-3">
            <span class="w-28 text-muted-foreground">IPv4</span><IpAddress ip="192.0.2.44" country="DE" :asn="3320" asn-org="Deutsche Telekom" />
          </p>
          <p class="flex items-center gap-3">
            <span class="w-28 text-muted-foreground">IPv6</span><IpAddress ip="2001:db8:85a3::8a2e:370:7334" country="FR" :asn="16276" asn-org="OVH" />
          </p>
          <p class="flex items-center gap-3">
            <span class="w-28 text-muted-foreground">Ohne Herkunft</span><IpAddress ip="198.51.100.7" />
          </p>
          <p class="flex items-center gap-3">
            <span class="w-28 text-muted-foreground">Relative Zeit</span><RelativeTime :value="Date.now() - 4 * 60_000" />
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Feld</TableHead>
                <TableHead>Bedeutung</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                <TableCell class="font-mono text-xs">
                  outcome
                </TableCell>
                <TableCell>was Schild mit der Anfrage gemacht hat</TableCell>
              </TableRow>
              <TableRow>
                <TableCell class="font-mono text-xs">
                  geo.asn
                </TableCell>
                <TableCell>Netz, nicht die Adresse</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
        <JsonView :value="demoEventData" label="Daten eines Ereignisses (Beispiel, lokal)" />
      </div>
      <div class="mt-6 grid gap-3 lg:grid-cols-2">
        <CommandBlock command="sudo ufw deny 6379/tcp" caption="So behebst du es (Befehl zum Kopieren)" />
        <CommandBlock command="sudo schild-agent enrol --gateway https://gw-1.example:8790 --pin sha256:9e4c1a7b3d5f20869e4c1a7b3d5f20869e4c1a7b3d5f20869e4c1a7b3d5f2086 --code K7QM-2XRP-9HWD-T4NA" caption="Lange Befehle brechen um statt zu scrollen" />
      </div>
    </StyleguideSection>

    <StyleguideSection id="dialogs" title="Dialoge und Seitenblätter" description="Folgenreiche Aktionen brauchen eine Bestätigung, besonders gefährliche das Eintippen eines Worts.">
      <div class="flex flex-wrap gap-2">
        <Dialog>
          <DialogTrigger as-child>
            <Button variant="outline">
              Dialog
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Regel im Probelauf</DialogTitle>
              <DialogDescription>Die Regel zählt mit echtem Traffic nur mit und sperrt nichts.</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button>Verstanden</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        <AlertDialog>
          <AlertDialogTrigger as-child>
            <Button variant="outline">
              Rückfrage
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Vorfall freischalten?</AlertDialogTitle>
              <AlertDialogDescription>Die Person kann die Website sofort wieder nutzen.</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Abbrechen</AlertDialogCancel>
              <AlertDialogAction>Freischalten</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
        <Button variant="destructive" @click="confirmOpen = true">
          Daten löschen …
        </Button>
        <ConfirmDialog
          v-model:open="confirmOpen"
          title="Daten zu dieser IP löschen?"
          description="Schild löscht alle Ereignisse zu dieser IP auf diesem Server."
          confirm-phrase="LÖSCHEN"
          confirm-label="Löschen"
          destructive
          :pending="confirmPending"
          @confirm="onConfirm"
        />
        <Sheet>
          <SheetTrigger as-child>
            <Button variant="outline">
              Seitenblatt
            </Button>
          </SheetTrigger>
          <SheetContent>
            <SheetHeader>
              <SheetTitle>Details</SheetTitle>
              <SheetDescription>Seitenblätter zeigen Details, ohne die Liste zu verlassen.</SheetDescription>
            </SheetHeader>
          </SheetContent>
        </Sheet>
        <Button variant="outline" @click="toast.success('Gespeichert', { description: 'Deine Änderungen sind übernommen.' })">
          Toast
        </Button>
        <Button variant="outline" @click="toast.error('Das hat nicht geklappt', { description: 'Versuch es gleich noch einmal.' })">
          Fehler-Toast
        </Button>
      </div>
    </StyleguideSection>

    <StyleguideSection id="menus" title="Menüs, Popover, Tooltips">
      <div class="flex flex-wrap items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger as-child>
            <Button variant="outline">
              Menü
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent class="w-56">
            <DropdownMenuLabel>Regel 942100</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem>Im Probelauf testen</DropdownMenuItem>
            <DropdownMenuItem>Ausnahme anlegen <DropdownMenuShortcut>A</DropdownMenuShortcut></DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive">
              Deaktivieren
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <Popover>
          <PopoverTrigger as-child>
            <Button variant="outline">
              Popover
            </Button>
          </PopoverTrigger>
          <PopoverContent class="text-sm">
            Die Vorfallnummer steht auf der Sperrseite. Mit ihr findest du die gesperrte Anfrage.
          </PopoverContent>
        </Popover>
        <Tooltip>
          <TooltipTrigger as-child>
            <Button variant="ghost" size="icon" aria-label="Was ist ein Probelauf?">
              <Info aria-hidden="true" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Eine Regel zählt nur mit und sperrt nichts.</TooltipContent>
        </Tooltip>
      </div>
      <div class="grid gap-6 lg:grid-cols-2">
        <Calendar v-model="calendarDate" class="w-fit rounded-lg border" :week-starts-on="1" />
        <ScrollArea class="h-56 rounded-lg border">
          <ul class="p-3 text-sm">
            <li v-for="e in events.slice(0, 30)" :key="e.id" class="flex justify-between gap-2 border-b py-1.5 last:border-0">
              <span class="font-mono text-xs">{{ e.path }}</span><RelativeTime :value="e.time" class="text-muted-foreground" />
            </li>
          </ul>
        </ScrollArea>
      </div>
    </StyleguideSection>

    <StyleguideSection id="navigation" title="Navigation">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="#/">
              Schild
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbLink href="#/incidents">
              Vorfälle
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>V-2026-0042</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <Tabs default-value="all">
        <TabsList>
          <TabsTrigger value="all">
            Alle
          </TabsTrigger>
          <TabsTrigger value="hub">
            CrowdSec Hub
          </TabsTrigger>
          <TabsTrigger value="local">
            Eigene
          </TabsTrigger>
        </TabsList>
        <TabsContent value="all" class="text-sm text-muted-foreground">
          Alle Regeln, die auf deinem Server aktiv sind.
        </TabsContent>
        <TabsContent value="hub" class="text-sm text-muted-foreground">
          Öffentliche Regeln gegen bekannte Lücken.
        </TabsContent>
        <TabsContent value="local" class="text-sm text-muted-foreground">
          Regeln, die du selbst angelegt hast.
        </TabsContent>
      </Tabs>
      <Pagination v-slot="{ page: current }" v-model:page="page" :items-per-page="25" :total="340" :sibling-count="1" show-edges>
        <PaginationContent v-slot="{ items }">
          <PaginationPrevious />
          <template v-for="(item, index) in items" :key="index">
            <PaginationItem v-if="item.type === 'page'" :value="item.value" :is-active="item.value === current">
              {{ item.value }}
            </PaginationItem>
            <PaginationEllipsis v-else :index="index" />
          </template>
          <PaginationNext />
        </PaginationContent>
      </Pagination>
      <Separator />
      <p class="text-sm text-muted-foreground">
        Mit <kbd class="rounded border bg-muted px-1 font-mono text-xs">⌘ K</kbd> oder <kbd class="rounded border bg-muted px-1 font-mono text-xs">Strg K</kbd> öffnest du die Suche.
      </p>
    </StyleguideSection>

    <StyleguideSection id="states" title="Leer, Fehler, Laden">
      <div class="grid gap-4 lg:grid-cols-2">
        <EmptyState title="Noch keine Vorfälle" description="Sobald Schild eine Anfrage abwehrt, steht sie hier mit Vorfallnummer.">
          <Button variant="outline" size="sm">
            Mehr erfahren
          </Button>
        </EmptyState>
        <ErrorState v-if="showError" detail="GET /api/v0/incidents: 502 Bad Gateway" @retry="showError = false" />
        <div v-else class="space-y-3 rounded-xl border p-6" aria-busy="true">
          <Skeleton class="h-5 w-1/3" />
          <Skeleton class="h-4 w-full" />
          <Skeleton class="h-4 w-5/6" />
          <Button size="sm" variant="ghost" @click="showError = true">
            Fehler wieder zeigen
          </Button>
        </div>
      </div>
    </StyleguideSection>

    <StyleguideSection id="traffic" title="Zugriffe und Bots" description="Was Schild mit einer Anfrage gemacht hat, auf der Tonleiter einer Farbe: nie Rot für Traffic. Prüfung der Bots immer in Worten. Karte und Streifen haben eine Tabelle oder Liste dahinter. Beispieldaten.">
      <div class="space-y-6">
        <div class="flex flex-wrap items-center gap-2">
          <RequestOutcomeBadge v-for="o in REQUEST_OUTCOME_KEYS" :key="o" :outcome="o" />
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <VerificationBadge v-for="v in VERIFICATION_KEYS" :key="v" :state="v" name="Googlebot" />
        </div>
        <div class="grid gap-6 lg:grid-cols-2">
          <SiteStrip :points="demoStrip" :anchor="demoStrip[30]!.t" />
          <WorldMap :items="demoCountries" active="DE" />
        </div>
      </div>
    </StyleguideSection>
  </div>
</template>
