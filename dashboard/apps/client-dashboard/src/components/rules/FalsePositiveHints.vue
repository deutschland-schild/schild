<script setup lang="ts">
import type { RuleExceptionInput } from '@/api/rules'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, CommandBlock, formatNumber, RelativeTime, Skeleton } from '@schild/ui'
import { Plus } from '@lucide/vue'
import { computed } from 'vue'
import { problemOf } from '@/api/client'
import { useFalsePositiveHints, useRequestRing, useWebsites } from '@/api/websites'
import { explainRule } from '@/lib/explain'
import { websitePath } from '@/lib/nav'
import { websiteName } from '@/lib/websites'

/**
 * Possible false positives of all websites (D36): a rule that hits almost only normal visitors on one
 * page, with a narrow exception (one rule, one page, one field, this website's hosts). `add` opens the
 * form filled (D84); the text below is for whoever keeps the rules as files.
 */
const emit = defineEmits<{ add: [preset: Partial<RuleExceptionInput>] }>()
const all = useWebsites()
const names = computed(() => new Map((all.data.value?.websites ?? []).map(w => [w.id, websiteName(w)])))
const hintsQ = useFalsePositiveHints('')
const hints = computed(() => hintsQ.data.value?.items ?? [])
// Without the request ring (MVP-22) the API answers requests_off: explain, no error banner.
const ringQ = useRequestRing()
const notYet = computed(() => (ringQ.isSuccess.value && ringQ.data.value === false) || (hintsQ.isError.value && problemOf(hintsQ.error.value)?.code === 'requests_off'))
</script>

<template>
  <Card data-testid="fp-hints">
    <CardHeader>
      <CardTitle>Mögliche Fehlalarme</CardTitle>
      <CardDescription>
        Regeln, die auf einer Seite fast nur normale Besucher:innen treffen. Die Ausnahme gilt nur für diese Seite, dieses Feld und die jeweilige Website. Mit „Ausnahme anlegen“ gilt sie sofort. Wer seine Regeln lieber als Datei im Repository pflegt, kopiert stattdessen den Text darunter.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <p v-if="notYet" class="text-sm text-muted-foreground">
        Mögliche Fehlalarme erkennt Schild mit dem Zugriffsprotokoll, und das ist ausgeschaltet (monitoring.requests.enabled in schild.yaml). Bis dahin hilft die Vorfallnummer: Unter „Sperren“ hebst du eine Sperre auf und meldest einen Fehlalarm.
      </p>
      <Skeleton v-else-if="hintsQ.isPending.value" class="h-24 w-full" />
      <p v-else-if="!hints.length" class="text-sm text-muted-foreground">
        Gerade keine. Schild meldet sich hier, wenn eine Regel auffällig oft normale Besucher:innen trifft.
      </p>
      <ul v-else class="space-y-5">
        <li v-for="h in hints" :key="`${h.site}-${h.rule_id}-${h.path}`" :data-hint="`${h.rule_id}|${h.path}`">
          <p class="font-medium">
            {{ explainRule(h.rule_id).title }} auf <span class="font-mono text-sm">{{ h.path }}</span><span v-if="h.target" class="text-muted-foreground"> (Feld {{ h.target }})</span>
          </p>
          <p class="mt-0.5 text-sm text-muted-foreground">
            <template v-if="h.site">
              <RouterLink :to="websitePath(h.site, 'events')" class="underline-offset-4 hover:underline">{{ names.get(h.site) ?? h.site }}</RouterLink> ·
            </template>
            Regel {{ h.rule_id }} · {{ formatNumber(h.detections) }} Erkennungen bei {{ formatNumber(h.clients_hit) }} Besucher:innen, davon {{ formatNumber(h.clients_in_session) }} mit normalem Besuch · seit <RelativeTime :value="h.since" />
          </p>
          <p class="mt-2 text-xs text-muted-foreground">
            {{ h.exception.scope === 'gateway' ? 'Diese Ausnahme gilt für alle Websites auf diesem Server, weil die Website keinen eigenen Namen hat.' : 'Gilt nur für die Adressen dieser Website, die anderen Websites prüft Schild weiter wie bisher.' }}
            Datei: <span class="font-mono">{{ h.exception.file }}</span>
          </p>
          <Button size="sm" variant="outline" class="mt-2" data-testid="fp-hint-add" @click="emit('add', { website: h.site || undefined, path: h.path, target: h.target, repository: 'crs', rules: [h.rule_id] })">
            <Plus aria-hidden="true" />
            Ausnahme anlegen
          </Button>
          <CommandBlock :command="h.exception.snippet" copy-label="Ausnahme kopieren" caption="Ausnahme (SecLang)" class="mt-2" />
        </li>
      </ul>
    </CardContent>
  </Card>
</template>
