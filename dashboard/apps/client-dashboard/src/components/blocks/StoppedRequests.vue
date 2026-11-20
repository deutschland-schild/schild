<script setup lang="ts">
import { Button, Card, CardContent, EmptyState, ErrorState, Input, IpAddress, Label, RelativeTime, Skeleton, StatusPill } from '@schild/ui'
import { Search } from '@lucide/vue'
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { errorMessage } from '@/api/client'
import { useIncidents, useWebsites } from '@/api/websites'
import { INCIDENT_STATE, incidentReason, incidentState } from '@/lib/behaviour'
import { normalizeIncident, validIncident } from '@/lib/incident'
import { websitePath } from '@/lib/nav'
import { websiteName } from '@/lib/websites'

/**
 * Requests schild stopped, with an incident number, the last 7 days of every website (D87, before the page
 * Vorfälle): the number from a block page finds one, a row opens it.
 */
const router = useRouter()
const q = useIncidents('', 7)
const items = computed(() => q.data.value?.items ?? [])
const sites = useWebsites()
const siteName = (id?: string) => id ? websiteName(sites.data.value?.websites.find(w => w.id === id), id) : ''

const input = ref('')
const touched = ref(false)
const inputError = computed(() => !touched.value || !input.value || validIncident(input.value) ? null : 'Eine Vorfallnummer hat 8 Zeichen, z. B. K7QM-4XWD. Sie enthält kein I, O, 0 oder 1.')
function lookup() {
  touched.value = true
  if (validIncident(input.value)) void router.push(`/incidents/${input.value}`)
}
</script>

<template>
  <div class="space-y-4">
    <Card>
      <CardContent>
        <form class="grid gap-2" novalidate @submit.prevent="lookup">
          <Label for="blocks-incident-input">Vorfallnummer</Label>
          <div class="flex flex-col gap-2 sm:flex-row">
            <Input
              id="blocks-incident-input"
              :model-value="input"
              placeholder="z. B. K7QM-4XWD"
              autocomplete="off"
              spellcheck="false"
              maxlength="9"
              class="font-mono text-base tracking-wider uppercase sm:max-w-56"
              :aria-invalid="!!inputError"
              data-testid="blocks-incident-input"
              @update:model-value="v => (input = normalizeIncident(String(v)))"
              @blur="touched = true"
            />
            <Button type="submit" data-testid="blocks-incident-search">
              <Search aria-hidden="true" />
              Vorfall suchen
            </Button>
          </div>
          <p :class="inputError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="inputError ? 'alert' : undefined">
            {{ inputError ?? 'Wer gestoppt wurde, kann dir die Nummer von der Sperrseite nennen.' }}
          </p>
        </form>
      </CardContent>
    </Card>

    <ErrorState v-if="q.isError.value && !q.data.value" title="Die gestoppten Anfragen lassen sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
    <Skeleton v-else-if="q.isPending.value" class="h-40 w-full" />
    <EmptyState v-else-if="!items.length" title="In den letzten 7 Tagen hat Schild keine Anfrage gestoppt." description="Stoppt eine Regel eine Anfrage, steht sie hier mit ihrer Vorfallnummer." data-testid="stopped-empty" />
    <Card v-else class="py-0">
      <CardContent class="overflow-x-auto px-0">
        <table class="w-full text-sm" data-testid="stopped-table">
          <thead class="text-left text-xs text-muted-foreground">
            <tr class="border-b">
              <th scope="col" class="px-4 py-2 font-medium">
                Vorfall
              </th>
              <th scope="col" class="px-4 py-2 font-medium">
                Adresse
              </th>
              <th scope="col" class="px-4 py-2 font-medium">
                Website und Grund
              </th>
              <th scope="col" class="px-4 py-2 font-medium">
                Stand
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="inc in items" :key="inc.incident" class="border-b last:border-0" data-testid="stopped-row">
              <td class="px-4 py-3 align-top">
                <RouterLink :to="`/incidents/${inc.incident}`" class="font-mono font-medium underline-offset-4 hover:underline">
                  {{ inc.incident }}
                </RouterLink>
                <p class="mt-0.5 text-xs text-muted-foreground">
                  <RelativeTime :value="inc.time" /><template v-if="(inc.count ?? 1) > 1">
                    · {{ inc.count }} Anfragen
                  </template>
                </p>
              </td>
              <td class="px-4 py-3 align-top">
                <IpAddress v-if="inc.request.ip" :ip="inc.request.ip" :country="inc.request.geo?.country" :asn="inc.request.geo?.asn" :asn-org="inc.request.geo?.as_org" />
              </td>
              <td class="px-4 py-3 align-top">
                <RouterLink v-if="inc.site" :to="websitePath(inc.site, 'events')" class="underline-offset-4 hover:underline">
                  {{ siteName(inc.site) }}
                </RouterLink>
                <p class="mt-0.5 text-xs text-muted-foreground">
                  {{ incidentReason(inc.reason)?.title ?? '' }}
                </p>
              </td>
              <td class="px-4 py-3 align-top">
                <StatusPill :tone="INCIDENT_STATE[incidentState(inc)].tone" size="sm">
                  {{ INCIDENT_STATE[incidentState(inc)].label }}
                </StatusPill>
              </td>
            </tr>
          </tbody>
        </table>
      </CardContent>
    </Card>
  </div>
</template>
