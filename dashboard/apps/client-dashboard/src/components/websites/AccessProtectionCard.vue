<script setup lang="ts">
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  ErrorState,
  Skeleton,
  toast,
} from '@schild/ui'
import { computed, ref } from 'vue'
import { useAccessProtection, useRemoveAccessProtection } from '@/api/access'
import { errorMessage } from '@/api/client'
import { accessTitle, ACCESS_COPY as C, scopeText, waysText } from '@/lib/access'
import AccessProtectionDialog from './AccessProtectionDialog.vue'

/**
 * The Zugriffsschutz module of a website (D56, D58), as simple as Netlify's card: two read-only rows, one button.
 * With `banner` it is the card on Zugriffe, the start page of a website (D68), while the whole website has the protection,
 * titled by its conditions ("Nur mit Passwort erreichbar"; nothing otherwise). On until lifted, no end.
 */
const props = defineProps<{ site: string, siteName: string, banner?: boolean }>()
const q = useAccessProtection(() => props.site)
const p = computed(() => q.data.value?.protection ?? null)
const dialog = ref(false)
const confirmRemove = ref(false)
const remove = useRemoveAccessProtection(() => props.site)

async function doRemove() {
  try {
    await remove.mutateAsync()
    toast.success(`${props.siteName} ist wieder für alle offen`)
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}
</script>

<template>
  <template v-if="banner">
    <div v-if="p?.scope === 'site'" class="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-status-warning/40 bg-status-warning-subtle p-4" data-testid="access-banner">
      <div class="grid gap-0.5">
        <p class="font-medium">
          {{ accessTitle(p) }}
        </p>
        <p class="text-sm text-muted-foreground">
          Alle anderen sehen die Wartungsseite. {{ C.waysLabel }}: {{ waysText(p) }}. {{ C.stays }}
        </p>
      </div>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" data-testid="access-remove" @click="confirmRemove = true">
          {{ C.remove }}
        </Button>
      </div>
    </div>
  </template>
  <Card v-else class="mb-4 min-w-0" data-testid="access-card">
    <CardHeader>
      <CardTitle>{{ C.title }}</CardTitle>
      <CardDescription>{{ C.lead }}</CardDescription>
    </CardHeader>
    <CardContent class="space-y-4 text-sm">
      <Skeleton v-if="q.isPending.value" class="h-16 w-full" />
      <ErrorState v-else-if="q.isError.value" title="Der Zugriffsschutz lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
      <template v-else>
        <dl class="grid gap-3 sm:grid-cols-[10rem_1fr]">
          <dt class="text-muted-foreground">
            {{ C.waysLabel }}
          </dt>
          <dd data-testid="access-ways">
            {{ p ? waysText(p) : C.off }}
          </dd>
          <dt class="text-muted-foreground">
            {{ C.scopeLabel }}
          </dt>
          <dd class="break-words" data-testid="access-scope">
            {{ p ? scopeText(p) : '–' }}
          </dd>
          <template v-if="p?.except?.length">
            <dt class="text-muted-foreground">
              Für alle offen
            </dt>
            <dd class="font-mono break-words">
              {{ p.except.join(', ') }}
            </dd>
          </template>
        </dl>
        <div class="flex flex-wrap gap-2">
          <Button data-testid="access-setup" @click="dialog = true">
            {{ p ? C.change : C.setup }}
          </Button>
          <Button v-if="p" variant="outline" data-testid="access-remove" @click="confirmRemove = true">
            {{ C.remove }}
          </Button>
        </div>
      </template>
    </CardContent>
  </Card>

  <AccessProtectionDialog v-model:open="dialog" :site="site" :site-name="siteName" :current="p" />
  <AlertDialog v-model:open="confirmRemove">
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>Zugriffsschutz aufheben?</AlertDialogTitle>
        <AlertDialogDescription>
          {{ p?.scope === 'site' ? 'Die Website ist danach sofort wieder für alle erreichbar.' : 'Die Bereiche sind danach sofort wieder für alle erreichbar.' }}
          Alle Anmeldungen enden. Das Passwort ist danach gelöscht.
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>Abbrechen</AlertDialogCancel>
        <AlertDialogAction data-testid="access-remove-confirm" @click="doRemove">
          Aufheben
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
