<script setup lang="ts">
import { Button, Input, Label } from '@schild/ui'
import { unwrap } from '@schild/app-kit'
import { computed, onMounted, ref, useId } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage, session, statusOf } from '@/api/client'
import AuthLayout from '@/components/AuthLayout.vue'
import { loadSession } from '@/router'

const route = useRoute()
const router = useRouter()
const password = ref('')
const error = ref<string | null>(null)
const pending = ref(false)
const id = useId()
const expired = computed(() => route.query.expired === '1')
const unreachable = computed(() => session.loaded && session.value === null)

onMounted(() => (document.getElementById(`${id}-pw`) as HTMLInputElement | null)?.focus())

async function submit() {
  if (!password.value || pending.value) return
  pending.value = true
  error.value = null
  try {
    session.value = await unwrap(api.POST('/auth/login', { body: { user: 'admin', password: password.value } }))
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') ? route.query.next : '/'
    await router.replace(next)
  }
  catch (err) {
    const status = statusOf(err)
    error.value = status === 401
      ? 'Das Passwort stimmt nicht. Versuch es noch einmal.'
      : errorMessage(err)
    password.value = ''
    ;(document.getElementById(`${id}-pw`) as HTMLInputElement | null)?.focus()
  }
  finally {
    pending.value = false
  }
}

async function retry() {
  await loadSession(true)
  if (session.value?.authenticated || session.value?.first_run) await router.replace('/')
}
</script>

<template>
  <AuthLayout title="Anmelden" description="Melde dich mit dem Passwort an, das du bei der Einrichtung festgelegt hast.">
    <div v-if="unreachable" class="mb-4 rounded-md border border-status-warning/40 bg-status-warning-subtle p-3 text-sm" role="alert">
      Schild antwortet gerade nicht. Prüf, ob der Dienst läuft (z. B. „systemctl status schild“).
      <Button variant="link" size="sm" class="h-auto p-0" @click="retry">
        Erneut versuchen
      </Button>
    </div>
    <p v-else-if="expired" class="mb-4 rounded-xl border bg-muted p-3 text-sm" role="status">
      Deine Sitzung ist abgelaufen. Melde dich bitte neu an.
    </p>
    <form class="grid gap-4" @submit.prevent="submit">
      <div class="grid gap-2">
        <Label :for="`${id}-pw`">Passwort</Label>
        <Input
          :id="`${id}-pw`"
          v-model="password"
          type="password"
          autocomplete="current-password"
          required
          :aria-invalid="!!error"
          :aria-describedby="error ? `${id}-err` : undefined"
          data-testid="login-password"
        />
        <p v-if="error" :id="`${id}-err`" class="text-sm text-destructive" role="alert">
          {{ error }}
        </p>
      </div>
      <Button type="submit" :disabled="!password || pending" class="w-full">
        {{ pending ? 'Anmelden …' : 'Anmelden' }}
      </Button>
      <details class="text-sm text-muted-foreground">
        <summary class="cursor-pointer select-none hover:text-foreground">
          Passwort vergessen?
        </summary>
        <p class="mt-2">
          Melde dich per SSH auf dem Server an und setze den Zugang zurück mit
          <code class="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">sudo /usr/local/bin/schild dashboard reset-password</code>,
          mit Docker <code class="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">docker exec schild schild dashboard reset-password</code>.
          Danach richtest du ein neues Passwort mit dem neuen Einmal-Code ein.
        </p>
      </details>
    </form>
  </AuthLayout>
</template>
