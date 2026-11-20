<script setup lang="ts">
import { unwrap } from '@schild/app-kit'
import { Button, Checkbox, Input, Label, toast } from '@schild/ui'
import { Check } from '@lucide/vue'
import { computed, ref, useId } from 'vue'
import { useRouter } from 'vue-router'
import { api, errorMessage, fieldErrors, session } from '@/api/client'
import { useAllowMyIp, useMyIp, useSettings } from '@/api/queries'
import AuthLayout from '@/components/AuthLayout.vue'

/**
 * First run: 1. set password, 2. allow your own IP (protect yourself from lock-out). There is no mode to
 * choose (D89): every rule source has its own switch under Regeln.
 */
const router = useRouter()
const uid = useId()
const STEPS = ['Passwort', 'Eigene IP']
const step = ref(session.value?.authenticated ? 1 : 0)
const authed = computed(() => !!session.value?.authenticated)

// ---------------------------------------------------------------- step 1: password
const code = ref('')
const password = ref('')
const repeat = ref('')
const touched = ref(false)
const pending = ref(false)
const serverError = ref<string | null>(null)
const codeError = ref<string | null>(null)

const strength = computed(() => {
  const p = password.value
  let score = 0
  if (p.length >= 12) score++
  if (p.length >= 16) score++
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) score++
  if (/\d/.test(p) || /[^a-z0-9]/i.test(p)) score++
  return score
})
const strengthLabel = computed(() => ['Zu kurz', 'Ausreichend', 'Gut', 'Stark', 'Sehr stark'][strength.value])
const pwError = computed(() => touched.value && password.value.length < 12 ? 'Mindestens 12 Zeichen. Ein Satz aus mehreren Wörtern ist leicht zu merken.' : null)
const repeatError = computed(() => touched.value && repeat.value !== password.value ? 'Die beiden Eingaben sind nicht gleich.' : null)

async function savePassword() {
  touched.value = true
  serverError.value = null
  codeError.value = null
  if (!code.value.trim()) codeError.value = 'Trag den Einrichtungscode ein. Er steht im Server-Log.'
  if (codeError.value || pwError.value || repeatError.value) return
  pending.value = true
  try {
    session.value = await unwrap(api.POST('/auth/setup', { body: { password: password.value, setup_code: code.value.trim() } }))
    step.value = 1
  }
  catch (err) {
    const fe = fieldErrors(err)
    if (fe.setup_code) codeError.value = 'Der Einrichtungscode stimmt nicht. Er steht im Server-Log und gilt nur einmal.'
    else if (fe.password) serverError.value = 'Das Passwort ist zu kurz. Mindestens 12 Zeichen.'
    else serverError.value = errorMessage(err)
  }
  finally {
    pending.value = false
  }
}

const settings = useSettings(authed)

// ---------------------------------------------------------------- step 2: own IP
const myIp = useMyIp(authed)
const allowMine = useAllowMyIp()
const allowMe = ref(true)
/** The test profile blocks nothing, whatever the switches say. */
const testProfile = computed(() => settings.data.value?.profile === 'test')

async function finish() {
  if (allowMe.value && !myIp.data.value?.allowlisted) {
    try {
      await allowMine.mutateAsync({ label: 'Meine IP (Einrichtung)', ttl: '7d' })
    }
    catch (err) {
      toast.error('Deine IP konnte nicht freigeschaltet werden', { description: errorMessage(err) })
    }
  }
  toast.success('Schild ist eingerichtet', {
    description: testProfile.value
      ? 'Testprofil: Schild sperrt nichts und zeigt nur, was es gesperrt hätte.'
      : 'Was welche Regelquelle tut, siehst du unter Regeln.',
  })
  await router.replace('/')
}
</script>

<template>
  <AuthLayout
    :title="step === 0 ? 'Willkommen bei Schild' : 'Nicht selbst aussperren'"
    :description="step === 0 ? 'Lege ein Passwort für dieses Dashboard fest. Es bleibt auf deinem Server.' : 'Schalte deine eigene IP frei, dann sperrt Schild sie nicht.'"
    wide
  >
    <template #top>
      <ol class="mb-6 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm" aria-label="Schritte der Einrichtung">
        <li v-for="(s, i) in STEPS" :key="s" class="flex items-center gap-2" :aria-current="i === step ? 'step' : undefined">
          <span
            :class="['flex size-6 items-center justify-center rounded-full border text-xs font-medium', i < step ? 'border-primary bg-primary text-primary-foreground' : i === step ? 'border-primary text-foreground' : 'text-muted-foreground']"
          >
            <Check v-if="i < step" class="size-3.5" aria-hidden="true" />
            <template v-else>{{ i + 1 }}</template>
          </span>
          <span :class="i === step ? 'font-medium' : 'text-muted-foreground'">{{ s }}<span v-if="i < step" class="sr-only"> (erledigt)</span></span>
          <span v-if="i < STEPS.length - 1" class="mx-1 h-px w-3 bg-border sm:w-6" aria-hidden="true" />
        </li>
      </ol>
    </template>

    <!-- Step 1 -->
    <form v-if="step === 0" class="grid gap-5" novalidate @submit.prevent="savePassword">
      <div class="grid gap-2">
        <Label :for="`${uid}-code`">Einrichtungscode</Label>
        <Input :id="`${uid}-code`" v-model="code" autocomplete="one-time-code" spellcheck="false" required class="font-mono" :aria-invalid="!!codeError" :aria-describedby="`${uid}-code-hint`" data-testid="setup-code" />
        <p :id="`${uid}-code-hint`" :class="codeError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="codeError ? 'alert' : undefined">
          {{ codeError ?? 'Zeigt „sudo /usr/local/bin/schild dashboard setup-code“ auf dem Server an, mit Docker „docker exec schild schild dashboard setup-code“. Er steht auch im Log im Feld setup_code.' }}
        </p>
      </div>
      <div class="grid gap-2">
        <Label :for="`${uid}-pw`">Neues Passwort</Label>
        <Input :id="`${uid}-pw`" v-model="password" type="password" autocomplete="new-password" required minlength="12" :aria-invalid="!!pwError" :aria-describedby="`${uid}-pw-hint`" data-testid="setup-password" />
        <div class="flex items-center gap-2" aria-hidden="true">
          <span v-for="i in 4" :key="i" :class="['h-1 flex-1 rounded-full', i <= strength ? (strength >= 3 ? 'bg-status-success' : 'bg-status-warning') : 'bg-muted']" />
        </div>
        <p :id="`${uid}-pw-hint`" :class="pwError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="pwError ? 'alert' : undefined">
          {{ pwError ?? (password ? `Stärke: ${strengthLabel}` : 'Mindestens 12 Zeichen.') }}
        </p>
      </div>
      <div class="grid gap-2">
        <Label :for="`${uid}-repeat`">Passwort wiederholen</Label>
        <Input :id="`${uid}-repeat`" v-model="repeat" type="password" autocomplete="new-password" required :aria-invalid="!!repeatError" :aria-describedby="repeatError ? `${uid}-repeat-err` : undefined" data-testid="setup-repeat" />
        <p v-if="repeatError" :id="`${uid}-repeat-err`" class="text-sm text-destructive" role="alert">
          {{ repeatError }}
        </p>
      </div>
      <p v-if="serverError" class="text-sm text-destructive" role="alert">
        {{ serverError }}
      </p>
      <Button type="submit" :disabled="pending" class="justify-self-end">
        {{ pending ? 'Wird gespeichert …' : 'Weiter' }}
      </Button>
    </form>

    <!-- Step 2 -->
    <div v-else class="grid gap-5">
      <div class="grid gap-3 rounded-xl border p-4">
        <Label class="flex items-start gap-2 leading-snug font-normal">
          <Checkbox v-model="allowMe" class="mt-0.5" data-testid="setup-allow-me" />
          <span>
            Meine IP <span v-if="myIp.data.value" class="font-mono">{{ myIp.data.value.ip }}</span> für 7 Tage freischalten
            <span class="block text-sm text-muted-foreground">Empfohlen, damit du dich beim Testen nicht selbst aussperrst.</span>
          </span>
        </Label>
      </div>
      <div class="flex justify-end gap-2">
        <Button :disabled="allowMine.isPending.value" data-testid="setup-finish" @click="finish">
          Einrichtung abschließen
        </Button>
      </div>
    </div>

    <p v-if="authed && step === 0" class="mt-4 text-sm text-muted-foreground">
      Du bist schon angemeldet.
    </p>
  </AuthLayout>
</template>
