<script setup lang="ts">
import type { AccessProtection, AccessProtectionInput } from '@/api/access'
import {
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  RadioGroup,
  RadioGroupItem,
  Textarea,
  toast,
} from '@schild/ui'
import { computed, ref, useId, watch } from 'vue'
import { useSetAccessProtection } from '@/api/access'
import { errorMessage, fieldErrors, statusOf } from '@/api/client'
import { ACCESS_COPY as C, isAccessAddress, isAccessPath, lines } from '@/lib/access'

/**
 * Configure the Zugriffsschutz of a website (D56, D58): scope, conditions and maintenance text, one primary
 * button. Every condition ticked must hold; the protection stays until it is lifted. Modelled on Netlify's password protection; the server validates again and marks fields.
 */
const props = defineProps<{ site: string, siteName: string, current: AccessProtection | null }>()
const open = defineModel<boolean>('open', { default: false })

const scope = ref<'site' | 'paths'>('site')
const pathsText = ref('')
const exceptText = ref('')
const usePassword = ref(true)
const password = ref('')
const useAddresses = ref(false)
const addressesText = ref('')
const ownNetworks = ref(false)
const message = ref('')
const touched = ref(false)
const serverErrors = ref<Record<string, string>>({})
const uid = useId()

watch(open, (v) => {
  if (!v) return
  const p = props.current
  scope.value = p?.scope ?? 'site'
  pathsText.value = (p?.paths ?? []).join('\n') || '/wp-admin/*\n/wp-login.php'
  exceptText.value = (p?.except ?? []).join('\n')
  usePassword.value = p ? p.password : true
  password.value = ''
  useAddresses.value = !!p?.addresses?.length
  addressesText.value = (p?.addresses ?? []).join('\n')
  ownNetworks.value = p?.own_networks ?? false
  message.value = p?.message ?? ''
  touched.value = false
  serverErrors.value = {}
})

const hasStoredPassword = computed(() => !!props.current?.password)
const paths = computed(() => lines(pathsText.value))
const except = computed(() => lines(exceptText.value))
const addresses = computed(() => lines(addressesText.value))

const pathsError = computed(() => {
  if (serverErrors.value.paths) return 'Das hat der Server nicht akzeptiert. Pfade beginnen mit / und haben * nur als /* am Ende.'
  if (!touched.value || scope.value !== 'paths') return null
  if (!paths.value.length) return 'Gib mindestens einen Pfad an.'
  const bad = paths.value.find(p => !isAccessPath(p))
  return bad ? `„${bad}“ geht nicht. Pfade beginnen mit / und haben * nur als /* am Ende.` : null
})
const exceptError = computed(() => {
  if (serverErrors.value.except) return 'Das hat der Server nicht akzeptiert. Nur einfache Pfade, ohne // und ohne „..“.'
  if (!touched.value || scope.value !== 'site') return null
  const bad = except.value.find(p => !isAccessPath(p, true) || p === '/')
  return bad ? `„${bad}“ geht nicht. Nur einfache Pfade wie /api/webhook oder /hooks/*.` : null
})
const passwordError = computed(() => {
  if (serverErrors.value.password) return 'Das Passwort braucht 8 bis 128 Zeichen.'
  if (!touched.value || !usePassword.value) return null
  if (!password.value && !hasStoredPassword.value) return 'Gib ein Passwort mit mindestens 8 Zeichen ein.'
  if (password.value && (password.value.length < 8 || password.value.length > 128)) return 'Das Passwort braucht 8 bis 128 Zeichen.'
  return null
})
const addressesError = computed(() => {
  if (serverErrors.value.addresses) return 'Das hat der Server nicht akzeptiert. Prüf die Schreibweise.'
  if (!touched.value || !useAddresses.value) return null
  if (!addresses.value.length) return 'Gib mindestens eine IP oder ein Netz an.'
  const bad = addresses.value.find(a => !isAccessAddress(a))
  return bad ? `„${bad}“ geht nicht. Eine IP wie 203.0.113.7 oder ein Netz wie 198.51.100.0/24 (IPv4 bis /16).` : null
})
const wayError = computed(() => touched.value && !usePassword.value && !useAddresses.value && !ownNetworks.value ? C.noWayIn : null)
const messageError = computed(() => serverErrors.value.message ? 'Höchstens 500 Zeichen, ohne Steuerzeichen.' : null)

const set = useSetAccessProtection(() => props.site)

async function submit() {
  touched.value = true
  serverErrors.value = {}
  if (pathsError.value || exceptError.value || passwordError.value || addressesError.value || wayError.value) return
  const body: AccessProtectionInput = {
    scope: scope.value,
    own_networks: ownNetworks.value,
    ...(scope.value === 'paths' ? { paths: paths.value } : {}),
    ...(scope.value === 'site' && except.value.length ? { except: except.value } : {}),
    ...(useAddresses.value ? { addresses: addresses.value } : {}),
    ...(usePassword.value && password.value ? { password: password.value } : {}),
    ...(!usePassword.value && hasStoredPassword.value ? { remove_password: true } : {}),
    ...(scope.value === 'site' && message.value.trim() ? { message: message.value.trim() } : {}),
  }
  try {
    await set.mutateAsync(body)
    open.value = false
    toast.success(`Zugriffsschutz für ${props.siteName} ist aktiv`, {
      description: props.current ? C.sessionsEnd : undefined,
    })
  }
  catch (err) {
    serverErrors.value = fieldErrors(err)
    if (statusOf(err) === 409) toast.error('Das hat nicht geklappt', { description: C.notBehindSchild })
    else if (!Object.keys(serverErrors.value).length) toast.error('Das hat nicht geklappt', { description: errorMessage(err) })
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <form class="grid gap-5" novalidate data-testid="access-dialog" @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>{{ C.title }} für {{ siteName }}</DialogTitle>
          <DialogDescription>{{ C.lead }}</DialogDescription>
        </DialogHeader>

        <fieldset class="grid gap-2">
          <legend class="mb-2 text-sm font-medium">
            {{ C.scopeLabel }}
          </legend>
          <RadioGroup v-model="scope" class="grid gap-2" :aria-label="C.scopeLabel">
            <Label v-for="o in [{ v: 'site', l: C.site, e: C.siteExplain }, { v: 'paths', l: C.paths, e: C.pathsExplain }]" :key="o.v" :for="`${uid}-${o.v}`" class="flex cursor-pointer items-start gap-3 rounded-md border p-3 font-normal has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-accent">
              <RadioGroupItem :id="`${uid}-${o.v}`" :value="o.v" class="mt-0.5" :data-testid="`access-scope-${o.v}`" />
              <span class="grid gap-0.5">
                <span class="font-medium">{{ o.l }}</span>
                <span class="text-sm text-muted-foreground">{{ o.e }}</span>
              </span>
            </Label>
          </RadioGroup>
        </fieldset>

        <div v-if="scope === 'paths'" class="grid gap-2">
          <Label :for="`${uid}-paths`">Pfade</Label>
          <Textarea :id="`${uid}-paths`" v-model="pathsText" rows="3" class="font-mono text-sm" spellcheck="false" :aria-invalid="!!pathsError" data-testid="access-paths" />
          <p :class="pathsError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="pathsError ? 'alert' : undefined">
            {{ pathsError ?? 'Ein Pfad pro Zeile. Ein Pfad gilt auch für alles darunter, /wp-login.php also auch für /wp-login.php/x. Groß- und Kleinschreibung zählt nicht.' }}
          </p>
        </div>

        <fieldset class="grid gap-3">
          <legend class="mb-1 text-sm font-medium">
            {{ C.waysLabel }}
          </legend>
          <p class="-mt-2 text-xs text-muted-foreground">
            {{ C.waysExplain }}
          </p>
          <div class="grid gap-2 rounded-md border p-3">
            <Label class="flex items-start gap-2 font-normal">
              <Checkbox v-model="usePassword" class="mt-0.5" data-testid="access-use-password" />
              <span class="grid gap-0.5"><span class="font-medium">{{ C.password }}</span><span class="text-sm text-muted-foreground">{{ C.passwordExplain }} {{ C.httpsNote }}</span></span>
            </Label>
            <div v-if="usePassword" class="grid gap-1 pl-6">
              <Input v-model="password" type="password" autocomplete="new-password" maxlength="128" :placeholder="hasStoredPassword ? 'Neues Passwort (optional)' : 'Mindestens 8 Zeichen'" :aria-label="C.password" :aria-invalid="!!passwordError" data-testid="access-password" />
              <p :class="passwordError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="passwordError ? 'alert' : undefined">
                {{ passwordError ?? (hasStoredPassword ? C.passwordKeep : 'Gib es nur an Leute weiter, die hinein sollen.') }}
              </p>
            </div>
          </div>
          <div class="grid gap-2 rounded-md border p-3">
            <Label class="flex items-start gap-2 font-normal">
              <Checkbox v-model="useAddresses" class="mt-0.5" data-testid="access-use-addresses" />
              <span class="grid gap-0.5"><span class="font-medium">{{ C.addresses }}</span><span class="text-sm text-muted-foreground">{{ C.addressesExplain }}</span></span>
            </Label>
            <div v-if="useAddresses" class="grid gap-1 pl-6">
              <Textarea v-model="addressesText" rows="2" class="font-mono text-sm" spellcheck="false" placeholder="203.0.113.7" :aria-label="C.addresses" :aria-invalid="!!addressesError" data-testid="access-addresses" />
              <p :class="addressesError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="addressesError ? 'alert' : undefined">
                {{ addressesError ?? C.addressesShared }}
              </p>
            </div>
          </div>
          <div class="grid gap-2 rounded-md border p-3">
            <Label class="flex items-start gap-2 font-normal">
              <Checkbox v-model="ownNetworks" class="mt-0.5" data-testid="access-own-networks" />
              <span class="grid gap-0.5"><span class="font-medium">{{ C.ownNetworks }}</span><span class="text-sm text-muted-foreground">{{ C.ownNetworksExplain }}</span></span>
            </Label>
          </div>
          <p v-if="useAddresses && ownNetworks" class="text-xs text-muted-foreground" data-testid="access-ips-together">
            {{ C.ipsTogether }}
          </p>
          <p v-if="wayError" class="text-sm text-destructive" role="alert">
            {{ wayError }}
          </p>
        </fieldset>

        <template v-if="scope === 'site'">
          <div class="grid gap-2">
            <Label :for="`${uid}-except`">{{ C.except }}</Label>
            <Textarea :id="`${uid}-except`" v-model="exceptText" rows="2" class="font-mono text-sm" spellcheck="false" placeholder="/api/stripe/webhook" :aria-invalid="!!exceptError" data-testid="access-except" />
            <p :class="exceptError ? 'text-sm text-destructive' : 'text-xs text-muted-foreground'" :role="exceptError ? 'alert' : undefined">
              {{ exceptError ?? C.exceptExplain }}
            </p>
          </div>
          <div class="grid gap-2">
            <Label :for="`${uid}-message`">{{ C.message }}</Label>
            <Textarea :id="`${uid}-message`" v-model="message" rows="2" maxlength="500" :placeholder="C.messagePlaceholder" :aria-invalid="!!messageError" data-testid="access-message" />
            <p v-if="messageError" class="text-sm text-destructive" role="alert">
              {{ messageError }}
            </p>
          </div>
        </template>

        <p class="text-xs text-muted-foreground">
          {{ C.stays }}
        </p>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="set.isPending.value" data-testid="access-submit">
            {{ set.isPending.value ? 'Wird gespeichert …' : current ? C.submitChange : C.submitNew }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
