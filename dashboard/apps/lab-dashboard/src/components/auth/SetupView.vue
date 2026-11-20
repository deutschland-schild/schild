<script setup lang="ts">
import { Button, Input } from '@schild/ui'
import { computed, ref } from 'vue'
import { useSetup } from '@/composables/useSession'
import { fieldErrors, problemMessage } from '@/lib/problem'
import FormField from '../FormField.vue'
import AuthCard from './AuthCard.vue'

const code = ref('')
const password = ref('')
const repeat = ref('')
const setup = useSetup()
const local = ref<Record<string, string>>({})
const errs = computed(() => ({ ...fieldErrors(setup.error.value), ...local.value }))
function submit() {
  local.value = {}
  if (!code.value.trim()) local.value.setup_code = 'Trag den Einrichtungscode ein. Er steht im Log des Lab-Servers.'
  if (password.value.length < 12) local.value.password = 'Mindestens 12 Zeichen.'
  else if (password.value !== repeat.value) local.value.repeat = 'Die beiden Passwörter sind nicht gleich.'
  if (Object.keys(local.value).length) return
  setup.mutate({ password: password.value, setup_code: code.value.trim() })
}
</script>

<template>
  <AuthCard title="Lab einrichten" description="Leg das Admin-Passwort fest. Danach meldest du dich damit an.">
    <form class="grid gap-4" @submit.prevent="submit">
      <FormField v-slot="{ id, aria }" label="Einrichtungscode" hint="Steht im Log des Lab-Servers. Du brauchst ihn auch über einen SSH-Tunnel." :error="errs.setup_code">
        <Input :id="id" v-model="code" v-bind="aria" autocomplete="one-time-code" class="font-mono" />
      </FormField>
      <FormField v-slot="{ id, aria }" label="Neues Passwort" hint="Mindestens 12 Zeichen." required :error="errs.password">
        <Input :id="id" v-model="password" v-bind="aria" type="password" autocomplete="new-password" />
      </FormField>
      <FormField v-slot="{ id, aria }" label="Passwort wiederholen" required :error="errs.repeat">
        <Input :id="id" v-model="repeat" v-bind="aria" type="password" autocomplete="new-password" />
      </FormField>
      <p v-if="setup.isError.value && !errs.password" class="text-sm font-medium text-status-danger" role="alert">
        {{ problemMessage(setup.error.value) }}
      </p>
      <Button type="submit" :disabled="setup.isPending.value">
        Passwort festlegen
      </Button>
    </form>
  </AuthCard>
</template>
