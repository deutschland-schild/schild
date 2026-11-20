<script setup lang="ts">
import { Button, Input } from '@schild/ui'
import { computed, ref } from 'vue'
import { useLogin } from '@/composables/useSession'
import { fieldErrors, problemMessage } from '@/lib/problem'
import FormField from '../FormField.vue'
import AuthCard from './AuthCard.vue'

const isMock = import.meta.env.VITE_MOCK === 'true'
const user = ref('admin')
const password = ref('')
const login = useLogin()
const errs = computed(() => fieldErrors(login.error.value))
function submit() {
  if (!password.value) return
  login.mutate({ user: user.value.trim() || 'admin', password: password.value })
}
</script>

<template>
  <AuthCard title="Anmelden" description="Nur für Menschen, die dieses Lab betreiben oder prüfen.">
    <form class="grid gap-4" @submit.prevent="submit">
      <FormField v-slot="{ id, aria }" label="Benutzer" :error="errs.user">
        <Input :id="id" v-model="user" v-bind="aria" autocomplete="username" />
      </FormField>
      <FormField v-slot="{ id, aria }" label="Passwort" required :error="errs.password">
        <Input :id="id" v-model="password" v-bind="aria" type="password" autocomplete="current-password" autofocus />
      </FormField>
      <p v-if="login.isError.value && !errs.password" class="text-sm font-medium text-status-danger" role="alert">
        {{ problemMessage(login.error.value) }}
      </p>
      <Button type="submit" :disabled="login.isPending.value || !password">
        {{ login.isPending.value ? 'Wird geprüft …' : 'Anmelden' }}
      </Button>
      <p v-if="isMock" class="text-xs text-muted-foreground">
        Testdaten: Jedes Passwort passt, außer „falsch“.
      </p>
    </form>
  </AuthCard>
</template>
