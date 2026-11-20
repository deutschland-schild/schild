<script setup lang="ts">
import { Skeleton } from '@schild/ui'
import { useQueryClient } from '@tanstack/vue-query'
import { nextTick, onScopeDispose, watch, watchEffect } from 'vue'
import { onUnauthorized, setCsrfToken } from '@/api/auth-state'
import { keys } from '@/api/queries'
import { LOGGED_OUT, useSessionQuery } from '@/composables/useSession'
import QueryState from '../QueryState.vue'
import LoginView from './LoginView.vue'
import SetupView from './SetupView.vue'

/** Shows setup, login or the app. Any 401 from the API returns to the login screen. */
const qc = useQueryClient()
const q = useSessionQuery()
watchEffect(() => setCsrfToken(q.data.value?.csrf_token))
onUnauthorized(() => qc.setQueryData(keys.session, LOGGED_OUT))
onScopeDispose(() => onUnauthorized(undefined))
// After login the focused button disappears; move focus to the main landmark so keyboard and screen readers continue there.
watch(() => q.data.value?.authenticated, (now, before) => {
  if (now && before === false) void nextTick(() => document.getElementById('main')?.focus({ preventScroll: true }))
})
</script>

<template>
  <div v-if="q.isPending.value || q.isError.value" class="grid min-h-svh place-items-center p-6">
    <div class="w-full max-w-sm">
      <QueryState :pending="q.isPending.value" :error="q.error.value" :retrying="q.isFetching.value" @retry="q.refetch()">
        <template #skeleton>
          <Skeleton class="h-64 w-full" />
        </template>
      </QueryState>
    </div>
  </div>
  <SetupView v-else-if="q.data.value?.first_run" />
  <LoginView v-else-if="!q.data.value?.authenticated" />
  <slot v-else />
</template>
