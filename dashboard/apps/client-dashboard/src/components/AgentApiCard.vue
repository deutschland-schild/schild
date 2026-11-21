<script setup lang="ts">
import type { AgentAPIInput } from '@/api/agentapi'
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CommandBlock,
  ConfirmDialog,
  ErrorState,
  RelativeTime,
  Skeleton,
  StatusPill,
  toast,
} from '@schild/ui'
import { ExternalLink } from '@lucide/vue'
import { computed, ref } from 'vue'
import { agentApiError, useAgentAPI, useAgentTokens, useSetAgentAPI } from '@/api/agentapi'
import { errorMessage } from '@/api/client'
import {
  AGENT_API_COPY as COPY,
  AGENT_API_DOCS,
  agentApiStatus,
  configText,
  listenText,
  needsConfirm,
  scopeLabel,
  sortTokens,
  TOKEN_ADD_COMMAND,
  TOKEN_ADD_COMMAND_DOCKER,
  TOKEN_STATE,
  tokenName,
  tokenState,
} from '@/lib/agentapi'

/**
 * The switch of the agent API (D103): opens and closes its listener while schild runs. Tokens are shown
 * read-only, they are created and revoked on the host. Switching off asks first when the firewall
 * container holds a token, because it fetches its blocks through this API.
 */
const q = useAgentAPI()
const s = computed(() => q.data.value)
const status = computed(() => s.value ? agentApiStatus(s.value) : null)
const set = useSetAgentAPI()

const tokensQuery = useAgentTokens()
const tokens = computed(() => sortTokens(tokensQuery.data.value ?? []).map(t => ({ ...t, name: tokenName(t), state: tokenState(t) })))

const confirmOpen = ref(false)
const pendingInput = ref<AgentAPIInput | null>(null)

function request(input: AgentAPIInput) {
  if (!s.value || set.isPending.value) return
  if (needsConfirm(s.value, input)) {
    pendingInput.value = input
    confirmOpen.value = true
    return
  }
  void send(input)
}

async function send(input: AgentAPIInput) {
  try {
    const st = await set.mutateAsync(input)
    confirmOpen.value = false
    toast.success(input.reset ? COPY.savedReset : st.enabled ? COPY.savedOn : COPY.savedOff)
    void tokensQuery.refetch()
  }
  catch (err) {
    confirmOpen.value = false
    toast.error(COPY.failed, { description: agentApiError(err) })
  }
}
</script>

<template>
  <Card id="agent-api" class="scroll-mt-20" data-testid="agent-api">
    <CardHeader>
      <CardTitle>{{ COPY.title }}</CardTitle>
      <CardDescription>{{ COPY.lead }}</CardDescription>
    </CardHeader>
    <CardContent class="space-y-4 text-sm">
      <ErrorState
        v-if="q.isError.value && !s"
        :title="COPY.loadFailed"
        :description="errorMessage(q.error.value)"
        :retrying="q.isFetching.value"
        @retry="q.refetch()"
      />
      <div v-else-if="!s || !status" class="space-y-3" data-testid="agent-api-loading">
        <Skeleton class="h-9 w-full" />
        <Skeleton class="h-16 w-full" />
      </div>
      <template v-else>
        <!-- Status and the switch -->
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0 flex-1 space-y-2">
            <StatusPill :tone="status.tone" data-testid="agent-api-status">
              <span class="sr-only">Stand: </span>{{ status.label }}
            </StatusPill>
            <p v-if="status.kind === 'off'" class="text-muted-foreground" data-testid="agent-api-text">
              {{ s.config_enabled ? COPY.offText : COPY.lockedText }}
            </p>
            <div v-else-if="status.kind === 'not_open'" class="rounded-lg border border-status-warning/40 bg-status-warning-subtle p-3" role="status" data-testid="agent-api-text">
              <p>{{ COPY.notOpenText }}</p>
              <p v-if="s.error" class="mt-1 font-mono text-xs break-words text-muted-foreground" data-testid="agent-api-error">
                {{ s.error }}
              </p>
            </div>
            <p v-else class="text-muted-foreground" data-testid="agent-api-text">
              {{ listenText(s.listen) }} {{ COPY.withoutToken }}
            </p>
          </div>
          <!-- enabled false in schild.yaml is final (D103): nothing to switch here -->
          <Button
            v-if="s.config_enabled"
            variant="outline"
            :disabled="set.isPending.value"
            :aria-label="s.enabled ? COPY.switchOffLabel : COPY.switchOnLabel"
            data-testid="agent-api-switch"
            @click="request({ enabled: !s.enabled })"
          >
            {{ s.enabled ? COPY.switchOff : COPY.switchOn }}
          </Button>
        </div>

        <!-- Set in the dashboard: what schild.yaml says, and the way back to it -->
        <div v-if="s.state_source === 'dashboard'" class="flex flex-wrap items-center justify-between gap-2 rounded-lg border bg-muted/40 p-3" data-testid="agent-api-source">
          <p class="min-w-0 flex-1 text-muted-foreground">
            Im Dashboard eingestellt<template v-if="s.updated_at">
              {{ ' ' }}<RelativeTime :value="s.updated_at" />
            </template>{{ s.actor ? ` von ${s.actor}` : '' }}. {{ configText(s.config_enabled) }}
          </p>
          <Button variant="ghost" size="sm" :disabled="set.isPending.value" data-testid="agent-api-reset" @click="request({ reset: true })">
            {{ COPY.reset }}
          </Button>
        </div>

        <!-- Tokens: read-only, they are created and revoked on the host -->
        <section aria-labelledby="agent-api-tokens-title" class="space-y-2">
          <h3 id="agent-api-tokens-title" class="font-medium">
            {{ COPY.tokens }}
          </h3>
          <div v-if="s.active_tokens === 0" class="space-y-2" data-testid="agent-api-no-token">
            <p class="text-muted-foreground">
              {{ COPY.noToken }}
            </p>
            <CommandBlock :command="TOKEN_ADD_COMMAND" :caption="COPY.commandCaption" :copy-label="COPY.commandCopy" />
            <CommandBlock :command="TOKEN_ADD_COMMAND_DOCKER" :caption="COPY.commandCaptionDocker" :copy-label="COPY.commandCopyDocker" />
            <p class="text-muted-foreground">
              {{ COPY.tokenOnce }}
            </p>
          </div>
          <p v-else class="text-muted-foreground" data-testid="agent-api-tokens-managed">
            {{ COPY.tokensManaged }}
            <code class="rounded bg-muted px-1 font-mono text-xs">schild token add</code> und
            <code class="rounded bg-muted px-1 font-mono text-xs">schild token revoke</code>.
          </p>

          <Skeleton v-if="tokensQuery.isPending.value" class="h-12 w-full" />
          <p v-else-if="tokensQuery.isError.value && !tokensQuery.data.value" class="text-muted-foreground" role="status">
            {{ COPY.tokensFailed }}
          </p>
          <ul v-else-if="tokens.length" class="divide-y rounded-xl border" data-testid="agent-api-tokens">
            <li v-for="t in tokens" :key="t.id" class="grid gap-1 px-3 py-2" :data-token="t.id" :data-token-state="t.state">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <span :class="['min-w-0 font-medium break-words', t.label ? '' : 'font-mono text-xs']">{{ t.name }}</span>
                <StatusPill :tone="TOKEN_STATE[t.state].tone" size="sm">
                  {{ TOKEN_STATE[t.state].label }}
                </StatusPill>
              </div>
              <p class="text-xs text-muted-foreground">
                {{ scopeLabel(t.scope) }} (<span class="font-mono">{{ t.scope }}</span>) ·
                <template v-if="t.state === 'revoked' && t.revoked_at">
                  widerrufen <RelativeTime :value="t.revoked_at" />
                </template>
                <template v-else-if="t.state === 'expired'">
                  abgelaufen <RelativeTime :value="t.expires_at" />
                </template>
                <template v-else>
                  läuft ab <RelativeTime :value="t.expires_at" />
                </template>
                ·
                <template v-if="t.last_used_at">
                  zuletzt benutzt <RelativeTime :value="t.last_used_at" />
                </template>
                <template v-else>
                  {{ COPY.neverUsed }}
                </template>
              </p>
            </li>
          </ul>
        </section>

        <p>
          <a
            :href="AGENT_API_DOCS"
            target="_blank"
            rel="noopener noreferrer"
            referrerpolicy="no-referrer"
            class="inline-flex items-center gap-1 text-muted-foreground underline underline-offset-4 hover:text-foreground hover:no-underline"
            data-testid="agent-api-docs"
          >
            {{ COPY.docs }}
            <span class="sr-only">{{ COPY.docsNewTab }}</span>
            <ExternalLink class="size-3 shrink-0" aria-hidden="true" />
          </a>
        </p>
      </template>
    </CardContent>

    <ConfirmDialog
      v-model:open="confirmOpen"
      :title="COPY.confirmTitle"
      :description="COPY.confirmText"
      :confirm-label="COPY.switchOff"
      :pending="set.isPending.value"
      @confirm="pendingInput && send(pendingInput)"
    />
  </Card>
</template>
