<script setup lang="ts">
import { Button } from '@schild/ui/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@schild/ui/components/ui/tooltip'
import { countryName, flagEmoji, isUnknownCountry } from '@schild/ui/lib/format'
import { cn } from '@schild/ui/lib/utils'
import { Check, Copy, Globe } from '@lucide/vue'
import { useClipboard } from '@vueuse/core'
import { computed } from 'vue'

/**
 * Visitor IP address in plaintext (local dashboard only, decision E7).
 * Flag + country and ASN in a tooltip, copy button. Never sent anywhere.
 */
const props = withDefaults(defineProps<{
  ip: string
  /** ISO 3166-1 alpha-2. */
  country?: string | null
  asn?: number | null
  asnOrg?: string | null
  copyable?: boolean
  class?: string
}>(), { country: null, asn: null, asnOrg: null, copyable: true, class: undefined })

const { copy, copied, isSupported } = useClipboard({ copiedDuring: 1500, legacy: true })
const flag = computed(() => flagEmoji(props.country))
const place = computed(() => isUnknownCountry(props.country) ? 'Land unbekannt' : countryName(props.country))
const network = computed(() => props.asn ? `AS${props.asn}${props.asnOrg ? ` · ${props.asnOrg}` : ''}` : 'Netz unbekannt')
</script>

<template>
  <span :class="cn('inline-flex max-w-full items-center gap-1.5', props.class)">
    <Tooltip>
      <TooltipTrigger as-child>
        <span class="inline-flex min-w-0 cursor-default items-center gap-1.5 rounded-sm" tabindex="0" :aria-label="`${ip}, ${place}, ${network}`">
          <span v-if="flag" aria-hidden="true" class="text-base leading-none">{{ flag }}</span>
          <Globe v-else class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" data-testid="ip-no-country" />
          <span class="truncate font-mono text-[13px]" data-testid="ip">{{ ip }}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        <p>{{ place }}</p>
        <p class="opacity-80">
          {{ network }}
        </p>
      </TooltipContent>
    </Tooltip>
    <Button
      v-if="copyable && isSupported"
      variant="ghost"
      size="icon-xs"
      :aria-label="copied ? 'Kopiert' : `IP-Adresse ${ip} kopieren`"
      @click.stop="copy(ip)"
    >
      <Check v-if="copied" class="text-status-success" aria-hidden="true" />
      <Copy v-else aria-hidden="true" />
    </Button>
  </span>
</template>
