<script setup lang="ts">
import { Button } from '@schild/ui/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@schild/ui/components/ui/dropdown-menu'
import { useTheme } from '@schild/ui/composables/useTheme'
import { Monitor, Moon, Sun } from '@lucide/vue'

const mode = useTheme()
</script>

<template>
  <DropdownMenu>
    <DropdownMenuTrigger as-child>
      <Button variant="ghost" size="icon-sm" aria-label="Darstellung wählen">
        <Moon v-if="mode === 'dark'" aria-hidden="true" />
        <Sun v-else-if="mode === 'light'" aria-hidden="true" />
        <Monitor v-else aria-hidden="true" />
      </Button>
    </DropdownMenuTrigger>
    <DropdownMenuContent align="end" class="w-40">
      <DropdownMenuLabel>Darstellung</DropdownMenuLabel>
      <DropdownMenuSeparator />
      <DropdownMenuRadioGroup v-model="mode">
        <DropdownMenuRadioItem value="light">
          <Sun aria-hidden="true" /> Hell
        </DropdownMenuRadioItem>
        <DropdownMenuRadioItem value="dark">
          <Moon aria-hidden="true" /> Dunkel
        </DropdownMenuRadioItem>
        <DropdownMenuRadioItem value="auto">
          <Monitor aria-hidden="true" /> Wie das System
        </DropdownMenuRadioItem>
      </DropdownMenuRadioGroup>
    </DropdownMenuContent>
  </DropdownMenu>
</template>
