import type { Updater } from '@tanstack/vue-table'
import type { ClassValue } from 'clsx'
import type { Ref } from 'vue'
import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** Merge Tailwind classes, later classes win. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** Apply a TanStack updater (value or function) to a ref. */
export function valueUpdater<T>(updaterOrValue: Updater<T>, ref: Ref<T>) {
  ref.value = typeof updaterOrValue === 'function'
    ? (updaterOrValue as (old: T) => T)(ref.value)
    : updaterOrValue
}
