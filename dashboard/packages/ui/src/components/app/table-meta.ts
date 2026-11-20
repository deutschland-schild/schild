import type { RowData } from '@tanstack/vue-table'

declare module '@tanstack/vue-table' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends RowData, TValue> {
    /** Human label used in the column visibility menu and for sort buttons. */
    label?: string
    /** Extra classes for header and cells (e.g. 'text-right', 'w-32'). */
    class?: string
    /** Hide on small screens unless enabled explicitly. */
    hideOnMobile?: boolean
  }
}

export {}
