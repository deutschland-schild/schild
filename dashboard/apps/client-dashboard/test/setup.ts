// jsdom gaps used by the app (in addition to packages/ui/test/setup.ts).
window.scrollTo = (() => {}) as typeof window.scrollTo
URL.createObjectURL ??= () => 'blob:test'
URL.revokeObjectURL ??= () => {}
