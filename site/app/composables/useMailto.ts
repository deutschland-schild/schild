import { mailto } from '~/utils/contact'

// mailto links without the address in the prerendered HTML: the href appears once the page runs in the browser.
export function useMailto() {
  const mounted = useMounted()
  return (subject: string) => mounted.value ? mailto(subject) : undefined
}
