// No forms: every call to action is a mailto link. The address is joined here and the links get it in the browser
// only (useMailto), so the prerendered HTML carries no address for simple harvesters. Impressum and Datenschutz
// show it as plain text on purpose.
const CONTACT_USER = 'info'
const CONTACT_DOMAIN = 'deutschland-schild.de'
export const contactEmail = () => `${CONTACT_USER}@${CONTACT_DOMAIN}`
export const mailto = (subject: string) => `mailto:${contactEmail()}?subject=${encodeURIComponent(`Deutschland-Schild: ${subject}`)}`
