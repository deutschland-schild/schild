// The current release of the Schild Gateway. This is the ONE place for the version on the website: the install
// commands (InstallPicker.vue), the changelog on /ueber and every link to the repository read it from here.
// A new release is a change to RELEASE_VERSION, nothing else. The date of a release is the one GitHub shows.
export const RELEASE_VERSION = '0.1.0-alpha.1'

export const REPO_URL = 'https://github.com/deutschland-schild/schild'
export const RELEASE_TAG = `v${RELEASE_VERSION}`
export const RELEASES_URL = `${REPO_URL}/releases`
export const RELEASE_URL = `${REPO_URL}/releases/tag/${RELEASE_TAG}`
export const RELEASE_DOWNLOAD = `${REPO_URL}/releases/download/${RELEASE_TAG}`
export const ISSUES_URL = `${REPO_URL}/issues`
export const CONTRIBUTING_URL = `${REPO_URL}/blob/main/CONTRIBUTING.md`
export const SECURITY_URL = `${REPO_URL}/blob/main/SECURITY.md`
// Files of the tagged source tree, e.g. the Docker quickstart.
export const RAW_URL = `https://raw.githubusercontent.com/deutschland-schild/schild/${RELEASE_TAG}`
export const IMAGE = `ghcr.io/deutschland-schild/schild:${RELEASE_VERSION}`
// Source file of a docs page on GitHub (HubChapter.vue, "Diskutieren").
export const sourceUrl = (file: string) => `${REPO_URL}/blob/main/${file}`
