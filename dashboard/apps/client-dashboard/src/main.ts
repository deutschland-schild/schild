import { installQuery } from '@schild/app-kit'
import { createApp } from 'vue'
import App from './App.vue'
import { apiPrefix } from './api/generated/operations'
import { createAppRouter } from './router'
import '@schild/ui/fonts.ts'
import '@schild/ui/styles.css'

async function bootstrap() {
  if (import.meta.env.VITE_MOCK === 'true') {
    // Stateful mock backend (MSW). Only in mock mode; tree-shaken from production builds.
    const { startMock } = await import('./mock/browser')
    await startMock(apiPrefix)
  }
  const app = createApp(App)
  const router = createAppRouter()
  app.use(router)
  installQuery(app)
  // Wait for the auth guard: before the first navigation no route is public, so App would flash the dashboard.
  await router.isReady()
  app.mount('#app')
}

void bootstrap()
