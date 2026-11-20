import { installQuery } from '@schild/app-kit'
import { createApp } from 'vue'
import { apiPrefix } from './api/generated/operations'
import App from './App.vue'
import { createAppRouter } from './router'
import '@schild/ui/fonts.ts'
import '@schild/ui/styles.css'

async function bootstrap() {
  if (import.meta.env.VITE_MOCK === 'true') {
    // Stateful lab mock (src/mock), seeded from contracts/api/fixtures/lab. Never part of a production build.
    const { startLabMock } = await import('./mock')
    await startLabMock(apiPrefix)
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
