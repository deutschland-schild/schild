<script setup lang="ts">
import AppFrame from './components/AppFrame.vue'
import AuthGate from './components/auth/AuthGate.vue'
</script>

<template>
  <AuthGate>
    <AppFrame />
  </AuthGate>
</template>
