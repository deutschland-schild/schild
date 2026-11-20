<script setup lang="ts">
// Compact installation guide on the start page: a clear choice of setup paths, each linking to its guide.
// All commands, Caddyfile checks, systemd units and rollback instructions live in /doku/gateway/00-installieren.
const paths = [
  {
    title: 'Caddy inkl. Schild',
    badge: 'Caddy-Distribution (empfohlen)',
    text: 'Schild bringt Caddy mit eingebautem WAF-Modul mit. Es lädt dein vorhandenes Caddyfile und startet mit einer Kopie deiner Zertifikate.',
    to: '/doku/gateway/00-installieren#du-nutzt-caddy-schild-als-caddy-distribution',
    cta: 'Anleitung für Caddy',
  },
  {
    title: 'Hinter nginx, Apache oder Load Balancer',
    badge: 'Proxy hinter deinem Webserver',
    text: 'Schild läuft auf Port 8080 hinter deinem Webserver. Deine Zertifikate bleiben, wo sie sind. Bei einem Ausfall leitet nginx auf Wunsch direkt an deine App weiter.',
    to: '/doku/gateway/00-installieren#du-nutzt-nginx-apache-oder-einen-load-balancer-schild-dahinter',
    cta: 'Anleitung für nginx & Apache',
  },
  {
    title: 'Linux-Binary mit systemd',
    badge: 'Ohne Docker · amd64 & arm64',
    text: 'Ein einzelnes statisches Binary inklusive gehärteter systemd-Units, Geodaten und SHA-256-Prüfsummen – direkt als Systemdienst installierbar.',
    to: '/doku/gateway/00-installieren#als-binary-mit-systemd',
    cta: 'Anleitung für Binary & systemd',
  },
]
</script>

<template>
  <div class="grid gap-4 md:grid-cols-3">
    <article v-for="p in paths" :key="p.title" class="flex flex-col justify-between rounded-xl border border-line bg-white p-5 shadow-xs">
      <div>
        <p class="text-xs font-semibold text-signal-deep">{{ p.badge }}</p>
        <h3 class="mt-1.5 text-base font-bold tracking-tight text-ink">{{ p.title }}</h3>
        <p class="mt-2 text-sm leading-relaxed text-slate">{{ p.text }}</p>
      </div>
      <NuxtLink :to="p.to" class="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-link hover:underline">
        {{ p.cta }} <span aria-hidden="true">→</span>
      </NuxtLink>
    </article>
  </div>
</template>
