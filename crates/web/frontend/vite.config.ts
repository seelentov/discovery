import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Собранный бандл встраивается в бинарник discovery-web через rust-embed (см.
// crates/web/src/lib.rs) и раздаётся с корня ("/"), поэтому относительные пути к ассетам
// обязательны — при абсолютных ("/assets/...") всё сломалось бы, стоит серверу отдавать
// дашборд не с корня (например, за reverse-proxy на под-пути).
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    // Дев-сервер Vite поднимается отдельно от discovery-web — проксируем API-запросы на
    // реальный бэкенд (порт по умолчанию из config.toml, [server].addr = 127.0.0.1:8088),
    // чтобы `npm run dev` работал против настоящих данных без CORS-возни.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8088',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
