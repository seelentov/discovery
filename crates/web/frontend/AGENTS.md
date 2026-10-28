# Фронтенд Discovery

Применяются корневые инструкции. React + TypeScript + Vite; точка входа `src/main.tsx`, приложение `src/App.tsx`, страницы в `src/pages`, API в `src/api`.

- Сохраняй существующие компоненты, стили и способы обращения к API. Доступность проверяй по ролям, подписям полей и клавиатурной навигации.
- `npm ci`, `npm run build`, `npm run lint` — существующие команды. Отдельного frontend Unit runner в `package.json` пока нет. Если новая клиентская логика требует Unit, добавь подходящий runner и тесты в рамках задачи; lint/сборка не заменяют Unit.
- После сборки фронтенда пересобери `discovery-agent`: production E2E работает со встроенным `dist`, а не с Vite dev server.
- Для E2E используй [discovery-e2e](../../../.agents/skills/discovery-e2e/SKILL.md). Сохраняй последовательный запуск: существующие specs используют данные предыдущих файлов.
- `vite.config.ts` проксирует `/api` на `127.0.0.1:8088`. При отдельном порте backend адаптируй конфигурацию своей задачи; один `--port` Vite не меняет proxy target.
- `e2e/.auth`, отчёты, traces, `node_modules` и `dist` не коммитятся. Не запускай два E2E-прогона одновременно внутри одного worktree.
