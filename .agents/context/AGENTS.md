# Контекстный индекс для формата CONTEXT

## Структура базовой директории
- `CONTEXT/specs/` — JSONL-выдержки ключевых спецификаций и решений.
- `CONTEXT/examples/` — описания эталонных файлов (human/feed) для быстрого доступа.

## Правила JSONL-записей
Каждая строка JSONL содержит поля:
- `date` — дата создания (ISO 8601, UTC).
- `type` — категория (`spec`, `insight`, `decision`).
- `title` — краткий заголовок события/артефакта.
- `summary` — ключевые тезисы (≤ 280 символов).
- `source` — относительный путь или ссылка на артефакт.
- `tags` — массив коротких тегов (строки).

## Наличие артефактов
- `CONTEXT/specs/2025-10-28_context_spec.jsonl` — ссылка на `docs/context_spec_1_2.md` с описанием @CONTEXT/1.2 + CTX-CANON/3.
- `CONTEXT/examples/2025-10-28_context_example.jsonl` — сводка по `example.context` и `contexts/example_feed.context` (human/feed профили).

## Инструментарий `.agents/tools`
- `ctx_lint.py` — lint/каноникализация @CONTEXT/1.2 (namespaces, GREF, feed, подписи).
- `log_metrics.py` — сбор токенов/времени/памяти из JSONL-логов Codex (`python .agents/tools/log_metrics.py <glob>`).
