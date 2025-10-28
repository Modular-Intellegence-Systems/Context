# CONTEXT/1.2 Workspace

> **Deterministic capsule format** для Flagship-агентов: единый язык общения между Reasoning Core, Memory Brain и Tooling Mesh.

![CI – Golden Suite](https://github.com/Modular-Intellegence-Systems/Context/actions/workflows/goldens.yml/badge.svg) ![Spec – CTX/1.2](https://img.shields.io/badge/spec-CTX--1.2-blue)

**Цель.** Гарантировать, что каждая `.context` капсула описана спецификацией и проверена golden-тестами, прежде чем попадёт в продуктивные пайплайны Modular Intellegence Systems.

## Repository Map

| Путь | Назначение |
| --- | --- |
| `docs/context_spec_1_2.md` | Нормативная спецификация CONTEXT/1.2 + CTX-CANON/3. |
| `docs/testing.md` | Руководство по запуску и расширению golden-наборов. |
| `.agents/tools/ctx_lint.py` | Эталонный парсер/линтер, используемый во всех проверках. |
| `tests/context/` | Позитивные и негативные `.context` сценарии. |
| `tests/outcomes/` | Эталонные выходные данные для golden-тестов. |
| `.github/workflows/goldens.yml` | CI, запускающий полный golden-suite на каждый push/PR. |

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # при отсутствии файла — убедитесь, что python>=3.11
python tests/run_goldens.py
```

Команда должна завершиться `0`. Любое расхождение между фактическим и ожидаемым выводом фиксирует регрессию и блокирует merge.

## Golden Suite & CI
- Workflow `goldens.yml` стартует на каждый push/PR и валидирует все сценарии.
- Локально запускай `python tests/run_goldens.py` до публикации коммитов.
- Новые конструкции спецификации сопровождаются обновлением golden-наборов и документации.

## Добавление новых сценариев
1. Создай новую `.context` капсулу в `tests/context/` и дай осмысленное имя.
2. Выполни `python tests/run_goldens.py` — получишь digest или описание ошибки.
3. Зафиксируй ожидаемый результат в `tests/outcomes/<name>.json`.
4. Обнови `docs/context_spec_1_2.md`/`docs/testing.md`, если поведение изменилось.
5. Отправь PR с трассой проверки, ссылкой на ADR (если применимо) и скриншотом зелёного CI.

## Status & Next Up
- ✅ Покрыты: resolver metadata, chunk payloads, TTL, confidence models, подписи (rotation/quorum), safe-hints, ошибки TAB/attachment hash mismatch/external relation, JSON round-trip placeholder.
- 🔄 В работе: pack/unpack, валидация тегов, внешние дескрипторы, Registry для публичного обмена.
- 🎯 Цель квартала: расширить негативные сценарии и протокол аудита конвертеров.

## Contributing
- Следуй `AGENTS.md` и Flagship-стандарту: 0 mocks, покрытие ≥85%, cyclomatic ≤10.
- Каждый PR сопровождается design brief + evidence (лог тестов, ссылки на ADR).
- Обсуждения и вопросы — в GitHub Discussions организации.

## Support
- Issues: предпочитаемые вопросы/доработки.
- Контакт: magraytlinov@gmail.com — core-команда отвечает в течение 24 часов будних дней.
- Репозиторий `Context` закреплён на главной странице Modular Intellegence Systems как обязательный вход в модульную экосистему.
