# Contributing

**English** · [Русский](#участие-в-разработке)

## The one rule

The administrator must never be locked out. Every change is judged against that first:
nothing may close a way in before the new way has been proven from a second window, and
every step that touches SSH must be able to roll back. A setting that is stronger on paper
but can strand someone on a remote server is not an improvement.

The second rule follows from the first: a change is run on a **fresh VPS** before it is
merged, and the pull request says which OS, version and provider. `bash -n` and ShellCheck
catch typos; only a real server shows what cloud-init, socket activation and a half-applied
upgrade do to a script — every one of those was found that way.

## Before you file a bug

Read the **Limits** section of the README. The things listed there are open on purpose,
with the reason for each. If what you found is one of them, it is not a bug.

If it is a vulnerability rather than a bug, do not open an issue: see
[SECURITY.md](SECURITY.md).

## Checking a change

```bash
bash -n harden.sh
shellcheck -S warning harden.sh
```

CI runs the same, plus the embedded scripts, `--check` and the alerts. Then, on a throwaway server:

1. Reinstall the OS, wait for the provider's cloud-init
2. Run the script end to end, including the login check from a second window
3. Reboot and confirm SSH comes back on the new port only
4. Attach the summary printed at the end (`/root/harden-report.txt`), with keys and IPs replaced

## Style

- One file. `curl … && sudo bash harden.sh` must keep working without anything else.
- Every user-facing string goes through `T "русский" "english"`.
- Comments say *why*, especially where the obvious approach was tried and failed.

## Releasing

```bash
tools/prepare-release.sh 2026.10.0     # version into harden.sh, URL and checksum into both READMEs
git commit -am "Release v2026.10.0"
git push origin main                   # wait for CI to pass
git tag v2026.10.0 && git push origin v2026.10.0
```

The Release workflow publishes only if the tag, the version inside the script and the
checksum in both READMEs agree, and the tagged commit is on `main`. A published release is
not edited: a mistake gets the next version number.

---

# Участие в разработке

[English](#contributing) · **Русский**

## Главное правило

Администратор никогда не должен остаться без доступа. Любое изменение оценивается прежде
всего по этому: ничто не может закрыть путь внутрь, пока новый путь не проверен из второго
окна, и каждый шаг, касающийся SSH, должен уметь откатываться. Настройка, которая сильнее
на бумаге, но может оставить человека без доступа к удалённому серверу, — не улучшение.

Второе правило следует из первого: изменение прогоняется на **свежем VPS** до слияния, и в
pull request указано, какая ОС, версия и хостер. `bash -n` и ShellCheck ловят опечатки;
только настоящий сервер показывает, что делают со скриптом cloud-init, socket activation и
недоустановленное обновление, — всё это было найдено именно так.

## Прежде чем сообщать об ошибке

Прочитайте раздел **Ограничения** в README. Перечисленное там оставлено намеренно, с
причиной для каждого пункта. Если найденное — одно из них, это не ошибка.

Если это уязвимость, а не ошибка, не создавайте задачу: см. [SECURITY.md](SECURITY.md).

## Проверка изменения

```bash
bash -n harden.sh
shellcheck -S warning harden.sh
```

CI делает то же самое, проверяет встроенные скрипты, `--check` и уведомления. Затем на
одноразовом сервере:

1. Переустановите ОС, дождитесь cloud-init хостера
2. Прогоните скрипт целиком, включая проверку входа из второго окна
3. Перезагрузите сервер и убедитесь, что SSH поднялся только на новом порту
4. Приложите итог из конца прогона (`/root/harden-report.txt`), заменив ключи и IP

## Стиль

- Один файл. `curl … && sudo bash harden.sh` должно работать без чего-либо ещё.
- Каждая строка для пользователя проходит через `T "русский" "english"`.
- Комментарии объясняют *почему* — особенно там, где очевидный способ был опробован и
  не сработал.

## Выпуск версии

```bash
tools/prepare-release.sh 2026.10.0     # версия в harden.sh, URL и контрольная сумма в оба README
git commit -am "Release v2026.10.0"
git push origin main                   # дождаться зелёного CI
git tag v2026.10.0 && git push origin v2026.10.0
```

Workflow Release публикует версию, только если тег, версия внутри скрипта и контрольная
сумма в обоих README совпадают, а коммит с тегом лежит в `main`. Опубликованный релиз не
правится: ошибка исправляется следующим номером версии.
