
# TelegramProxyChecker v5

Один Windows EXE без установки Python, Erlang или Git на компьютере пользователя.

## Что внутри

- GUI на Tkinter.
- `mtp_ping` из `seriyps/mtproto_proxy`.
- Erlang/OTP runtime.
- Загрузка свежего списка Grim1313.
- Настоящий MTProto `req_pq/res_pq` handshake и Telegram ping.
- DC -5..-1 и 1..5.
- Normal / DD / Fake-TLS(EE).
- Сортировка по лучшему ping.
- `tg://proxy` -> Telegram Desktop.
- Экспорт рабочих прокси.

`mtp_ping` официально описан проектом как инструмент, который выполняет MTProto `req_pq/res_pq` и Telegram ping через DC, а не просто TCP-проверку.

## Сборка

1. Создайте новый GitHub repository.
2. Загрузите весь этот проект.
3. Откройте Actions -> workflow `Build Windows EXE`.
4. Дождитесь окончания.
5. В workflow выберите Artifacts -> `TelegramProxyChecker-Windows`.
6. Внутри будет один `TelegramProxyChecker.exe`.

На компьютере пользователя не требуются Python/Erlang/Git.

## Примечание

Размер EXE будет заметным, потому что внутрь запакован Erlang runtime. Это сделано специально, чтобы пользователь запускал один файл.
