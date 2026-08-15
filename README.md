# Telegram Proxy Checker v5.12

Windows GUI checker for Telegram MTProto proxy links.

## Что исправлено в v5.12
- свежий список после скачивания сразу появляется в таблице;
- при массовой проверке больше нет всплывающих окон на каждый прокси;
- `mtp_ping` запускается без создания консольного окна Windows;
- протокол (`normal` / `secure` / `fake-tls`) передаётся в `mtp_ping` явно;
- поддерживаются Fake-TLS secrets в hex и URL-safe base64;
- вывод `mtp_ping` разбирается по актуальному формату `DC +N ... ping=... OK`;
- ошибка конкретного `mtp_ping` показывается в строке таблицы, а не теряется за общим сообщением;
- ссылка для Telegram формируется заново из server/port/secret и открывается через зарегистрированный `tg://` handler;
- GitHub Actions использует актуальные версии actions.

## Сборка
GitHub Actions → Build Windows EXE → Run workflow.


## v5.12 fix

Windows builds now remove relocatable OTP `erl.ini` files that can contain absolute GitHub runner paths. The application also sets the bundled Erlang runtime root/PATH before starting `escript`, preventing `Could not load module D:\\a\...` errors when checking MTProto proxies.


## Публикация релиза

Workflow запускается вручную через **Actions → Build Windows EXE → Run workflow**.
После успешной сборки GitHub Actions автоматически создаёт/обновляет релиз **v5.12** и прикладывает к нему `TelegramProxyChecker.exe`.
Готовый EXE также сохраняется как GitHub Actions Artifact.
