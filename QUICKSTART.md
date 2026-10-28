# Discovery — быстрый старт

Discovery — система мониторинга сетевых устройств. Ниже — чистая установка и первый запуск. Выберите готовый бинарник/пакет для своей ОС и архитектуры либо соберите приложение из исходников. Наличие инструкции для платформы не означает, что соответствующий релизный артефакт уже опубликован.

## Запуск из бинарника

Распакуйте полученный архив в отдельный каталог. В нём должны находиться `discovery-agent` (Windows: `discovery-agent.exe`), `LICENSE` и этот файл. Откройте терминал в этом каталоге и создайте папку `data`.

Создайте `config.toml`:

```toml
[server]
addr = "127.0.0.1:8088"
enable_rest = true
enable_webui = true

[storage]
default_database = "main"

[[storage.databases]]
name = "main"
kind = "sqlite"
file_path = "data/discovery.sqlite3"

[logging]
level = "info"
file = ""
```

Это минимальная локальная конфигурация. Данные сохраняются в SQLite относительно рабочего каталога процесса. Запускайте приложение из одного и того же каталога; без настроенного storage используется память, и данные теряются при остановке.

Перед первым запуском задайте:

- `DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD` — выбранный вами одноразовый пароль администратора, минимум 8 символов.
- `DISCOVERY_SECRET_KEY` — 32 случайных байта в Base64 для хранения зашифрованных секретов, включая SSH/SNMPv3. Сохраните ключ отдельно и используйте тот же при следующих запусках.

Примеры ниже содержат заполнители: замените их своими значениями, не копируйте заполнители буквально. Не публикуйте файл окружения, пароль и ключ.

### macOS / Linux

Создайте каталог данных и один раз сгенерируйте ключ:

```sh
mkdir -p data
openssl rand -base64 32
```

Сохраните выданный ключ. В локальном терминале задайте окружение и запустите:

```sh
export CONFIG_FILE="$PWD/config.toml"
export DISCOVERY_SECRET_KEY='вставьте-сохранённый-ключ-Base64'
export DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD='задайте-свой-одноразовый-пароль'
./discovery-agent
```

### Windows (PowerShell)

```powershell
New-Item -ItemType Directory -Force data | Out-Null
$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($keyBytes)
$rng.Dispose()
[Convert]::ToBase64String($keyBytes)
```

Сохраните выданный ключ, затем:

```powershell
$env:CONFIG_FILE = Join-Path (Get-Location).Path 'config.toml'
$env:DISCOVERY_SECRET_KEY = 'вставьте-сохранённый-ключ-Base64'
$env:DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD = 'задайте-свой-одноразовый-пароль'
.\discovery-agent.exe
```

## Первый вход

Откройте [локальный интерфейс](http://127.0.0.1:8088). Пользователь — **admin**, пароль — заданный `DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD`. После входа приложение потребует сменить пароль.

Публичного пароля по умолчанию нет. При пустом хранилище пользователей сервер не запустится без начального пароля. После успешного создания пользователя и смены пароля bootstrap-переменную можно убрать; она не сбрасывает пароль существующего пользователя.

Для первой проверки добавьте профиль и конфигурацию обнаружения для доступного тестового устройства, затем проверьте появление устройства и результаты опроса. Используйте протоколы, доступные в вашей версии.

Процесс работает в терминале; остановка — `Ctrl+C`. Запустите его снова с тем же конфигом и ключом: SQLite сохранит учётные записи и настройки. В примере логи выводятся в терминал.

## Linux-пакеты (.deb / .rpm)

Если получен пакет под вашу архитектуру, установите его (подставьте настоящее имя):

```sh
sudo apt install ./discovery-agent.deb
```

или:

```sh
sudo dnf install ./discovery-agent.rpm
```

Пакет создаёт системного пользователя и ключ в `/etc/discovery-agent/discovery.env`. На чистой установке нужно добавить bootstrap-пароль перед запуском:

```sh
sudoedit /etc/discovery-agent/discovery.env
```

Добавьте строку `DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD=ваш-одноразовый-пароль`, сохранив существующий `DISCOVERY_SECRET_KEY`. Затем:

```sh
sudo systemctl start discovery-agent
sudo systemctl status discovery-agent
sudo journalctl -u discovery-agent -n 100 --no-pager
```

Конфигурация — `/etc/discovery-agent/config.toml`, данные — `/var/lib/discovery-agent/`. Поставляемый конфиг слушает `0.0.0.0:8088`; открывайте `http://<адрес-сервера>:8088` из доверенной сети. Для публичного доступа настройте HTTPS на reverse proxy.

## Docker из исходников

Нужны Docker с Compose и полный checkout проекта. Windows/macOS используют Linux-контейнеры. В корне репозитория создайте `.env` на основе `.env.example`, если своего `.env` ещё нет. Задайте `DISCOVERY_SECRET_KEY` и `DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD` тем же способом, что выше.

```sh
docker compose up -d --build
docker compose logs --tail=100 discovery-agent
```

Интерфейс — [localhost:8088](http://localhost:8088). SQLite хранится в именованном томе `discovery-data`. Остановка с сохранением тома:

```sh
docker compose down
```

Не добавляйте `-v`, если хотите сохранить данные. При нескольких экземплярах изолируйте Compose project и измените опубликованный HTTP-порт. Доступность устройств из контейнера зависит от маршрутизации и разрешений сети.

## Сборка из исходников

Нужны Rust/Cargo, Node.js/npm и native build tools для целевой платформы. Версию Node выбирайте по `engines` зависимостей в `crates/web/frontend/package-lock.json`; не игнорируйте несовместимость, которую сообщает npm. Linux toolchain-зависимости перечислены также в `Dockerfile`; Windows MSVC требует соответствующие Build Tools/SDK, macOS — Apple Command Line Tools.

Из корня checkout:

```sh
cd crates/web/frontend
npm ci
npm run build
cd ../../..
cargo build --release --locked -p discovery-agent
```

Результат: `target/release/discovery-agent` (Windows: `.exe`). UI встроен в бинарник, поэтому после изменения фронтенда повторите обе сборки. Перенесите бинарник в отдельный каталог и выполните первый раздел этой инструкции; не запускайте его с незнакомым корневым `config.toml` проекта.

Сборка шести целей Windows/macOS/Linux × x86_64/ARM64 требует подходящих toolchain и отдельной проверки каждой цели. Подробности для разработчика — `.agents/skills/discovery-build/SKILL.md` в исходном репозитории.

## Если запуск не удался

- Нет начального администратора: проверьте bootstrap-переменную и длину пароля.
- Порт занят: измените `[server].addr` и адрес в браузере, не останавливайте чужой процесс.
- SQLite не открывается: проверьте наличие каталога `data`, права записи и рабочий каталог.
- Данные исчезли после рестарта: проверьте, какой `CONFIG_FILE` прочитан и настроен ли сохраняемый storage.
- Секреты не сохраняются/не читаются: проверьте Base64-ключ и его совпадение с первоначальным; не генерируйте новый вместо потерянного без понимания последствий.
- Устройство недоступно: проверьте маршрут, firewall, параметры протокола и необходимые ОС-разрешения. Доступ к UI сам по себе не подтверждает доступ к устройствам.
