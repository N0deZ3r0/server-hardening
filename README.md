# server-hardening

Настройка и защита нового сервера **Debian 12/13 / Ubuntu 22.04–26.04** одной командой.

## Запуск

Зайди на сервер под root и выполни:

```bash
curl -fsSL https://raw.githubusercontent.com/N0deZ3r0/server-hardening/main/harden.sh -o harden.sh && sudo bash harden.sh
```

Скрипт сам перезапускается внутри `tmux`: если SSH оборвётся, зайди снова и выполни `tmux attach -t harden`.


## Что спросит

1. Имя нового пользователя (получит sudo)
2. SSH-ключ: вставить вручную, взять с GitHub (`github.com/<ник>.keys`) или скопировать у root
3. Новый порт SSH (предложит случайный)
4. Какие ещё порты открыть (например `80,443`)
5. Автоперезагрузка после обновления ядра, блокировка пароля root, CrowdSec, Lynis

Затем попросит **проверить вход в новом окне**. Старый порт закрывается только после твоего «да».
Если ответишь «нет», настройки SSH откатятся.

## Что настраивается

| Область | Что делается |
|---|---|
| SSH | новый порт, только ключи, `PermitRootLogin no`, `AllowUsers`, пост-квантовый KEX (mlkem768/sntrup761, если версия OpenSSH их поддерживает), убраны слабые шифры, DH-модули и хост-ключи |
| Пользователи | sudo-пользователь, политика паролей (12+ символов), журнал sudo, пароль root заблокирован |
| Firewall | UFW: всё входящее запрещено, для SSH включён rate-limit |
| Защита от перебора | fail2ban (sshd + recidive, растущий бан до 4 недель), CrowdSec по желанию |
| Ядро | sysctl: kptr/dmesg restrict, BPF hardening, ptrace, защита от redirect/spoofing, BBR |
| Аудит | auditd (изменения пользователей, sudo, ssh, cron, модулей ядра), Lynis |
| Обновления | unattended-upgrades + needrestart, автоперезагрузка ночью (по желанию) |
| Прочее | AppArmor, chrony, постоянный journald, запрет core dump, отключены лишние модули ядра, баннер |
| Вход | сводка о сервере при входе по SSH (IP, нагрузка, RAM, диск, обновления, статус служб); вручную — `server-status` |

## Без вопросов (через переменные окружения)

```bash
sudo NEW_USER=sysop SSH_PORT=42222 GITHUB_KEYS_USER=mygithub EXTRA_PORTS=80,443 \
     AUTO_REBOOT=yes LOCK_ROOT=yes INSTALL_CROWDSEC=no RUN_LYNIS=yes bash harden.sh
```

Подтверждение входа по новому порту всё равно спрашивается: это защита от потери доступа.

## Важно

- **Docker** открывает порты в обход UFW. Публикуй их как `-p 127.0.0.1:8080:80` или используй `ufw-docker`.
- Для SSH-туннелей (например, к БД) поменяй в `/etc/ssh/sshd_config.d/00-hardening.conf` `AllowTcpForwarding no` на `local`.
- Бэкап исходных конфигов: `/root/harden-backup-*`, отчёт: `/root/harden-report.txt`, лог: `/var/log/harden.log`.

## Сводка при входе на уже настроенный сервер

```bash
sudo bash harden.sh --install-status
```

Отключить: `sudo rm /etc/profile.d/99-server-status.sh`. Без сводки при установке: `SERVER_STATUS=no`.
