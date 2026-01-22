# wa + Tailscale Setup Guide

Документація по налаштуванню wa для роботи з Tailscale мережею.

## Архітектура

```
Mac (YOUR_MAC_TAILSCALE_IP)          Ubuntu Server (YOUR_SERVER_TAILSCALE_IP)
        │                              │
        └── SSH + Tailscale ───────► wa daemon
                                        │
                                   WezTerm panes
```

## Setup на Ubuntu Server

### 1. Встановлення wa
```bash
cd /data/projects/wezterm_automata
cargo install --path crates/wa
```

### 2. Конфігурація wa
Створити `~/.config/wa/wa.toml`:
```toml
# wa.toml - Unified configuration for wezterm_automata

[general]
log_level = "info"
data_dir = "~/.local/share/wa"
# Bind на Tailscale IP для доступу з Mac
bind_address = "YOUR_SERVER_TAILSCALE_IP:8880"

[ingest]
poll_interval_ms = 200
backpressure_limit = 4096
gap_detection = true

[storage]
db_path = "~/.local/share/wa/wa.db"
retention_days = 30
checkpoint_interval_ms = 60000

[patterns]
packs = ["builtin:core", "builtin:codex", "builtin:claude_code"]

[patterns.state_gating]
enabled = true
require_agent_match = true

[workflows]
enabled = ["handle_compaction", "handle_usage_limits"]
max_concurrent = 3

[workflows.handle_usage_limits]
enabled = true
# failover_profile = "backup_account"
pause_on_limit = true

[safety]
rate_limit_per_pane = 30
require_prompt_active = true
audit_redaction = true

[metrics]
enabled = false
bind = "127.0.0.1:9464"
```

### 3. Запуск wa daemon
```bash
wa watch --foreground  # Для тестування
wa watch               # У фоні
```

## Setup на Mac

### 1. SSH конфігурація
Додати в `~/.ssh/config`:
```ssh
Host your-server-alias
    HostName YOUR_SERVER_TAILSCALE_IP
    User YOUR_USERNAME
    IdentityFile ~/.ssh/YOUR_SSH_KEY
    # Forward wa IPC socket (опціонально)
    LocalForward 9999 /data/projects/wezterm_automata/.wa/ipc.sock
    # Зберігати з'єднання
    ControlMaster auto
    ControlPath ~/.ssh/YOUR_SSH_KEY
    ControlPersist 10m
```

### 2. wa команди через SSH
```bash
# Прямі SSH команди
ssh YOUR_SERVER_TAILSCALE_IP -i ~/.ssh/YOUR_SSH_KEY "wa robot state"
ssh YOUR_SERVER_TAILSCALE_IP -i ~/.ssh/YOUR_SSH_KEY "wa robot send PANE_ID 'command'"

# Зручні alias
alias war="ssh YOUR_SERVER_TAILSCALE_IP -i ~/.ssh/YOUR_SSH_KEY wa robot"
```

## Використання

### Основні wa команди
```bash
# Статус панелей
wa robot state

# Відправка команди
wa robot send PANE_ID "echo hello"

# Пошук по виводу
wa search "error"

# Отримати текст з панелі
wa robot get-text PANE_ID --lines 20

# Очікування паттерну
wa robot wait-for PANE_ID "claude:task_complete"
```

### З Mac через SSH
```bash
# Підключитися і працювати
ssh your-server-alias
wa robot state

# Або напряму
war state
war send 55 "start task"
war search "compilation failed"
```

## Tested Configuration

- **Ubuntu Server:** 25.10 на Tailscale IP YOUR_SERVER_TAILSCALE_IP
- **Mac Client:** Через SSH key `YOUR_SSH_KEY`
- **wa Version:** 0.1.0
- **Status:** ✅ Працює (налаштовано 22.01.2026)

## Notes

- wa daemon працює постійно і спостерігає за WezTerm панелями
- Попередження "Pane not found" нормальні - панелі закрилися
- Конфігурація `~/.config/wa/wa.toml` не комітиться (user-specific)