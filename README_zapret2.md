# zapret2 (Linux Fork by AI)

> **fork сделан ИИ**  
> Оптимизированная версия для Linux с авто-подбором индивидуальных стратегий для каждого домена.

## Возможности

- 🚀 **Авто-подбор стратегий**: Каждый домен получает свою рабочую конфигурацию
- 📦 **Пакетный режим**: Быстрое тестирование списка доменов
- 💾 **Автосохранение**: Стратегии сохраняются в `domain_strategies.conf`
- 🖥️ **Простой TUI**: Интуитивное текстовое меню

## Быстрый старт

```bash
# Запуск TUI меню
./zapret2.sh

# Авто-подбор для конкретных доменов
./zapret2.sh --auto --domains="youtube.com,rutracker.org" --batch

# Показать справку
./zapret2.sh --help
```

## Конфигурация

### Основные настройки
Файл: `config` (создается из `config.default`)
- Параметры firewall
- Настройки ipset
- Параметры nfqws2
- Сетевые интерфейсы

### Стратегии доменов
Файл: `domain_strategies.conf` (обновляется автоматически)

**Формат:** `домен|протокол|стратегия`

**Пример:**
```
rutracker.org|http|--lua-desync=http_hostcase
youtube.com|https-tls12|--lua-desync=fake:blob=fake_default_tls:tcp_md5
```

## Требования

- **ОС**: Только Linux (требуется nftables/nfqws)
- **Зависимости**: bash, blockcheck2.sh, zapret утилиты

---

**Оригинальный проект**: [bol-van/zapret2](https://github.com/bol-van/zapret2)  
**Автор оригинала**: bol-van  
**Эта версия**: Fork сделан ИИ для Linux
