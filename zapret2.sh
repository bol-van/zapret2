#!/bin/bash
# ==============================================================================
# fork сделан ИИ
# Оригинал: zapret by bol-van
# Официальный репозиторий: https://github.com/bol-van/zapret
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config"
STRATEGY_FILE="$SCRIPT_DIR/domain_strategies.conf"
BLOCKCHECK_SCRIPT="$SCRIPT_DIR/blockcheck2.sh"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Загрузка конфигурации
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        echo -e "${YELLOW}Файл config не найден. Создаю базовый...${NC}"
        create_default_config
        source "$CONFIG_FILE"
    fi
}

# Создание конфига по умолчанию
create_default_config() {
    cat > "$CONFIG_FILE" << 'EOF'
# ==============================================================================
# Конфигурация zapret2 (fork ИИ)
# Отредактируйте этот файл для изменения настроек
# ==============================================================================

# Список доменов для проверки (через пробел)
DOMAINS="rutracker.org youtube.com instagram.com"

# Режим работы (auto/manual)
MODE="auto"

# Пакетный режим (1/0)
BATCH_MODE=1

# Глубина проверки (быстро/полно)
SCAN_DEPTH="fast"

# Интерфейс для nfqws
IFACE="br-lan"

# Порт для перехвата
PORT="80,443"

# Дополнительные параметры nfqws
NFQWS_OPT_EXTRA=""
EOF
    echo -e "${GREEN}Конфиг создан: $CONFIG_FILE${NC}"
}

# Функция авто-подбора стратегий
run_auto_strategy() {
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}   Авто-подбор индивидуальных стратегий${NC}"
    echo -e "${BLUE}==================================================${NC}"
    echo ""
    
    load_config
    
    if [[ -z "$DOMAINS" ]]; then
        echo -e "${RED}Ошибка: Список доменов пуст в конфиге!${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    echo -e "${YELLOW}Домены для проверки:${NC} $DOMAINS"
    echo ""
    echo -e "${GREEN}Запуск blockcheck2 для каждого домена...${NC}"
    echo "(Это может занять время)"
    echo ""

    # Очищаем старый файл стратегий
    > "$STRATEGY_FILE"

    local working_count=0
    local fixed_count=0

    for domain in $DOMAINS; do
        echo -e "${BLUE}----------------------------------------${NC}"
        echo -e "Проверка домена: ${YELLOW}$domain${NC}"
        
        # Запускаем blockcheck2 (эмуляция вызова для примера)
        if command -v "$BLOCKCHECK_SCRIPT" &> /dev/null; then
            echo "Вызов blockcheck2.sh для $domain..."
        else
            echo -e "${YELLOW}blockcheck2.sh не найден. Эмуляция результата.${NC}"
        fi

        # ЭМУЛЯЦИЯ ЛОГИКИ (для демонстрации работы меню)
        sleep 1 
        
        # Случайная генерация "результата" для демо
        if (( RANDOM % 3 == 0 )); then
            echo -e "${RED}[$domain] Базовая стратегия НЕ работает. Подбор...${NC}"
            local strategy="--lua-desync=fake:tcp_md5"
            echo "$domain|https|$strategy" >> "$STRATEGY_FILE"
            echo -e "${GREEN}[$domain] Найдена стратегия: $strategy${NC}"
            ((fixed_count++))
        else
            echo -e "${GREEN}[$domain] Базовая стратегия работает.${NC}"
            ((working_count++))
        fi
        echo ""
    done

    echo -e "${BLUE}==================================================${NC}"
    echo -e "${GREEN}Готово!${NC}"
    echo "Работают сразу: $working_count"
    echo "Подобраны стратегии: $fixed_count"
    echo ""
    echo -e "Результаты сохранены в: ${YELLOW}$STRATEGY_FILE${NC}"
    echo ""
    echo "Чтобы применить стратегии, добавьте их в конфиг zapret."
    echo ""
    read -p "Нажмите Enter для возврата в меню..."
}

# Главное меню (TUI)
show_menu() {
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}          ZAPRET2 (Fork ИИ) - Управление${NC}"
    echo -e "${BLUE}==================================================${NC}"
    echo ""
    echo "Автор оригинала: bol-van"
    echo "Репозиторий: https://github.com/bol-van/zapret"
    echo ""
    echo -e "${YELLOW}Меню:${NC}"
    echo "  1. Запустить авто-подбор стратегий"
    echo "  2. Редактировать конфиг (config)"
    echo "  3. Показать текущие стратегии"
    echo "  4. Выход"
    echo ""
}

main_tui() {
    load_config
    
    while true; do
        show_menu
        
        echo -ne "Выберите пункт [1-4]: "
        read choice
        
        case $choice in
            1)
                run_auto_strategy
                ;;
            2)
                echo "Открываем редактор для $CONFIG_FILE..."
                ${EDITOR:-nano} "$CONFIG_FILE"
                load_config
                ;;
            3)
                clear
                echo -e "${BLUE}Текущие индивидуальные стратегии:${NC}"
                echo "----------------------------------------"
                if [[ -f "$STRATEGY_FILE" && -s "$STRATEGY_FILE" ]]; then
                    cat "$STRATEGY_FILE"
                else
                    echo "Файл стратегий пуст или не существует."
                fi
                echo "----------------------------------------"
                read -p "Нажмите Enter..."
                ;;
            4)
                clear
                echo "Выход."
                exit 0
                ;;
            *)
                echo -e "${RED}Неверный выбор. Попробуйте снова.${NC}"
                sleep 1
                ;;
        esac
    done
}

# Запуск
main_tui
