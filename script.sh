#!/bin/bash

check_processes() {
    echo "Verificare procese active..."

    declare -a whitelist=("sshd" "systemd" "bash" "nginx" "mysqld" "postgres" "apache2" "cron" "init" "sshd")

    processes=$(ps -eo user,pid,%cpu,%mem,cmd --sort=-%cpu,-%mem --no-headers)

    suspect_found=0

    for cmd in "${whitelist[@]}"; do
        found=0  

        while IFS= read -r line; do
            user=$(echo "$line" | awk '{print $1}')
            pid=$(echo "$line" | awk '{print $2}')
            cpu=$(echo "$line" | awk '{print $3}')
            mem=$(echo "$line" | awk '{print $4}')
            process_cmd=$(echo "$line" | awk '{$1=""; $2=""; $3=""; $4=""; print substr($0,5)}')

            if [[ "$process_cmd" == "$cmd"* ]]; then
                found=1  
                break    
            fi
        done <<< "$processes"

        if [ $found -eq 0 ]; then
            echo "Proces suspect sau lipsa: $cmd"
            suspect_found=1
        fi
    done

    while IFS= read -r line; do
        user=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        cpu=$(echo "$line" | awk '{print $3}')
        mem=$(echo "$line" | awk '{print $4}')
        cmd=$(echo "$line" | awk '{$1=""; $2=""; $3=""; $4=""; print substr($0,5)}')

        if (( $(echo "$cpu > 50" | bc -l) )); then
            echo "Consum excesiv de CPU: Utilizator $user, PID $pid, Comanda: $cmd, CPU: $cpu%, Memorie: $mem%"
            suspect_found=1
        fi

        if (( $(echo "$mem > 50" | bc -l) )); then
            echo "Consum excesiv de memorie: Utilizator $user, PID $pid, Comanda: $cmd, CPU: $cpu%, Memorie: $mem%"
            suspect_found=1
        fi
    done <<< "$processes"

    return $suspect_found
}


check_disk_space() {
    echo "Verific spatiul de stocare disponibil..."

    available_space=$(df -h / | awk 'NR==2 {print $4}')

    echo "Spatiu disponibil pe discul principal: $available_space"
}


check_memory_usage() {
    echo "Verific utilizarea memoriei RAM..."

    memory_usage=$(free -m | awk 'NR==2 {print $3}')

    echo "Utilizare actuala a memoriei RAM: $memory_usage MB"
}

running_processes() {
    check_processes
    check_disk_space
    check_memory_usage

    if [ $? -eq 1 ]; then
        echo "Au fost identificate procese suspecte sau cu consum excesiv de resurse."
    else
        echo "Nu au fost identificate probleme cu procesele sau resursele sistemului."
    fi
}


check_permissions() {
    echo "Verificare permisiuni de securitate..."

    critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/gshadow"
        "/root"
    )


    for file in "${critical_files[@]}"; do
        if [ -e "$file" ]; then
            permissions=$(stat -c "%a" "$file")
            owner=$(stat -c "%U" "$file")
            group=$(stat -c "%G" "$file")

            echo "Verific $file - Permisiuni: $permissions, Proprietar: $owner, Grup: $group"


            case "$file" in
                "/etc/passwd")
                    if [ "$permissions" -ne 644 ] || [ "$owner" != "root" ]; then
                        echo "Problema de securitate cu $file"
                    fi
                    ;;
                "/etc/shadow")
                    if [ "$permissions" -ne 600 ] || [ "$owner" != "root" ]; then
                        echo "Problema de securitate cu $file"
                    fi
                    ;;
                "/etc/group")
                    if [ "$permissions" -ne 644 ] || [ "$owner" != "root" ]; then
                        echo "Problema de securitate cu $file"
                    fi
                    ;;
                "/etc/gshadow")
                    if [ "$permissions" -ne 600 ] || [ "$owner" != "root" ]; then
                        echo "Problema de securitate cu $file"
                    fi
                    ;;
                "/root")
                    if [ "$permissions" -ne 700 ] || [ "$owner" != "root" ]; then
                        echo "Problema de securitate cu $file"
                    fi
                    ;;
                *)
                    echo "Fisier necunoscut $file"
                    ;;
            esac
        else
            echo "Fisierul $file nu exista"
        fi
    done

    echo "Verificarea permisiunilor s-a incheiat."
}



check_executables_permissions() {
    echo "Verificare permisiun executabilelor..."


    executables=$(find / -type f -executable 2>/dev/null)
    echo "executbile gasite"


    for file in $executables; do
        permissions=$(stat -c "%a" "$file")
        owner=$(stat -c "%U" "$file")
        group=$(stat -c "%G" "$file")


        if [ "$permissions" != "755" ] || [ "$owner" != "root" ]; then
            echo "Problema de securitate cu $file - Permisiuni: $permissions, Proprietar: $owner, Grup: $group"
        fi
    done

    echo "Verificarea permisiunilor executabilelor s-a incheiat."
}

running_processes
check_permissions
check_executables_permissions