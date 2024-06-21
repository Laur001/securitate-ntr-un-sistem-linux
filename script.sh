#!/bin/bash

check_running_processes() {
    echo "Verific procesele active..."


    processes=$(ps -eo user,pid,cmd)

    while read -r line; do
        user=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        cmd=$(echo "$line" | awk '{$1=""; $2=""; print $0}')

        if [ "$user" != "root" ]; then
            echo "Proces suspect: Utilizator $user, PID $pid, Comanda: $cmd"
        fi
    done <<< "$processes"

    echo "Verificarea proceselor active s-a incheiat."
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

check_running_processes
check_permissions
check_executables_permissions