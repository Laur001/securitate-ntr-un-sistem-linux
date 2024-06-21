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


check_running_processes