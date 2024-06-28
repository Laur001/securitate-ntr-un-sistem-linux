#!/bin/bash

LOGFILE="/var/log/system_security_check.log"
PROBLEMS=()

if [ "$(id -u)" != "0" ]; then
    zenity --error --text="Acest script trebuie rulat ca root"
    exit 1
fi

zenity --info --text="Verificare Securitate Sistem - $(date)" | tee -a $LOGFILE

check_processes() {
    processes=$(ps -eo user,pid,etime,cmd --sort=-%cpu,-%mem --no-headers)
    total_processes=$(echo "$processes" | wc -l)

    zenity --info --text="Verificare procese active..." | tee -a $LOGFILE

    echo "$processes" > /tmp/running_processes.txt
    zenity --text-info --filename=/tmp/running_processes.txt

    # declare -a critical_users=("root" "www-data" "mysql" "postgres")
    declare -a known_malicious=("WannaCry" "NotPetya" "Mirai")
    declare -a trusted_paths=("/bin" "/usr/bin" "/sbin" "/usr/sbin" "/usr/local/bin")

    suspect_found=0

    current=0
    while IFS= read -r line; do
        ((current++))
        user=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        etime=$(echo "$line" | awk '{print $3}')
        cmd=$(echo "$line" | awk '{for (i=4; i<=NF; i++) printf "%s ", $i; print ""}' | awk '{print $1}')
        cmd_full=$(echo "$line" | awk '{for (i=4; i<=NF; i++) printf "%s ", $i; print ""}')

        echo "$((current * 100 / total_processes))"
        echo "# Verificare proces PID: $pid"

        echo "Checking process: User=$user, PID=$pid, Etime=$etime, Cmd=$cmd_full" >> $LOGFILE

        cmd_dir=$(dirname "$cmd")
        if [[ ! " ${trusted_paths[@]} " =~ " ${cmd_dir} " ]]; then
            PROBLEMS+=("Proces cu cale neacreditata: Utilizator $user, PID $pid, Comanda: $cmd_full")
            suspect_found=1
        fi

        if [[ " ${known_malicious[@]} " =~ " ${cmd} " ]]; then
            PROBLEMS+=("Proces cunoscut ca fiind rau intentionat: Utilizator $user, PID $pid, Comanda: $cmd_full")
            suspect_found=1
        fi

        lsof_output=$(lsof -p $pid)
        if echo "$lsof_output" | grep -q "irc"; then
            PROBLEMS+=("Conexiune IRC suspecta: Utilizator $user, PID $pid, Comanda: $cmd_full")
            suspect_found=1
        fi

        if echo "$cmd_full" | grep -q "^\."; then
            PROBLEMS+=("Proces lansat din director ascuns: Utilizator $user, PID $pid, Comanda: $cmd_full")
            suspect_found=1
        fi

        if [[ $user != "root" ]] && [[ $(id -u $user) -eq 0 ]]; then
            PROBLEMS+=("Proces root lansat de utilizator neautorizat: Utilizator $user, PID $pid, Comanda: $cmd_full")
            suspect_found=1
        fi

        child_processes=$(pgrep -P $pid)
        if [ -n "$child_processes" ] && [ $suspect_found -eq 1 ]; then
            PROBLEMS+=("Proces cu procese copil: Utilizator $user, PID $pid, Comanda: $cmd_full, Copii: $child_processes")

            for child in $child_processes; do
                child_cmd_full=$(ps -p $child -o args=)
                PROBLEMS+=("Proces copil suspect: PID $child, Comanda: $child_cmd_full")
            done
        fi

    done <<< "$processes" | zenity --progress --auto-close --title="Verificare procese active" --text="Verificare procese..." --percentage=0

    return $suspect_found
}


check_permissions() {
    critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/gshadow"
        "/root"
    )

    total_files=${#critical_files[@]}
    
    (
        for ((i=0; i<total_files; i++)); do
            file="${critical_files[i]}"
            
            percentage=$(( (i + 1) * 100 / total_files ))
            echo "$percentage"
            echo "# Verificare fisier: $file"

            if [ -e "$file" ]; then
                permissions=$(stat -c "%a" "$file")
                owner=$(stat -c "%U" "$file")
                group=$(stat -c "%G" "$file")

                case "$file" in
                    "/etc/passwd")
                        if [ "$permissions" -ne 644 ] || [ "$owner" != "root" ]; then
                            PROBLEMS+=("Problema de securitate cu $file")
                        fi
                        ;;
                    "/etc/shadow")
                        if [ "$permissions" -ne 600 ] || [ "$owner" != "root" ]; then
                            PROBLEMS+=("Problema de securitate cu $file")
                        fi
                        ;;
                    "/etc/group")
                        if [ "$permissions" -ne 644 ] || [ "$owner" != "root" ]; then
                            PROBLEMS+=("Problema de securitate cu $file")
                        fi
                        ;;
                    "/etc/gshadow")
                        if [ "$permissions" -ne 600 ] || [ "$owner" != "root" ]; then
                            PROBLEMS+=("Problema de securitate cu $file")
                        fi
                        ;;
                    "/root")
                        if [ "$permissions" -ne 700 ] || [ "$owner" != "root" ]; then
                            PROBLEMS+=("Problema de securitate cu $file")
                        fi
                        ;;
                    *)
                        PROBLEMS+=("Fisier necunoscut $file")
                        ;;
                esac
            else
                PROBLEMS+=("Fisierul $file nu exista")
            fi

            echo "$percentage"
            echo "# Verificare fisier: $file"
        done

        if command -v sestatus &>/dev/null; then
            selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')
            if [ "$selinux_status" != "enabled" ]; then
                PROBLEMS+=("SELinux nu este activat")
            fi
        else
            PROBLEMS+=("Comanda sestatus nu este disponibila")
        fi

        if command -v ufw &>/dev/null; then
            firewall_status=$(ufw status | grep "Status" | awk '{print $2}')
            if [ "$firewall_status" != "active" ]; then
                PROBLEMS+=("Firewall-ul nu este activ")
            fi
        else
            PROBLEMS+=("Comanda ufw nu este disponibila")
        fi

        sudo_users=$(getent group sudo | awk -F: '{print $4}' | tr ',' '\n')
        for user in $sudo_users; do
            if ! id "$user" &>/dev/null; then
                PROBLEMS+=("Utilizator sudo necunoscut: $user")
            fi
        done

        is_snap_file() {
            local file="$1"
            local snap_path_prefix="/snap/"
            if [[ "$file" == $snap_path_prefix* ]]; then
                return 0
            else
                return 1
            fi
        }

        snap_files=(
            "/snap/bin"
            "/snap/core"
            "/snap/snapd"
        )

        for snap_file in "${snap_files[@]}"; do
            if ! is_snap_file "$snap_file"; then
                PROBLEMS+=("Fisier Snap invalid: $snap_file")
            fi
        done

    ) | zenity --progress --auto-close --title="Verificare permisiuni fisiere" --text="Verificare permisiuni..." --percentage=0

    zenity --info --text="Verificare permisiuni terminata"
}



check_executables_permissions() {
    executables=$(find / -type f -executable 2>/dev/null)
    total_executables=$(echo "$executables" | wc -l)
    
    current=0
    while IFS= read -r file; do
        ((current++))
        
        echo "$((current * 100 / total_executables))"
        echo "# Verificare executabil: $file"
        
        permissions=$(stat -c "%a" "$file")
        owner=$(stat -c "%U" "$file")
        group=$(stat -c "%G" "$file")

        if [[ "$permissions" != "755" ]] || [[ "$owner" != "root" ]]; then
            PROBLEMS+=("Problema de permisiuni cu $file - Permisiuni: $permissions, Proprietar: $owner")
        fi


        file_type=$(file -b "$file")
        if [[ "$file_type" == *"ELF"* ]]; then

            if [[ "$file" != /usr/bin/* && "$file" != /usr/sbin/* && "$file" != /bin/* && "$file" != /sbin/* ]]; then
                PROBLEMS+=("Executabil ELF suspect in locatie neobisnuita: $file")
            fi
        fi


        if lsof -i -a -p $(pgrep -f "$file") 2>/dev/null | grep -q 'ESTABLISHED'; then
            PROBLEMS+=("Executabil $file are conexiuni de retea deschise - potential pericol de securitate")
        fi


        known_malicious=(
            "wannacry"
            "notpetya"
            "ransomware"
            "trojan"
            "keylogger"
            "virus"
            "exploit"
            "payload"
            "rootkit"
            "cryptolocker"
        )
        file_basename=$(basename "$file")
        if [[ " ${known_malicious[@]} " =~ " ${file_basename} " ]]; then
            PROBLEMS+=("Executabil cunoscut ca fiind rau intentionat: $file")
        fi

        if [[ "$file" == *.sh || "$file" == *.py || "$file" == *.pl ]]; then
            if grep -qiE "(rm -rf|dd if=|:(){|mkfs\.)" "$file"; then
                PROBLEMS+=("Executabil $file contine comenzi periculoase")
            fi
        fi

    done <<< "$executables" | zenity --progress --auto-close --title="Verificare permisiuni executabile" --text="Verificare executabile..." --percentage=0

    zenity --info --text="Verificarea permisiunilor executabilelor s-a incheiat." | tee -a $LOGFILE
}


check_for_viruses() {
    if ! command -v clamscan &> /dev/null; then
        zenity --info --text="ClamAV nu este instalat. Instalare ClamAV..." | tee -a $LOGFILE
        apt-get update
        apt-get install -y clamav
        freshclam
    fi

    total_files=$(find /home -type f | wc -l)
    current=0
    
    clamscan -r /home | while IFS= read -r line; do
        ((current++))
        echo "$((current * 100 / total_files))"
        echo "# Scanare fisier: $line"
    done | tee -a $LOGFILE | zenity --progress --auto-close --title="Verificare virusi" --text="Scanare pentru virusi..." --percentage=0

    zenity --info --text="Scanarea pentru virusi s-a incheiat." | tee -a $LOGFILE
}

monitor_network_traffic() {
 
    zenity --info --text="Monitorizare trafic retea pentru 20 de secunde..." | tee -a "$LOGFILE"

    if ! command -v iftop &> /dev/null; then
        zenity --info --text="iftop nu este instalat. Instalare iftop..." | tee -a "$LOGFILE"
        if sudo apt-get update && sudo apt-get install -y iftop; then
            zenity --info --text="iftop a fost instalat cu succes." | tee -a "$LOGFILE"
        else
            zenity --error --text="Nu s-a putut instala iftop. Verificati jurnalul pentru detalii." | tee -a "$LOGFILE"
            return 1
        fi
    fi

    check_malicious_traffic() {
        local iftop_output="$1"
        local malicious_detected=0
        local PROBLEMS=()  

        local malicious_patterns=(
            "irc"          
            "malware"     
            "exploit"      
            "ssh bruteforce" 
        )

        for pattern in "${malicious_patterns[@]}"; do
            if grep -q "$pattern" <<< "$iftop_output"; then
                PROBLEMS+=("Detectat trafic de retea potential malitios: $pattern")
                malicious_detected=1
            fi
        done

        PROBLEMS_GLOBAL=("${PROBLEMS[@]}")
        return $malicious_detected
    }

    {
        iftop -t -s 20 > /tmp/iftop_output &
        IFTOP_PID=$!

        for ((i = 1; i <= 20; i++)); do
            echo $((i * 100 / 20))
            sleep 1
        done
        wait $IFTOP_PID
    } | zenity --progress --auto-close --title="Monitorizare trafic retea" --text="Monitorizare trafic retea..." --percentage=0


    zenity --text-info --title="Detalii Trafic Retea" --filename=/tmp/iftop_output


    if check_malicious_traffic "$(cat /tmp/iftop_output)"; then
        if [ ${#PROBLEMS_GLOBAL[@]} -gt 0 ]; then
            zenity --warning --text="S-a detectat trafic de retea potential malitios." | tee -a "$LOGFILE"
        else
            zenity --info --text="Nu s-a detectat trafic de retea potential malitios." | tee -a "$LOGFILE"
        fi
    else
        zenity --info --text="Nu s-a detectat trafic de retea potential malitios." | tee -a "$LOGFILE"
    fi


    zenity --info --text="Monitorizarea traficului retelei s-a incheiat." | tee -a "$LOGFILE"
}


check_user_integrity() {
    users=$(cut -d: -f1 /etc/passwd)
    total_users=$(echo "$users" | wc -l)
    progress_file=$(mktemp)
    log_file=$(mktemp)

    (
        i=0
        for user in $users; do
            ((i++))
            percentage=$((i * 100 / total_users))
            

            echo "$percentage" > "$progress_file"
            
            if ! id "$user" &>/dev/null; then
                echo "Utilizator necunoscut: $user" >> "$log_file"
                PROBLEMS+=("Utilizator necunoscut: $user")
            else
                echo "Utilizator valid: $user" >> "$log_file"
            fi
            
            echo "# Verificare utilizator: $user" > "$progress_file"
        done

        echo "100" > "$progress_file"
        echo "# Verificare completa" >> "$log_file"

    ) | zenity --progress --auto-close --title="Verificare integritate utilizatori" --text="Verificare utilizatori..." --percentage=0 < "$progress_file"

    zenity --text-info --title="Detalii Verificare Utilizatori" --filename="$log_file"
    
    rm "$progress_file" "$log_file"
}

check_file_checksums() {
    echo "10" | zenity --progress --title="System Check" --text="Checking file checksums..." --percentage=10 --auto-close --no-cancel

    checksum_file="/var/log/file_checksums.log"
    if [ ! -f "$checksum_file" ]; then
        find /etc -type f -exec sha256sum {} + > "$checksum_file"
        zenity --info --text="Fisierul de control al checksum-urilor a fost creat." | tee -a "$LOGFILE"
    fi

    current_checksums=$(find /etc -type f -exec sha256sum {} +)
    previous_checksums=$(cat "$checksum_file")

    if diff <(echo "$current_checksums") <(echo "$previous_checksums") > /dev/null; then
        zenity --info --text="Nu au fost gasite modificari in checksum-urile fisierelor din /etc." | tee -a "$LOGFILE"
    else
       
        zenity --question --text="Au fost gasite modificari in checksum-urile fisierelor din /etc. Doriti sa verificati aceste modificari?" \
            --ok-label="Da" --cancel-label="Nu" | tee -a "$LOGFILE"

        if [ $? -eq 0 ]; then

            diff_output=$(diff <(echo "$current_checksums") <(echo "$previous_checksums"))
            zenity --text-info --title="Modificari in checksum-urile fisierelor din /etc" --width=800 --height=600 --filename=<(echo "$diff_output") | tee -a "$LOGFILE"
            

            PROBLEMS+=("Modificari in checksum-urile fisierelor din /etc")
        else

            echo "Modificari in checksum-urile fisierelor din /etc respinse de utilizator." | tee -a "$LOGFILE"
        fi
    fi
}


check_package_integrity() {
 
    PROGRESS_PERCENT=0


    (
        echo "$PROGRESS_PERCENT"
        echo "# Starting package integrity check..."


        if ! command -v debsums &> /dev/null; then
            echo "10"
            echo "# Installing debsums for package integrity check..."
            apt-get update -qq
            apt-get install -y debsums
            PROGRESS_PERCENT=20
        else
            PROGRESS_PERCENT=10
        fi
        echo "$PROGRESS_PERCENT"
        echo "# debsums is installed."


        echo "# Running debsums..."
        total_packages=$(dpkg -l | grep '^ii' | wc -l)
        current_package=0

        debsums -s | while IFS= read -r line; do
            PROBLEMS+=("Problema de integritate pachet: $line")
            current_package=$((current_package + 1))
            PROGRESS_PERCENT=$((30 + (current_package * 70 / total_packages)))
            echo "$PROGRESS_PERCENT"
            echo "# Checking package $current_package of $total_packages: $line"
        done | tee -a $LOGFILE

        echo "100"
        echo "# Package integrity check completed."
    ) | zenity --progress --title="System Check" --percentage=0 --auto-close --no-cancel --text="Initializing package integrity check..."


    zenity --info --text="Verificarea integritatii pachetelor s-a incheiat." | tee -a $LOGFILE
}

check_suspicious_files() {
 
    PROGRESS_PERCENT=50


    (
        echo "$PROGRESS_PERCENT"
        echo "# Starting suspicious files check..."

        echo "# Scanning for suspicious files..."
        suspicious_files=$(find / -type f \( -name ".*" -o -name "*.bak" -o -name "*.tmp" \) 2>/dev/null)
        total_files=$(echo "$suspicious_files" | wc -l)
        current_file=0

        if [ $total_files -eq 0 ]; then
            PROGRESS_PERCENT=100
            echo "$PROGRESS_PERCENT"
            echo "# No suspicious files found."
        else
            echo "# Found $total_files suspicious files."
            for file in $suspicious_files; do
                PROBLEMS+=("Fisier suspect: $file")
                current_file=$((current_file + 1))
                PROGRESS_PERCENT=$((50 + (current_file * 50 / total_files)))
                echo "$PROGRESS_PERCENT"
                echo "# Checking suspicious file $current_file of $total_files: $file"
            done
        fi

        echo "100"
        echo "# Suspicious files check completed."
    ) | zenity --progress --title="System Check" --percentage=50 --auto-close --no-cancel --text="Initializing suspicious files check..."


    zenity --info --text="Verificarea fisierelor suspecte s-a incheiat." | tee -a $LOGFILE
}


check_open_ports() {
    echo "70" | zenity --progress --title="System Check" --text="Checking open ports..." --percentage=70 --auto-close --no-cancel

    open_ports=$(ss -tuln | awk 'NR>1{print $5}' | sed 's/.*://')
    known_ports=$(cat /etc/services | awk '{print $2}' | grep -oP '\d+')

    PROGRESS_PERCENT=70
    total_ports=$(echo "$open_ports" | wc -l)
    current_port=0

    for port in $open_ports; do
        current_port=$((current_port + 1))
        PROGRESS_PERCENT=$((70 + (current_port * 30 / total_ports)))
        
        if ! echo "$known_ports" | grep -q "^$port$"; then
            port_details=$(ss -tuln | grep ":$port " | awk '{print $1, $5}')
            PROBLEMS+=("Port necunoscut deschis: $port ($port_details)")
        fi

        echo "$PROGRESS_PERCENT"
        echo "# Checking port $current_port of $total_ports: $port"
    done | tee -a $LOGFILE

    echo "100" | zenity --progress --title="System Check" --text="Finalizing open ports check..." --percentage=100 --auto-close --no-cancel

    if [ ${#PROBLEMS[@]} -gt 0 ]; then
        zenity --question --text="Au fost gasite porturi deschise necunoscute. Doriti sa verificati aceste modificari?" --ok-label="Da" --cancel-label="Nu" | tee -a "$LOGFILE"
        
        if [ $? -eq 0 ]; then
            details=$(printf "%s\n" "${PROBLEMS[@]}")
            action=$(zenity --list --radiolist --title="Actiuni pentru porturi necunoscute" --text="Selectati actiunea:" --column="Select" --column="Actiune" TRUE "Inchide porturile" FALSE "Notifica administratorul")
            
            if [ "$action" = "Inchide porturile" ]; then
                for port in $open_ports; do
                    if ! echo "$known_ports" | grep -q "^$port$"; then
                        fuser -k "$port/tcp"
                        fuser -k "$port/udp"
                        echo "Port $port inchis." | tee -a $LOGFILE
                    fi
                done
                zenity --info --text="Porturile necunoscute au fost inchise." | tee -a $LOGFILE
            else
                echo "$details" | mail -s "Porturi necunoscute deschise" admin@example.com
                zenity --info --text="Administratorul a fost notificat." | tee -a $LOGFILE
            fi
        else
            echo "Modificari in porturile deschise respinse de utilizator." | tee -a "$LOGFILE"
        fi
    else
        zenity --info --text="Nu au fost gasite porturi necunoscute deschise." | tee -a $LOGFILE
    fi
}

check_rootkits() {
    echo "90" | zenity --progress --title="System Check" --text="Checking for rootkits..." --percentage=90 --auto-close --no-cancel

    if ! command -v chkrootkit &> /dev/null; then
        zenity --info --text="chkrootkit nu este instalat. Instalare chkrootkit..." | tee -a $LOGFILE
        apt-get update
        apt-get install -y chkrootkit
    fi

    chkrootkit | tee -a $LOGFILE

    zenity --info --text="Verificarea rootkit-urilor s-a incheiat." | tee -a $LOGFILE
}

generate_report() {
    zenity --info --text="Generare raport..." | tee -a $LOGFILE
    
    report="Raport de securitate - $(date)\n\n"
    report+="Verificare procese active: $(check_processes)\n"
    report+="Verificare spatiu pe disc: $(check_disk_space)\n"
    report+="Verificare utilizare memorie: $(check_memory_usage)\n"
    report+="Verificare permisiuni fisiere critice: $(check_permissions)\n"
    report+="Verificare permisiuni executabile: $(check_executables_permissions)\n"
    report+="Verificare trafic retea: $(monitor_network_traffic)\n"
    report+="Verificare checksum fisiere: $(check_file_checksums)\n"
    report+="Verificare integritate pachete: $(check_package_integrity)\n"
    report+="Verificare integritate utilizatori: $(check_user_integrity)\n"
    report+="Verificare fisiere suspecte: $(check_suspicious_files)\n"
    report+="Verificare porturi deschise: $(check_open_ports)\n"
    report+="Verificare rootkits: $(check_rootkits)\n"
    report+="Scanare pentru virusi: $(check_for_viruses)\n"
    
    echo -e "$report" > $LOGFILE
    zenity --info --text="Raportul a fost generat la $LOGFILE" | tee -a $LOGFILE
}

show_problems() {
    if [ ${#PROBLEMS[@]} -eq 0 ]; then
        zenity --info --text="Nu au fost gasite probleme de securitate."
    else
        problem_text="Probleme de securitate detectate:\n\n"
        for problem in "${PROBLEMS[@]}"; do
            problem_text+="$problem\n"
        done
        zenity --warning --text="$problem_text"
    fi
}

main_menu() {
    while true; do
        action=$(zenity --list --title="Meniu Principal" --column="Actiune" \
            "Verificare procese" \
            "Verificare spatiu pe disc" \
            "Verificare utilizare memorie" \
            "Verificare permisiuni fisiere critice" \
            "Verificare permisiuni executabile" \
            "Monitorizare trafic retea" \
            "Verificare checksum fisiere" \
            "Verificare integritate pachete" \
            "Scanare pentru virusi" \
            "Verificare integritate utilizatori" \
            "Verificare fisiere suspecte" \
            "Verificare porturi deschise" \
            "Verificare rootkits" \
            "Generare raport complet" \
            "Afisare probleme detectate" \
            "Iesire" \
            --width=800 --height=600)  

        case $action in
            "Verificare procese")
                check_processes
                ;;
            "Verificare spatiu pe disc")
                check_disk_space
                ;;
            "Verificare utilizare memorie")
                check_memory_usage
                ;;
            "Verificare permisiuni fisiere critice")
                check_permissions
                ;;
            "Verificare permisiuni executabile")
                check_executables_permissions
                ;;
            "Monitorizare trafic retea")
                monitor_network_traffic
                ;;
            "Verificare checksum fisiere")
                check_file_checksums
                ;;
            "Verificare integritate pachete")
                check_package_integrity
                ;;
            "Scanare pentru virusi")
                check_for_viruses
                ;;
            "Verificare integritate utilizatori")
                check_user_integrity
                ;;
            "Verificare fisiere suspecte")
                check_suspicious_files
                ;;
            "Verificare porturi deschise")
                check_open_ports
                ;;
            "Verificare rootkits")
                check_rootkits
                ;;
            "Generare raport complet")
                generate_report
                ;;
            "Afisare probleme detectate")
                show_problems
                ;;
            "Iesire")
                exit 0
                ;;
            *)
                zenity --error --text="Optiune invalida"
                ;;
        esac
    done
}

main_menu