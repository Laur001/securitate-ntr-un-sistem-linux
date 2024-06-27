Verificare Procese Active (check_processes)
Verifica procesele active pe sistem.
Aspecte Verificate:
- Identifica procesele care consuma resurse excesive (CPU, memorie).
- Verifica integritatea si autenticitatea proceselor de sistem critice.
- Detecteaza procese necunoscute sau suspecte.


Verificare Spatiu pe Disc (check_disk_space)
Verifica utilizarea spatiului pe disc.
Aspecte Verificate:
- Monitorizeaza spatiul utilizat pe fiecare partitie.
- Detecteaza partitii cu spatiu insuficient.
- Verifica daca exista fisiere mari sau directoare care ocupa spatiu excesiv.


Verificare Utilizare Memorie (check_memory_usage)
Monitorizeaza utilizarea memoriei RAM.
Aspecte Verificate:
- Identifica procesele care consuma memorie excesiva.
- Verifica scurgerile de memorie si comportamente neobisnuite ale proceselor.
- Detecteaza si raporteaza despre utilizarea neasteptata a memoriei.


Verificare Permisiuni Fisiere Critice (check_permissions)
Verifica permisiunile fisierelor critice de sistem.
Aspecte Verificate:
- Analizeaza si corecteaza permisiunile incorecte ale fisierelor de configurare si de sistem.
- Detecteaza modificari neautorizate ale permisiunilor fisierelor critice.
- Asigura ca doar utilizatorii autorizati au acces la fisierele de sistem.


Verificare Permisiuni Executabile (check_executables_permissions)
Verifica permisiunile fisierelor executabile.
Aspecte Verificate:
- Identifica fisierele executabile cu permisiuni neobisnuite sau periculoase.
- Verifica daca fisierele executabile sunt protejate corect impotriva modificarilor neautorizate.
- Asigura ca doar utilizatorii autorizati pot executa fisierele marcate ca executabile.


Verificare Fisiere Suspecte (check_suspicious_files)
Scaneaza sistemul pentru fisiere suspecte.
Aspecte Verificate:
- Cauta fisiere cu extensii neobisnuite (de exemplu, .), fisiere de backup (.bak) sau fisiere temporare (*.tmp).
- Numara si raporteaza despre fisierele suspecte gasite in sistem.
- Identifica fisiere care ar putea reprezenta o amenintare de securitate sau un risc potential.


Verificare Integritate Pachete (check_package_integrity)
Verifica integritatea pachetelor software instalate pe sistem.
Aspecte Verificate:
- Verifica existenta utilitarului debsums si, daca nu este instalat, il instaleaza.
Ruleaza debsums pentru a verifica fisierele pachetelor instalate impotriva informatiilor de control (control sums) din baza de date dpkg.
- Raporteaza despre orice discrepante gasite in fisierele pachetelor instalate.


Verificare Checksum-uri Fisiere (check_file_checksums)
Verifica checksum-urile (sume de control) ale fisierelor din directorul /etc.
Aspecte Verificate:
- Creaza un fisier de jurnal pentru a inregistra checksum-urile fisierelor din /etc daca acesta nu exista deja.
- Compara checksum-urile actuale ale fisierelor din /etc cu cele anterioare inregistrate pentru a detecta modificari.
- Raporteaza despre orice modificari gasite in checksum-urile fisierelor din /etc.


Verificare Integritate Utilizatori (check_user_integrity)
Verifica integritatea utilizatorilor existenti pe sistem.
Aspecte Verificate:
- Enumera utilizatorii din fisierul /etc/passwd si verifica existenta fiecarui utilizator.
- Raporteaza despre utilizatorii care nu au un ID de utilizator valid sau care nu pot fi autentificati.
- Asigura ca toti utilizatorii de pe sistem sunt legitimi si pot fi autentificati corect.


Monitorizare Trafic Retea (monitor_network_traffic)
Monitorizeaza traficul de retea pentru o perioada de timp specificata.
Aspecte Verificate:
- Verifica daca utilitarul iftop este instalat, si il instaleaza daca nu este.
- Ruleaza iftop pentru a captura si afisa traficul de retea in timp real timp de 20 de secunde.
- Afiseaza detalii despre traficul de intrare si iesire, inclusiv adresele IP implicate si volumele de date transferate.


Verificare pentru Virusi (check_for_viruses)
Scaneaza sistemul pentru detectarea viruselor.
Aspecte Verificate:
- Verifica daca clamscan (parte a ClamAV) este instalat pe sistem si, daca nu este, il instaleaza.
- Ruleaza o scanare recursiva a directorului /home pentru a cauta si detecta eventuale infectari cu virusi.
- Afiseaza progresul scanarii si detaliile despre fisierele scanate.
- Raporteaza despre orice virusuri sau amenintari detectate in timpul scanarii.

Verificare Porturi Deschise (check_open_ports)
Verifica porturile deschise pe sistem.
Aspecte Verificate:
- Identifica porturile de retea care sunt in mod activ in ascultare (LISTEN).
- Verifica daca porturile deschise sunt autorizate si cunoscute.
- Raporteaza despre porturile care nu sunt specificate in /etc/services sau care ar putea reprezenta o potentiala vulnerabilitate de securitate.


Verificare Rootkits (check_rootkits)
Verifica prezenta rootkit-urilor pe sistem.
Aspecte Verificate:
- Utilizeaza chkrootkit pentru a scana sistemul in cautarea semnelor de infectie cu rootkit-uri.
- Detecteaza modificari neautorizate in fisierele de sistem critice.
- Identifica procese suspecte sau comportamente care ar putea indica prezenta unui rootkit.


Generare Raport (generate_report)
Genereaza un raport de securitate detaliat.
Aspecte Verificate:
- Include rezultatele tuturor functiilor de verificare intr-un raport structurat.
- Asigura ca utilizatorul are o privire de ansamblu asupra starii securitatii sistemului.
- Salvarea raportului intr-un fisier specificat pentru referinte ulterioare si audit.