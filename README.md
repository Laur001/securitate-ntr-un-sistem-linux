# securitate intr-un sistem linux

# 19.06.2024 
- functie care realizeaza verificarea proceselor active in sistem 
- functia verifica daca procesele care ruleaza apartin utilizatorului

# 20.06.2024
- functie care verifica permisiunile root-ului,grupurilor si a altor utilizatori asupra anumitor fisiere cheie din sistem 
- in functie se fac verificari care verifica daca permisiunile deja existente respecta un anumit format, in caz contrar fisierul/directorul este considerat vulnerabil si trebuie analizat mai in detaliu

# 21.06.2024
- check_executables_permissions()
- functie cauta in sistem fisiere care sunt executabile dupa care verifica existenta de posibile vulnerabilitati. se asigura ca permisiunile de citire, scriere si executie apartin doar utilizatorului root , iar in cazul grupurilor si a altor utilizatori dor permisiuni de citire si de executie , nu si de modificare a continutului 
- prin modificarea continutului de catre alti utilizatori inafara de root,prin permisune de scriere , fisierul poate fi modificat incat sa contina cod malitios si apoi executat

