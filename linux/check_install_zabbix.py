#!/usr/bin/env python3
"""
Script de vérification de l'installation Zabbix 7.0 LTS sur Debian 12
=====================================================================
Ce script vérifie :
- La configuration réseau (IP statique, hostname, DNS)
- L'installation des paquets (Zabbix Server, Agent2, MariaDB, Apache, PHP)
- La base de données Zabbix (existence, utilisateur, tables)
- Les fichiers de configuration (serveur, agent, PHP)
- Les services actifs
- L'accès HTTP au frontend Zabbix
- Le temps écoulé depuis le premier boot du jour

Auteur : Eric MALETRAS - BTS SIO SISR
"""

import os
import sys
import subprocess
import socket
import re
import json
from datetime import datetime

# =============================================
# INSTALLATION DES DÉPENDANCES SI NÉCESSAIRES
# =============================================
REQUIRED_APT_LIBS = ["python3-requests", "python3-bs4"]

def install_required_packages():
    """Vérifie et installe automatiquement les bibliothèques via apt"""
    for pkg in REQUIRED_APT_LIBS:
        try:
            subprocess.run(["dpkg", "-s", pkg], check=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            subprocess.check_call(["apt", "install", "-y", pkg],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

install_required_packages()

import requests
from bs4 import BeautifulSoup

# =============================================
# VARIABLES GLOBALES
# =============================================
total = 0
score = 0
log_messages = []

# Variables de configuration (seront définies par l'utilisateur)
EXPECTED_HOSTNAME = ""
EXPECTED_IP = ""

# Paquets attendus pour Zabbix
EXPECTED_PACKAGES = [
    "zabbix-server-mysql",
    "zabbix-frontend-php",
    "zabbix-apache-conf",
    "zabbix-sql-scripts",
    "zabbix-agent2",
    "mariadb-server",
    "apache2"
]

# Services attendus
EXPECTED_SERVICES = [
    "zabbix-server",
    "zabbix-agent2",
    "apache2",
    "mariadb"
]

# =============================================
# FONCTIONS UTILITAIRES
# =============================================

def log(message):
    """Ajoute un message au log et l'affiche."""
    log_messages.append(message)
    print(message)

def show_score():
    """Affiche le score provisoire."""
    if total > 0:
        note_provisoire = round((score / total) * 20, 2)
        print(f"    >>> Score provisoire : {score}/{total} ({note_provisoire}/20)")
    print()

def execute_sql(query):
    """Exécute une requête SQL sur la base Zabbix et retourne le résultat."""
    try:
        result = subprocess.getoutput(f'mysql -u root -N -e "{query}" 2>/dev/null')
        return result.strip()
    except Exception as e:
        return None

def get_default_interface():
    """Détecte l'interface réseau principale."""
    try:
        result = subprocess.getoutput("ip -o -4 addr show | awk '{print $2}' | sort -u")
        interfaces = result.split("\n")
        interfaces = [iface for iface in interfaces if iface and iface != "lo"]
        if interfaces:
            return interfaces[0]
    except Exception as e:
        pass
    return None

# =============================================
# VÉRIFICATIONS RÉSEAU
# =============================================

def check_hostname():
    """Vérifie si le nom de la machine correspond au nom attendu."""
    global score, total
    total += 1
    try:
        hostname = socket.gethostname()
        if hostname == EXPECTED_HOSTNAME:
            log(f"[OK] Nom de la VM correct : {hostname}")
            score += 1
        else:
            log(f"[ERREUR] Nom de la VM incorrect (Attendu: {EXPECTED_HOSTNAME}, Actuel: {hostname})")
    except Exception as e:
        log(f"[ERREUR] Erreur lors de la recuperation du nom de la VM : {e}")

def check_static_ip():
    """Vérifie que l'IP est bien en statique et correspond à l'IP attendue."""
    global score, total
    total += 1

    interface = get_default_interface()
    if not interface:
        log("[ERREUR] Impossible de detecter l'interface reseau principale.")
        return

    try:
        with open("/etc/network/interfaces", "r") as f:
            interfaces_content = f.read()

        # Vérifier si l'interface est configurée en statique
        is_static = f"iface {interface} inet static" in interfaces_content
        
        # Extraire l'IP configurée
        ip_match = re.search(r'address\s+(\d+\.\d+\.\d+\.\d+)', interfaces_content)
        ip_found = ip_match.group(1) if ip_match else None

        if is_static and ip_found == EXPECTED_IP:
            log(f"[OK] IP statique correcte : {EXPECTED_IP} sur {interface}")
            score += 1
        elif not is_static:
            log(f"[ERREUR] L'interface {interface} n'est pas configuree en statique")
        elif ip_found != EXPECTED_IP:
            log(f"[ERREUR] IP configuree ({ip_found}) ne correspond pas a l'attendue ({EXPECTED_IP})")

    except Exception as e:
        log(f"[ERREUR] Erreur lors de la verification de l'IP statique : {e}")

def check_dns():
    """Vérifie que le DNS est bien configuré."""
    global score, total
    total += 1
    try:
        with open("/etc/resolv.conf", "r") as f:
            resolv_content = f.read()

        if "nameserver" in resolv_content:
            log("[OK] Serveur DNS configure dans /etc/resolv.conf")
            score += 1
        else:
            log("[ERREUR] Pas de serveur DNS configure dans /etc/resolv.conf")

    except Exception as e:
        log(f"[ERREUR] Erreur lors de la verification de /etc/resolv.conf : {e}")

# =============================================
# VÉRIFICATIONS DES PAQUETS
# =============================================

def check_packages():
    """Vérifie que tous les paquets Zabbix sont installés."""
    global score, total
    log("\n--- Verification des PAQUETS ---")

    for package in EXPECTED_PACKAGES:
        total += 1
        result = subprocess.getoutput(f"dpkg -l | grep -E '^ii\\s+{package}'")
        if package in result:
            log(f"[OK] {package} est installe")
            score += 1
        else:
            log(f"[ERREUR] {package} n'est pas installe")

# =============================================
# VÉRIFICATIONS BASE DE DONNÉES
# =============================================

def check_database():
    """Vérifie que la base de données Zabbix existe et est correctement configurée."""
    global score, total
    log("\n--- Verification de la BASE DE DONNEES ---")

    # Vérifier si la base existe
    total += 1
    result = execute_sql("SHOW DATABASES LIKE 'zabbix';")
    if result and "zabbix" in result:
        log("[OK] Base de donnees 'zabbix' existante")
        score += 1
    else:
        log("[ERREUR] Base de donnees 'zabbix' non trouvee")
        return False

    # Vérifier si l'utilisateur zabbix existe
    total += 1
    result = execute_sql("SELECT User FROM mysql.user WHERE User='zabbix';")
    if result and "zabbix" in result:
        log("[OK] Utilisateur 'zabbix' existe dans MariaDB")
        score += 1
    else:
        log("[ERREUR] Utilisateur 'zabbix' non trouve dans MariaDB")

    # Vérifier le nombre de tables (environ 200+ pour Zabbix 7.0)
    total += 1
    result = execute_sql("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'zabbix';")
    try:
        table_count = int(result) if result else 0
        if table_count >= 180:
            log(f"[OK] Schema Zabbix importe ({table_count} tables)")
            score += 1
        else:
            log(f"[ERREUR] Schema Zabbix incomplet ({table_count} tables, attendu ~200+)")
    except:
        log("[ERREUR] Impossible de compter les tables Zabbix")

    return True

def check_mariadb_security():
    """Vérifie si MariaDB a été sécurisé."""
    global score, total
    log("\n--- Verification de la SECURITE MariaDB ---")

    # Vérifier l'authentification root
    total += 1
    root_auth = subprocess.getoutput("mysql -u root -Nse \"SELECT plugin FROM mysql.user WHERE User='root' AND Host='localhost';\"")
    if "unix_socket" in root_auth or root_auth.strip():
        log("[OK] Authentification root securisee (unix_socket ou mot de passe)")
        score += 1
    else:
        log("[ERREUR] Authentification root non securisee")

    # Vérifier si la base test a été supprimée
    total += 1
    test_db = subprocess.getoutput("mysql -u root -Nse \"SHOW DATABASES LIKE 'test';\"")
    if test_db.strip() == "":
        log("[OK] Base de test supprimee")
        score += 1
    else:
        log("[WARN] Base de test toujours presente (recommande de la supprimer)")

# =============================================
# VÉRIFICATIONS DES FICHIERS DE CONFIGURATION
# =============================================

def check_zabbix_server_conf():
    """Vérifie la configuration du serveur Zabbix."""
    global score, total
    log("\n--- Verification de la CONFIGURATION SERVEUR ---")

    conf_file = "/etc/zabbix/zabbix_server.conf"
    total += 1

    if not os.path.exists(conf_file):
        log(f"[ERREUR] Fichier {conf_file} non trouve")
        return

    try:
        with open(conf_file, "r") as f:
            content = f.read()

        # Vérifier que DBPassword est configuré (pas commenté)
        if re.search(r'^DBPassword=', content, re.MULTILINE):
            log("[OK] DBPassword configure dans zabbix_server.conf")
            score += 1
        else:
            log("[ERREUR] DBPassword non configure dans zabbix_server.conf")

    except Exception as e:
        log(f"[ERREUR] Erreur lecture {conf_file} : {e}")

def check_zabbix_agent_conf():
    """Vérifie la configuration de l'agent Zabbix."""
    global score, total
    log("\n--- Verification de la CONFIGURATION AGENT ---")

    conf_file = "/etc/zabbix/zabbix_agent2.conf"
    total += 3  # 3 vérifications

    if not os.path.exists(conf_file):
        log(f"[ERREUR] Fichier {conf_file} non trouve")
        return

    try:
        with open(conf_file, "r") as f:
            content = f.read()

        # Vérifier Server
        if re.search(r'^Server=127\.0\.0\.1', content, re.MULTILINE):
            log("[OK] Server=127.0.0.1 configure")
            score += 1
        else:
            log("[WARN] Server n'est pas configure sur 127.0.0.1")

        # Vérifier ServerActive
        if re.search(r'^ServerActive=127\.0\.0\.1', content, re.MULTILINE):
            log("[OK] ServerActive=127.0.0.1 configure")
            score += 1
        else:
            log("[WARN] ServerActive n'est pas configure sur 127.0.0.1")

        # Vérifier Hostname
        hostname_match = re.search(r'^Hostname=(.+)$', content, re.MULTILINE)
        if hostname_match:
            log(f"[OK] Hostname configure : {hostname_match.group(1)}")
            score += 1
        else:
            log("[WARN] Hostname non configure explicitement")

    except Exception as e:
        log(f"[ERREUR] Erreur lecture {conf_file} : {e}")

def check_php_timezone():
    """Vérifie que le fuseau horaire PHP est configuré."""
    global score, total
    log("\n--- Verification de la CONFIGURATION PHP ---")

    total += 1
    php_ini = "/etc/php/8.2/apache2/php.ini"

    if not os.path.exists(php_ini):
        log(f"[ERREUR] Fichier {php_ini} non trouve")
        return

    try:
        with open(php_ini, "r") as f:
            content = f.read()

        # Chercher date.timezone non commenté
        tz_match = re.search(r'^date\.timezone\s*=\s*(.+)$', content, re.MULTILINE)
        if tz_match:
            log(f"[OK] Fuseau horaire PHP configure : {tz_match.group(1)}")
            score += 1
        else:
            log("[ERREUR] Fuseau horaire PHP (date.timezone) non configure")

    except Exception as e:
        log(f"[ERREUR] Erreur lecture {php_ini} : {e}")

# =============================================
# VÉRIFICATIONS DES SERVICES
# =============================================

def check_services():
    """Vérifie que tous les services sont actifs."""
    global score, total
    log("\n--- Verification des SERVICES ---")

    for service in EXPECTED_SERVICES:
        total += 1
        result = subprocess.getoutput(f"systemctl is-active {service}")
        if result.strip() == "active":
            log(f"[OK] Service {service} actif")
            score += 1
        else:
            log(f"[ERREUR] Service {service} inactif ou non trouve")

def check_ports():
    """Vérifie que les ports Zabbix sont en écoute."""
    global score, total
    log("\n--- Verification des PORTS ---")

    ports_to_check = [
        ("10051", "Zabbix Server (trapper)"),
        ("10050", "Zabbix Agent"),
        ("80", "Apache HTTP"),
        ("3306", "MariaDB")
    ]

    for port, description in ports_to_check:
        total += 1
        result = subprocess.getoutput(f"ss -tlnp | grep ':{port}'")
        if port in result:
            log(f"[OK] Port {port} en ecoute ({description})")
            score += 1
        else:
            log(f"[ERREUR] Port {port} non en ecoute ({description})")

# =============================================
# VÉRIFICATION ACCÈS HTTP
# =============================================

def check_zabbix_frontend():
    """Vérifie que le frontend Zabbix est accessible."""
    global score, total
    log("\n--- Verification du FRONTEND ZABBIX ---")

    total += 2  # 2 vérifications

    # Vérifier l'accès HTTP
    try:
        response = requests.get(f"http://127.0.0.1/zabbix/", timeout=5, allow_redirects=True)
        if response.status_code == 200:
            log("[OK] Frontend Zabbix accessible sur http://localhost/zabbix/")
            score += 1

            # Vérifier que ce n'est pas l'assistant d'installation
            if "setup.php" in response.url or "step=" in response.text.lower():
                log("[ERREUR] L'assistant d'installation est toujours actif")
            elif "zabbix" in response.text.lower():
                log("[OK] Frontend Zabbix operationnel (page de connexion)")
                score += 1
            else:
                log("[WARN] Page inattendue sur /zabbix/")
        else:
            log(f"[ERREUR] Frontend Zabbix inaccessible (Code HTTP {response.status_code})")

    except requests.exceptions.RequestException as e:
        log(f"[ERREUR] Impossible d'acceder au frontend Zabbix : {e}")

def check_zabbix_host():
    """Vérifie que l'hôte Zabbix server existe dans la base."""
    global score, total
    log("\n--- Verification de l'HOTE ZABBIX SERVER ---")

    total += 1
    result = execute_sql("SELECT host FROM zabbix.hosts WHERE host='Zabbix server';")
    if result and "Zabbix server" in result:
        log("[OK] Hote 'Zabbix server' present dans la base")
        score += 1
    else:
        log("[ERREUR] Hote 'Zabbix server' non trouve dans la base")

# =============================================
# VÉRIFICATION DU TEMPS (BOOT TIME)
# =============================================

def check_boot_time():
    """
    Mesure le temps écoulé depuis le premier boot du jour.
    Temps imparti : 2h30 (150 minutes) pour avoir les 7 points
    -1 point par tranche de 37.5 minutes au-delà
    """
    global score, total
    log("\n--- Verification du TEMPS ---")
    total += 7  # Ce test vaut 7 points

    try:
        # Méthode 1 : Utiliser journalctl --list-boots
        result = subprocess.run(["journalctl", "--list-boots"], capture_output=True, text=True)
        
        if result.returncode != 0 or not result.stdout:
            # Méthode 2 : Utiliser uptime -s
            uptime_result = subprocess.getoutput("uptime -s")
            if uptime_result:
                boot_time = datetime.strptime(uptime_result.strip(), "%Y-%m-%d %H:%M:%S")
                log(f"[INFO] Heure de demarrage de la VM : {boot_time}")
            else:
                log("[ERREUR] Impossible de recuperer l'heure de boot")
                return
        else:
            # Parser la sortie de journalctl
            boots = []
            lines = result.stdout.splitlines()
            for line in lines:
                if line.strip() and not line.startswith("IDX"):
                    parts = line.split()
                    if len(parts) >= 5:
                        # Format: IDX BOOT_ID FIRST_ENTRY LAST_ENTRY
                        # Extraire la date du premier boot
                        try:
                            boot_time_str = " ".join(parts[2:5])
                            boot_time = datetime.strptime(boot_time_str, "%a %Y-%m-%d %H:%M:%S")
                            boots.append(boot_time)
                        except:
                            continue

            today = datetime.now().date()
            boots_today = [b for b in boots if b.date() == today]
            
            if not boots_today:
                # Utiliser uptime -s comme fallback
                uptime_result = subprocess.getoutput("uptime -s")
                boot_time = datetime.strptime(uptime_result.strip(), "%Y-%m-%d %H:%M:%S")
            else:
                boot_time = min(boots_today)

        now = datetime.now()
        elapsed = now - boot_time
        elapsed_seconds = elapsed.total_seconds()
        elapsed_minutes = int(elapsed_seconds / 60)

        # Temps imparti : 150 minutes (2h30)
        temps_imparti = 150 * 60  # en secondes

        if elapsed_seconds <= temps_imparti:
            points = 7
        else:
            extra = elapsed_seconds - temps_imparti
            quarter = temps_imparti / 4  # 37.5 minutes
            points = 7 - int(extra // quarter)
            if points < 0:
                points = 0

        log(f"[INFO] Premier boot du jour : {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
        log(f"[INFO] Heure actuelle : {now.strftime('%Y-%m-%d %H:%M:%S')}")
        log(f"[INFO] Temps ecoule : {elapsed_minutes} minutes ({elapsed_minutes // 60}h{elapsed_minutes % 60:02d})")
        log(f"[INFO] Temps imparti : 150 minutes (2h30)")
        log(f"[INFO] Score temps attribue : {points}/7")
        score += points

    except Exception as e:
        log(f"[ERREUR] Erreur lors de la verification du temps de boot : {e}")

# =============================================
# VÉRIFICATION ANTI-FRAUDE
# =============================================

def check_vm_freshness():
    """
    Vérifie que les fichiers critiques sont du jour.
    Si un fichier n'est pas du jour, remet le score à 0.
    """
    global score, total
    log("\n--- Verification ANTI-FRAUDE ---")

    today = datetime.now().date()
    fraud_detected = False

    files_to_check = [
        ("/etc/zabbix/zabbix_server.conf", "Configuration Zabbix Server"),
        ("/etc/zabbix/zabbix_agent2.conf", "Configuration Zabbix Agent"),
        ("/etc/apache2/conf-enabled/zabbix.conf", "Configuration Apache Zabbix"),
    ]

    for file_path, label in files_to_check:
        if os.path.exists(file_path):
            try:
                # Utiliser lstat pour ne pas suivre les liens symboliques
                stat_info = os.lstat(file_path)
                file_date = datetime.fromtimestamp(stat_info.st_mtime).date()
                if file_date != today:
                    log(f"[ERREUR] {label} ({file_path}) n'est pas du jour (date: {file_date})")
                    fraud_detected = True
                else:
                    log(f"[OK] {label} est du jour")
            except Exception as e:
                log(f"[WARN] Impossible de verifier {file_path} : {e}")

    if fraud_detected:
        log("\n[ATTENTION] Fichiers dates d'un autre jour detectes !")
        log("[ATTENTION] Cela peut indiquer une tentative de reutilisation d'une VM.")
        # Note : On ne remet pas forcément à 0 mais on signale

# =============================================
# ENVOI DES RÉSULTATS
# =============================================

def envoyer_donnees(nom, prenom, commentaires, note):
    """Envoie les résultats au serveur externe."""
    nom_clean = nom.strip().replace(" ", "-")
    prenom_clean = prenom.strip().replace(" ", "-")
    filename = f"ZABBIX_INSTALL-{nom_clean}-{prenom_clean}.json"
    url = f"http://www.ericm.fr/logsapi/logreceiver.php?filename={filename}"

    headers = {"Content-Type": "application/json"}
    data = {
        "nom": nom,
        "prenom": prenom,
        "commentaires": commentaires,
        "note": note,
        "score": score,
        "total": total
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            print(f"\n[OK] Resultats envoyes avec succes sous {filename}")
        else:
            print(f"\n[WARN] Echec de l'envoi. Code HTTP : {response.status_code}")
    except Exception as e:
        print(f"\n[WARN] Erreur lors de l'envoi (non bloquant) : {e}")

# =============================================
# FONCTION PRINCIPALE
# =============================================

def main():
    global score, total, EXPECTED_HOSTNAME, EXPECTED_IP

    print("\n" + "=" * 60)
    print("   VERIFICATION INSTALLATION ZABBIX 7.0 - BTS SIO SISR")
    print("=" * 60)

    # Demander les informations
    nom = input("\nEntrez votre nom : ")
    prenom = input("Entrez votre prenom : ")
    EXPECTED_HOSTNAME = input("Entrez le nom de la VM (ex: srv-zabbix) : ")
    EXPECTED_IP = input("Entrez l'IP de la VM (sans CIDR, ex: 192.168.x.10) : ")

    print("\n" + "=" * 60)
    print("   LANCEMENT DES VERIFICATIONS")
    print("=" * 60)

    # Vérifications réseau
    log("\n--- Verification de la CONFIGURATION RESEAU ---")
    check_hostname()
    check_static_ip()
    check_dns()
    show_score()

    # Vérifications paquets
    check_packages()
    show_score()

    # Vérifications base de données
    if check_database():
        check_mariadb_security()
    show_score()

    # Vérifications configuration
    check_zabbix_server_conf()
    check_zabbix_agent_conf()
    check_php_timezone()
    show_score()

    # Vérifications services et ports
    check_services()
    check_ports()
    show_score()

    # Vérification frontend
    check_zabbix_frontend()
    check_zabbix_host()
    show_score()

    # Vérification temps
    check_boot_time()
    show_score()

    # Vérification anti-fraude
    check_vm_freshness()

    # Calcul de la note finale
    score_sur_20 = round((score / total) * 20, 2) if total > 0 else 0

    # Résumé
    print("\n" + "=" * 60)
    print("   RESUME DES TESTS")
    print("=" * 60)
    print(f"Candidat : {prenom} {nom}")
    print(f"Score brut : {score}/{total}")
    print(f"Note finale : {score_sur_20}/20")

    if score_sur_20 >= 18:
        print("\n*** EXCELLENT ! Installation Zabbix parfaitement configuree.")
    elif score_sur_20 >= 14:
        print("\n** Bon travail ! Quelques ajustements mineurs necessaires.")
    elif score_sur_20 >= 10:
        print("\n* Passable. Des elements importants sont manquants.")
    else:
        print("\n[X] Insuffisant. Verifiez votre installation.")

    # Envoi des résultats
    log_output = "\n".join(log_messages)
    envoyer_donnees(nom, prenom, log_output, score_sur_20)


if __name__ == "__main__":
    main()
