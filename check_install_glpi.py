#!/usr/bin/env python3

import os
import sys
import subprocess
import socket
import re
import json
from datetime import datetime

# Liste des bibliothèques requises sous Debian
REQUIRED_APT_LIBS = ["python3-requests", "python3-bs4"]

def install_required_packages():
    """ Vérifie et installe automatiquement les bibliothèques via apt """
    for pkg in REQUIRED_APT_LIBS:
        try:
            subprocess.run(["dpkg", "-s", pkg], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
#            log(f"[⚠] {pkg} n'est pas installé, installation en cours...")
            subprocess.check_call(["apt", "install", "-y", pkg])
#            log(f"[✔] {pkg} installé avec succès.")

# Installer les paquets si besoin
install_required_packages()

# Importer les bibliothèques après installation
import requests
from bs4 import BeautifulSoup


# Variables de score
total = 0
score = 0

# Demander le nom et le prénom de l'utilisateur
nom = input("\nEntrez votre nom : ")
prenom = input("Entrez votre prénom : ")

# Variables globales (prêtes pour un prompt plus tard)
EXPECTED_HOSTNAME = input("\nEntrez le nom de la VM : ")
EXPECTED_DOMAIN = input("\nEntrez le nom de domaine : ")
EXPECTED_IP = input("\nEntrez l'IP (sans le CIDR) de la VM : ")

# Liste pour stocker les messages
log_messages = []

def log(message):
    """Ajoute un message au log et l'affiche ensuite."""
    log_messages.append(message)


def check_hostname(expected_hostname=EXPECTED_HOSTNAME):
    """ Vérifie si le nom de la machine correspond au nom attendu """
    global score, total
    total += 1
    try:
        hostname = socket.gethostname()
        if hostname == expected_hostname:
            log(f"[✔] Nom de la VM correct : {hostname}")
            score += 1
        else:
            log(f"[✖] Nom de la VM incorrect (Attendu: {expected_hostname}, Actuel: {hostname})")
    except Exception as e:
        log(f"[✖] Erreur lors de la récupération du nom de la VM : {e}")

def get_default_interface():
    """ Détecte l'interface réseau principale en listant celles ayant une adresse IP """
    try:
        # Lister les interfaces actives et leur adresse IP
        result = subprocess.getoutput("ip -o -4 addr show | awk '{print $2}' | sort -u")
        interfaces = result.split("\n")

        # Exclure les interfaces spéciales (lo = loopback)
        interfaces = [iface for iface in interfaces if iface and iface != "lo"]

        if interfaces:
            return interfaces[0]  # Prendre la première interface détectée
        else:
            return None
    except Exception as e:
        log(f"[✖] Erreur lors de la détection de l'interface réseau : {e}")
        return None


def check_static_ip(expected_ip=EXPECTED_IP):
    """ Vérifie que l'IP est bien en statique et correspond à l'IP attendue """
    global score, total
    total += 1

    interface = get_default_interface()
    if not interface:
        log("[✖] Impossible de détecter l'interface réseau principale.")
        return

    try:
        with open("/etc/network/interfaces", "r") as f:
            interfaces_content = f.readlines()

        # Vérifier si l'interface détectée est configurée en statique
        is_static = any(f"iface {interface} inet static" in line for line in interfaces_content)
        ip_found = None

        for line in interfaces_content:
            if "address" in line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)  # Extraction de l'IP sans le masque
                if ip_match:
                    ip_found = ip_match.group(1)

        if is_static and ip_found == expected_ip:
            log(f"[✔] L'IP est bien en statique et correspond à {expected_ip} sur {interface}")
            score += 1
        elif not is_static:
            log(f"[✖] L'interface {interface} n'est pas configurée en statique")
        elif ip_found != expected_ip:
            log(f"[✖] L'IP configurée ({ip_found}) sur {interface} ne correspond pas à l'attendue ({expected_ip})")

    except Exception as e:
        log(f"[✖] Erreur lors de la vérification de l'IP statique : {e}")


def check_hosts(expected_ip=EXPECTED_IP, expected_hostname=EXPECTED_HOSTNAME):
    """ Vérifie la configuration de /etc/hosts :
        - 127.0.1.1 associé au hostname
        - expected_ip associé au hostname
    """
    global score, total
    total += 2  # Deux vérifications distinctes

    try:
        with open("/etc/hosts", "r") as f:
            hosts_content = f.readlines()

        has_127 = any(line.startswith("127.0.1.1") and expected_hostname in line for line in hosts_content)
        has_ip = any(line.startswith(expected_ip) and expected_hostname in line for line in hosts_content)

        if has_127:
            log(f"[✔] 127.0.1.1 est bien associé au {expected_hostname}")
            score += 1
        else:
            log(f"[✖] 127.0.1.1 n'est pas correctement associé à {expected_hostname} dans /etc/hosts")

        if has_ip:
            log(f"[✔] {expected_ip} est bien associé au {expected_hostname}")
            score += 1
        else:
            log(f"[✖] L'IP {expected_ip} n'est pas correctement associée à {expected_hostname} dans /etc/hosts")

    except Exception as e:
        log(f"[✖] Erreur lors de la lecture de /etc/hosts : {e}")


def check_dns():
    """ Vérifie que le DNS est bien configuré dans /etc/resolv.conf """
    global score, total
    total += 1
    try:
        with open("/etc/resolv.conf", "r") as f:
            resolv_content = f.read()
        
        if "nameserver" in resolv_content:
            log("[✔] /etc/resolv.conf contient bien un serveur DNS")
            score += 1
        else:
            log("[✖] Pas de serveur DNS configuré dans /etc/resolv.conf")

    except Exception as e:
        log(f"[✖] Erreur lors de la vérification de /etc/resolv.conf : {e}")

def check_packages():
    """ Vérifie que Apache, MariaDB et PHP sont installés """
    global score, total
    packages = ["apache2", "mariadb-server", "php"]
    total += len(packages)
    missing = []

    for package in packages:
        result = subprocess.getoutput(f"dpkg -l | grep {package}")
        if package in result:
            log(f"[✔] {package} est installé")
            score += 1
        else:
            log(f"[✖] {package} n'est pas installé")
            missing.append(package)


def check_mariadb_security():
    """ Vérifie si MariaDB a été sécurisé avec mysql_secure_installation """
    global score, total
    total += 3  # Ce test vaut maintenant 3 points (1 par critère)

    try:
        # Vérifier si le compte root a un mot de passe ou unix_socket
        root_auth = subprocess.getoutput("mysql -u root -Nse \"SELECT plugin FROM mysql.user WHERE User='root' AND Host='localhost';\"")

        if "unix_socket" in root_auth:
            log("[✔] L'authentification root se fait via unix_socket (sécurisé).")
            score += 1
        elif root_auth.strip():
            log("[⚠] L'authentification root utilise un mot de passe sécurisé.")
            score += 1
        else:
            log("[✖] Problème : L'authentification root n'est pas sécurisée !")

        # Vérifier si l'accès root distant est désactivé
        root_remote = subprocess.getoutput("mysql -u root -Nse \"SELECT Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');\"")

        if root_remote.strip() == "":
            log("[✔] L'accès root distant est désactivé.")
            score += 1
        else:
            log("[✖] Attention : L'accès root distant est activé ! Sécurisez-le.")

        # Vérifier si la base de test a été supprimée
        test_db = subprocess.getoutput("mysql -u root -Nse \"SHOW DATABASES LIKE 'test';\"")

        if test_db.strip() == "":
            log("[✔] La base de test a été supprimée (bon point pour la sécurité).")
            score += 1
        else:
            log("[✖] La base de test existe toujours ! Pensez à la supprimer.")

    except Exception as e:
        log(f"[✖] Erreur lors de la vérification de la sécurité de MariaDB : {e}")



def check_phpmyadmin():
    """ Vérifie que phpMyAdmin est installé, configuré et accessible """
    global score, total
    total += 3

    # Vérifier si phpMyAdmin est installé
    result = subprocess.getoutput("dpkg -l | grep phpmyadmin")
    if "phpmyadmin" in result:
        log("[✔] phpMyAdmin est installé")
        score += 1
    else:
        log("[✖] phpMyAdmin n'est pas installé")

    # Vérifier la configuration Apache
    if os.path.exists("/etc/apache2/conf-available/phpmyadmin.conf"):
        log("[✔] Configuration Apache pour phpMyAdmin trouvée")
        score += 1
    else:
        log("[✖] Pas de configuration Apache pour phpMyAdmin")

    # Vérifier si phpMyAdmin répond en HTTP
    try:
        response = requests.get("http://localhost/phpmyadmin", timeout=3)
        if response.status_code == 200:
            log("[✔] phpMyAdmin est accessible via HTTP")
            score += 1
        else:
            log(f"[✖] phpMyAdmin ne répond pas correctement (Code HTTP {response.status_code})")
    except requests.exceptions.RequestException:
        log("[✖] Impossible d'accéder à phpMyAdmin")


def check_glpi_db():
    """ Vérifie que la base de données GLPI et son utilisateur existent dans MariaDB """
    global score, total
    total += 2  # 1 point pour l'utilisateur, 1 point pour la base de données

    # Commandes SQL
    check_user_cmd = "SELECT User FROM mysql.user WHERE User='glpi';"
    check_db_cmd = "SHOW DATABASES LIKE 'glpi';"

    try:
        # Vérifier si l'utilisateur glpi existe
        user_check = subprocess.getoutput(f"echo \"{check_user_cmd}\" | mariadb -u root -N 2>/dev/null")
        if "glpi" in user_check:
            log("[✔] L'utilisateur 'glpi' existe dans MariaDB")
            score += 1
        else:
            log("[✖] L'utilisateur 'glpi' n'existe pas dans MariaDB")

        # Vérifier si la base de données glpi existe
        db_check = subprocess.getoutput(f"echo \"{check_db_cmd}\" | mariadb -u root -N 2>/dev/null")
        if "glpi" in db_check:
            log("[✔] La base de données 'glpi' existe dans MariaDB")
            score += 1
        else:
            log("[✖] La base de données 'glpi' n'existe pas dans MariaDB")

    except Exception as e:
        log(f"[✖] Erreur lors de la vérification de la base GLPI : {e}")


def check_php_extensions():
    """ Vérifie que l'extension PHP intl est installée et activée """
    global score, total
    total += 2  # 1 point si l'extension est installée et activée

    # Vérifier si php-intl est installé
    package_check = subprocess.getoutput("dpkg -l | grep php-intl")
    if "php-intl" in package_check:
        log("[✔] Le paquet php-intl est installé")
        score += 1
    else:
        log("[✖] Le paquet php-intl n'est pas installé")

    # Vérifier si l'extension intl est activée
    extension_check = subprocess.getoutput("php -m | grep intl")
    if "intl" in extension_check:
        log("[✔] L'extension intl est activée dans PHP")
        score += 1
    else:
        log("[✖] L'extension intl n'est pas activée dans PHP")

def get_glpi_vhost():
    """Récupère le ServerName du VirtualHost GLPI et vérifie qu'il correspond bien au domaine attendu."""
    global score, total
    total += 1  # Ajoute un point total pour cette vérification

    try:
        with open("/etc/apache2/sites-available/glpi.conf", "r") as f:
            content = f.read()

        match = re.search(r"ServerName\s+(\S+)", content)
        if match:
            vhost = match.group(1)  # Récupère le ServerName trouvé
            log(f"[ℹ] GLPI est configuré sur {vhost}")

            # Vérification que le ServerName se termine bien par le domaine attendu
            if vhost.endswith(f".{EXPECTED_DOMAIN}"):
                log(f"[✔] Le domaine GLPI ({vhost}) est bien dans {EXPECTED_DOMAIN}")
                score += 1  # ✅ Ajout du point si la correspondance est bonne
            else:
                log(f"[✖] Le domaine GLPI ({vhost}) ne correspond pas à l'attendu (*.{EXPECTED_DOMAIN})")

            return vhost
        else:
            log("[✖] Aucun ServerName trouvé pour GLPI dans la configuration Apache.")
            return None

    except Exception as e:
        log(f"[✖] Impossible de lire le VirtualHost GLPI : {e}")
        return None
 


def check_glpi():
    """ Vérifie que GLPI est installé et accessible via son VirtualHost """
    global score, total
    total += 2

    vhost = get_glpi_vhost()
    if not vhost:
        log("[✖] Aucun ServerName trouvé pour GLPI, impossible de tester l'accès HTTP")
        return

    log(f"[ℹ] GLPI est configuré sur {vhost}, test de l'accès HTTP...")
    score += 1

    try:
        response = requests.get(f"http://{vhost}", timeout=3)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else "Sans titre"

            if "install.php" in response.text.lower():
                log("[✖] GLPI n'est pas totalement configuré (install.php détecté)")
            elif "GLPI" in title:
                log(f"[✔] GLPI est bien installé et accessible via {vhost}")
                score += 1
            else:
                log(f"[✖] Page inattendue pour GLPI sur {vhost}")
        else:
            log(f"[✖] GLPI ne répond pas correctement sur {vhost} (Code HTTP {response.status_code})")

    except requests.exceptions.RequestException:
        log(f"[✖] Impossible d'accéder à GLPI sur {vhost}")




def check_services():
    """ Vérifie que Apache et MariaDB sont bien actifs """
    global score, total
    services = ["apache2", "mariadb"]
    total += len(services)
    inactive = []

    for service in services:
        result = subprocess.getoutput(f"systemctl is-active {service}")
        if result.strip() == "active":
            log(f"[✔] {service} est actif")
            score += 1
        else:
            log("f[✖] {service} est inactif")
            inactive.append(service)

def check_boot_time():
    """
    Mesure le temps écoulé depuis le premier boot du jour et attribue un score sur 5 points.
    - Temps écoulé <= XX minutes => 5 points
    - Pour chaque tranche de 22,5 minutes (1/4 de 90 minutes) en plus, on retire 1 point.
    """
    global score, total
    total += 5  # Ce test vaut 5 points
    try:
        result = subprocess.run(["journalctl", "--list-boots"], capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout:
            log("[✖] Erreur : Impossible de récupérer les informations de boot.")
            return

        boots = []
        lines = result.stdout.splitlines()
        # Ignorer la première ligne (en-tête) et parcourir les boots
        for line in lines[1:]:
            parts = line.split()
            # On retire le fuseau horaire : on prend uniquement les 3 premiers éléments de la date
            boot_time_str = " ".join(parts[2:5])
            boot_time = datetime.strptime(boot_time_str, "%a %Y-%m-%d %H:%M:%S")
            boots.append(boot_time)

        today = datetime.now().date()
        boots_today = [b for b in boots if b.date() == today]
        if not boots_today:
            log("[✖] Aucun boot trouvé pour aujourd'hui.")
            return

        first_boot = min(boots_today)
        now = datetime.now()
        elapsed_time = now - first_boot
        elapsed_seconds = elapsed_time.total_seconds()

        # Temps imparti de 90 minutes (5400 secondes)
        temps_imparti = 40 * 60
        if elapsed_seconds <= temps_imparti:
            points = 5
        else:
            extra = elapsed_seconds - temps_imparti
            quarter = temps_imparti / 4  # 22,5 minutes
            points = 5 - int(extra // quarter)
            if points < 0:
                points = 0

        log(f"[ℹ] Premier boot du jour : {first_boot}")
        log(f"[ℹ] Temps écoulé depuis le premier boot d'aujourd'hui : {elapsed_time}")
        log(f"[:] Temps imparti inital: 40 mn")
        log(f"[ℹ] Score boot time attribué : {points}/5")
        score += points

    except Exception as e:
        log(f"[✖] Erreur lors de la vérification du temps de boot : {e}")




# Exécution des tests
print("\n===== Vérification de la configuration =====\n")
check_hostname()
check_static_ip()
check_hosts()
check_dns()
check_packages()
check_mariadb_security()
check_phpmyadmin()
check_glpi_db()
check_php_extensions()
check_glpi()
check_services()
check_boot_time()

# Calcul de la note normalisée sur 20
score_sur_20 = round((score / total) * 20, 2) if total > 0 else 0

# Ajouter la note finale au log
log_messages.append("\n===== Résumé des tests =====")
log_messages.append(f"Score final : {score}/{total} ({score_sur_20}/20)")

if score_sur_20 == 20:
    log_messages.append("✅ Tout est parfaitement configuré !")
elif score_sur_20 >= 14:
    log_messages.append("⚠️ Quelques ajustements mineurs sont nécessaires.")
else:
    log_messages.append("❌ Problèmes détectés, intervention recommandée !")

# Afficher le log dans le terminal
print("\n".join(log_messages))

# Fonction pour envoyer les résultats

def envoyer_donnees(nom, prenom, commentaires, note):
    """Envoie les résultats du test au serveur externe en JSON avec filename en paramètre d'URL."""
    
    # Définir le nom du fichier attendu par le serveur
    filename = f"GLPI-{nom}-{prenom}.json"
    
    # Construire l'URL avec le paramètre filename
    url = f"http://www.imcalternance.com/logsapi/logreceiver.php?filename={filename}"
    
    headers = {"Content-Type": "application/json"}
    data = {
        "nom": nom,
        "prenom": prenom,
        "commentaires": commentaires,
        "note": score_sur_20
    }

    # 🔍 Debug : Afficher le JSON avant envoi
    print("\n📤 JSON envoyé :")
#    print(json.dumps(data, indent=4, ensure_ascii=False))  

    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f"\n✅ Les résultats ont été envoyés avec succès sous {filename}.")
        else:
            print(f"\n❌ Échec de l'envoi. Statut HTTP : {response.status_code}")
            print(f"🔍 Réponse du serveur : {response.text}")  # Debug de la réponse serveur
    except Exception as e:
        print(f"\n❌ Erreur lors de l'envoi : {e}")


# Transformer les logs en texte avant envoi
log_output = "\n".join(log_messages)

# Envoyer les résultats
envoyer_donnees(nom, prenom, log_output, score_sur_20)
