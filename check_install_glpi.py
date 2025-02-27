#!/usr/bin/env python3

import os
import sys
import subprocess
import socket
import re

# Liste des bibliothèques requises sous Debian
REQUIRED_APT_LIBS = ["python3-requests", "python3-bs4"]

def install_required_packages():
    """ Vérifie et installe automatiquement les bibliothèques via apt """
    for pkg in REQUIRED_APT_LIBS:
        try:
            subprocess.run(["dpkg", "-s", pkg], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"[⚠] {pkg} n'est pas installé, installation en cours...")
            subprocess.check_call(["apt", "install", "-y", pkg])
            print(f"[✔] {pkg} installé avec succès.")

# Installer les paquets si besoin
install_required_packages()

# Importer les bibliothèques après installation
import requests
from bs4 import BeautifulSoup


# Variables de score
total = 0
score = 0


# Variables globales (prêtes pour un prompt plus tard)
EXPECTED_HOSTNAME = "tux-01"
EXPECTED_IP = "192.168.62.133"

def check_hostname(expected_hostname=EXPECTED_HOSTNAME):
    """ Vérifie si le nom de la machine correspond au nom attendu """
    global score, total
    total += 1
    try:
        hostname = socket.gethostname()
        if hostname == expected_hostname:
            print(f"[✔] Nom de la VM correct : {hostname}")
            score += 1
        else:
            print(f"[✖] Nom de la VM incorrect (Attendu: {expected_hostname}, Actuel: {hostname})")
    except Exception as e:
        print(f"[✖] Erreur lors de la récupération du nom de la VM : {e}")

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
        print(f"[✖] Erreur lors de la détection de l'interface réseau : {e}")
        return None


def check_static_ip(expected_ip=EXPECTED_IP):
    """ Vérifie que l'IP est bien en statique et correspond à l'IP attendue """
    global score, total
    total += 1

    interface = get_default_interface()
    if not interface:
        print("[✖] Impossible de détecter l'interface réseau principale.")
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
            print(f"[✔] L'IP est bien en statique et correspond à {expected_ip} sur {interface}")
            score += 1
        elif not is_static:
            print(f"[✖] L'interface {interface} n'est pas configurée en statique")
        elif ip_found != expected_ip:
            print(f"[✖] L'IP configurée ({ip_found}) sur {interface} ne correspond pas à l'attendue ({expected_ip})")

    except Exception as e:
        print(f"[✖] Erreur lors de la vérification de l'IP statique : {e}")


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
            print("[✔] 127.0.1.1 est bien associé au hostname")
            score += 1
        else:
            print(f"[✖] 127.0.1.1 n'est pas correctement associé à {expected_hostname} dans /etc/hosts")

        if has_ip:
            print(f"[✔] {expected_ip} est bien associé au hostname")
            score += 1
        else:
            print(f"[✖] L'IP {expected_ip} n'est pas correctement associée à {expected_hostname} dans /etc/hosts")

    except Exception as e:
        print(f"[✖] Erreur lors de la lecture de /etc/hosts : {e}")


def check_dns():
    """ Vérifie que le DNS est bien configuré dans /etc/resolv.conf """
    global score, total
    total += 1
    try:
        with open("/etc/resolv.conf", "r") as f:
            resolv_content = f.read()
        
        if "nameserver" in resolv_content:
            print("[✔] /etc/resolv.conf contient bien un serveur DNS")
            score += 1
        else:
            print("[✖] Pas de serveur DNS configuré dans /etc/resolv.conf")

    except Exception as e:
        print(f"[✖] Erreur lors de la vérification de /etc/resolv.conf : {e}")

def check_packages():
    """ Vérifie que Apache, MariaDB et PHP sont installés """
    global score, total
    total += 1
    packages = ["apache2", "mariadb-server", "php"]
    missing = []

    for package in packages:
        result = subprocess.getoutput(f"dpkg -l | grep {package}")
        if package in result:
            print(f"[✔] {package} est installé")
            score += 1
        else:
            print(f"[✖] {package} n'est pas installé")
            missing.append(package)

def check_phpmyadmin():
    """ Vérifie que phpMyAdmin est installé, configuré et accessible """
    global score, total
    total += 1

    # Vérifier si phpMyAdmin est installé
    result = subprocess.getoutput("dpkg -l | grep phpmyadmin")
    if "phpmyadmin" in result:
        print("[✔] phpMyAdmin est installé")
        package_ok = True
    else:
        print("[✖] phpMyAdmin n'est pas installé")
        package_ok = False

    # Vérifier la configuration Apache
    if os.path.exists("/etc/apache2/conf-available/phpmyadmin.conf"):
        print("[✔] Configuration Apache pour phpMyAdmin trouvée")
        config_ok = True
    else:
        print("[✖] Pas de configuration Apache pour phpMyAdmin")
        config_ok = False

    # Vérifier si phpMyAdmin répond en HTTP
    try:
        response = requests.get("http://localhost/phpmyadmin", timeout=3)
        if response.status_code == 200:
            print("[✔] phpMyAdmin est accessible via HTTP")
            access_ok = True
        else:
            print(f"[✖] phpMyAdmin ne répond pas correctement (Code HTTP {response.status_code})")
            access_ok = False
    except requests.exceptions.RequestException:
        print("[✖] Impossible d'accéder à phpMyAdmin")
        access_ok = False

    # Valider le test si tout est bon
    if package_ok and config_ok and access_ok:
        score += 1

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
            print("[✔] L'utilisateur 'glpi' existe dans MariaDB")
            score += 1
        else:
            print("[✖] L'utilisateur 'glpi' n'existe pas dans MariaDB")

        # Vérifier si la base de données glpi existe
        db_check = subprocess.getoutput(f"echo \"{check_db_cmd}\" | mariadb -u root -N 2>/dev/null")
        if "glpi" in db_check:
            print("[✔] La base de données 'glpi' existe dans MariaDB")
            score += 1
        else:
            print("[✖] La base de données 'glpi' n'existe pas dans MariaDB")

    except Exception as e:
        print(f"[✖] Erreur lors de la vérification de la base GLPI : {e}")


def check_php_extensions():
    """ Vérifie que l'extension PHP intl est installée et activée """
    global score, total
    total += 1  # 1 point si l'extension est installée et activée

    # Vérifier si php-intl est installé
    package_check = subprocess.getoutput("dpkg -l | grep php-intl")
    if "php-intl" in package_check:
        print("[✔] Le paquet php-intl est installé")
        package_ok = True
    else:
        print("[✖] Le paquet php-intl n'est pas installé")
        package_ok = False

    # Vérifier si l'extension intl est activée
    extension_check = subprocess.getoutput("php -m | grep intl")
    if "intl" in extension_check:
        print("[✔] L'extension intl est activée dans PHP")
        extension_ok = True
    else:
        print("[✖] L'extension intl n'est pas activée dans PHP")
        extension_ok = False

    # Valider le test si tout est bon
    if package_ok and extension_ok:
        score += 1


def get_glpi_vhost():
    """ Récupère le ServerName du VirtualHost GLPI """
    try:
        with open("/etc/apache2/sites-available/glpi.conf", "r") as f:
            content = f.read()

        match = re.search(r"ServerName\s+(\S+)", content)
        if match:
            return match.group(1)  # Retourne le ServerName trouvé
        else:
            return None
    except Exception as e:
        print(f"[✖] Impossible de lire le VirtualHost GLPI : {e}")
        return None

def check_glpi():
    """ Vérifie que GLPI est installé et accessible via son VirtualHost """
    global score, total
    total += 1

    vhost = get_glpi_vhost()
    if not vhost:
        print("[✖] Aucun ServerName trouvé pour GLPI, impossible de tester l'accès HTTP")
        return

    print(f"[ℹ] GLPI est configuré sur {vhost}, test de l'accès HTTP...")

    try:
        response = requests.get(f"http://{vhost}", timeout=3)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else "Sans titre"

            if "install.php" in response.text.lower():
                print("[✖] GLPI n'est pas totalement configuré (install.php détecté)")
            elif "GLPI" in title:
                print(f"[✔] GLPI est bien installé et accessible via {vhost}")
                score += 1
            else:
                print(f"[✖] Page inattendue pour GLPI sur {vhost}")
        else:
            print(f"[✖] GLPI ne répond pas correctement sur {vhost} (Code HTTP {response.status_code})")

    except requests.exceptions.RequestException:
        print(f"[✖] Impossible d'accéder à GLPI sur {vhost}")




def check_services():
    """ Vérifie que Apache et MariaDB sont bien actifs """
    global score, total
    total += 1
    services = ["apache2", "mariadb"]
    inactive = []

    for service in services:
        result = subprocess.getoutput(f"systemctl is-active {service}")
        if result.strip() == "active":
            print(f"[✔] {service} est actif")
            score += 1
        else:
            print(f"[✖] {service} est inactif")
            inactive.append(service)

def display_final_score():
    """ Affiche le score final sur 20 """
    print("\n===== Résumé =====")

    # Calcul de la note normalisée sur 20
    score_sur_20 = round((score / total) * 20, 2) if total > 0 else 0

    print(f"Score final : {score}/{total} ({score_sur_20}/20)")

    if score_sur_20 == 20:
        print("✅ Tout est parfaitement configuré !")
    elif score_sur_20 >= 14:
        print("⚠️ Quelques ajustements mineurs sont nécessaires.")
    else:
        print("❌ Problèmes détectés, intervention recommandée !")


# Exécution des tests
print("\n===== Vérification de la configuration =====\n")
check_hostname()
check_static_ip()
check_hosts()
check_dns()
check_packages()
check_phpmyadmin()
check_glpi_db()
check_php_extensions()
check_glpi()
check_services()
display_final_score()

