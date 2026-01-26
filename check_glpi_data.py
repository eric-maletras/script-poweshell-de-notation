#!/usr/bin/env python3
"""
Script de vérification des données GLPI
=========================================
Ce script vérifie :
- Que GLPI est toujours installé et accessible
- Que les données manuelles sont complètes (lieux, imprimantes, équipements réseau, moniteurs, serveurs)
- Que les données importées (10 aléatoires) sont présentes
- Le temps mis depuis le début du TP (basé sur la date de création d'un élément importé)

Auteur : Eric MALETRAS - BTS SIO SISR
"""

import os
import sys
import subprocess
import socket
import re
import json
import random
import html
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

# Données manuelles attendues avec TOUS les champs liés
EXPECTED_LOCATIONS = [
    {"name": "M2L - Bâtiment Principal", "comment": "Bâtiment principal de la M2L", "parent": None},
    {"name": "RDC - Accueil", "comment": "Hall d'accueil", "parent": "M2L - Bâtiment Principal"},
    {"name": "RDC - Administration", "comment": "Bureaux administratifs", "parent": "M2L - Bâtiment Principal"},
    {"name": "RDC - Local technique", "comment": "Salle serveurs et baie de brassage", "parent": "M2L - Bâtiment Principal"},
    {"name": "Étage 1 - Salle 107", "comment": "Salle de formation 16 postes", "parent": "M2L - Bâtiment Principal"},
    {"name": "Étage 1 - Salle 108", "comment": "Salle de formation 16 postes", "parent": "M2L - Bâtiment Principal"},
    {"name": "Étage 1 - Salle 109", "comment": "Salle de formation 16 postes", "parent": "M2L - Bâtiment Principal"},
    {"name": "Étage 2 - Salle 200", "comment": "Salle TP réseau", "parent": "M2L - Bâtiment Principal"},
    {"name": "Étage 2 - Salle 201", "comment": "Salle TP système", "parent": "M2L - Bâtiment Principal"},
]

EXPECTED_SERVERS = [
    {"name": "SRV-DC01", "manufacturer": "Dell", "model": "PowerEdge R640", "serial": "DELL-SRV-001", 
     "type": "Serveur", "comment": "Contrôleur de domaine AD", "location": "RDC - Local technique", "status": "En service"},
    {"name": "SRV-GLPI", "manufacturer": "HP", "model": "ProLiant DL380 Gen10", "serial": "HP-SRV-002", 
     "type": "Serveur", "comment": "Serveur GLPI", "location": "RDC - Local technique", "status": "En service"},
    {"name": "SRV-FILES", "manufacturer": "Dell", "model": "PowerEdge R740", "serial": "DELL-SRV-003", 
     "type": "Serveur", "comment": "Serveur de fichiers", "location": "RDC - Local technique", "status": "En service"},
]

EXPECTED_MONITORS = [
    {"name": "MON-ADM-01", "manufacturer": "Dell", "model": "P2422H", "serial": "CN0M5X7J742", 
     "type": "24 pouces", "location": "RDC - Administration", "status": "En service"},
    {"name": "MON-ADM-02", "manufacturer": "Dell", "model": "P2422H", "serial": "CN0M5X7J743", 
     "type": "24 pouces", "location": "RDC - Administration", "status": "En service"},
    {"name": "MON-ADM-03", "manufacturer": "HP", "model": "E24 G4", "serial": "3CQ1234XYZ", 
     "type": "24 pouces", "location": "RDC - Administration", "status": "En service"},
    {"name": "MON-ACCUEIL-01", "manufacturer": "HP", "model": "E22 G4", "serial": "3CQ1234ABC", 
     "type": "22 pouces", "location": "RDC - Accueil", "status": "En service"},
    {"name": "MON-TECH-01", "manufacturer": "Dell", "model": "P2722H", "serial": "CN0M5X7J800", 
     "type": "27 pouces", "location": "RDC - Local technique", "status": "En service"},
]

EXPECTED_NETWORKEQUIPMENTS = [
    {"name": "SW-CORE-01", "manufacturer": "Cisco", "model": "Catalyst 2960-48", "serial": "FCW2145A0PQ", 
     "type": "Switch", "location": "RDC - Local technique", "status": "En service"},
    {"name": "SW-ETAGE1-01", "manufacturer": "Cisco", "model": "Catalyst 2960-24", "serial": "FCW2145A0PR", 
     "type": "Switch", "location": "Étage 1 - Salle 107", "status": "En service"},
    {"name": "SW-ETAGE2-01", "manufacturer": "Cisco", "model": "Catalyst 2960-24", "serial": "FCW2145A0PS", 
     "type": "Switch", "location": "Étage 2 - Salle 200", "status": "En service"},
    {"name": "AP-WIFI-RDC", "manufacturer": "Ubiquiti", "model": "UniFi AP AC Pro", "serial": "F09FC2345678", 
     "type": "Borne Wi-Fi", "location": "RDC - Accueil", "status": "En service"},
    {"name": "AP-WIFI-ETG1", "manufacturer": "Ubiquiti", "model": "UniFi AP AC Pro", "serial": "F09FC2345679", 
     "type": "Borne Wi-Fi", "location": "Étage 1 - Salle 108", "status": "En service"},
    {"name": "FW-M2L-01", "manufacturer": "Stormshield", "model": "SN310", "serial": "SN310A12345", 
     "type": "Pare-feu", "location": "RDC - Local technique", "status": "En service"},
]

EXPECTED_PRINTERS = [
    {"name": "IMP-ADM-01", "manufacturer": "HP", "model": "LaserJet Pro M404dn", "serial": "CNBJP12345", 
     "type": "Laser N&B", "location": "RDC - Administration", "status": "En service"},
    {"name": "IMP-ADM-02", "manufacturer": "HP", "model": "Color LaserJet Pro M454dw", "serial": "CNBJP12346", 
     "type": "Laser Couleur", "location": "RDC - Administration", "status": "En service"},
    {"name": "IMP-FORM-107", "manufacturer": "Brother", "model": "HL-L5200DW", "serial": "E78452K1J", 
     "type": "Laser N&B", "location": "Étage 1 - Salle 107", "status": "En service"},
    {"name": "IMP-FORM-109", "manufacturer": "Brother", "model": "HL-L5200DW", "serial": "E78452K2M", 
     "type": "Laser N&B", "location": "Étage 1 - Salle 109", "status": "En service"},
    {"name": "IMP-ACCUEIL", "manufacturer": "HP", "model": "OfficeJet Pro 9015", "serial": "CN52R1H0KP", 
     "type": "Jet d'encre", "location": "RDC - Accueil", "status": "En service"},
]

# Données importées (postes de travail) - échantillon pour vérification aléatoire
IMPORTED_COMPUTERS = [
    "109-05", "109-08", "109-10", "109-06", "109-09", "109-04", "109-15", "109-11", "109-14", "109-12",
    "109-07", "201-07", "204-09", "109-03", "204-11", "204-12", "204-03", "204-06", "204-04", "108-03",
    "108-04", "108-10", "108-12", "108-14", "108-13", "108-09", "201-06", "108-11", "201-13", "201-16",
    "204-10", "204-15", "201-04", "204-02", "201-01", "204-07", "204-05", "204-08", "201-15", "sdp-03",
    "108-02", "201-vp", "sdp-05", "sdp-06", "sdp-04", "sdp-01", "110-vp", "sdp-02", "204-01", "334-01",
    "svt-03", "329-09", "231-vp", "222-01", "113-01", "236-16", "236-12", "234-02", "236-03", "228-vp",
    "311-04", "204-14", "201-10", "201-08", "201-02", "201-03", "200-14", "200-05", "236-09", "233-15",
    "233-02", "234-03", "236-13", "108-01", "236-02", "114-01", "236-08", "233-14", "236-01", "235-09",
    "236-10", "236-14", "232-01", "329-02", "329-05", "329-08", "329-07", "233-03", "235-12", "220-01"
]

# =============================================
# FONCTIONS UTILITAIRES
# =============================================

def log(message):
    """Ajoute un message au log et l'affiche ensuite."""
    log_messages.append(message)

def execute_sql(query):
    """Exécute une requête SQL sur la base GLPI et retourne le résultat."""
    try:
        result = subprocess.getoutput(f'mysql -u root -N -e "{query}" glpi 2>/dev/null')
        return result.strip()
    except Exception as e:
        return None

def get_glpi_vhost():
    """Récupère le ServerName du VirtualHost GLPI."""
    try:
        with open("/etc/apache2/sites-available/glpi.conf", "r") as f:
            content = f.read()
        match = re.search(r"ServerName\s+(\S+)", content)
        if match:
            return match.group(1)
    except:
        pass
    return None

# =============================================
# VÉRIFICATIONS DE BASE
# =============================================

def check_glpi_installed():
    """Vérifie que GLPI est installé et accessible."""
    global score, total
    total += 3  # 3 points : fichiers, vhost, accès HTTP

    # Vérifier les fichiers GLPI
    if os.path.exists("/var/www/glpi/index.php"):
        log("[✔] Fichiers GLPI présents dans /var/www/glpi")
        score += 1
    else:
        log("[✖] Fichiers GLPI non trouvés dans /var/www/glpi")
        return False

    # Vérifier le VirtualHost
    vhost = get_glpi_vhost()
    if vhost:
        log(f"[✔] VirtualHost GLPI configuré : {vhost}")
        score += 1
    else:
        log("[✖] VirtualHost GLPI non trouvé")
        return False

    # Vérifier l'accès HTTP
    try:
        response = requests.get(f"http://{vhost}", timeout=5)
        if response.status_code == 200 and "GLPI" in response.text:
            log(f"[✔] GLPI accessible via http://{vhost}")
            score += 1
            return True
        else:
            log(f"[✖] GLPI ne répond pas correctement sur {vhost}")
    except requests.exceptions.RequestException as e:
        log(f"[✖] Impossible d'accéder à GLPI : {e}")
    
    return False

def check_database_exists():
    """Vérifie que la base de données GLPI existe."""
    global score, total
    total += 1

    result = execute_sql("SHOW DATABASES LIKE 'glpi';")
    if result and "glpi" in result:
        log("[✔] Base de données 'glpi' existante")
        score += 1
        return True
    else:
        log("[✖] Base de données 'glpi' non trouvée")
        return False

# =============================================
# VÉRIFICATION DES DONNÉES MANUELLES
# =============================================

def check_locations():
    """Vérifie que tous les lieux attendus sont présents avec leur hiérarchie et commentaire."""
    global score, total
    log("\n--- Vérification des LIEUX ---")
    
    for loc in EXPECTED_LOCATIONS:
        total += 1
        name = loc["name"]
        expected_comment = loc["comment"]
        expected_parent = loc["parent"]
        points = 0
        errors = []
        
        # Requête pour récupérer le lieu avec son parent
        query = f"""
            SELECT l.id, l.comment, l.locations_id, p.name as parent_name
            FROM glpi_locations l
            LEFT JOIN glpi_locations p ON l.locations_id = p.id
            WHERE l.name = '{name}';
        """
        result = execute_sql(query)
        
        if result:
            parts = result.split("\t")
            loc_id = parts[0] if len(parts) > 0 else None
            # Décoder les entités HTML (ex: &#38; -> &)
            comment = html.unescape(parts[1]) if len(parts) > 1 else ""
            parent_id = parts[2] if len(parts) > 2 else "0"
            parent_name = parts[3] if len(parts) > 3 else ""
            
            # Vérifier le commentaire
            if expected_comment and expected_comment not in comment:
                errors.append(f"Commentaire manquant/incorrect (attendu: {expected_comment})")
            
            # Vérifier le parent
            if expected_parent:
                if parent_id == "0" or not parent_name or expected_parent not in parent_name:
                    errors.append(f"Parent incorrect (attendu: {expected_parent}, trouvé: {parent_name or 'aucun'})")
            
            if not errors:
                log(f"[✔] Lieu complet : {name}")
                score += 1
            else:
                log(f"[⚠] Lieu trouvé mais incomplet : {name}")
                for err in errors:
                    log(f"    └─ {err}")
        else:
            log(f"[✖] Lieu manquant : {name}")

def check_servers():
    """Vérifie que tous les serveurs sont présents avec toutes leurs données liées."""
    global score, total
    log("\n--- Vérification des SERVEURS ---")
    
    for srv in EXPECTED_SERVERS:
        total += 1
        name = srv["name"]
        errors = []
        
        # Requête avec jointures pour récupérer toutes les données liées
        query = f"""
            SELECT c.id, c.serial, c.comment,
                   m.name as manufacturer, 
                   cm.name as model,
                   ct.name as type,
                   l.name as location,
                   s.name as status
            FROM glpi_computers c
            LEFT JOIN glpi_manufacturers m ON c.manufacturers_id = m.id
            LEFT JOIN glpi_computermodels cm ON c.computermodels_id = cm.id
            LEFT JOIN glpi_computertypes ct ON c.computertypes_id = ct.id
            LEFT JOIN glpi_locations l ON c.locations_id = l.id
            LEFT JOIN glpi_states s ON c.states_id = s.id
            WHERE c.name = '{name}';
        """
        result = execute_sql(query)
        
        if result:
            parts = result.split("\t")
            serial = parts[1] if len(parts) > 1 else ""
            # Décoder les entités HTML (ex: &#38; -> &)
            comment = html.unescape(parts[2]) if len(parts) > 2 else ""
            manufacturer = parts[3] if len(parts) > 3 else ""
            model = parts[4] if len(parts) > 4 else ""
            comp_type = html.unescape(parts[5]) if len(parts) > 5 else ""
            location = parts[6] if len(parts) > 6 else ""
            status = parts[7] if len(parts) > 7 else ""
            
            # Vérifications
            if srv["serial"] and srv["serial"] not in serial:
                errors.append(f"N° série (attendu: {srv['serial']}, trouvé: {serial or 'vide'})")
            if srv["manufacturer"] and srv["manufacturer"].lower() not in manufacturer.lower():
                errors.append(f"Fabricant (attendu: {srv['manufacturer']}, trouvé: {manufacturer or 'vide'})")
            if srv["model"] and srv["model"].lower() not in model.lower():
                errors.append(f"Modèle (attendu: {srv['model']}, trouvé: {model or 'vide'})")
            if srv["type"] and srv["type"].lower() not in comp_type.lower():
                errors.append(f"Type (attendu: {srv['type']}, trouvé: {comp_type or 'vide'})")
            if srv["location"] and srv["location"] not in location:
                errors.append(f"Lieu (attendu: {srv['location']}, trouvé: {location or 'vide'})")
            if srv["status"] and srv["status"].lower() not in status.lower():
                errors.append(f"Statut (attendu: {srv['status']}, trouvé: {status or 'vide'})")
            if srv["comment"] and srv["comment"].lower() not in comment.lower():
                errors.append(f"Commentaire (attendu: {srv['comment']}, trouvé: {comment or 'vide'})")
            
            if not errors:
                log(f"[✔] Serveur complet : {name}")
                score += 1
            else:
                log(f"[⚠] Serveur trouvé mais incomplet : {name}")
                for err in errors:
                    log(f"    └─ {err}")
        else:
            log(f"[✖] Serveur manquant : {name}")

def check_monitors():
    """Vérifie que tous les moniteurs sont présents avec toutes leurs données liées."""
    global score, total
    log("\n--- Vérification des MONITEURS ---")
    
    for mon in EXPECTED_MONITORS:
        total += 1
        name = mon["name"]
        errors = []
        
        query = f"""
            SELECT m.id, m.serial,
                   mf.name as manufacturer, 
                   mm.name as model,
                   mt.name as type,
                   l.name as location,
                   s.name as status
            FROM glpi_monitors m
            LEFT JOIN glpi_manufacturers mf ON m.manufacturers_id = mf.id
            LEFT JOIN glpi_monitormodels mm ON m.monitormodels_id = mm.id
            LEFT JOIN glpi_monitortypes mt ON m.monitortypes_id = mt.id
            LEFT JOIN glpi_locations l ON m.locations_id = l.id
            LEFT JOIN glpi_states s ON m.states_id = s.id
            WHERE m.name = '{name}';
        """
        result = execute_sql(query)
        
        if result:
            parts = result.split("\t")
            serial = parts[1] if len(parts) > 1 else ""
            manufacturer = parts[2] if len(parts) > 2 else ""
            model = parts[3] if len(parts) > 3 else ""
            mon_type = html.unescape(parts[4]) if len(parts) > 4 else ""
            location = parts[5] if len(parts) > 5 else ""
            status = parts[6] if len(parts) > 6 else ""
            
            if mon["serial"] and mon["serial"] not in serial:
                errors.append(f"N° série (attendu: {mon['serial']}, trouvé: {serial or 'vide'})")
            if mon["manufacturer"] and mon["manufacturer"].lower() not in manufacturer.lower():
                errors.append(f"Fabricant (attendu: {mon['manufacturer']}, trouvé: {manufacturer or 'vide'})")
            if mon["model"] and mon["model"].lower() not in model.lower():
                errors.append(f"Modèle (attendu: {mon['model']}, trouvé: {model or 'vide'})")
            if mon["type"] and mon["type"].lower() not in mon_type.lower():
                errors.append(f"Type/Taille (attendu: {mon['type']}, trouvé: {mon_type or 'vide'})")
            if mon["location"] and mon["location"] not in location:
                errors.append(f"Lieu (attendu: {mon['location']}, trouvé: {location or 'vide'})")
            if mon["status"] and mon["status"].lower() not in status.lower():
                errors.append(f"Statut (attendu: {mon['status']}, trouvé: {status or 'vide'})")
            
            if not errors:
                log(f"[✔] Moniteur complet : {name}")
                score += 1
            else:
                log(f"[⚠] Moniteur trouvé mais incomplet : {name}")
                for err in errors:
                    log(f"    └─ {err}")
        else:
            log(f"[✖] Moniteur manquant : {name}")

def check_network_equipments():
    """Vérifie que tous les équipements réseau sont présents avec toutes leurs données liées."""
    global score, total
    log("\n--- Vérification des ÉQUIPEMENTS RÉSEAU ---")
    
    for equip in EXPECTED_NETWORKEQUIPMENTS:
        total += 1
        name = equip["name"]
        errors = []
        
        query = f"""
            SELECT n.id, n.serial,
                   mf.name as manufacturer, 
                   nm.name as model,
                   nt.name as type,
                   l.name as location,
                   s.name as status
            FROM glpi_networkequipments n
            LEFT JOIN glpi_manufacturers mf ON n.manufacturers_id = mf.id
            LEFT JOIN glpi_networkequipmentmodels nm ON n.networkequipmentmodels_id = nm.id
            LEFT JOIN glpi_networkequipmenttypes nt ON n.networkequipmenttypes_id = nt.id
            LEFT JOIN glpi_locations l ON n.locations_id = l.id
            LEFT JOIN glpi_states s ON n.states_id = s.id
            WHERE n.name = '{name}';
        """
        result = execute_sql(query)
        
        if result:
            parts = result.split("\t")
            serial = parts[1] if len(parts) > 1 else ""
            manufacturer = parts[2] if len(parts) > 2 else ""
            model = parts[3] if len(parts) > 3 else ""
            # Décoder les entités HTML (ex: &#38; -> &)
            eq_type = html.unescape(parts[4]) if len(parts) > 4 else ""
            location = parts[5] if len(parts) > 5 else ""
            status = parts[6] if len(parts) > 6 else ""
            
            if equip["serial"] and equip["serial"] not in serial:
                errors.append(f"N° série (attendu: {equip['serial']}, trouvé: {serial or 'vide'})")
            if equip["manufacturer"] and equip["manufacturer"].lower() not in manufacturer.lower():
                errors.append(f"Fabricant (attendu: {equip['manufacturer']}, trouvé: {manufacturer or 'vide'})")
            if equip["model"] and equip["model"].lower() not in model.lower():
                errors.append(f"Modèle (attendu: {equip['model']}, trouvé: {model or 'vide'})")
            if equip["type"] and equip["type"].lower() not in eq_type.lower():
                errors.append(f"Type (attendu: {equip['type']}, trouvé: {eq_type or 'vide'})")
            if equip["location"] and equip["location"] not in location:
                errors.append(f"Lieu (attendu: {equip['location']}, trouvé: {location or 'vide'})")
            if equip["status"] and equip["status"].lower() not in status.lower():
                errors.append(f"Statut (attendu: {equip['status']}, trouvé: {status or 'vide'})")
            
            if not errors:
                log(f"[✔] Équipement réseau complet : {name}")
                score += 1
            else:
                log(f"[⚠] Équipement réseau trouvé mais incomplet : {name}")
                for err in errors:
                    log(f"    └─ {err}")
        else:
            log(f"[✖] Équipement réseau manquant : {name}")

def check_printers():
    """Vérifie que toutes les imprimantes sont présentes avec toutes leurs données liées."""
    global score, total
    log("\n--- Vérification des IMPRIMANTES ---")
    
    for printer in EXPECTED_PRINTERS:
        total += 1
        name = printer["name"]
        errors = []
        
        query = f"""
            SELECT p.id, p.serial,
                   mf.name as manufacturer, 
                   pm.name as model,
                   pt.name as type,
                   l.name as location,
                   s.name as status
            FROM glpi_printers p
            LEFT JOIN glpi_manufacturers mf ON p.manufacturers_id = mf.id
            LEFT JOIN glpi_printermodels pm ON p.printermodels_id = pm.id
            LEFT JOIN glpi_printertypes pt ON p.printertypes_id = pt.id
            LEFT JOIN glpi_locations l ON p.locations_id = l.id
            LEFT JOIN glpi_states s ON p.states_id = s.id
            WHERE p.name = '{name}';
        """
        result = execute_sql(query)
        
        if result:
            parts = result.split("\t")
            serial = parts[1] if len(parts) > 1 else ""
            manufacturer = parts[2] if len(parts) > 2 else ""
            model = parts[3] if len(parts) > 3 else ""
            # Décoder les entités HTML (ex: &#38; -> &)
            pr_type = html.unescape(parts[4]) if len(parts) > 4 else ""
            location = parts[5] if len(parts) > 5 else ""
            status = parts[6] if len(parts) > 6 else ""
            
            if printer["serial"] and printer["serial"] not in serial:
                errors.append(f"N° série (attendu: {printer['serial']}, trouvé: {serial or 'vide'})")
            if printer["manufacturer"] and printer["manufacturer"].lower() not in manufacturer.lower():
                errors.append(f"Fabricant (attendu: {printer['manufacturer']}, trouvé: {manufacturer or 'vide'})")
            if printer["model"] and printer["model"].lower() not in model.lower():
                errors.append(f"Modèle (attendu: {printer['model']}, trouvé: {model or 'vide'})")
            if printer["type"] and printer["type"].lower() not in pr_type.lower():
                errors.append(f"Type (attendu: {printer['type']}, trouvé: {pr_type or 'vide'})")
            if printer["location"] and printer["location"] not in location:
                errors.append(f"Lieu (attendu: {printer['location']}, trouvé: {location or 'vide'})")
            if printer["status"] and printer["status"].lower() not in status.lower():
                errors.append(f"Statut (attendu: {printer['status']}, trouvé: {status or 'vide'})")
            
            if not errors:
                log(f"[✔] Imprimante complète : {name}")
                score += 1
            else:
                log(f"[⚠] Imprimante trouvée mais incomplète : {name}")
                for err in errors:
                    log(f"    └─ {err}")
        else:
            log(f"[✖] Imprimante manquante : {name}")

# =============================================
# VÉRIFICATION DES DONNÉES IMPORTÉES
# =============================================

def check_imported_computers():
    """Vérifie que 10 ordinateurs importés (choisis aléatoirement) sont présents."""
    global score, total
    log("\n--- Vérification des DONNÉES IMPORTÉES (10 aléatoires) ---")
    
    # Sélectionner 10 ordinateurs au hasard
    sample = random.sample(IMPORTED_COMPUTERS, 10)
    
    for computer in sample:
        total += 1
        query = f"SELECT id, name, serial FROM glpi_computers WHERE name = '{computer}';"
        result = execute_sql(query)
        
        if result:
            log(f"[✔] Ordinateur importé trouvé : {computer}")
            score += 1
        else:
            log(f"[✖] Ordinateur importé manquant : {computer}")

def get_import_timestamp():
    """
    Récupère la date de création du premier ordinateur importé (hors serveurs)
    pour calculer le temps écoulé depuis le début du TP.
    """
    # Chercher la date de création d'un ordinateur importé (pas les serveurs ajoutés manuellement)
    query = """SELECT MIN(date_creation) FROM glpi_computers 
               WHERE name NOT LIKE 'SRV-%' 
               AND date_creation IS NOT NULL;"""
    result = execute_sql(query)
    
    if result and result != "NULL":
        try:
            return datetime.strptime(result, "%Y-%m-%d %H:%M:%S")
        except:
            pass
    return None

# =============================================
# VÉRIFICATION DU TEMPS
# =============================================

def check_time_elapsed():
    """
    Mesure le temps écoulé depuis l'import des données.
    Temps imparti : 1h30 (90 minutes) pour avoir 20/20
    -1 point par tranche de 22.5 minutes (1/4 de 90 min) au-delà
    """
    global score, total
    log("\n--- Vérification du TEMPS ---")
    total += 7  # Ce test vaut 7 points

    # Récupérer le timestamp du premier élément manuel créé
    # On prend la date de création d'un lieu ou d'une imprimante (saisie manuelle)
    query = """SELECT MIN(date_creation) FROM (
                   SELECT date_creation FROM glpi_locations WHERE date_creation IS NOT NULL
                   UNION ALL
                   SELECT date_creation FROM glpi_printers WHERE date_creation IS NOT NULL
                   UNION ALL
                   SELECT date_creation FROM glpi_monitors WHERE date_creation IS NOT NULL
               ) AS combined;"""
    result = execute_sql(query)
    
    if not result or result == "NULL":
        log("[⚠] Impossible de déterminer la date de début du TP")
        return

    try:
        start_time = datetime.strptime(result, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        elapsed = now - start_time
        elapsed_seconds = elapsed.total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        # Temps imparti : 90 minutes
        temps_imparti = 90 * 60  # en secondes
        
        if elapsed_seconds <= temps_imparti:
            points = 7
        else:
            extra = elapsed_seconds - temps_imparti
            quarter = temps_imparti / 4  # 22.5 minutes
            points = 7 - int(extra // quarter)
            if points < 0:
                points = 0

        log(f"[ℹ] Début du TP détecté : {start_time}")
        log(f"[ℹ] Heure actuelle : {now}")
        log(f"[ℹ] Temps écoulé : {int(elapsed_minutes)} minutes")
        log(f"[ℹ] Temps imparti : 90 minutes")
        log(f"[ℹ] Score temps attribué : {points}/7")
        score += points

    except Exception as e:
        log(f"[✖] Erreur lors du calcul du temps : {e}")

# =============================================
# FONCTION PRINCIPALE
# =============================================

def main():
    """Point d'entrée principal du script."""
    global score, total
    
    # Demander les informations de l'étudiant
    print("\n" + "=" * 60)
    print("   VÉRIFICATION DES DONNÉES GLPI - BTS SIO SISR")
    print("=" * 60)
    
    nom = input("\nEntrez votre nom : ")
    prenom = input("Entrez votre prénom : ")
    
    print("\n" + "=" * 60)
    print("   LANCEMENT DES VÉRIFICATIONS")
    print("=" * 60)

    # Vérifications de base
    log("\n--- Vérification de l'INSTALLATION GLPI ---")
    if not check_glpi_installed():
        log("[✖] GLPI non installé correctement - Arrêt des vérifications")
    else:
        if check_database_exists():
            # Vérifications des données manuelles
            check_locations()
            check_servers()
            check_monitors()
            check_network_equipments()
            check_printers()
            
            # Vérification des données importées
            check_imported_computers()
            
            # Vérification du temps
            check_time_elapsed()

    # Calcul de la note finale
    score_sur_20 = round((score / total) * 20, 2) if total > 0 else 0
    
    # Résumé
    log_messages.append("\n" + "=" * 60)
    log_messages.append("   RÉSUMÉ DES TESTS")
    log_messages.append("=" * 60)
    log_messages.append(f"Candidat : {prenom} {nom}")
    log_messages.append(f"Score brut : {score}/{total}")
    log_messages.append(f"Note finale : {score_sur_20}/20")
    
    if score_sur_20 >= 18:
        log_messages.append("\n🏆 EXCELLENT ! Toutes les données sont correctement configurées.")
    elif score_sur_20 >= 14:
        log_messages.append("\n✅ Bon travail ! Quelques ajustements mineurs nécessaires.")
    elif score_sur_20 >= 10:
        log_messages.append("\n⚠️ Passable. Des éléments importants sont manquants.")
    else:
        log_messages.append("\n❌ Insuffisant. Vérifiez votre configuration.")

    # Afficher tous les logs
    print("\n".join(log_messages))
    
    # Envoyer les résultats (optionnel)
    envoyer_donnees(nom, prenom, "\n".join(log_messages), score_sur_20)

def envoyer_donnees(nom, prenom, commentaires, note):
    """Envoie les résultats du test au serveur externe."""
    # Nommage : underscore entre mots activité, tiret entre activité/nom/prénom
    # Remplacer les espaces dans nom/prénom par des tirets
    nom_clean = nom.strip().replace(" ", "-")
    prenom_clean = prenom.strip().replace(" ", "-")
    filename = f"GLPI_DATA-{nom_clean}-{prenom_clean}.json"
    url = f"http://www.ericm.fr/logsapi/logreceiver.php?filename={filename}"
    
    headers = {"Content-Type": "application/json"}
    data = {
        "nom": nom,
        "prenom": prenom,
        "commentaires": commentaires,
        "note": note
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            print(f"\n✅ Résultats envoyés avec succès sous {filename}")
        else:
            print(f"\n⚠️ Échec de l'envoi. Code HTTP : {response.status_code}")
    except Exception as e:
        print(f"\n⚠️ Erreur lors de l'envoi (non bloquant) : {e}")


if __name__ == "__main__":
    main()
