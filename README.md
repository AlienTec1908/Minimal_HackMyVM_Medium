# Minimal - HackMyVM (Medium)

![Minimal.png](Minimal.png)

## Übersicht

*   **VM:** Minimal
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Minimal)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 23. November 2023
*   **Original-Writeup:** https://alientec1908.github.io/Minimal_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Minimal" zu erlangen. Der Weg dorthin umfasste mehrere Schritte: Zuerst wurde eine Local File Inclusion (LFI)-Schwachstelle auf der Webseite entdeckt, die das Auslesen des Quellcodes von `admin.php` ermöglichte. Anschließend wurde eine Schwachstelle im Passwort-Reset-Mechanismus (`reset_pass.php`) ausgenutzt, um das Passwort des `admin`-Benutzers zu ändern. Mit Admin-Zugriff konnte eine PHP-Reverse-Shell über eine unsichere Dateiupload-Funktion hochgeladen werden, was zu initialem Zugriff als `www-data` führte. Die finale Rechteausweitung zu Root gelang durch Ausnutzung einer Buffer-Overflow-Schwachstelle in einem benutzerdefinierten Programm (`/opt/quiz/shop`), das `www-data` mittels `sudo` als Root ausführen durfte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `gobuster`
*   Burp Suite (impliziert)
*   `nikto`
*   `sqlmap` (versucht, nicht erfolgreich)
*   `curl`
*   `base64`
*   CyberChef (impliziert für Base64-Dekodierung)
*   Bash Scripting
*   `md5sum`
*   `grep`
*   `nc` (netcat)
*   Python3
*   `pwn` (Python-Bibliothek)
*   `sudo`
*   `mysql`
*   Standard Linux-Befehle (`ls`, `cat`, `find`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Minimal" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.111) mit `arp-scan` identifiziert. Hostname `minimal.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.9p1) und Port 80 (HTTP, Apache 2.4.52) mit dem Titel "Minimal Shop". Das `HttpOnly`-Flag für `PHPSESSID` war nicht gesetzt.
    *   `gobuster` fand diverse PHP-Dateien (`index.php`, `login.php`, `admin.php`, `config.php` (leer), `reset_pass.php`, `shop_cart.php`, etc.).
    *   `sqlmap`-Versuche auf `login.php` scheiterten.
    *   Eine Local File Inclusion (LFI)-Schwachstelle wurde in `shop_cart.php` im Parameter `action` gefunden. Mittels `php://filter/read=convert.base64-encode/resource=admin.php` wurde der Quellcode von `admin.php` ausgelesen.

2.  **Password Reset Exploit & Admin Access:**
    *   Die Untersuchung der Passwort-Reset-Funktionalität (`reset_pass.php`) ergab, dass der Reset-Token für den `admin`-Benutzer durch Base64-Kodierung eines MD5-Hashes von "admin" + einer Zahl (1-100) generiert wurde.
    *   Ein Bash-Skript wurde verwendet, um gültige Tokens zu bruteforcen und das Passwort des `admin`-Benutzers auf `patata` zu setzen.
    *   Erfolgreicher Login in `/admin.php` mit den Credentials `admin:patata`.

3.  **Initial Access (RCE via File Upload als `www-data`):**
    *   Das Admin-Panel (`/admin.php`) erlaubte das Hochladen von Produktbildern.
    *   Eine PHP-Reverse-Shell (`rev.php`) wurde präpariert und über das Admin-Panel in das Verzeichnis `/imgs/` hochgeladen.
    *   Durch Aufrufen von `http://minimal.hmv/imgs/rev.php` wurde eine Reverse Shell zu einem Netcat-Listener als Benutzer `www-data` aufgebaut.
    *   Die User-Flag (`HMV{can_you_find_the_teddy_bear?}`) wurde in `/home/white/user.txt` gefunden (Zugriff als `www-data` möglich aufgrund unsicherer Home-Verzeichnis-Berechtigungen).

4.  **Privilege Escalation (von `www-data` zu `root` via Buffer Overflow):**
    *   `sudo -l` als `www-data` zeigte, dass das Programm `/opt/quiz/shop` als `root` ohne Passwort ausgeführt werden durfte: `(root) NOPASSWD: /opt/quiz/shop`.
    *   Das Programm `/opt/quiz/shop` wurde als anfällig für einen Buffer Overflow identifiziert.
    *   Ein Python-Exploit-Skript (`hacker.py`) wurde unter Verwendung der `pwn`-Bibliothek erstellt. Der Payload nutzte ein `pop rdi; ret` Gadget, die Adresse von `/bin/sh` und die Adresse von `system()`, um eine Shell zu starten.
    *   Auf dem Zielsystem wurde `nc -lvnp 8000 | sudo /opt/quiz/shop` gestartet, um Eingaben von Netcat an das `shop`-Programm (ausgeführt als Root) weiterzuleiten.
    *   Das Python-Exploit-Skript wurde vom Angreifer-System ausgeführt und sendete den präparierten Payload an den Netcat-Listener auf dem Ziel.
    *   Der Buffer Overflow wurde erfolgreich ausgelöst, was zu einer Root-Shell führte.
    *   Die Root-Flag (`HMV{never_gonna_RP_you_down}`) wurde in `/root/root.txt` gefunden.

5.  **Database Exploration (optional):**
    *   Als `www-data` konnte der Inhalt von `/var/www/html/config.php` gelesen werden, der Datenbank-Credentials (`shop_admin:Hey-Pls-Dont-Crack-This-Passwd`) für die MySQL-Datenbank `shop` enthielt.
    *   In der Datenbank wurden bcrypt-Hashes für `admin` und `ben` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Local File Inclusion (LFI):** Die Datei `shop_cart.php` war anfällig für LFI über den `action`-Parameter, was das Auslesen von Quellcode ermöglichte.
*   **Schwacher Passwort-Reset-Mechanismus:** Vorhersagbare Reset-Tokens (Base64(MD5(Username + Zahl))) ermöglichten die Übernahme des Admin-Kontos.
*   **Unsicherer Dateiupload:** Das Admin-Panel erlaubte das Hochladen von PHP-Dateien, was zu Remote Code Execution (RCE) führte.
*   **Unsichere `sudo`-Regel:** `www-data` durfte ein benutzerdefiniertes Programm (`/opt/quiz/shop`) als Root ausführen.
*   **Buffer Overflow:** Das mit `sudo`-Rechten ausführbare Programm `/opt/quiz/shop` war anfällig für einen Buffer Overflow, der zur Privilegieneskalation zu Root genutzt wurde.
*   **Informationslecks:** Datenbank-Credentials in `config.php`, unsichere Home-Verzeichnis-Berechtigungen.

## Flags

*   **User Flag (`/home/white/user.txt`):** `HMV{can_you_find_the_teddy_bear?}`
*   **Root Flag (`/root/root.txt`):** `HMV{never_gonna_RP_you_down}`

## Tags

`HackMyVM`, `Minimal`, `Medium`, `LFI`, `Password Reset Exploit`, `File Upload RCE`, `sudo Exploit`, `Buffer Overflow`, `pwn`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `MySQL`
