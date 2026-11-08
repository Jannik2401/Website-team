# Team Hub – Phase 1

Interne Team-Management-Plattform (Node.js + Express + SQLite). Selbst gehostet, keine externen Dienste, keine Tracker, keine Fremd-Schriften (DSGVO-freundlich).

## Start
```
npm install
npm start
```
Beim ersten Start wird der Superadmin angelegt. Benutzername und temporäres Passwort stehen **einmalig in der Konsole**. Beim ersten Login muss das Passwort geändert werden.

Aufruf: http://127.0.0.1:3000

## Betrieb (Produktion)
- Hinter einen Reverse-Proxy mit HTTPS stellen (nginx, Caddy) und starten mit
  `NODE_ENV=production TRUST_PROXY=1 npm start`
- Umgebungsvariablen: `PORT` (3000), `HOST` (127.0.0.1), `DATA_DIR` (./data)
- Daten: `data/teamhub.db`. Tägliche Backups (14 Stück) liegen in `data/backups/`. Zusätzlich das Verzeichnis extern sichern.

## Enthalten in Phase 1
- Login mit bcrypt-Hashing, serverseitigen Sitzungen (HttpOnly/SameSite-Cookie), Login-Drosselung, Passwortwechsel beim ersten Login
- Rollen: Superadmin, Administrator, Teamleitung, Teammitglied – Rechteprüfung auf dem Server
- Benutzerverwaltung: anlegen, sperren, entsperren, löschen, Rolle ändern, Passwort zurücksetzen
- Aufgaben: zuweisen, Priorität, Fälligkeit, Status, Fortschritt, Kommentare
- Dashboard, Teamübersicht, Benachrichtigungen, Aktivitätsprotokoll, Hell-/Dunkelmodus, responsive Seitenleiste

## Rechte
- Superadmin: alles; legt Administratoren an, ändert Rollen
- Administrator: verwaltet Teamleitungen und Teammitglieder, sieht alle Aufgaben und das Protokoll
- Teamleitung: weist Aufgaben anderen zu
- Teammitglied: sieht eigene bzw. selbst erstellte Aufgaben

## Geplante Phasen
2. Strafpunkte, Abwesenheiten, Ankündigungen (mit Bestätigung)
3. Kalender (inkl. Abwesenheiten), Support-System, Kummerkasten (anonym)
4. Teamchat, Dokumentenverwaltung (Versionen, Ordnerrechte)
5. Umfragen, Wissensdatenbank, Geburtstage/Jubiläen

## Erweitern
Neue Funktion = neue Tabellen in `db.js`, neue Routen in `server.js` (Muster: `api.get('/x', auth, need(rang), …)`), neue View-Funktion in `public/app.js` und Eintrag in `NAV` und `routes`.
