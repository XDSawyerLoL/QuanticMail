# Quantic Mail — édition Windows locale

L'application n'utilise **aucun site Hostinger pour afficher Quantic Mail**.

## Architecture
- Fenêtre native Electron.
- Interface Quantic Mail exportée et embarquée dans l'installateur.
- Serveur local HTTP sur `127.0.0.1:18787`, non exposé au réseau.
- Relais Quantic autonome sur `127.0.0.1:18788` avec état dans le profil Windows.
- Messages, contacts et clés privées conservés dans le profil local IndexedDB.
- Identity Vault accessible dans l'application. Importer le coffre `.quantic-vault` ou associer l'appareil comme appareil secondaire : l'identité stockée dans le navigateur web n'est PAS copiée implicitement.

## Installation
Dans le dépôt GitHub, ouvrez **Actions > QuanticMail - installateur Windows local** puis téléchargez l'artefact `quanticmail-windows-local` d'une exécution réussie. Extraire le ZIP et lancer `QuanticMail-Setup-1.3.1.exe`.

## Compilation Windows
Sur Windows x64 avec Node.js 22 :

```powershell
npm install
npm run desktop:dist
```

Le fichier final est dans `desktop-dist/`.

## Réseau réel, sans Hostinger
L'interface et le relais fonctionnent entièrement sur le poste. Le fonctionnement du courrier entre plusieurs machines dépend de la capacité de joindre un autre relais Quantic. Le relais local est limité volontairement à 127.0.0.1 (pas d'ouverture de port automatique).

- Sans relais partagé accessible ni connexion P2P, deux PC derrière deux box Internet ne peuvent pas se découvrir ni échanger automatiquement.
- Pour une fédération réellement indépendante, configurer des pairs Quantic accessibles (idéalement HTTPS avec TLS) et l'amorçage réseau correspondant.
- La configuration actuelle de la Web App conserve un relais public Render de secours. Cette édition Windows ne passe pas par Hostinger, mais un relais Render peut être contacté si les réglages réseau utilisateurs le permettent. Ce n'est pas une promesse de P2P sans infrastructure.
- Une messagerie complètement hors ligne ne peut pas transmettre de courriers à distance ; le réseau est requis pour les échanges, pas pour l'interface embarquée.

## Sécurité et limites
Version alpha, non auditée. L'installateur généré automatiquement est **non signé** et peut déclencher SmartScreen. Pas de migration silencieuse du profil navigateur ni des clés privées. Les ports locaux sont fixes pour conserver le même stockage de profil entre les lancements.
