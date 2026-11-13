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
Dans le dépôt GitHub, ouvrez **Actions > QuanticMail - installateur Windows local** puis téléchargez l'artefact `quanticmail-windows-local` d'une exécution réussie. Utiliser le fichier `QuanticMail-Setup-1.3.6.exe` publié directement dans les **Releases** GitHub (aucun ZIP nécessaire).

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

## Première connexion sans mot de passe

1. Dans Windows, ouvrir **Retrouver ma boîte existante** puis indiquer l'adresse canonique figurant sur le site Quantic Mail originel (rubrique **Appareils**).
2. Télécharger le fichier `.quantic-device-request` créé sur ce PC : il ne contient pas la clé privée du compte maître.
3. Dans le navigateur original où l'identité fonctionne déjà, ouvrir **Appareils > Pairing par fichiers** et sélectionner la demande. L'appareil maître signe le certificat.
4. Dans Windows, importer le fichier `.quantic-device-cert`. La nouvelle installation utilise des clés d'appareil différentes, autorisées par une signature du compte maître.

Ce parcours ne requiert pas de mot de passe. Il ne synchronise pas automatiquement l'historique ni les relais distants. Si l'identité est reconnue mais les messages du correspondant n'arrivent pas, contrôler la connectivité réseau séparément.


## Quantic ID réellement reconnu dans Windows (v1.3.6)

- Identity Vault est un programme distinct de QuanticMail. Il expose son état sur `http://127.0.0.1:47621/v1/status` et signe une preuve à la demande sur `/v1/assert`.
- L'application Windows vérifie cryptographiquement la preuve locale (Ed25519 ou P-256 QHK/1), sans mots de passe ni copie de clés privées, avant d'afficher la boîte.
- Une identité Quantic ID `qid_...` n'est **pas** une identité cryptographique de messagerie `nom~empreinte@quantic`. Une session Quantic ID déverrouillée ne reconstitue pas à elle seule une boîte chiffrée existante dans un autre profil navigateur.
- Si la boîte existe uniquement dans un autre navigateur, l'écran dit « Quantic ID reconnu. Ta boîte reste à relier » et propose l'association par demande/certificat signé. Une autorisation par l'ancien appareil reste nécessaire ; l'ancien navigateur doit être conservé jusqu'à la liaison.
- Si le Quantic ID est verrouillé/absent, un message explicite s'affiche au lieu d'une demande de mot de passe de coffre.


## Compte unique Quantic ID (v1.3.6)

L'identité personnelle Quantic ID (`qid_...`) est le **seul compte de connexion** du logiciel Windows. Les clés d'appareil de messagerie restent distinctes des clés de signature d'Identity Vault : c'est une séparation cryptographique, pas un second compte utilisateur.

- Après preuve cryptographique locale et installation des clés de mail, l'application propose une **association explicite une seule fois** entre le `qid_...` vérifié et l'identité `@quantic` locale.
- L'association est enregistrée dans la base locale et vérifiée lors de chaque ouverture, y compris sur les pages Appareils et Identity Vault. Un autre Quantic ID déverrouillé ne donne pas accès à la boîte associée au premier.
- Une nouvelle boîte créée volontairement depuis Windows, pour un Quantic ID qui n'a **aucune** boîte existante, est immédiatement associée au QID vérifié. Cela ne transforme pas ni ne remplace une boîte web existante.
- Une boîte préexistante dans le navigateur possède des clés privées chiffrantes **qu'Identity Vault ne contient pas**. Sans elles, il est impossible de déchiffrer les messages historiques. L'association avec le Quantic ID ne peut pas fabriquer ces clés : la liaison signée par l'ancien appareil reste indispensable pour migrer sans perte.
- Le coffre `.quantic-vault` chiffré avec mot de passe reste une **sauvegarde facultative**, jamais un mot de passe de connexion Quantic ID.
- Limite actuelle : cette association du compte QID au stockage local ne constitue pas encore un annuaire mondial de boîtes piloté par QID ni une migration transparente des clés depuis d'autres navigateurs. L'authentification centrale par QID sur les relais distants et une liaison directe navigateur → Windows devront être traitées séparément.

## Correction envoi / authentification appareil (v1.3.6)

- Symptôme : « Authentification de l'appareil Quantic invalide » lors de l'envoi, malgré Quantic ID déverrouillé.
- Cause corrigée : les anciennes versions pouvaient enregistrer la racine côté relais en `d-<10 hex>` alors que le navigateur et le manifeste signé utilisaient `d-<32 hex>`. Le relais refusait ensuite le jeton d'appareil présenté avec l'identifiant différent.
- L'enregistrement de la racine envoie maintenant son `deviceId` local exact. Le relais embarqué migre de façon compatible les files d'attente et reçus de l'ancien ID vers le nouveau, avec les mêmes clés et le même jeton ; aucune restauration, recréation de boîte ou suppression de messages n'est requise.
- L'envoi vérifie la réponse de l'enregistrement **avant** de récupérer une préclé et de transmettre le message. En cas de non-acceptation par tous les relais, la fenêtre d'envoi et le contenu du brouillon restent affichés ; le message chiffré est gardé dans la file locale.
- Le test d'installation `scripts/smoke-desktop.mjs` démarre un vrai relais de test, reproduit le rejet d'appareil en ancien format, réenregistre en 32 caractères, vérifie un envoi HTTP 202 et une relève HTTP 200 ; aucune clé ni donnée utilisateur n'est utilisée.
- Ne pas confondre acceptation **locale** par un relais avec livraison au correspondant via Internet : la fédération et la découverte de la boîte distante restent à vérifier séparément. Ne jamais promettre une livraison distante sur la seule base d'un HTTP 202 local.
