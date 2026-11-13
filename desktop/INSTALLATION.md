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
Dans le dépôt GitHub, ouvrez **Actions > QuanticMail - installateur Windows local** puis téléchargez l'artefact `quanticmail-windows-local` d'une exécution réussie. Utiliser le fichier `QuanticMail-Setup-1.3.8.exe` publié directement dans les **Releases** GitHub (aucun ZIP nécessaire).

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


## Quantic ID réellement reconnu dans Windows (v1.3.8)

- Identity Vault est un programme distinct de QuanticMail. Il expose son état sur `http://127.0.0.1:47621/v1/status` et signe une preuve à la demande sur `/v1/assert`.
- L'application Windows vérifie cryptographiquement la preuve locale (Ed25519 ou P-256 QHK/1), sans mots de passe ni copie de clés privées, avant d'afficher la boîte.
- Une identité Quantic ID `qid_...` n'est **pas** une identité cryptographique de messagerie `nom~empreinte@quantic`. Une session Quantic ID déverrouillée ne reconstitue pas à elle seule une boîte chiffrée existante dans un autre profil navigateur.
- Si la boîte existe uniquement dans un autre navigateur, l'écran dit « Quantic ID reconnu. Ta boîte reste à relier » et propose l'association par demande/certificat signé. Une autorisation par l'ancien appareil reste nécessaire ; l'ancien navigateur doit être conservé jusqu'à la liaison.
- Si le Quantic ID est verrouillé/absent, un message explicite s'affiche au lieu d'une demande de mot de passe de coffre.


## Compte unique Quantic ID (v1.3.8)

L'identité personnelle Quantic ID (`qid_...`) est le **seul compte de connexion** du logiciel Windows. Les clés d'appareil de messagerie restent distinctes des clés de signature d'Identity Vault : c'est une séparation cryptographique, pas un second compte utilisateur.

- Après preuve cryptographique locale et installation des clés de mail, l'application propose une **association explicite une seule fois** entre le `qid_...` vérifié et l'identité `@quantic` locale.
- L'association est enregistrée dans la base locale et vérifiée lors de chaque ouverture, y compris sur les pages Appareils et Identity Vault. Un autre Quantic ID déverrouillé ne donne pas accès à la boîte associée au premier.
- Une nouvelle boîte créée volontairement depuis Windows, pour un Quantic ID qui n'a **aucune** boîte existante, est immédiatement associée au QID vérifié. Cela ne transforme pas ni ne remplace une boîte web existante.
- Une boîte préexistante dans le navigateur possède des clés privées chiffrantes **qu'Identity Vault ne contient pas**. Sans elles, il est impossible de déchiffrer les messages historiques. L'association avec le Quantic ID ne peut pas fabriquer ces clés : la liaison signée par l'ancien appareil reste indispensable pour migrer sans perte.
- Le coffre `.quantic-vault` chiffré avec mot de passe reste une **sauvegarde facultative**, jamais un mot de passe de connexion Quantic ID.
- Limite actuelle : cette association du compte QID au stockage local ne constitue pas encore un annuaire mondial de boîtes piloté par QID ni une migration transparente des clés depuis d'autres navigateurs. L'authentification centrale par QID sur les relais distants et une liaison directe navigateur → Windows devront être traitées séparément.

## Correction envoi / authentification appareil (v1.3.8)

- Symptôme : « Authentification de l'appareil Quantic invalide » lors de l'envoi, malgré Quantic ID déverrouillé.
- Cause corrigée : les anciennes versions pouvaient enregistrer la racine côté relais en `d-<10 hex>` alors que le navigateur et le manifeste signé utilisaient `d-<32 hex>`. Le relais refusait ensuite le jeton d'appareil présenté avec l'identifiant différent.
- L'enregistrement de la racine envoie maintenant son `deviceId` local exact. Le relais embarqué migre de façon compatible les files d'attente et reçus de l'ancien ID vers le nouveau, avec les mêmes clés et le même jeton ; aucune restauration, recréation de boîte ou suppression de messages n'est requise.
- L'envoi vérifie la réponse de l'enregistrement **avant** de récupérer une préclé et de transmettre le message. En cas de non-acceptation par tous les relais, la fenêtre d'envoi et le contenu du brouillon restent affichés ; le message chiffré est gardé dans la file locale.
- Le test d'installation `scripts/smoke-desktop.mjs` démarre un vrai relais de test, reproduit le rejet d'appareil en ancien format, réenregistre en 32 caractères, vérifie un envoi HTTP 202 et une relève HTTP 200 ; aucune clé ni donnée utilisateur n'est utilisée.
- Ne pas confondre acceptation **locale** par un relais avec livraison au correspondant via Internet : la fédération et la découverte de la boîte distante restent à vérifier séparément. Ne jamais promettre une livraison distante sur la seule base d'un HTTP 202 local.

## Correctif « Synchronisation de sécurité bloquée – 403 » (v1.3.8)

- Quantic ID affiché « actif » signifie que le coffre local est authentifié. Cela ne prouve pas qu'un autre relais possède déjà le manifeste de sécurité signé de cette boîte.
- Ancien défaut : l'interface tentait `GET /api/quantic/manifest` en local. Sur 404 local (aucun manifeste pour le nouveau relais), elle essayait ensuite le relais Render. Le 403 de ce service externe apparaissait comme un blocage de toute la synchronisation de sécurité Windows.
- Nouveau comportement : en application Windows, **seul le relais embarqué `127.0.0.1:18787/api/quantic/manifest`** sert d'autorité de synchronisation du manifeste local. 404 local signifie « manifeste absent » et permet d'y publier une copie **déjà signée et vérifiée**. Aucun 403/404 local n'entraîne de repli vers Render ou Hostinger.
- Une erreur 401 ou 403 venant **réellement du relais local** reste bloquante, avec un message distinguant sa source ; l'application ne désactive jamais la vérification cryptographique.
- Tests : sélection unique du relais embarqué, absence de fallback externe après 404, échec fermé après 403, manifeste signé publié et lu en 200, fausse signature refusée en 401. Le test utilise un relais temporaire avec des clés jetables, jamais les données de l'utilisateur.
- Limite : la synchronisation d'un manifeste dans le relais local n'assure pas la communication avec un correspondant hébergé sur un relais distant. Le réseau inter-relais reste un sujet indépendant.


## Correction 403 après migration vers le relais local (v1.3.8)

Le code de la passerelle HTTP Windows pouvait renvoyer **HTTP 403 avec réponse vide** avant même que le relais local ne traite une requête de manifeste. L'interface affichait alors par erreur « relais local refuse le manifeste signé » ; une erreur cryptographique du manifeste n'était pas démontrée.

- Reconnait explicitement les deux noms de boucle locale `127.0.0.1:18787` et `localhost:18787` tout en exigeant un port exact et une origine HTTP égale au nom d'hôte de la requête.
- Garde refusées les origines distantes, hôtes non autorisés, erreurs de port et demandes cross-site ; l'application reste liée uniquement à `127.0.0.1`.
- Le 403 du filtre de passerelle renvoie désormais un JSON avec un motif stable (`LOCAL_GATEWAY_HOST`, `LOCAL_GATEWAY_ORIGIN` ou `LOCAL_GATEWAY_CROSSSITE`) et un en-tête `x-quantic-local-guard`. Aucun mot de passe, jeton ni contenu de coffre n'est journalisé.
- Le formulaire de synchronisation distingue dorénavant le filtrage HTTP du serveur local et le refus réel de signature par le relais ; aucun contournement de vérification cryptographique n'est introduit.
- Tests de sécurité : accès HTTP au relais avec les en-têtes `Origin` et `Sec-Fetch-Site` de Chromium pour GET et POST manifeste, rejet d'une origine externe (403 JSON), rejet de requêtes cross-site et contrôle de normalisation de `localhost`.

En cas de refus après installation, **copier le nouveau message complet** : son motif permet de localiser la règle bloquante. Ne pas supprimer le répertoire de données Quantic Mail ; ne pas créer une nouvelle boîte.
