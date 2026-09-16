# Quantic Relay autonome et durable — Design

Date : 2026-09-16
Statut : design approuvé en conversation, en attente de revue de la spec écrite
Base : `feat/quantic-network-v1-multirelay`

## Objectif

Créer un programme `quantic-relay` autonome, exécutable sans Next.js et sans Render, qui implémente Quantic Relay Protocol V1 et conserve durablement les identités publiques, appareils autorisés, enveloppes chiffrées et accusés de livraison entre les redémarrages.

Le relais reste un transporteur. Il ne devient jamais propriétaire de l’identité Quantic et ne reçoit ni clés privées, ni mot de passe d’Identity Vault, ni contenu de message en clair.

## Critère de réussite principal

Le scénario suivant doit fonctionner de bout en bout :

1. démarrer `quantic-relay` sur un répertoire de données temporaire ;
2. enregistrer Alice et Bob selon le protocole cryptographique existant ;
3. envoyer une enveloppe chiffrée d’Alice vers un appareil de Bob ;
4. arrêter complètement le processus du relais ;
5. redémarrer le relais sur le même répertoire de données ;
6. Bob récupère la même enveloppe ;
7. Bob l’accuse ;
8. après un nouveau redémarrage, l’enveloppe n’est plus proposée et l’accusé reste disponible pour Alice jusqu’à son acknowledgement.

Ce test est la preuve que Render n’est plus nécessaire à la durabilité d’un relais Quantic.

## Portée de cette tranche

Cette tranche inclut :

- serveur HTTP Node.js autonome ;
- compatibilité exacte avec les routes Quantic Relay Protocol V1 actuelles ;
- stockage durable local sur disque ;
- écriture atomique de l’état avant réponse de succès aux mutations ;
- configuration par variables d’environnement et arguments simples ;
- CORS compatible avec les clients QuanticMail distants ;
- arrêt propre ;
- tests unitaires de sérialisation et tests d’intégration restart/recovery ;
- documentation d’exécution locale et d’auto-hébergement.

Cette tranche n’inclut pas :

- réplication automatique entre plusieurs relais ;
- consensus ou base distribuée ;
- découverte signée des endpoints d’une identité ;
- transport direct appareil-à-appareil ;
- chiffrement additionnel du fichier d’état côté serveur ;
- interface d’administration web.

Ces fonctions restent des étapes ultérieures de Quantic Network V1.

## Architecture retenue

### 1. Réutiliser le moteur cryptographique existant

Le comportement fonctionnel reste défini par `lib/quantic/relay.ts` :

- validation des locators et fingerprints ;
- preuve de possession ;
- enregistrement d’identité ;
- certificats d’appareils ;
- authentification par token d’appareil ;
- résolution d’identité ;
- files d’enveloppes ;
- accusés ;
- TTL et rate limiting.

Le serveur autonome ne réimplémente pas cette logique. Il appelle le même moteur afin d’éviter deux protocoles divergents.

### 2. Ajouter une frontière de persistance minimale

Pour éviter un refactor prématuré de tout le moteur, `lib/quantic/relay.ts` exposera une représentation sérialisable contrôlée de son état ainsi que deux opérations :

- export de l’état persistant ;
- restauration d’un état validé au démarrage.

La représentation persistée couvre :

- `identities` ;
- `aliases` ;
- `challenges` ;
- `devices` ;
- `queues` ;
- `receipts` ;
- `sendWindows` si encore pertinents lors de la restauration.

Les `Map` et `Set` internes ne sont jamais écrits directement par sérialisation implicite. Une structure JSON versionnée est produite explicitement afin de pouvoir faire évoluer le format.

Format initial :

```json
{
  "format": "quantic-relay-state",
  "version": 1,
  "savedAt": "2026-09-16T00:00:00.000Z",
  "identities": [],
  "aliases": [],
  "challenges": [],
  "devices": [],
  "queues": [],
  "receipts": [],
  "sendWindows": []
}
```

Au chargement, les éléments expirés sont nettoyés selon les TTL déjà appliqués par le moteur.

### 3. Stockage JSON atomique

Le module de stockage du relais autonome utilise un seul fichier d’état par défaut :

`./data/relay-state.json`

Une mutation suit cette séquence :

1. appliquer la mutation au moteur ;
2. produire le snapshot versionné ;
3. créer le répertoire de données si nécessaire ;
4. écrire le snapshot dans un fichier temporaire situé dans le même répertoire ;
5. synchroniser et fermer le fichier ;
6. renommer atomiquement le fichier temporaire vers `relay-state.json` ;
7. seulement ensuite envoyer la réponse HTTP de succès.

Le fichier est créé avec des permissions restrictives quand la plateforme le permet.

Ce choix privilégie la simplicité et la vérifiabilité pour V1. SQLite pourra remplacer ce backend plus tard derrière une abstraction de stockage si le volume ou la concurrence l’exigent.

### 4. Serveur HTTP autonome

Un nouveau dossier `standalone-relay/` contient le point d’entrée serveur et l’adaptateur HTTP.

Le serveur utilise les API Node.js intégrées afin d’éviter d’ajouter une dépendance de framework serveur uniquement pour cette tranche.

Routes exposées :

- `GET /api/quantic/health`
- `POST /api/quantic/challenge`
- `POST /api/quantic/register`
- `GET /api/quantic/resolve`
- `POST /api/quantic/devices/register`
- `POST /api/quantic/send`
- `GET /api/quantic/pull`
- `POST /api/quantic/ack`
- `GET /api/quantic/receipts`
- `POST /api/quantic/receipts`
- `OPTIONS /api/quantic/*`

Les schémas JSON, paramètres, headers et statuts doivent rester compatibles avec les routes Next.js existantes.

### 5. Configuration

Valeurs par défaut sûres :

- host : `127.0.0.1`
- port : `8787`
- data dir : `./data`

Variables :

- `QUANTIC_RELAY_HOST`
- `QUANTIC_RELAY_PORT`
- `QUANTIC_RELAY_DATA_DIR`

Le bind sur `0.0.0.0` est volontairement explicite pour l’usage LAN/VPS. Pour une exposition Internet, le protocole exige HTTPS ; le relais peut être placé derrière Caddy, Nginx, Traefik ou tout reverse proxy TLS standard.

### 6. CORS et sécurité HTTP

Le serveur autorise les clients web Quantic sur les routes du protocole avec :

- `GET`, `POST`, `OPTIONS` ;
- `Content-Type`, `Authorization` ;
- pas de cookies ni credentials cross-origin nécessaires.

Le serveur impose une taille maximale de corps JSON cohérente avec la limite actuelle des enveloppes et rejette les contenus hors JSON sur les routes qui l’exigent.

Les erreurs `RelayError` conservent leurs codes HTTP actuels. Les erreurs internes non prévues renvoient `500` sans fuite de stack trace au client.

### 7. Démarrage et arrêt

Au démarrage :

1. lire `relay-state.json` s’il existe ;
2. vérifier le format et la version ;
3. restaurer l’état ;
4. purger les données expirées ;
5. écouter sur host/port configurés.

Si le fichier est absent, le relais démarre vide.

Si le fichier est corrompu ou d’une version inconnue, le relais refuse de démarrer plutôt que d’écraser silencieusement les données existantes.

Sur `SIGINT`/`SIGTERM`, le serveur cesse d’accepter de nouvelles connexions, persiste un dernier snapshot puis termine.

## Compatibilité avec QuanticMail

Le client de la PR #13 peut ajouter directement le relais :

- local : `http://localhost:8787`
- distant : `https://relay.example.org`

Aucune migration de l’adresse Quantic n’est nécessaire. L’adresse canonique reste liée à la clé publique de signature de l’utilisateur et non au relais.

Le relais autonome doit répondre au health check avec :

```json
{
  "ok": true,
  "protocol": "quantic-relay/1",
  "service": "Quantic Network Relay"
}
```

## Tests

### Tests unitaires

- snapshot d’un état vide ;
- round-trip snapshot → restauration ;
- conservation des `Map`/`Set` et objets JWK ;
- rejet d’un format inconnu ;
- rejet d’un JSON invalide ;
- purge des challenges/messages/reçus expirés ;
- écriture atomique sans fichier final partiel ;
- conservation du dernier fichier valide si une écriture temporaire échoue.

### Tests HTTP

- health V1 ;
- CORS preflight ;
- erreurs de méthode ;
- erreurs JSON ;
- propagation correcte des `RelayError` ;
- limite de taille du body.

### Test d’intégration de durabilité

Un test démarre réellement le serveur sur un port libre et un dossier temporaire, effectue le scénario Alice → Bob, arrête le serveur, le redémarre puis vérifie la récupération et les accusés.

Le test doit exercer le protocole HTTP et le stockage disque, pas seulement appeler des fonctions internes.

## Scripts prévus

Le `package.json` racine recevra au minimum :

- `relay:start` — lancer le relais autonome ;
- `relay:dev` — lancer le relais en développement ;
- tests du relais inclus dans `npm test` ou dans un script invoqué par la CI.

Aucun abonnement, service cloud ou base managée n’est requis pour lancer le relais sur une machine possédée par l’utilisateur.

## Déploiement visé

Le même programme doit pouvoir fonctionner sur :

- PC Windows/Linux/macOS avec Node.js ;
- mini-PC ou Raspberry Pi ;
- NAS capable d’exécuter Node.js ou un conteneur ;
- VPS ;
- future installation Quantic OS.

Un conteneur pourra être fourni dans cette tranche si cela reste léger et ne modifie pas le design du moteur ; l’exécutable Node direct reste la référence fonctionnelle.

## Évolution après cette tranche

Une fois le relais autonome et durable validé :

1. publication signée des endpoints de relais associés à une identité ;
2. découverte de plusieurs relais d’un correspondant ;
3. réplication/store-and-forward inter-relais ;
4. politique de réplication pilotée par l’utilisateur ;
5. transport direct appareil-à-appareil opportuniste ;
6. intégration native dans Quantic Glide et Quantic OS.

## Décisions explicites

- Le relais autonome est construit dans le dépôt QuanticMail pour réutiliser le moteur existant.
- Le premier backend durable est JSON atomique, pas SQLite.
- Le serveur HTTP est basé sur Node.js natif, pas Express/Fastify.
- Le relais écoute uniquement en loopback par défaut.
- Une mutation n’est considérée réussie qu’après persistance du nouvel état.
- Un fichier d’état corrompu ne doit jamais être remplacé automatiquement par un état vide.
- L’identité canonique ne dépend jamais du relais utilisé.
