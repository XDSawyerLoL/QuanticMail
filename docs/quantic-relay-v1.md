# Quantic Relay Protocol V1

Quantic Relay V1 est le contrat de transport de Quantic Network. Un relais est un transporteur d’enveloppes chiffrées et un point de résolution temporaire ; il n’est pas propriétaire de l’identité Quantic et ne doit jamais recevoir les clés privées ni le contenu en clair.

## Identité

L’identité canonique reste `handle~fingerprint@quantic`. Le fingerprint est dérivé de la clé publique de signature détenue par l’utilisateur. Changer de relais ne change pas cette identité.

## Découverte et santé

Un relais V1 doit répondre à :

`GET /api/quantic/health`

avec un document JSON contenant au minimum :

```json
{
  "ok": true,
  "protocol": "quantic-relay/1"
}
```

Les relais distants doivent être servis en HTTPS. HTTP est toléré uniquement pour `localhost`, `127.0.0.1` et `::1` pendant le développement ou l’auto-hébergement local.

## Endpoints V1

Une implémentation complète expose les routes Quantic actuelles :

- `POST /api/quantic/challenge` — émet un challenge de preuve de possession.
- `POST /api/quantic/register` — publie ou restaure une identité racine après vérification cryptographique.
- `GET /api/quantic/resolve` — résout une identité et ses appareils autorisés.
- `POST /api/quantic/devices/register` — enregistre un appareil secondaire certifié par l’identité racine.
- `POST /api/quantic/send` — accepte une enveloppe chiffrée destinée à un appareil.
- `GET /api/quantic/pull` — récupère les enveloppes chiffrées en attente pour un appareil.
- `POST /api/quantic/ack` — confirme la réception d’enveloppes.
- `GET /api/quantic/receipts` — récupère les accusés de livraison.
- `POST /api/quantic/receipts` — accuse la consommation des reçus de livraison.

Les schémas de message et les preuves cryptographiques sont ceux de `lib/quantic/relay.ts`, `lib/quantic/crypto.ts` et `lib/quantic/device.ts`.

## CORS

Pour permettre à un client QuanticMail chargé depuis une autre origine de l’utiliser, un relais web doit accepter les requêtes cross-origin sur `/api/quantic/*` :

- méthodes : `GET`, `POST`, `OPTIONS`
- en-têtes : `Content-Type`, `Authorization`

Le token d’authentification reste un secret local de l’appareil. Aucun cookie cross-origin n’est requis par le protocole.

## Bascule et affinité

Le client conserve une liste locale ordonnée de relais. Le premier relais actif est utilisé normalement. Une bascule est autorisée sur :

- erreur réseau ;
- HTTP `408`, `425`, `429` ;
- HTTP `5xx` ;
- HTTP `404` uniquement pour les opérations de recherche distribuée actuellement prévues par le client (`resolve` et `send`).

Les erreurs logiques ou cryptographiques (`401`, `403`, `428`, etc.) ne doivent pas être masquées par une bascule automatique.

Quand une requête réussit sur un relais de secours, ce relais devient le **relais actif** de l’appareil. Les requêtes suivantes commencent par lui afin que `send`, `pull`, `ack` et `receipts` restent cohérents sur la même file de transport. L’utilisateur peut changer explicitement de relais actif depuis `/network`.

## Stockage et sécurité

Un relais peut stocker temporairement :

- identités publiques et certificats d’appareils ;
- enveloppes chiffrées ;
- accusés de livraison ;
- challenges et métadonnées de routage nécessaires au protocole.

Il ne doit pas recevoir :

- clés privées de chiffrement ;
- clé privée de signature ;
- mot de passe d’Identity Vault ;
- sujet ou corps du message en clair.

La boîte lisible et l’outbox durable restent sur l’appareil utilisateur.

## Auto-hébergement actuel

Deux implémentations compatibles avec le même protocole V1 existent dans le dépôt :

1. les routes `/api/quantic/*` intégrées à QuanticMail/Next.js ;
2. le programme Node.js autonome décrit dans `docs/quantic-relay-standalone.md`.

Une instance complète de QuanticMail peut donc toujours agir comme relais lorsqu’elle est déployée en HTTPS. Son implémentation serveur intégrée conserve actuellement l’état du relais en mémoire de processus.

Le relais autonome réutilise le même moteur cryptographique et le même contrat HTTP mais ajoute un stockage JSON versionné et atomique. Son état survit aux arrêts et redémarrages lorsque le même répertoire de données est réutilisé. Il peut tourner sur une machine locale, un mini-PC, un NAS compatible Node.js ou un VPS sans base de données ni service cloud obligatoire.

Une fois publié en HTTPS, son origine peut être ajoutée depuis la page `/network` de QuanticMail. En local, `http://localhost:8787` est accepté.

## Limites de V1 alpha

Cette version enlève l’hypothèse d’un endpoint unique côté client et permet désormais d’exécuter un relais durable indépendamment de Render, mais elle ne constitue pas encore un réseau pair-à-pair complet :

- pas encore de réplication automatique des files entre relais ;
- pas encore de découverte signée d’endpoints attachés à l’identité ;
- pas encore de transport direct appareil-à-appareil ;
- l’interface web doit encore être chargée depuis un hébergeur si elle n’est pas déjà disponible localement.

La persistance locale d’un relais ne garantit donc pas encore qu’un expéditeur utilisant exclusivement le relais A trouve automatiquement un destinataire inscrit exclusivement sur le relais B. La découverte et le store-and-forward inter-relais constituent les prochaines étapes.

Ces points correspondent aux étapes suivantes de Quantic Network V1 et doivent être traités sans modifier l’identité canonique des utilisateurs.
