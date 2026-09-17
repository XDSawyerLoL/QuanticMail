# Quantic Relay Protocol V1

Quantic Relay V1 est le contrat de transport de Quantic Network. Un relais transporte des enveloppes chiffrées et des métadonnées de routage minimales ; il n’est jamais propriétaire de l’identité Quantic et ne doit jamais recevoir les clés privées ni le contenu en clair.

## Identité utilisateur

L’identité canonique reste `handle~fingerprint@quantic`. Le fingerprint est dérivé de la clé publique de signature détenue par l’utilisateur. Changer de relais ne change pas cette identité.

L’**Identity Manifest V1 reste inchangé**. Federation V1 n’ajoute pas les endpoints réseau dans le manifeste d’identité historique : les routes sont publiées dans un objet séparé, signé par la même identité, afin de conserver la compatibilité avec les clients V1 existants.

## Route Manifest signé

Federation V1 introduit `quantic-route-manifest` V1. Il lie une identité canonique à une liste ordonnée de relais autorisés et contient notamment :

- l’adresse canonique de l’utilisateur ;
- la séquence indépendante du Route Manifest ;
- la séquence d’Identity Manifest sur laquelle il s’appuie ;
- pour chaque relais : `relayId`, endpoint, priorité, protocoles et clé publique de signature ;
- les dates d’émission et d’expiration ;
- la signature P-256 de l’identité propriétaire.

Un Route Manifest est accepté uniquement si sa signature est valide, si la clé de propriété correspond à l’Identity Manifest vérifié, si les séquences sont cohérentes et si chaque `relayId` correspond cryptographiquement à la clé publique annoncée. Les rollbacks et conflits à séquence identique sont refusés.

La possession d’un Route Manifest signé permet de router vers un relais autorisé sans faire de cet endpoint une autorité sur l’identité.

## Identité du relais

Le relais autonome possède sa propre paire de clés P-256 persistante, distincte des identités utilisateurs. Son `relayId` est le SHA-256 de sa clé publique SPKI.

`POST /api/quantic/federation/hello` renvoie une preuve signée et liée à un nonce fourni par l’appelant. Cette preuve contient le `relayId`, l’endpoint public, les protocoles/capacités et la clé publique du relais. Le client ou le relais d’origine vérifie ensuite que le `relayId`, la clé et l’endpoint correspondent à l’entrée autorisée du Route Manifest.

## Découverte et santé

Un relais V1 répond à :

`GET /api/quantic/health`

avec un document JSON contenant au minimum :

```json
{
  "ok": true,
  "protocol": "quantic-relay/1"
}
```

Le relais autonome annonce également son `relayId` et `quantic-federation/1` lorsqu’il dispose de son identité de fédération.

Les relais distants doivent être servis en HTTPS. HTTP est toléré uniquement pour `localhost`, `127.0.0.1` et `::1` pendant le développement ou l’auto-hébergement local.

## Endpoints Relay V1

Une implémentation complète expose les routes Quantic historiques :

- `POST /api/quantic/challenge` — émet un challenge de preuve de possession ;
- `POST /api/quantic/register` — publie ou restaure une identité racine après vérification cryptographique ;
- `GET /api/quantic/resolve` — résout une identité et ses appareils autorisés ;
- `POST /api/quantic/devices/register` — enregistre un appareil secondaire certifié ;
- `POST /api/quantic/send` — accepte une enveloppe chiffrée locale ;
- `GET /api/quantic/pull` — récupère les enveloppes chiffrées en attente ;
- `POST /api/quantic/ack` — confirme la réception ;
- `GET /api/quantic/receipts` — récupère les accusés de livraison ;
- `POST /api/quantic/receipts` — accuse la consommation des reçus.

Les schémas historiques restent ceux de `lib/quantic/relay.ts`, `lib/quantic/crypto.ts` et `lib/quantic/device.ts`.

## Endpoints Federation V1

Le relais autonome expose en plus :

- `POST /api/quantic/federation/hello` — preuve d’identité du relais liée à un nonce ;
- `POST /api/quantic/federation/send` — point d’entrée local de l’expéditeur. Le bearer token de l’appareil est vérifié **uniquement sur son relais A** ;
- `POST /api/quantic/federation/forward` — ingress inter-relais. Le relais B reçoit une enveloppe portable signée et chiffrée, les manifestes nécessaires et une preuve signée du relais précédent ;
- `POST /api/quantic/federation/receipt` — réception sur A d’un accusé de livraison signé par le relais B autorisé.

Le chemin direct couvert par Federation V1 est :

```text
Alice/appareil
     │ bearer local
     ▼
Relais A
     │ enveloppe chiffrée + preuve appareil + preuve relais A
     ▼
Relais B autorisé par le Route Manifest de Bob
     │
     ▼
Bob/appareil → ACK
     │
     └── reçu signé par B ──► Relais A ──► reçu local Alice
```

Le bearer token d’Alice ne quitte jamais A. B valide la signature de l’enveloppe contre l’appareil actif de l’Identity Manifest d’Alice, vérifie le Route Manifest de Bob, vérifie qu’il est lui-même un relais autorisé, puis insère uniquement le blob chiffré dans la file de Bob.

## Anti-rejeu et idempotence

Chaque transfert fédéré possède un `federationId` et un digest SHA-256 de l’enveloppe canonique. Le relais destinataire conserve un état durable :

- une nouvelle paire `federationId + digest` peut être acceptée ;
- une répétition exacte est idempotente et ne crée pas une seconde enveloppe ;
- la réutilisation du même `federationId` avec un autre digest est refusée ;
- les entrées expirées sont purgées.

Les états entrants, sortants, anti-rejeu et les reçus fédérés en attente font partie du snapshot durable du relais autonome.

## Reçus de livraison

Un reçu fédéré n’est produit qu’après l’ACK du destinataire sur son relais. Il est signé avec la clé persistante du relais destinataire et lie au minimum le `federationId`, le digest de l’enveloppe, les identités/appareils source et destination, la séquence de route et la date de livraison.

A n’accepte le reçu que s’il correspond à son transfert sortant enregistré et si sa signature vérifie contre le relais autorisé dans le Route Manifest utilisé pour l’envoi. Le reçu est ensuite transformé en reçu Quantic normal, lisible par l’appareil d’Alice via `/api/quantic/receipts`.

## CORS

Pour permettre à un client QuanticMail chargé depuis une autre origine de l’utiliser, un relais web accepte les requêtes cross-origin sur `/api/quantic/*` :

- méthodes : `GET`, `POST`, `OPTIONS` ;
- en-têtes : `Content-Type`, `Authorization`.

Le token d’authentification reste un secret local de l’appareil. Aucun cookie cross-origin n’est requis par le protocole.

## Bascule et affinité

Le client conserve une liste locale ordonnée de relais. Une bascule est autorisée sur les erreurs réseau et les statuts explicitement retryables. Les erreurs logiques ou cryptographiques (`401`, `403`, `428`, etc.) ne doivent pas être masquées par une bascule automatique.

Pour Federation V1, le Route Manifest du destinataire peut contenir plusieurs relais classés par priorité. A réalise un handshake signé avec chaque candidat avant `/forward` et peut essayer le candidat suivant si le transport échoue. Un endpoint n’est pas accepté simplement parce qu’il répond : son identité doit correspondre à l’entrée signée du Route Manifest.

## Stockage et sécurité

Un relais peut stocker temporairement :

- identités publiques et certificats d’appareils ;
- Route Manifests publics signés ;
- enveloppes chiffrées ;
- accusés de livraison ;
- challenges et métadonnées de routage ;
- état anti-rejeu et files de fédération.

Il ne doit pas recevoir :

- clés privées de chiffrement utilisateur ;
- clés privées de signature utilisateur ;
- mot de passe d’Identity Vault ;
- bearer token d’un appareil hébergé par un autre relais ;
- sujet ou corps du message en clair.

La boîte lisible et les secrets utilisateurs restent sur les appareils.

## Auto-hébergement

Deux surfaces Relay V1 existent dans le dépôt : les routes `/api/quantic/*` intégrées à QuanticMail/Next.js et le programme Node.js autonome décrit dans `docs/quantic-relay-standalone.md`.

Federation V1 et sa persistance inter-relais sont implémentées dans le relais autonome. Celui-ci peut tourner sur une machine locale, un mini-PC, un NAS compatible Node.js ou un VPS sans base de données ni service cloud obligatoire. Une publication Internet doit être protégée par HTTPS.

## Limites exactes de Federation V1

Federation V1 prouve le transport direct **A → B lorsqu’A possède déjà un Route Manifest signé et valide pour Bob**. Elle ne prétend pas encore résoudre automatiquement le premier contact avec une identité totalement inconnue du réseau.

Ne sont pas encore fournis par cette tranche :

- découverte universelle d’une route inconnue via DHT/gossip ou annuaire décentralisé ;
- réplication générale des files entre relais ;
- routage multi-hop arbitraire entre plusieurs relais intermédiaires ;
- transport direct appareil-à-appareil avec traversal NAT/P2P ;
- obligation cryptographique post-quantique de bout en bout.

GitHub peut rester un checkpoint/bootstrap optionnel pour les manifestes existants, mais Federation V1 ne l’utilise pas comme autorité obligatoire pour le test A→B. La découverte maillée et l’application stricte du profil post-quantique appartiennent aux plans séparés Discovery Mesh et Crypto V2.
