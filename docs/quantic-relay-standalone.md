# Quantic Relay autonome

Quantic Relay est le transport autonome de Quantic Network. Il expose Quantic Relay Protocol V1 et Federation V1 sans lancer l’interface Next.js de QuanticMail, et conserve son état localement sur disque.

Le relais ne possède pas l’identité de l’utilisateur : les adresses restent liées aux clés Quantic. Il ne stocke pas les clés privées utilisateur ni les messages en clair. Il conserve les identités publiques, les appareils autorisés, les enveloppes chiffrées, les Route Manifests vérifiés, les accusés de livraison et l’état de fédération nécessaire au routage.

## Prérequis

- Node.js 22 ou compatible ;
- le dépôt QuanticMail ;
- aucune base de données, aucun abonnement et aucun service cloud obligatoires.

## Démarrage local

```bash
npm install
npm run relay:start
```

Par défaut le relais écoute uniquement sur la machine locale :

```text
http://127.0.0.1:8787
```

Son état durable est écrit dans :

```text
./data/relay-state.json
```

Son identité cryptographique de relais est conservée séparément dans :

```text
./data/relay-identity.json
```

Cette identité P-256 est persistante : redémarrer avec le même répertoire conserve le même `relayId`. Le fichier de clé privée doit rester protégé par les permissions du système.

Le health check est disponible sur :

```text
GET http://127.0.0.1:8787/api/quantic/health
```

et annonce `quantic-relay/1`, ainsi que le `relayId` et `quantic-federation/1` lorsque la fédération est active.

## Configuration

Trois variables d’environnement suffisent :

- `QUANTIC_RELAY_HOST` — adresse d’écoute, `127.0.0.1` par défaut ;
- `QUANTIC_RELAY_PORT` — port, `8787` par défaut ;
- `QUANTIC_RELAY_DATA_DIR` — répertoire durable, `./data` par défaut.

Exemple Linux/macOS :

```bash
QUANTIC_RELAY_HOST=0.0.0.0 \
QUANTIC_RELAY_PORT=8787 \
QUANTIC_RELAY_DATA_DIR=/var/lib/quantic-relay \
npm run relay:start
```

Exemple PowerShell :

```powershell
$env:QUANTIC_RELAY_HOST = "0.0.0.0"
$env:QUANTIC_RELAY_PORT = "8787"
$env:QUANTIC_RELAY_DATA_DIR = "C:\QuanticRelay\data"
npm run relay:start
```

Pour le développement avec redémarrage automatique :

```bash
npm run relay:dev
```

## Ajouter le relais à QuanticMail

Dans QuanticMail, ouvrir `/network` puis ajouter l’origine du relais.

Sur la même machine :

```text
http://localhost:8787
```

Pour un relais publié sur Internet :

```text
https://relay.example.org
```

Le client conserve sa liste de relais localement. Changer de relais ne change pas l’adresse canonique `handle~fingerprint@quantic`.

## Federation V1

Chaque relais autonome dispose d’une identité de relais persistante. `POST /api/quantic/federation/hello` produit une preuve signée liée au nonce de l’appelant. Un autre relais vérifie cette preuve et compare `relayId`, clé publique et endpoint avec le Route Manifest signé du destinataire.

Le flux direct supporté est :

```text
Alice sur A
   │
   │ POST /api/quantic/federation/send
   ▼
Relais A ── handshake signé ──► Relais B
   │                             │
   └──── enveloppe chiffrée ────►│
                                 ▼
                                Bob
                                 │ ACK
                                 ▼
Relais A ◄── reçu signé ─────── Relais B
   │
   ▼
reçu local pour Alice
```

Alice s’authentifie auprès de A avec son bearer token local. Ce token n’est jamais transmis à B. L’enveloppe elle-même porte la preuve cryptographique de l’appareil expéditeur ; B peut donc valider Alice à partir de son Identity Manifest sans posséder son token.

B accepte un transfert uniquement si son propre `relayId`, sa clé et son endpoint figurent dans le Route Manifest valide de Bob. L’enveloppe chiffrée est alors déposée dans la file locale de l’appareil de Bob.

## Route Manifest

Le Route Manifest est distinct de l’Identity Manifest V1. Il est signé par la clé de propriété de l’identité et peut annoncer plusieurs relais ordonnés par priorité. Le relais d’origine vérifie les signatures, les séquences, les expirations et la cohérence `relayId ↔ clé publique` avant de tenter un transfert.

La présence d’un endpoint dans un Route Manifest signé signifie que l’utilisateur a autorisé cet endpoint à recevoir son trafic Quantic ; l’endpoint ne devient pas pour autant propriétaire de l’identité.

## Persistance et redémarrage

Chaque mutation du protocole est écrite sur disque avant confirmation au client. Les écritures sont sérialisées et le fichier est remplacé atomiquement : un échec d’écriture restaure l’état précédent en mémoire au lieu de laisser diverger l’état mémoire et le disque.

Le snapshot durable inclut :

- identités et appareils locaux ;
- files d’enveloppes chiffrées et reçus locaux ;
- Route Manifests vérifiés ;
- IDs de fédération déjà vus et leurs digests ;
- transferts fédérés entrants et sortants ;
- reçus fédérés en attente de transmission.

L’anti-rejeu survit donc à un redémarrage : une répétition exacte reste idempotente et la réutilisation d’un même `federationId` avec un digest différent reste refusée.

Les tests couvrent également le comportement historique du relais local : file chiffrée, ACK et reçus survivent aux arrêts/redémarrages complets.

`relay-state.json` contient des données opérationnelles importantes. Même si les messages sont chiffrés, le répertoire doit être protégé et sauvegardé si la conservation durable est requise. Si le fichier est corrompu ou utilise un format inconnu, le relais refuse de démarrer plutôt que de repartir silencieusement avec un état vide.

## Publication sur Internet

Le serveur autonome parle HTTP en interne. Le HTTP en clair convient au loopback et au développement local ; un relais accessible sur Internet doit être publié en **HTTPS**.

Configuration recommandée :

```text
Internet
   │ HTTPS
   ▼
Caddy / Nginx / Traefik
   │ HTTP local
   ▼
Quantic Relay :8787
```

Le reverse proxy gère TLS et transmet les requêtes vers `127.0.0.1:8787`. Le bind `0.0.0.0` doit être demandé explicitement ; la valeur par défaut `127.0.0.1` évite d’exposer involontairement un relais neuf.

## Arrêt propre

`SIGINT` et `SIGTERM` déclenchent l’arrêt propre du serveur. Le relais cesse d’accepter de nouvelles connexions, ferme le serveur HTTP puis effectue un dernier flush durable de son état.

## Ce que Federation V1 prouve

Le test d’acceptation lance deux relais autonomes avec deux répertoires séparés. Alice existe uniquement sur A et Bob uniquement sur B. A reçoit un Route Manifest de Bob déjà connu et signé, chiffre et signe une enveloppe, vérifie cryptographiquement B, transfère l’enveloppe, Bob la récupère et la déchiffre, puis son ACK provoque un reçu signé par B que A transforme en reçu local pour Alice.

Ce scénario ne nécessite ni SMTP/IMAP, ni Gmail/Outlook/Proton, ni GitHub Registry comme autorité de transport.

## Limites actuelles

Federation V1 ne fournit pas encore la découverte universelle d’un destinataire dont aucune route n’est connue. Le transport A→B fonctionne lorsqu’A dispose déjà d’un Route Manifest signé et valide pour Bob.

Restent hors de cette version :

- DHT/gossip ou autre Discovery Mesh pour le premier contact automatique ;
- réplication générale des queues entre relais ;
- routage multi-hop arbitraire ;
- transport direct appareil-à-appareil et traversal NAT/P2P ;
- obligation stricte d’un profil post-quantique de bout en bout ;
- client QuanticMail totalement local/PWA/desktop supprimant toute dépendance d’hébergement pour charger l’interface.

Render peut donc être un relais/bootstrap parmi d’autres et n’est plus une autorité nécessaire au chemin de transport Federation V1. La découverte maillée et Crypto V2 restent des tranches séparées.
