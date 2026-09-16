# Quantic Relay autonome

Quantic Relay est le transport autonome de Quantic Network. Il expose Quantic Relay Protocol V1 sans lancer l’interface Next.js de QuanticMail et conserve son état localement sur disque.

Le relais ne possède pas l’identité de l’utilisateur : les adresses restent liées aux clés Quantic. Il ne stocke pas les clés privées ni les messages en clair. Il conserve les identités publiques, les appareils autorisés, les enveloppes chiffrées, les accusés de livraison et les métadonnées nécessaires au protocole.

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

Le health check est disponible sur :

```text
GET http://127.0.0.1:8787/api/quantic/health
```

et doit annoncer `quantic-relay/1`.

## Configuration

Trois variables d’environnement suffisent :

- `QUANTIC_RELAY_HOST` — adresse d’écoute, `127.0.0.1` par défaut ;
- `QUANTIC_RELAY_PORT` — port, `8787` par défaut ;
- `QUANTIC_RELAY_DATA_DIR` — répertoire durable, `./data` par défaut.

Exemple Linux/macOS pour écouter sur le réseau :

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

## Persistance et redémarrage

Chaque mutation du protocole est écrite sur disque avant que le relais confirme son succès au client. Les écritures sont sérialisées et le fichier est remplacé atomiquement : un échec d’écriture ne doit pas laisser un fichier final partiel ni faire diverger silencieusement l’état mémoire de l’état durable.

Le scénario suivant est couvert par les tests d’intégration :

1. Alice et Bob sont enregistrés ;
2. Alice envoie une enveloppe chiffrée à Bob ;
3. le relais est complètement arrêté ;
4. le relais redémarre avec le même répertoire de données ;
5. Bob récupère l’enveloppe ;
6. Bob l’accuse puis le relais redémarre à nouveau ;
7. l’enveloppe a disparu de la file de Bob et l’accusé est disponible pour Alice ;
8. Alice consomme l’accusé ;
9. après un dernier redémarrage, l’accusé n’est plus présent.

Le fichier `relay-state.json` contient donc des données opérationnelles importantes. Même si les enveloppes sont chiffrées, le répertoire doit rester protégé par les permissions du système d’exploitation et être sauvegardé si le relais doit garantir une conservation durable.

Si `relay-state.json` est corrompu ou utilise un format inconnu, le relais refuse de démarrer. Il ne remplace jamais silencieusement un état existant par une base vide.

## Publication sur Internet

Le serveur autonome parle HTTP. Le HTTP en clair convient au loopback et au développement local ; un relais accessible sur Internet doit être publié en **HTTPS**.

La configuration recommandée est :

```text
Internet
   │ HTTPS
   ▼
Caddy / Nginx / Traefik
   │ HTTP local
   ▼
Quantic Relay :8787
```

Le reverse proxy gère le certificat TLS et transmet les requêtes vers `127.0.0.1:8787`. Il n’est pas nécessaire de modifier le protocole Quantic.

Le bind `0.0.0.0` est volontaire : il doit être demandé explicitement. La valeur par défaut `127.0.0.1` évite d’exposer involontairement un relais neuf au réseau.

## Arrêt propre

`SIGINT` et `SIGTERM` déclenchent l’arrêt propre du serveur. Le relais cesse d’accepter de nouvelles connexions, attend la fermeture du serveur HTTP puis effectue un dernier flush durable de son état.

## Ce que cette version ne fait pas encore

Le relais autonome supprime la dépendance obligatoire à Render **pour le transport et sa persistance**, mais Quantic Network n’est pas encore un réseau pair-à-pair complet.

Il manque encore :

- la découverte signée des relais associés à une identité ;
- la réplication ou le store-and-forward entre plusieurs relais ;
- le transport direct appareil-à-appareil ;
- un client QuanticMail totalement local/PWA/desktop pour ne plus dépendre d’un hébergeur lors du chargement de l’interface web.

Render peut donc devenir un relais/bootstrap parmi d’autres. Une interface QuanticMail ouverte depuis un déploiement Render dépend toutefois encore de cet hébergement pour charger l’application elle-même tant qu’une version locale n’est pas installée.
