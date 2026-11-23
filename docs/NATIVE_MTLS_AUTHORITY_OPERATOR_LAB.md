# Quantic Sillage — quatre autorités mTLS en processus séparés (laboratoire)

Le dépôt comporte désormais un programme d'opérateur **Linux, en
lecture seule**, capable d'exécuter une autorité d'attestation hors du
processus du relais. Chaque autorité possède un répertoire privé,
sa clé de signature Ed25519, son certificat TLS, une politique approuvée
et un instantané de relais **épinglé**, qui ne sont pas partagés avec
ses trois homologues.

**Cette fonctionnalité ne déploie aucun serveur sur Internet, ne
constitue pas une infrastructure de confiance indépendante, ne
provisionne aucun vrai utilisateur et ne réécrit jamais les clés de
Quantic Mail.** Tous les services écoutent uniquement
`127.0.0.1`. Pour quatre machines réelles, il faudrait mettre en
place quatre tunnels authentifiés, opérés séparément, ainsi que
leurs politiques, circuits de révocation et journaux propres.

## Arborescence d'une autorité

Créer un dossier local absolu, réservé à cet opérateur, avec
permissions POSIX `0700`. Il doit contenir, chacun sous son nom exact :

| Fichier | Contenu | Permissions |
|---|---|---|
| `operator.json` | Configuration de démarrage et empreintes publiques approuvées | 0600 |
| `ca.pem` | Certificat de l'autorité CA client | 0600 ou 0644 |
| `server.crt` | Certificat TLS du service, dont l'empreinte est approuvée | 0600 ou 0644 |
| `server.key` | Clé privée TLS de ce service seulement | 0600 |
| `signer.pem` | Clé Ed25519 privée **distincte** de toutes les autres autorités, format PKCS#8 PEM | 0600 |
| `state.json` | Instantané autonome `quantic-relay-state` v3, sans modification de sa date | 0600 |
| `policy.json` | Liste des appareils autorisés et empreintes de racines approuvées par cet opérateur | 0600 |

Un exemple de `operator.json` (**les empreintes ci-dessous sont des
placeholders, jamais des valeurs à copier**) :

```json
{
  "format": "quantic-native-authority-operator-lab/v1",
  "labOnly": true,
  "authorityId": "authority-a",
  "port": 45501,
  "pins": {
    "caPin": "SHA256_DES_OCTETS_CA_PEM",
    "tlsPin": "SHA256_DER_CERTIFICAT_TLS",
    "signerPin": "SHA256_SPKI_DER_ED25519",
    "statePin": "SHA256_DES_OCTETS_STATE_JSON",
    "policyPin": "SHA256_DES_OCTETS_POLICY_JSON"
  },
  "clientPins": ["SHA256_DER_CERTIFICAT_CLIENT_MTLS"]
}
```

Les champs `pin` sont des SHA-256 de 64 caractères hexadécimaux
minuscules, calculés sur les **octets indiqués**. L'empreinte du
certificat TLS doit être celle du DER X.509, et non celle du texte PEM.
Les clientPins sont également des empreintes de certificats DER X.509.
La clé Ed25519 est identifiée par son SPKI DER. Les empreintes de
l'instantané et de la politique sont les SHA-256 exacts des fichiers.
Les fichiers ne doivent pas contenir de lien symbolique ou de lien
physique supplémentaire.

Chaque opérateur doit **approuver la configuration et son empreinte via
un canal indépendant**. Copier une même clé privée Ed25519 ou faire
valider toute la politique par un unique serveur ne suffit pas à
constituer quatre autorités indépendantes.

## Démarrage d'une seule autorité

Avec Node 24 sur Linux et un dossier déjà préparé :

```bash
node scripts/run-native-checkpoint-authority-lab.mjs \
  /srv/quantic-lab/authority-a \
  CONFIG_SHA256_APPROUVE_HORS_BANDE
```

L'outil refuse un dossier ou fichier mal protégé, une empreinte
incorrecte, des certificats incohérents, une mauvaise clé Ed25519,
des politiques invalides et un instantané trop ancien. La sortie
JSON fournit uniquement l'identifiant public, le port loopback et
les empreintes publiques pour les clients. Les clés privées et les
messages ne sont jamais imprimés.

L'état `savedAt` de l'instantané doit dater de moins de **30 secondes**
lors de la signature de chaque attestation. Un instantané est chargé
**une seule fois** : si l'état est périmé, les demandes deviennent
invalides et **aucune date n'est artificiellement actualisée**.
Pour reprendre le service, il faut une nouvelle validation
indépendante de l'instantané et de son empreinte, puis un redémarrage
contrôlé. Il ne s'agit pas encore d'un service permanent autonome.

## Quatre processus et tolérance à une panne

Le test `tests/native-authority-operator-processes.test.mjs` :
- crée quatre répertoires et quatre clés Ed25519 indépendantes ;
- lance quatre **processus Node distincts**, chacun avec ses fichiers,
  sa clé signataire et son service mTLS ;
- reçoit un checkpoint signé de trois autorités concordantes, même
  si l'une est arrêtée ;
- constate qu'avec deux autorités restantes, le quorum échoue ;
- refuse une politique modifiée sans renouveler son empreinte,
  une empreinte de configuration incorrecte et un instantané périmé,
  même s'il a été repinné.

Le test utilise des certificats et identités **synthétiques**,
fabriqués uniquement pendant la CI ; il n'emploie ni serveur
physique ni compte existant. Il ne démontre pas une tolérance
aux compromissions simultanées, aux partitions de réseau complexes
ni une gouvernance indépendante.

## Étape pour l'essai réel entre deux PC

Il reste à déployer les autorités chez quatre opérateurs réellement
séparés, à établir la distribution et la révocation des manifestes et
politiques signées, à transporter les appels HTTPS mTLS via quatre
chemins approuvés, et à configurer les deux ponts Scattering. À ce
stade seulement, il sera possible de lancer le parcours
`MailAttest`, puis le test de message chiffré PC A → PC B,
réception conservée après redémarrage et accusé contrôlé.

**Aucune clé historique ni identité Web réelle ne doit être supprimée
ou migrée pendant ce laboratoire.**
