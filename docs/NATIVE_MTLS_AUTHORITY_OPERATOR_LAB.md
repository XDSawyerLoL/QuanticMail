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

## Renouvellement signé et monotone (format opérateur v2)

Le mode historique `quantic-native-authority-operator-lab/v1` reste
inchangé : instantanés figés, arrêt des attestations au-delà de
30 secondes. **Le nouveau format v2** ajoute le champ
`renewalPublicKey` (SPKI DER Ed25519, base64url) au
`operator.json` épinglé hors bande. Cette clé appartient à un
**opérateur d'approbation distinct** et ne doit pas être la clé
`signer.pem` utilisée pour signer les attestations.

L'autorité v2 utilise le répertoire privé
`renewals/` (0700), et crée automatiquement
`accepted-head.json` (0600). Le fichier contient
`format: "quantic-native-authority-head/v1"`,
`sequence` et `chainHash`. La racine de cette chaîne est dérivée
de l'identifiant de l'autorité, du hash de `operator.json` et
des empreintes épinglées de l'instantané et de la politique initiaux.
Chaque version doit augmenter `sequence` **d'une unité**, inclure
l'empreinte exacte du parent, et disposer de deux nouveaux fichiers
`state.json` et `policy.json` privés, intégralement approuvés.

### Une étape de renouvellement

1. Un opérateur indépendant obtient un **nouvel instantané réel** de
   l'état signé et sa politique, avec une valeur `savedAt` authentique.
   Il vérifie son origine et les versions des manifestes ; le programme
   ne prétend pas démontrer cette provenance à lui seul. Copier
   l'ancien instantané et actualiser artificiellement sa date n'est
   **pas** un renouvellement valide.
2. Il prépare `renewals/000001/` (0700) avec
   `state.json` et `policy.json` (0600). Le dossier suivant doit
   s'appeler `000002`, etc. Aucun de ces fichiers ne peut être un
   lien symbolique.
3. Le signataire indépendant récupère et **vérifie hors bande**
   `chainHash` de la dernière version acceptée. Sa clé Ed25519
   PKCS#8 reste **hors du répertoire de l'autorité**, idéalement sur
   une machine d'administration séparée.
4. La commande suivante vérifie les fichiers préparés, la fraîcheur
   de l'instantané (moins de 30 secondes), l'absence de recul de
   version et la correspondance de la clé d'approbation. Elle crée
   **en dernier** le fichier `approval.json` avec écriture exclusive
   et synchronisation disque, sans modifier les deux instantanés :

```bash
node scripts/approve-native-authority-renewal-lab.mjs \
  /srv/quantic-lab/authority-a \
  HASH_OPERATOR_JSON_APPROUVE \
  /autre/dossier/prive/renewal-signer.pem \
  1 \
  HASH_CHAINE_PRECEDENTE_APPROUVE \
  --synthetic-only
```

5. À la prochaine requête mTLS, l'autorité lit la nouvelle approbation
   Ed25519, contrôle la séquence, le parent, la date et les SHA-256
   exacts des deux fichiers ; elle synchronise
   `accepted-head.json` **avant** de signer une attestation avec le
   nouvel état. Aucune URL d'administration ne permet de modifier cet
   état à distance.

Après un redémarrage, l'autorité reconstruit la chaîne jusqu'au numéro
accepté. Une approbation falsifiée, une politique remplacée, un
retour de version ou une erreur de disque entraîne un **refus**.
Une génération partiellement préparée sans `approval.json` n'est
pas consommée ; le serveur garde l'état précédent, qui peut cependant
devenir périmé. Un fichier d'approbation partiel ou invalide
ne doit pas être supprimé ou remplacé sans audit opérateur.

Une seule instance v2 peut utiliser un répertoire : le fichier privé
`.authority-active.lock` empêche un deuxième processus simultané.
Un arrêt normal libère ce verrou. Après un crash, il reste en place
et nécessite une vérification **manuelle** de l'arrêt du processus,
de la dernière version enregistrée et de l'intégrité des répertoires.
Il n'existe aucune reprise automatique du verrou.

### Ce qui n'est pas encore acquis

Ce mécanisme protège la **continuité d'une chaîne d'approbations
locales** ; il ne prouve ni l'origine physique des instantanés ni
l'indépendance réelle de quatre autorités. Le fichier de progression
est conservé sur le même poste et n'est pas encore ancré dans un
témoin append-only hors machine : la restauration d'une copie
complète ancienne des fichiers par un administrateur malveillant
reste un risque de rollback. Les opérateurs doivent conserver
hors bande la dernière empreinte de chaîne.

Le renouvellement demeure **supervisé**, même si le service utilise
les nouvelles générations sans redémarrer. Il n'y a pas encore de
pipeline fiable de publication en continu : en l'absence d'un
instantané signé de moins de 30 secondes, la délivrance des
attestations s'arrête au lieu de prolonger artificiellement la
validité de l'ancien état.

Les tests `tests/native-authority-renewal-lab.test.mjs` couvrent
les signatures forgées, la perte de fraîcheur, la reprise de la
progression après redémarrage, les refus de rollback et les accès
concurrents. Le laboratoire `native-authority-operator-processes`
exerce l'adoption réelle d'une génération signée par quatre
processus HTTPS mTLS, ainsi que le verrou exclusif.
