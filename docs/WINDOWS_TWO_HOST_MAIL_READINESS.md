# Quantic Mail — précontrôle de deux postes Windows (laboratoire uniquement)

Ce parcours **ne provisionne pas les autorités**, ne connecte pas de
compte Quantic ID réel, n'active pas de migration et ne démontre pas une
transmission entre deux ordinateurs physiques. Il vérifie les conditions de
confiance d'un futur essai avant tout envoi.

## Prérequis sur chaque poste

1. Un coffre natif **fictif** déjà créé avec `Provision` ou
   `ProvisionPair`, sur un NTFS local, contrôlé par son propriétaire.
2. Le `desktop.json` privé du coffre contient `labOnly:true`,
   `windowsLab.enabled:true`, les pins classiques/PQ, l'adresse et
   l'appareil Quantic, `pqMode.authority` (quatre autorités), ainsi
   que `windowsScattering` avec un endpoint
   `http://127.0.0.1:PORT/` et un jeton local.
3. `contacts.json` doit contenir **un seul** correspondant fictif,
   avec quatre clés publiques canoniques (P-256 signature et chiffrement,
   ML-KEM-768 et ML-DSA-65) et une expiration dans le futur.
4. Un dossier **séparé** du transport contenant un `scattering.json`
   déjà écrit par le chemin natif approuvé, avec `labOnly:true`,
   `role:client` ou `relay`, `queueDir`, `stateDir`,
   `recvPort`, `httpPort`, `secretHex` et `epochHex`.
   Les secrets du transport restent exclusivement dans le stockage
   privé : **jamais dans le fichier public de confiance**.
5. Quatre autorités **véritablement indépendantes** disposant chacune
   d'un service HTTPS mTLS `/native-checkpoint`, d'une clé de
   signature Ed25519 différente, d'un certificat TLS distinct, et
   d'une politique d'identité maintenue indépendamment du relais.
   Chaque client doit disposer des certificats client/CA nécessaires
   sous les noms privés `peer-*.pem`.

Les certificats et les clés ne peuvent pas être inventés à partir du
`desktop.json` ou du résultat du provisionneur. L'opérateur doit obtenir
leurs empreintes par un canal authentifié, hors du poste à contrôler.

## Fichier de confiance public (obtenu indépendamment)

Un fichier JSON `C:\QuanticLab\trust-approved.json` respecte ce schéma :

```json
{
  "format": "quantic-two-host-trust-lab/v1",
  "labOnly": true,
  "self": {
    "address": "ADRESSE_CANONIQUE_FICTIVE_DE_CE_POSTE",
    "deviceId": "IDENTIFIANT_APPAREIL",
    "rootPin": "SHA256_RACINE_P256",
    "pqRootPin": "SHA256_RACINE_ML_DSA",
    "classicalSigningPin": "SHA256_SIGNATURE_P256",
    "classicalEncryptionPin": "SHA256_CHIFFREMENT_P256",
    "mlKemPin": "SHA256_ML_KEM",
    "mlDsaPin": "SHA256_ML_DSA"
  },
  "peer": {
    "address": "ADRESSE_CANONIQUE_FICTIVE_AUTRE_POSTE",
    "deviceId": "IDENTIFIANT_APPAREIL_AUTRE_POSTE",
    "rootPin": "SHA256_RACINE_P256_AUTRE_POSTE",
    "pqRootPin": "SHA256_RACINE_ML_DSA_AUTRE_POSTE",
    "classicalSigningPin": "SHA256_SIGNATURE_P256_AUTRE_POSTE",
    "classicalEncryptionPin": "SHA256_CHIFFREMENT_P256_AUTRE_POSTE",
    "mlKemPin": "SHA256_ML_KEM_AUTRE_POSTE",
    "mlDsaPin": "SHA256_ML_DSA_AUTRE_POSTE"
  },
  "authorities": [
    {"pin": "SHA256_CLE_ED25519_AUTORITE_1", "tlsPin": "SHA256_CERT_TLS_1"},
    {"pin": "SHA256_CLE_ED25519_AUTORITE_2", "tlsPin": "SHA256_CERT_TLS_2"},
    {"pin": "SHA256_CLE_ED25519_AUTORITE_3", "tlsPin": "SHA256_CERT_TLS_3"},
    {"pin": "SHA256_CLE_ED25519_AUTORITE_4", "tlsPin": "SHA256_CERT_TLS_4"}
  ],
  "carrierRole": "client"
}
```

Les valeurs ci-dessus sont des **placeholders, pas des empreintes
valides**. Chacune des empreintes doit comporter exactement 64 caractères
hexadécimaux minuscules. Pour un poste receveur opérant comme relais,
le champ `carrierRole` est `relay`. Ce fichier est strictement public :
aucun mot de passe, certificat privé, jeton, `secretHex` ou
`epochHex` ne doit y apparaître.

Le hash SHA256 de ce fichier doit être transmis **indépendamment** du
fichier lui-même et du logiciel à tester, puis fourni avec
`-ExpectedTrustSha256`. Calculer le hash sur une copie reçue via le
même canal compromis ne procure aucune authentification.

## Commandes dans le paquet Windows vérifié

Mode **hors ligne** (aucun appel à une autorité) :

```powershell
.\Start-Windows-PQ-Lab.ps1 -Operation MailPreflight `
  -ExpectedManifestSha256 MANIFEST_SHA256_INDEPENDANT `
  -TrustedBinarySha256 BINAIRE_SHA256_INDEPENDANT `
  -PrivateDirectory "C:\QuanticLab\Alice" `
  -CarrierDirectory "C:\QuanticLab\AliceCarrier" `
  -TrustFile "C:\QuanticLab\trust-approved.json" `
  -ExpectedTrustSha256 TRUST_SHA256_INDEPENDANT
```

Pour demander en plus les attestations récentes de **3 autorités
indépendantes sur 4**, utiliser `-Operation MailAttest` avec les
mêmes paramètres. Cette seconde opération vérifie les manifestes,
les profils PQ, les racines et les contacts auprès de l'autorité mTLS.
Elle refuse les certificats TLS mal épinglés, les signatures insuffisantes,
l'expiration ou les incohérences avec les pins approuvés.

Les configurations privées sont lues via les opérations NTFS natives
`--windows-client-read-lab` du binaire épinglé. Aucun secret ne figure
dans le rapport JSON. Une erreur empêche toute conclusion de conformité.

## Limites de la preuve

- `offline-public-anchors-verified` signifie seulement que les
  fichiers de configuration locaux sont cohérents avec des **empreintes
  approuvées hors bande**. Ce n'est pas une signature d'autorité vérifiée.
- `fresh-mtls-3-of-4-quorum-and-contact-verified` signifie que les
  quatre services mTLS ont été interrogés et qu'au moins trois
  attestations fraîches et concordantes ont été vérifiées **par le code
  d'attestation existant**. Ce n'est ni une inscription Quantic ID, ni
  une démonstration de livraison réseau.
- Le client Scattering continue d'écouter sur loopback ; les
  processus `Scattering-Pacer` et `sink` physiques, leurs ports UDP
  et leurs règles réseau doivent être préparés et mesurés séparément.
  Aucun pare-feu ni NAT n'est modifié automatiquement.
- Il faut encore une préparation indépendante des autorités et de la
  politique de signature, puis un vrai essai **PC A → PC B → PC A**
  avec file durable, accusé explicite, redémarrage et audit réseau
  indépendant. La clé de propriétaire historique n'est pas migrée.

Les tests `tests/native-windows-mail-readiness.test.mjs` exercent les
pins, les remplacements malveillants de clés, les incohérences de
contacts et de ports, et les échecs de quorum via une source simulée.
Le test de quatre **véritables services mTLS** reste
`tests/native-identity-bridge.test.mjs`. Ces tests ne remplacent
pas un essai physique ni un audit indépendant.
