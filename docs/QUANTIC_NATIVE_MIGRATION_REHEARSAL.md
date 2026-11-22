# Identity Vault — historique Web vers appareil natif (préparation, 22/11/2026)

> **Statut : expérience locale, non destructive.** Aucun compte client n'a été
> migré, aucune clé historique supprimée, aucun ancien appareil révoqué et
> aucune autorité financière contactée par ce module.

## Avancement réel

`lib/quantic/native-enrollment-request.mjs` vérifie la demande précise
d'inscription native : domaine réservé, adresse canonique, racine P-256,
empreintes de la clé de signature et de chiffrement, identifiant d'appareil
dérivé de la clé de chiffrement, séquence du manifeste, nonce et durée
maximum **30 secondes**. Le *broker* natif vérifie indépendamment la
demande et exige une approbation locale. Le contrôleur postquantique
`desktop/native-vault-controller.mjs` expose désormais
`signEnrollment(challenge)` et les clés publiques natives, comme le
contrôleur classique. L'opération d'inscription en mode PQ exige également
`pqMode.historicalRootPin` (SHA-256 de la clé publique de propriété
historique SPKI), enregistrée indépendamment du défi et de l'archive
fournie. Le défi doit désigner exactement `pqMode.address`.
**En l'absence de cette empreinte de confiance, l'inscription est refusée.**
Ce champ ne modifie pas l'ouverture des messages déjà autorisés.
**Le contrôleur ne transmet jamais les clés privées à la page Web.**

`lib/quantic/migration-rehearsal.mjs` croise :

1. L'archive chiffrée `.qma` authentifiée, vérifiée par le véritable
   moteur de preuve historique P-256 / ML-KEM / ML-DSA, avec l'empreinte
   de propriété enregistrée indépendamment de l'archive.
2. Le manifeste historique signé et l'ancien appareil d'origine ;
   la préparation actuelle est **réservée au compte maître/racine**,
   sans association en attente.
3. Les deux appareils actifs dans un manifeste plus récent, un
   Crypto Profile hybride signé, et les checkpoints frais de l'autorité.
4. Les clés publiques postquantiques conservées de l'ancien appareil,
   qui doivent correspondre **exactement** à celles de son profil
   actuel. La racine ML-DSA du **compte** est vérifiée séparément
   contre l'empreinte postquantique de confiance : elle ne doit pas être
   confondue avec la clé ML-DSA de l'appareil historique. Si l'archive
   ne contient pas aussi la clé privée de cette racine, sa garde reste
   explicitement à établir avant toute mise à jour du profil.
5. Une seconde lecture des deux appareils par la source d'autorité
   approuvée, pour détecter un changement de racine, de registre,
   de profil ou d'identifiant pendant l'examen.

Les tests génèrent de véritables clés P-256, ML-KEM-768 et ML-DSA-65,
un ancien manifeste signé, un profil hybride signé, une archive chiffrée,
et exercent les refus d'une racine remplacée, d'un appareil absent, d'un
profil altéré et d'un changement entre deux lectures.

L'origine `peerSource` **doit** provenir du fournisseur d'attestations
mTLS vérifiant un quorum indépendant ; le module ne prouve pas à lui seul
que la fonction fournie est honnête. Les fixtures utilisent des sources
simulées, pas des comptes ni des hôtes physiques réels.

## Réconciliation exacte de la copie historique (laboratoire)

`lib/quantic/migration-reconcile.mjs` compare en lecture seule deux
captures **distinctes** : les enregistrements historiques déchiffrés et
leur copie relue depuis le stockage cible. Les messages (`id`), contacts
(`handle`), préclés (`preKeyId`) et envois en attente (`id`) sont
comparés intégralement après normalisation de l'ordre des champs. Les
enregistrements absents, modifiés, supplémentaires ou dupliqués
entraînent un refus. Le rapport ne contient ni identifiants de ligne, ni
contenus de courrier, ni clés privées. Des références d'objets source
partagées avec la cible sont refusées afin d'éviter un contrôle trivial.

Tests : `node --test tests/migration-reconcile.test.mjs`
(inclus aussi dans `npm test`). Ce comparateur n'effectue aucune écriture
et ne valide **ni** la persistance après redémarrage, **ni** l'exhaustivité
des messages encore détenus par les relais distants, **ni** la
synchronisation face aux modifications concurrentes. Il ne prend pas en
charge une conversion du schéma des enregistrements : celle-ci
nécessiterait une procédure de correspondance vérifiable dédiée.
Les anciennes préclés restent historiques et ne doivent pas être remises
à l'état disponible.

Même si toutes les collections correspondent, les autorisations de
restauration, d'inscription en production et de suppression restent à
`false`. Une vraie migration exige ensuite une copie contrôlée,
une relecture indépendante après redémarrage, un gel ou un journal
transactionnel des écritures concurrentes et la réconciliation de la
file distante avant une éventuelle bascule atomique.

## Pourquoi ne pas encore basculer les vrais comptes ?

La continuité des clés **n'est pas** la continuité de la boîte complète.
Les messages déjà reçus, contacts et envois en attente doivent être
comparés record par record ; un compteur et une archive ne prouvent pas
que la file distante est entièrement récupérable. Les préclés anciennes
doivent rester historiques, sans réactivation ou double consommation.
Les jetons d'authentification doivent être recréés sous autorisation
effective de la nouvelle identité. Le nouveau coffre doit prouver son
propre cycle d'envoi/réception authentifié et sa récupération après
redémarrage sur Windows réel.

L'ancien secret maître de l'identité reste **exportable dans IndexedDB**.
Aucun déplacement de fichiers ne peut annuler une compromission passée.
L'identifiant canonique étant historiquement dérivé de la clé de
propriété initiale, une rotation de la racine nécessite une politique
d'identité et une transition signée spécifiques. **Ne pas supprimer
ni prétendre sécuriser rétroactivement cette clé.**

Les fonctions de préparation et de répétition renvoient explicitement
`liveRegistrationAuthorized:false`,
`liveRestoreAuthorized:false` et
`legacyDeletionAuthorized:false`.
Une validation de laboratoire ne doit jamais être interprétée par une
interface comme une autorisation de publication ou de révocation.

## Ordre des étapes restantes

- Confirmer un mode de garde native du secret maître (ou une rotation
  contrôlée, compatible avec l'identité canonique existante).
- Créer un orchestrateur d'inscription **avec** consentement local de
  l'utilisateur, signature de la racine et vérification du registre
  durable ; n'autoriser aucune requête depuis un renderer non fiable.
- Effectuer la copie contrôlée de messages, contacts, préclés et outbox
  avec réconciliation complète et anti-rejeu, sans transfert implicite
  de vieux tokens.
- Vérifier le transport réel vers le nouvel appareil, le retour de
  données, la récupération et la réémission des autorisations.
- Seulement après tests sur des appareils réels, autoriser une
  transition atomique auditée et une éventuelle révocation, avec
  conservation d'une sauvegarde historique hors ligne.

**Ne pas fusionner ce changement en déploiement public avant une revue
indépendante des flux du coffret et des droits de révocation.**
