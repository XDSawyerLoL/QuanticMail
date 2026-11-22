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

## Windows : relecture durable isolée après redémarrage (données synthétiques)

Nouveau laboratoire : `lib/quantic/migration-durable-lab.mjs`,
`labs/quantic-native/vault/windows_migration_storage.go` et
`scripts/migration-windows-readback-lab.mjs`. Le contrôleur Windows
natif reçoit **uniquement deux instantanés AES-256-GCM déjà chiffrés**,
`source.sealed` et `candidate.sealed`, dans un **nouveau** répertoire
NTFS privé. Le contrôle existant du coffre impose propriétaire/ACL,
absence de lien dur ou de reparse point, création sans écrasement et
synchronisation du fichier. Chaque enveloppe est liée à son rôle
source/candidat et à l'empreinte de racine historique indépendante par
les données authentifiées AES-GCM ; les clés AES ne sont pas écrites
sur disque ni passées en argument à l'exécutable Go.

Le test Windows démarre **un nouveau processus Node**, relit les deux
enveloppes au travers de l'exécutable natif, vérifie son SHA-256 fourni
séparément, déchiffre avec la clé reçue par `stdin`, puis exécute
`reconcileHistoricalCollections`. Il vérifie également le refus de
réutilisation du dossier, le refus d'écrasement, l'interdiction d'accès
à un fichier quelconque du coffre, le refus d'une cible corrompue et
la **récupérabilité intacte de la copie source**, sans effacement.
Test : `node --test tests/migration-windows-durable.test.mjs`, avec
`QUANTIC_WINDOWS_VAULT_TEST` pointant vers le binaire Go Windows
compilé et pinné par SHA-256. Le workflow `native-vault-lab.yml`
exécute ce test sur un runner Windows réel après compilation.

**Portée strictement limitée :** données synthétiques ; aucun compte,
aucune archive privée Web ni clé de production importée. La taille
maximale du JSON déchiffré est **96 000 octets**, donc ce laboratoire
ne sait pas encore restaurer une archive réelle jusqu'à 16 Mio.
La source du test est une copie de référence chiffrée, pas une
preuve de verrouillage des écritures dans IndexedDB. La récupération
désigne ici la **lecture de la copie de référence intacte**, pas un
retour arrière transactionnel d'une identité effectivement migrée.
Le flush du fichier ne garantit pas une durabilité absolue du répertoire
face à une panne d'alimentation. Il manque aussi le contrôle des relais
distants, les écritures concurrentes, un journal/commit atomique, le
redémarrage après coupure électrique et l'essai sur deux machines
physiques. Le même utilisateur Windows, l'administrateur ou un malware
dans la session peuvent encore interférer avec le laboratoire.

Le rapport maintient
`liveRegistrationAuthorized:false`,
`liveRestoreAuthorized:false`,
`legacyDeletionAuthorized:false`,
`durableTargetVerified:false` et
`remoteQueueReconciled:false`. **Ne pas utiliser pour de vraies
identités, ni fusionner en production sans une revue indépendante.**

## Copie par blocs 16 Mio, journal d'audit et relais local (22/11)

Le format de laboratoire `migration-chunked-lab.mjs` accepte une
**copie JSON de collections synthétiques jusqu'à 16 Mio**, scindée en
blocs d'environ 80 Kio, authentifiés par AES-256-GCM. L'empreinte du
contenu historique est figée dans un manifeste chiffré **avant** le
premier bloc. Une reprise ne peut pas mélanger deux versions : elle
relit et authentifie les blocs existants, écrit exclusivement les
blocs absents, puis exige une relecture complète après redémarrage.
`MigrationFullSmoke` couvre ce scénario sur Windows, y compris une
interruption artificielle après trois blocs.

Nouveau contrôle `migration-relay-observation-lab.mjs` : exclusivement
sur le **relais local 127.0.0.1** avec un compte de laboratoire, il
effectue deux lectures authentifiées **GET /api/quantic/pull** et
**GET /api/quantic/receipts**, sans appeler ACK, POST, renouvellement
de préclés ou migration. Le comparateur détecte disparition, ajout et
modification d'enveloppes/reçus, confronte ces observations au maintien
intégral des anciennes collections (outbox et préclés notamment), et
ne renvoie aucun contenu de message ni identifiant dans son rapport.
Un test avec le **véritable relais persistant**, redémarré entre les
deux observations, vérifie le maintien des messages non acquittés et
la détection d'une arrivée concurrente.

Le relais existant limite la lecture à **100 éléments** pour les
messages et 100 pour les reçus, sans pagination ni point de cohérence
signé. Un résultat stable ou vide ne prouve donc **ni** l'exhaustivité
de la file distante, **ni** son absence de changement concurrent,
**ni** que le serveur contacté est authentifié par la seule
empreinte passée au client. Le contrôle refuse le réseau distant
et maintient inconditionnellement `remoteQueueReconciled:false`.
Un futur fournisseur d'attestation lié à l'identité de relais, des
curseurs/instantanés complets et une barrière de concurrence indépendante
sont requis avant toute décision réelle.

Le journal `migration-audit-journal-lab.mjs` enregistre sur NTFS,
par création exclusive, des événements chiffrés AES-GCM à chaîne
d'empreintes SHA-256 : **prepared**, **snapshot-verified**,
**relay-observed**, puis éventuellement **blocked**. Le composant
Windows `windows_migration_audit.go` refuse les noms non prévus,
les formats étrangers et les remplacements. Seuls des compteurs,
booléens et empreintes cryptographiques sont admissibles dans les
faits du journal ; aucun secret, message ou token ne doit être stocké.
Le scénario Windows de 16 Mio écrit une intention avant redémarrage,
puis une preuve de comparaison après relecture. Une observation
réelle du relais **ne fait pas partie** du scénario de 16 Mio :
une preuve de relais ne peut donc pas être simulée pour compléter
arbitrairement sa phase suivante.

**Ce journal n'est pas un commit atomique de migration.** Il n'existe
aucune transition vers une identité réelle, aucun ACK, aucune
réactivation de préclé et aucun effacement. Les flags
`liveRestoreAuthorized` et `legacyDeletionAuthorized`
restent à `false` dans tous les scénarios. Le crash-process
est testé ; la coupure électrique, la synchronisation durable du
répertoire, les écritures Web concurrentes et l'attestation du
relais distant restent à démontrer avant toute restauration réelle.

Tests :
`node --experimental-transform-types --test tests/migration-relay-observation.test.mjs tests/migration-audit-journal-lab.test.mjs`.
Le workflow natif Windows inclut également ces régressions et
`MigrationFullSmoke` avec journal local.

## Attestation intégrale signée de file locale (laboratoire)

Le relais autonome dispose maintenant d'un mode **explicitement opt-in**,
`migrationSnapshotLab:true`, accepté uniquement lorsque le serveur est
lié à `127.0.0.1` et utilise son stockage de laboratoire **sans PostgreSQL**.
Ce mode est désactivé par défaut et interdit sur un relais public. La
route `GET /api/quantic/lab/migration-snapshot` exige le jeton du
propriétaire du périphérique, un `nonce` inédit, et refuse les
requêtes Cross-Origin. Elle est réservée aux identités fictives de test.

Contrairement aux anciens endpoints `/pull` et `/receipts`, qui
n'exposent que **100 éléments**, le mode laboratoire lit d'un coup
**toutes les entrées encore conservées en mémoire sur un relais unique**,
dans les limites actuelles de **500 enveloppes et 500 reçus** par boîte.
Le contrôle refuse les ensembles trop volumineux (12 Mio de données
sérialisées par catégorie) au lieu d'émettre une preuve partielle.
La lecture passe par `RelayRuntime.read`, attend les écritures déjà
soumises au processus, et capture les deux catégories sans mutation
entre les deux instantanés internes.

Le serveur renvoie uniquement une liste ordonnée d'empreintes SHA-256,
des compteurs et des racines SHA-256. L'ensemble, l'adresse canonique,
l'identifiant d'appareil, le nonce, la date et la clé publique
d'identité du relais sont **signés ECDSA P-256**. Le validateur
`verifyMigrationLabMailbox` vérifie la signature et que l'identité
cryptographique du signataire correspond à une **empreinte de relais
confiée indépendamment** au vérificateur. Le comparateur
`compareMigrationLabMailboxes` refuse le réemploi d'un nonce et
détecte les entrées apparues, modifiées ou disparues entre deux
captations. Les tests créent plus de 100 messages fictifs, redémarrent
le vrai relais avec son stockage durable, et vérifient que toutes
les empreintes persistent et qu'un nouvel arrivant est détecté.

**Portée de la preuve :** exhaustive pour les entrées *encore stockées
dans un seul relais de laboratoire au moment de la capture*, pas pour
l'historique complet, un ensemble de relais fédérés, les messages
déjà acquittés/expirés, ni les écritures arrivées juste après la
signature. Aucune barrière de concurrence durable ou consensus
entre relais n'est encore réalisé. Ainsi, même avec deux attestations
valides et identiques, les indicateurs `remoteQueueReconciled`,
`liveRestoreAuthorized` et `legacyDeletionAuthorized`
demeurent **toujours faux**. Cela n'est pas une preuve suffisante
pour une bascule réelle ; celle-ci exigera une clôture transactionnelle
du flux de réception, un accusé de conservation répliqué et une
transition d'identité auditée et réversible.

Test : `node --experimental-transform-types --test
tests/migration-signed-full-relay.test.mjs`.

## Barrière d'écriture persistée par relais de laboratoire

Le mode isolé `migrationSnapshotLab:true` accepte maintenant, **uniquement
sur le serveur local de test à `127.0.0.1` sans PostgreSQL**, la
configuration d'un secret opérateur **indépendant** (`migrationLabOperatorSecret`).
Sans ce secret fort (32 caractères minimum), aucune fermeture/réouverture
du relais n'est autorisée. La route de capture simple reste en lecture seule.

Le laboratoire ajoute trois endpoints, protégés par
`X-Quantic-Lab-Operator` (secret fourni hors bande), et sans CORS :
`POST /api/quantic/lab/freeze`, `GET /api/quantic/lab/fence-status`,
`POST /api/quantic/lab/release?fenceId=...`. Le secret opérateur n'est
jamais persisté et n'est pas le jeton de boîte mail. Le verrou est
**global au processus de laboratoire**, pas uniquement à une adresse.

La fermeture est insérée dans la file de mutations sérialisées
`RelayRuntime`. Une fois les opérations déjà acceptées et enregistrées,
le relais **sauvegarde atomiquement dans `relay-state.json` le
contenu de ses files et l'enregistrement `migrationLabFence`**
(identifiant aléatoire, empreinte de relais, date, phase `frozen`).
Le serveur refuse ensuite toutes les routes classiques (423) et le
moteur bloque également ses `mutate` et ses `read` ordinaires,
certaines lectures historiques pouvant effectuer des nettoyages.
Seule la capture spécifiquement non mutante du laboratoire reste
disponible. À la relance, le même fichier recharge le verrou ; tenter
un redémarrage sans le mode laboratoire le **refuse** plutôt que
désactiver silencieusement la protection.

Une capture signée prise pendant le gel contient désormais
`fenceId`, inclus dans la signature ECDSA P-256 et lié à la clé
indépendamment identifiée du relais. Deux captures sous des verrous
différents ne peuvent pas être considérées identiques. Après
vérification, un opérateur autorisé peut **annuler le gel**
(`release`) grâce à l'identifiant exact du verrou. Cette ouverture
ne migre aucun compte et ne supprime aucune ancienne clé.

Le test `tests/migration-relay-durable-fence.test.mjs` vérifie
la fermeture, le rejet des envois et des ACK, les captures signées
à travers un redémarrage, le maintien du verrou après arrêt,
le refus de faux opérateurs et la réouverture contrôlée.

**Limites cruciales** : il s'agit d'un verrou de laboratoire
**mono-relais / mono-processus**, sans prise en charge d'un cluster,
des autres relais fédérés ou de PostgreSQL. La sauvegarde disque
utilise un fichier temporaire synchronisé et un renommage, mais
n'établit pas encore une preuve de durabilité après coupure
d'alimentation (fsync du répertoire, cas limites du système de fichiers).
Les fichiers de boîtes expirés ne sont pas récupérés, aucun
accusé de conservation distribué n'est produit, aucune identité
réelle n'est restaurée. `remoteQueueReconciled:false`,
`liveRestoreAuthorized:false` et
`legacyDeletionAuthorized:false` demeurent impératifs.
La prochaine étape est une **coordination cryptographique multi-relais**
sur la base de ces verrous locaux, suivie d'un protocole de
quorum/rollback résistant aux déconnexions et d'une migration réelle
testée sans perte de préclés ou de courrier.

## Coordination multi-relais dans des processus distincts (laboratoire)

`lib/quantic/migration-multirelay-coordinator-lab.mjs` coordonne désormais
**2 à 4 relais de laboratoire indépendants**, tous liés à
`http://127.0.0.1:<port>`. Chaque relais possède son propre répertoire,
sa propre identité et sa propre clé de signature ECDSA P-256. La liste
des empreintes `relayId` est fournie indépendamment du réseau, sans
confiance dans une réponse de statut seule.

**Séquence de laboratoire :** vérification des identités et des files non
gelées ; écriture synchronisée d'une intention aléatoire
`transactionId` dans `coordinator-intent.json` ; fermeture séquentielle
des relais avec ce même identifiant ; relecture de chaque statut ;
capture et vérification de deux instantanés signés complets par
relais, liés à son `fenceId` ; sauvegarde locale des empreintes des
preuves ; dernière vérification de toutes les fermetures. Aucun
jeton, secret opérateur, message ni clé privée ne figure dans le
journal du coordinateur. Les fichiers du journal sont remplacés par
écriture temporaire, synchronisation, renommage et synchronisation
du répertoire lorsque disponible.

Une réponse HTTP de fermeture **perdue après l'enregistrement** ne
provoque pas un nouveau verrou : la reprise consulte
`fence-status` et exige que le `transactionId` corresponde à celui
de l'intention persistée, puis reprend à partir des relais non
encore fermés. Si un relais est injoignable, le coordinateur
**ne prétend pas avoir réussi** et laisse les verrous déjà appliqués
actifs. Il faut soit reprendre avec les mêmes paramètres, soit
effectuer un **rollback explicitement demandé**. Une réouverture
partielle produit `synthetic-rollback-incomplete` et reste
réessayable après rétablissement des relais. Les fichiers de preuve
sont vérifiés cryptographiquement, mais seules leurs empreintes
sont conservées.

Une seule opération est autorisée à la fois par répertoire de
coordination grâce à `.coordinator-active.lock` créé exclusivement.
Une coupure brutale du coordinateur peut laisser ce fichier :
**ne pas le supprimer automatiquement**. L'opérateur doit vérifier
que le processus est arrêté, inspecter les verrous distants et
décider consciemment de reprendre ou d'annuler. Une suppression
automatique risquerait deux coordinateurs concurrents.

Les tests `tests/migration-multirelay-coordinator.test.mjs`
démarrent **deux vrais serveurs dans deux processus système distincts**
(avec états et clés de relais différents). Ils vérifient les gels
persistants après redémarrage, les signatures indépendantes, un
envoi interdit, une perte de réponse HTTP pourtant enregistrée par
le premier relais, la récupération, la panne du second relais lors
d'un rollback, puis l'annulation complète. Le test vérifie aussi
que le fichier du coordinateur ne contient aucun secret et qu'un
second opérateur ne peut pas acquérir le verrou de fichier.

**Ce n'est pas un protocole de consensus ou un commit distribué.**
Pendant la fermeture séquentielle, un autre relais peut encore
recevoir des messages. Une fois tous les relais observés gelés,
la preuve ne porte que sur les files **encore retenues** sur ces
relais précis. Les relais fédérés non listés, les messages déjà
expirés/acquittés et les coupures d'alimentation ne sont pas
couverts ; les journaux locaux ne forment pas un journal de quorum
indépendant. La coordination n'envoie jamais un ACK et retourne
toujours `remoteQueueReconciled:false`,
`liveRestoreAuthorized:false`, `legacyDeletionAuthorized:false`.
Il reste à établir une barrière de réception à l'échelle de tous
les relais possibles, une preuve de conservation des messages
en vol et un mécanisme de convergence après partition réseau,
avant toute migration réelle.

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
