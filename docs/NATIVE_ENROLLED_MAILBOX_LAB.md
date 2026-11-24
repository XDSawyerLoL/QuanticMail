# Relais de messagerie natif inscrit — laboratoire

Le nouvel exécutable serveur Linux est `scripts/serve-native-enrolled-mailbox.mjs`.
Il n'utilise pas le routeur Web historique : seules les opérations
`send/pull/ack/recover` existent sur 127.0.0.1, destinées au pont Scattering.
Le chemin de données est exclusivement `native-mailbox-state.json`, dans
un répertoire POSIX privé existant (0700), distinct des répertoires historiques.
Le démarrage réserve un verrou exclusif et la persistance synchronise le
fichier puis le répertoire. Un échec ambigu après renommage bloque les accès ;
un verrou abandonné exige une réconciliation manuelle. Ce n'est pas un ancrage
externe contre la restauration intégrale de l'ancien disque.

## Démarrage supervisé

`node --experimental-transform-types scripts/serve-native-enrolled-mailbox.mjs /chemin/config.json PIN_CONFIG --synthetic-only`

Configuration privée 0600, empreinte SHA-256 exacte approuvée indépendamment :
`format: "quantic-native-enrolled-mailbox-lab/v1"`, `labOnly: true`,
`dataDir`, `port`, `authority` (configuration mTLS existante des quatre
autorités). Pour l'inscription initiale uniquement, ajouter `rosterPin`,
`quorumPin`, `enrollment: {request,votes,credential,approved:true}`.
Le champ credential contient exclusivement `tokenHash` et la signature
du contrôleur Ed25519 lié par les racines propriétaires. Le helper
`makeNativeEnrollmentCredential` crée le jeton sur le poste du candidat ;
seule sa preuve publique est destinée à l'opérateur. L'intégration du helper
au coffre Windows et le stockage local du jeton restent à effectuer.

Au démarrage, l'opérateur obtient un instantané public minimal des manifestes
et profils ; il l'utilise dans les renouvellements indépendants signés.
La date correspond à un état lu effectivement dans le runtime, pas à une
ancienne copie réhorodatée. Les attestations 3/4 fraîches restent obligatoires
pour chaque opération. Un nouveau démarrage sans bloc enrollment conserve les
comptes et files déjà inscrits. Une répétition du bloc d'inscription est
refusée : aucune rotation silencieuse du jeton, aucun écrasement.

## Portée

La CI teste deux comptes fictifs, quatre clés opérateur réelles de laboratoire,
le chiffrement hybride et les signatures, le redémarrage et la récupération,
le refus d'accès sans approbation et la séparation du fichier historique.
Les autorités de ce test sont appelées directement dans le processus de test ;
le vrai transport mTLS à quatre sites, le pont UDP et l'interface Windows
restent à relier dans un test physique de bout en bout. Pas de déploiement
de production ni de compte réel inscrit.
