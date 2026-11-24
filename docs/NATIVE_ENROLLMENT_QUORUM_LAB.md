# Quantic ID — quorum d'inscription de laboratoire

## Frontières de confiance

Les quatre opérateurs disposent de clés Ed25519 distinctes. Leur liste publique
contient exactement quatre objets `{pin, publicKey}` : empreinte SHA-256 du SPKI
DER, et SPKI DER encodé en base64url. L'empreinte de cette liste est calculée avec
`enrollmentRosterPin` (tri des quatre empreintes) et authentifiée hors bande.
Elle est **différente** de l'empreinte du quorum d'ancrage du coffre natif.
Ne jamais utiliser une liste ou une empreinte proposée par le candidat comme
ancre de confiance.

## Parcours opérateur

1. Le candidat prépare sa nouvelle identité dans l'Alpha Windows (PR #93).
   L'opérateur examine la candidature publique QSENROLL1.
2. Chaque opérateur, sur son propre Linux, utilise
   `node scripts/verify-native-enrollment-possession-lab.mjs /chemin/cle.pem PIN_OPERATEUR PIN_QUORUM --synthetic-only /chemin/roster.json PIN_ROSTER`.
   Les paramètres doivent être authentifiés indépendamment. Il échange
   QSPROOF1 et QSPROOFREPLY1 avec l'interface « Prouver mon identité de test ».
   Il approuve explicitement le vote. Le code QSVOTE1 contient le vote signé
   (JSON base64url), pas une autorisation de session.
3. Trois votes distincts, sur la même candidature et le même roster, valides
   quinze minutes, sont requis. La candidature publique reste valide au plus
   24 heures. Une preuve invalide, un vote dupliqué, un mauvais roster ou deux
   opérateurs ne permettent aucune préparation.
4. L'opérateur récupère un **véritable** instantané courant du relais avec le
   manifeste et le profil du candidat et sa propre politique précédente.
   Le fichier de configuration de préparation, épinglé hors bande, contient
   `format: "quantic-native-enrollment-policy-preparation-lab/v1"`,
   `labOnly: true`, `approved: true`, `request` (candidature décodée),
   `votes` (objets QSVOTE1 décodés), `trusted` (roster), `rosterPin`,
   `quorumPin`, `stateFile`, `statePin`, `previousPolicyFile` et
   `previousPolicyPin`. Les chemins sont absolus et les empreintes des deux
   fichiers sont calculées sur leurs octets exacts. Il peut ensuite exécuter
   `node scripts/prepare-native-enrollment-policy-lab.mjs /chemin/config.json PIN_CONFIG --synthetic-only`.
   La sortie standard est une politique proposée, non installée.
5. Chaque opérateur vérifie le résultat, le place dans sa prochaine génération
   de renouvellement et utilise la procédure séparée
   `approve-native-authority-renewal-lab.mjs`. L'autorité accepte la nouvelle
   génération après signature indépendante et écriture durable du head.
   Les trois attestations de checkpoint restent requises pour le courrier.

Le programme ne publie pas automatiquement le manifeste dans le relais, ne
crée pas de jeton réseau, ne change pas les politiques existantes et ne génère
pas de date de fraîcheur artificielle. Le chemin historique de renouvellement
opérateur reste disponible : le quorum d'inscription est imposé dans ce nouveau
parcours, et non dans toutes les opérations administratives historiques. Les
administrateurs indépendants restent une hypothèse de confiance.

Les tests exercent des clés et signatures réelles, une candidature fictive et
trois répertoires de renouvellement distincts sur un même environnement.
Ils ne démontrent pas l'indépendance géographique, la disponibilité du relais,
ni l'inscription distante d'un compte réel. Aucune utilisation de production.
