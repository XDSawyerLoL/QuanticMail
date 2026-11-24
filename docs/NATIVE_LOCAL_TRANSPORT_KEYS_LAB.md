# Demandes de certificats de transport natifs Windows

La préparation de messagerie génère deux clés ECDSA P-256 distinctes
sur le PC (ancrage du journal et attestations de checkpoint). Les fichiers
PEM locaux sont créés exclusivement et protégés par ACL NTFS propriétaire
+ SYSTEM. Ils ne sont pas des clés matériellement non exportables et ne
sont pas chiffrés au repos par cette étape. Le jeton et les clés d'identité
restent protégés par leurs coffres séparés.

Le formulaire retourne deux codes publics QSCRED1 et QSTLS1. Le deuxième
contient deux CSR DER signées par leurs propres clés, le digest de candidature,
le hash du jeton et une signature Ed25519 du contrôleur lié à l'identité.
Le réexport conserve les mêmes clés. Aucune clé privée dans ces codes.

Sur Linux l'opérateur vérifie le dossier JSON épinglé contenant request
(QSENROLL1), approvals (QSAPPROVAL1), credential (QSCRED1), transport
(QSTLS1), rosterPin et quorumPin :
`node --experimental-transform-types scripts/verify-native-transport-csr-lab.mjs /chemin/config.json SHA256 --synthetic-only`.
La sortie contient seulement les deux CSR publiques vérifiées, à soumettre
aux CA indépendantes. L'opérateur doit approuver l'émission séparément, avec
extension clientAuth, digitalSignature, CA:false, sujet CN exact de la CSR
et durée courte. Ne pas copier des extensions arbitraires de la CSR.

Le dossier d'activation v2 conserve le format de #105 sauf le champ format
(quantic-native-windows-activation-lab/v2) et les objets anchorTls et
checkpointTls : uniquement ca et cert (PEM en base64 standard), aucun key.
Les packages v1 ou contenant une clé injectée sont refusés. Le moteur exige
les clés locales correspondantes, deux clés distinctes, certificat client
valide à la date courante et chaîne vers la CA épinglée par le dossier.
Les ancres indépendantes et les checkpoints doivent toujours autoriser
les certificats émis. Le dépôt sur un poste réel, la génération CA contrôlée,
le pont Scattering et l'essai physique restent à réaliser.
