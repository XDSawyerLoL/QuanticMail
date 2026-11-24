# Session de messagerie native à jeton scellé — laboratoire

Le mode Windows `windowsScattering.credentialMode: "vault-sealed-v1"`
interdit le champ `token` dans desktop.json. Il sélectionne le broker
graphique natif après ouverture des deux coffres et vérification des
empreintes de la candidature, du quorum et du contrôleur. Le jeton
`mailbox-token.vault` est déchiffré dans le processus Go, utilisé uniquement
par le transport local, puis sa copie en mémoire est effacée à la fermeture.
Les copies temporaires internes aux bibliothèques ou à l'OS ne sont pas
garanties effacées. Aucun jeton n'est envoyé au contrôleur Node ni écrit dans
un fichier JSON, stdout, arguments ou presse-papiers.

Le transport n'accepte que quatre opérations, sur le port loopback
explicitement configuré. Pas de proxy, redirection ni URL distante. Le serveur
local et le système restent des éléments de confiance (un processus local
compromis peut intercepter un port ou la mémoire). Les attestations du
broker et du relais restent requises. Envoi : session conservée pendant la
signature, l'écriture durable et l'approbation du dépôt. Réception : même
session pour lecture, ouverture et accusé après vérification du reçu chiffré.
Les anciens modes synthétiques restent isolés et n'ont pas accès au jeton
scellé. Aucun repli vers un jeton en clair en mode scellé.

La configuration authentifiée des contacts, des autorités et du port
Scattering reste nécessaire. Cette PR ne crée pas cette configuration
automatiquement et ne déploie pas les autorités. Pas de migration réelle.
