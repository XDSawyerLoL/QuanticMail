# Transport TLS natif scellé — laboratoire

Les deux clés mTLS de la candidature sont générées localement. Leur PKCS#8
est chiffré par AES-256-GCM, avec un nonce aléatoire, un en-tête authentifié
liant le rôle et le digest de candidature, et une clé dérivée par HMAC-SHA256
du jeton aléatoire de 256 bits déjà scellé par les deux secrets du coffre.
Aucun fichier PEM de clé privée n'est créé par ce mode. Le mode refuse les
anciens PEM de transport ; pas de migration destructive ni rotation implicite.
Les certificats et CA restent publics. Le contrôleur Ed25519 reste ACL-only.

Lors de l'import les deux secrets déverrouillent le jeton, puis les clés
scellées. La configuration est écrite sans clé privée en clair. Le fichier
desktop.json est toujours écrit en dernier. Dans le broker vivant, les
clés TLS sont déchiffrées uniquement dans Go ; aucun secret TLS n'est
transmis à Node. Les quatre requêtes mTLS de checkpoint sont parallèles,
strictement limitées aux autorités configurées et au compte ou à ses contacts.
Le contrôleur vérifie indépendamment les trois signatures et lie le manifeste
et profil reçus ; un bundle malveillant ou incompatible est refusé. Pas
de redirection, pas de proxy. Un opérateur malveillant peut causer un refus
de service en renvoyant un bundle incompatible en premier.

La prévalidation hors ligne reste disponible ; le mode de diagnostic live
historique, sans dialogue de coffre, refuse ce mode. Les opérations de
messagerie graphiques utilisent le broker. Les copies internes des
bibliothèques et de l'OS ne sont pas garanties effacées ; aucune protection
contre un OS compromis. Pas de migration d'un compte réel ni déploiement.
