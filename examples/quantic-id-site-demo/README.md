# Quantic ID — démonstration locale

Ce démonstrateur valide l'authentification d'un site par preuve Quantic ID et un cache de présence éphémère, sans mot de passe de site ni stockage durable des présences.

Lancement : installer Node.js 22, ouvrir Quantic Identity Vault sur le même PC, puis exécuter :
node examples/quantic-id-site-demo/server.mjs

Ouvrir ensuite http://127.0.0.1:41985 ; déverrouiller Identity Vault ; sélectionner « Se connecter avec Quantic ID ». Verrouiller le coffre ; le navigateur détecte le changement, révoque la présence et l'affichage se met à jour. Si le navigateur ne peut pas notifier le site, le bail expire en dix secondes.

L'accès à Identity Vault se fait uniquement sur http://127.0.0.1:47621. Le site ne reçoit aucune clé privée. La preuve est liée à l'origine du site et vérifiée cryptographiquement sur le serveur. Un renouvellement nécessite une nouvelle preuve. Les jetons ne sont stockés ni dans un cookie durable, ni dans localStorage, ni dans une base de données.

Tests automatisés : node --test tests/quantic-id-site-demo.test.mjs

Limites : démonstration sur un seul PC ; aucune intégration réelle sur SWAPP.TV ; aucune révocation universelle quand Identity Vault se verrouille sans navigateur actif ; aucune preuve de sécurité face à une machine compromise ; aucun mécanisme de données autorisées persistantes. Les applications sur d'autres sites ont besoin d'une intégration explicite, d'une politique RGPD propre et de protections CSRF et XSS auditées. Ce prototype ne doit pas être exposé à Internet ni utilisé pour des comptes clients.