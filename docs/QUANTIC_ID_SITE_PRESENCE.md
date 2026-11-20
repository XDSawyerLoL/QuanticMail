# Quantic ID — présence éphémère sur les sites compatibles (spécification)

## Intention

Quand le propriétaire déverrouille son Quantic ID, il peut s'authentifier avec une preuve signée, propre à l'origine du site. L'identité appartient au propriétaire et n'a pas besoin d'un compte central ni de Quantic Network. Le site peut afficher un pseudonyme et l'état « connecté » seulement tant que la session Quantic ID est valide.

Dès que l'utilisateur verrouille son coffre, le site qui reçoit la notification **révoque la présence immédiatement** : suppression des entrées mémoire, invalidation du badge en temps réel, fermeture de l'accès lié à la session. En cas de fermeture brutale, perte réseau ou fermeture du navigateur, la preuve de présence expire automatiquement au plus tard après sa durée de bail (10 secondes par défaut, maximum 30 secondes dans le prototype).

Les visiteurs qui consultent une ancienne page ouverte doivent recevoir une notification du site (WebSocket ou SSE) ou rafraîchir leur état de présence, sinon ils peuvent voir temporairement un affichage obsolète. « Disparition instantanée partout » ne peut être garantie hors ligne.

## Protocole candidat côté site

1. Le navigateur demande un défi aléatoire à usage unique pour l'origine HTTPS exacte.
2. Quantic Identity Vault déverrouillé signe `{version,keyId,challenge,audience,issuedAt}` ; aucune clé privée ne quitte le coffre. L'utilisateur choisit distinctement les informations de profil que le site peut voir.
3. Le site valide cryptographiquement la signature Ed25519 ou P-256, l'empreinte de la clé, l'origine, le délai court et l'unicité du défi.
4. Le site crée une présence **en mémoire volatile seulement**. Il ne place pas le jeton secret dans une URL, un journal, un cookie durable ou localStorage. Il le garde dans une session éphémère protégée.
5. La présence est renouvelée uniquement à l'aide de **nouvelles preuves Quantic ID** tant que le coffre reste déverrouillé ; garder une ancienne session web ouverte ne suffit pas.
6. Le verrouillage demande la révocation de toutes les présences de cette identité sur ce site ; l'interface retire instantanément l'utilisateur. Si la requête n'aboutit pas, le bail expire automatiquement sans nouvelle preuve.
7. Aucun registre global de présence persistant n'est écrit dans la base ; un redémarrage du site fait disparaître toutes les présences.

### Séparation stricte des données

**Volatiles, jamais persistées par le module** : état en ligne, preuve signée, défi, clé de session et session de présence, éventuellement pseudonyme temporaire choisi.

**Persistantes seulement avec finalité valable et autorisations claires** : informations de profil données volontairement, préférences, publications, factures nécessaires aux obligations légales, etc. Le site doit informer des finalités, fondements juridiques, destinataires et durées de conservation. Un utilisateur doit pouvoir retirer un consentement facultatif et demander l'effacement selon les conditions applicables. Les données conservées ne recréent jamais la présence en ligne quand le coffre est verrouillé.

Un identifiant public stable `qid_...` utilisé sur plusieurs sites permet potentiellement la corrélation des comptes : pour une protection renforcée, prévoir des identifiants pseudonymes différents par site ou une preuve cryptographique à divulgation minimale. **Non implémenté dans ce prototype.**

### Cache : deux sens différents

- Pour l'état connecté, utiliser le **cache applicatif en mémoire** du site, avec expiration courte et révocation. Ce n'est pas le cache HTTP ordinaire.
- Réponses de présence et données sensibles : `Cache-Control: no-store`, pas de CDN public, pas de sauvegarde automatique de présence, et exclusion des logs contenant les tokens. Côté navigateur, vider les données de session de l'interface et fermer WebSocket/SSE à la révocation. `Clear-Site-Data` ne purge pas le serveur distant.
- Les sites tiers **restent responsables** de leurs éventuelles sauvegardes, copies, journaux et traitements ; Quantic ID seul ne peut pas garantir leur suppression universelle.

### Bibliothèque disponible

`lib/quantic-id/site-presence.mjs` fournit le vérificateur cryptographique de preuve Quantic ID et une gestion en mémoire `begin / activate / renew / lock / listVisible`. Aucun serveur de présence commun n'est créé.

Ce module constitue un **prototype de référence côté site**, pas une fonctionnalité déjà intégrée aux sites tiers ni au processus de verrouillage de l'application Quantic Identity Vault. Il reste à développer les événements de verrouillage, une intégration front/back site, une protection CSRF contre les appels non sollicités, la diffusion live et la politique de persistance explicite. Les sessions réelles et tests de bout en bout ne sont pas validés.
