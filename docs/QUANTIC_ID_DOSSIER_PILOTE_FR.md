# Quantic ID — dossier de pré-pilote cybersécurité
État : 20 novembre 2026 — document de travail, non commercial et non certifié.

## Proposition de valeur

**Quantic ID — Votre identité vous appartient. Votre présence aussi.**

Quantic ID vise une authentification cryptographique locale, sans mot de passe confié au site, et une présence en ligne strictement temporaire : quand le coffre est déverrouillé, un site compatible peut afficher la présence de l'utilisateur ; quand il se verrouille, la session est révoquée et le bail de présence expire rapidement si le signal de verrouillage n'arrive pas.

Les données conservées volontairement par le site (préférences, commandes, publications) doivent être séparées de l'état « présent » et soumises à leurs propres finalités, durées de conservation et bases légales. Aucune suppression universelle des données ne peut être garantie par le seul logiciel Quantic ID.

## Différenciation à démontrer

1. Propriété locale de l'identité, sans fournisseur d'identité central obligatoire.
2. Présence vérifiée cryptographiquement, sans annuaire central permanent.
3. Verrouillage qui entraîne la révocation des sessions des sites autorisés.
4. Identifiants pseudonymes **différents par site** afin de limiter le pistage intersites (à développer).
5. Quantic Secure Core : coffre portable avec chiffrement authentifié, sans dépendance obligatoire à un OS ou à Quantic Network (prototype non encore migré).
6. SDK d'intégration simple, interopérable et auditable.

Ne pas affirmer « premier au monde », « incopiable », « inviolable », « certifié ANSSI » ou « conformité RGPD garantie » sans études ni évaluations indépendantes.

## État vérifié

- PR #45 : cryptographie portable QSC1 et bibliothèque de présence site éphémère.
- Démonstrateur local compatible Identity Vault à lancer via Node.js 22 (site : http://127.0.0.1:41985).
- Tests automatisés CI : 272 réussis, aucun échec sur commit d83196bf7fe4bec506124e41b0c1ce6d547a1df7.
- **Non validé** : installation et test manuel sur PC utilisateur, vraie intégration SWAPP.TV, révocation universelle de sites, confidentialité intersites, attaque en session déverrouillée, migration réelle du coffre et audit externe.

## Démonstration destinée à un partenaire

Parcours de démonstration :
1. Identité verrouillée, profil absent du site.
2. Identité déverrouillée, défi signé pour l'origine du site et profil visible.
3. Verrouillage : profil retiré, session rendue inutilisable et absence de nouveau renouvellement.
4. Coupure réseau : expiration constatée, sans persistance de présence en base.
5. Autorisations : les données que le site conserve volontairement restent séparées ; les supprimer est un autre droit et un autre processus.

Critères de sécurité à faire auditer :
- Aucun mot de passe ou clé privée Quantic ID sur le serveur du site.
- Les preuves signées expirées, usurpées, rejouées ou destinées à un autre site sont rejetées.
- La révocation empêche toute nouvelle action autorisée même si une page reste ouverte.
- Le profil disparaît à la réception du verrouillage ; en cas de perte de signal, la présence expire au plus tard à la fin d'un bail court testé.
- Les informations mises en cache, journaux, sauvegardes et permissions font l'objet d'une politique vérifiable.

## Déploiement commercial responsable

**Étape 1 :** démonstrateur et tests sur poste Windows réel, puis Linux.
**Étape 2 :** consolidation du coffre, autorisations des sites et révocation, revue de menaces.
**Étape 3 :** pilote restreint sur SWAPP.TV, puis 2 à 3 partenaires volontaires ; aucune donnée utilisateur sensible avant audit.
**Étape 4 :** proposition B2B d'intégration + support, version grand public distincte, éventuel marché public après évaluation.

Indicateurs à mesurer : taux de connexion et d'échec, latence, temps de disparition, absence de secrets côté serveur, couverture des attaques automatisées, incidents, effort d'intégration et perception des utilisateurs.

## Financement public à étudier

Source officielle : https://cyber.gouv.fr/actualites/appel-a-projets-national-du-ncc-fr-soutien-au-developpement-de-solutions-de-cybersecurite/

Appel NCC-FR (ANSSI), publié le 18 novembre 2026 : projets de PME/startups immatriculées en France, financement annoncé de 30 000 à 100 000 euros selon éligibilité, première relève le **17 février 2027 à 12 h** ; clôture finale le 19 janvier 2028. Le projet doit correspondre au thème précis d'un axe officiel : authentification USB, certificats d'identité numérique, normalisation ou autre thème éligible. **La pertinence de Quantic ID reste à vérifier : le fait de relever de la cybersécurité ne suffit pas.**

Dossier à constituer si les conditions sont réunies : entité juridique et éligibilité, description technique, justification du verrou technologique, budget prévisionnel, calendrier du développement, stratégie de sécurité et évaluation, éléments de souveraineté, lettres d'intérêt de partenaires.

## Jalons

- J0 : code et démonstrateur local disponibles, CI validée.
- J+7 à J+14 (objectif indicatif) : tests manuels, corrections de sécurité critiques, revue du modèle de menaces.
- J+30 (objectif indicatif) : décision de lancement du pilote conditionnée aux audits, aux résultats et à l'absence de faille majeure.
- Avant 17 février 2027 : déposer un dossier NCC-FR **uniquement si** les critères d'éligibilité et la maturité du projet sont satisfaits.

Sources et suivi : https://github.com/XDSawyerLoL/QuanticMail/issues/46 et https://github.com/XDSawyerLoL/QuanticMail/pull/45.
