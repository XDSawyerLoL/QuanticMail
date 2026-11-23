# Quantic Scattering — Secure Lab V1.4

**Statut : recherche isolée, non déployable en production.** Cette branche abandonne les formules de relativité simulée comme moteur de transport. Elle teste une idée plus concrète : données et leurres chiffrés dans des trames identiques, correction des pertes 8/16, placement des fragments indépendant de l'activité, anti-rejeu et adversaires qui connaissent l'algorithme mais pas la clé.

## Ce qui fonctionne dans le laboratoire

- **168 octets fixes par datagramme**, 12 octets de nonce aléatoire, 140 octets de texte chiffré et 16 octets de tag AES-256-GCM. Les champs séquence, type, identité de fragment et message sont *dans le chiffré*. Le contenu est indistinguable seulement sous les hypothèses cryptographiques usuelles ; le trafic physique reste observable.
- **Dérivation HKDF-SHA256** d'une clé par session externe de 16 octets ; la session doit être unique et autorisée hors bande. Aucun handshake sécurisé n'est implémenté ici.
- **Rejet après déchiffrement** des rejouements/stales dans une fenêtre glissante de 2 048 séquences, en acceptant le désordre. L'état n'est pas persisté : redémarrer avec le même ID de session pourrait réautoriser d'anciens paquets. En production, il faudra une négociation authentifiée de sessions fraîches et une politique de reprise durable.
- **Reed–Solomon 8 données + 8 parités GF(256)**, fragments de 118 octets, validés pour toutes les 12 870 combinaisons de huit fragments. Charge utile maximale par message dans ce profil : 942 octets. Le code GF(256) n'a pas subi d'audit de résistance aux canaux auxiliaires.
- **28 créneaux par fenêtre**, quelle que soit l'activité ; les positions éventuelles de données sont choisies à partir d'une clé de session, jamais à partir de l'arrivée d'un message.
- **Politique antipodale** : 8 couples de positions distantes de 14 créneaux sur une fenêtre circulaire de 28. Toute rafale continue de 14 suppressions supprime exactement 8 fragments, laissant 8 fragments décodables. Cette garantie suppose une seule rafale continue de taille ≤14, 16 fragments dans la même fenêtre, absence d'autres pertes et un récepteur ayant les fragments restants.
- **Vraies transmissions UDP sur 127.0.0.1** dans les tests ; pas d'essais sur deux PC ni d'observateur système indépendant.

## Reproduction

Windows : `REJOUER_WINDOWS.bat` avec Node.js 22 ou plus récent.

Linux/macOS :

```sh
node --test tests/v14.test.mjs
node scripts/run-audit.mjs 5000
```

Le rapport synthétique est produit dans `results/v14-benchmark.json`. Le code n'utilise aucune API distante ni dépendance NPM. Les secrets des essais sont des constantes publiques : **ne jamais les réutiliser en production**.

## Méthodes adversariales

La simulation compare **stratifié public, stratifié à clé, uniforme à clé, antipodal à clé**, sous neuf scénarios : pertes iid 2 %, rafale de 14, deux rafales courtes, suppression des 14 premiers/derniers paquets, 14 suppressions aléatoires, ciblage de neuf positions de la méthode publique, ciblage de neuf positions de la géométrie antipodale et ciblage de sept paires antipodales. Les masques sont identiques pour toutes les méthodes, les graines sont reproductibles et indépendantes de l'activité.

**Contre-exemples sérieux :** la méthode antipodale n'est pas supérieure dans tous les scénarios. Les suppressions de sept paires connues la dégradent, et un adversaire qui connaît la clé peut viser neuf fragments utiles et empêcher la récupération. Les attaquants adaptatifs, la corrélation des extrémités, la congestion réelle, les canaux de contrôle et les reprises après crash ne sont pas résolus.

## Ce qui n'est PAS démontré

Ce projet ne démontre ni indécelabilité physique, ni anonymat Internet, ni supériorité générale sur les mixnets, ni nouveauté brevetable. La propriété d'égalité du nombre et de la taille des trames est démontrée **par construction pour le calendrier nominal**, mais les détails du système d'exploitation, des horloges et du routage peuvent révéler l'activité. Un débit de couverture permanent a un coût : 28 × 168 octets / 1,6 s = **0,254016 Go/jour** par direction avant en-têtes réseau.

**Aucun changement de Quantic Mail / Identity Vault / réseau de production.** Aucune clé d'identité utilisateur n'est lue ou utilisée.

## Étapes de production encore bloquantes

1. Authentification mutuelle des identités et établissement post-quantique des sessions, rotation de clé, continuité après redémarrage.
2. Implémentation d'un cadenceur réel indépendant de l'activité, profils d'horloge, buffering borné, congestion et reprise contrôlée.
3. Validation indépendante de l'indécelabilité du canal complet : métadonnées, routage, canaux de contrôle, relais et adversaires adaptatifs.
4. Audit cryptographique externe, test de sécurité des terminaisons et analyses de compromis de clés.

**Décision** : poursuivre en laboratoire ; intégration à la production interdite sans franchir ces verrous.
