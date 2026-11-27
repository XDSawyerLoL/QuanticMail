# Quantic Sillage — radar mathématique et cryptographique (23 novembre 2026)

> Recherche appliquée ciblée, **pas** inventaire exhaustif de toutes les publications mathématiques. Statuts scientifiques distingués ci-dessous. Aucun théorème nouveau, audit de sécurité complet ou sécurité prouvée du protocole n'est revendiqué.

## Héritage mathématique utile

| Domaine / origine | Conséquence technique Quantic |
| --- | --- |
| Kerckhoffs (1883), Shannon (1949) : sécurité et théorie de l'information | Le secret ne doit pas résider dans l'algorithme de Scattering ; le chiffrement seul ne cache pas les métadonnées. |
| Bayes, Neyman–Pearson : théorie des tests statistiques | Pour parler d'anonymat, définir ce que voit l'attaquant et mesurer un avantage de distinction face au hasard. |
| Merkle (1979) : engagements cryptographiques | Vérifier l'intégrité des archives et des instantanés du relais ; la fraîcheur et l'exhaustivité demandent des preuves distinctes. |
| McEliece (1978) : codes correcteurs ; Ajtai (1996) et Regev (2005) : réseaux euclidiens / LWE | Préparer l'agilité entre familles d'algorithmes ; ne pas remplacer ML-KEM par un KEM expérimental non audité. |
| Preuves à divulgation nulle de connaissance (1980s), indistinguabilité différentielle | Pour Quantic ID/Pay, preuve sélective ; pour Scattering, bornes formelles si notre modèle concorde réellement avec leurs hypothèses. |

## Publications et normes triées par robustesse des preuves

1. **NIST IR 8547, octobre 2026 — norme/guide institutionnel** : transition progressive des clés publiques vulnérables ; ML-KEM-768 recommandé comme paramétrage par défaut ; HQC sélectionné comme alternative en cours de normalisation. **Action :** documenter la racine d'identité post-quantique, la continuité signée et l'interdiction de downgrade. https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf
2. **NIST SP 800-227, septembre 2025 — recommandations finales** : exigences de construction autour des KEM. **Action :** revue du combinateur P-256/ML-KEM-768, liaison au contexte et gestion des erreurs. https://csrc.nist.gov/pubs/sp/800/227/final
3. **NIST, sélection de HQC, mars 2025 — sélection, PAS standard finalisé** : mécanisme alternatif fondé sur les codes. **Action :** prévoir une interface fournisseur substituable ; ne pas activer un protocole non standardisé en production. https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption
4. **Das, « One Unverified Coordinate Is Enough », ePrint 2026/2239, révision du 12 novembre — préprint** : analyse d'attaques sur des implémentations ML-KEM présentant une vérification fautive du rejet implicite. **Action :** isoler les clés natives, suivre les vulnérabilités et tester les cas malformés et erreurs cryptographiques. Ne signifie pas que tous les ML-KEM sont cassés. https://eprint.iacr.org/2026/2239
5. **Signal SPQR/Triple Ratchet, 2025 et formalisation publiée en 2026** : évolution du secret partagé et récupération après compromission. **Action :** étudier et adapter des constructions éprouvées ; ne pas écrire de ratchet propriétaire pour les comptes réels avant revue formelle. https://signal.org/blog/spqr/ ; https://signal.org/docs/specifications/doubleratchet/
6. **Jollès et al., PoPETs 2026(2) — article évalué par les pairs** : le trafic de couverture et les retards ne garantissent pas l'absence de fingerprinting dans Nym ; comparaison des coûts. **Action :** mesurer la distinction réel/leurre par tailles, retards, directions et rafales. https://petsymposium.org/popets/2026/popets-2026-0055.php
7. **Ingo, Druschel, Garg, arXiv 2611.22732, 17 novembre 2026 — préprint non encore validé indépendamment** : bornes d'indistinguabilité pour des mixnets parallèles sous hypothèses spécifiques. **Action :** étudier les modèles de mélange et les compromis latence/charge ; aucune garantie n'est transférable directement à notre transport UDP. https://arxiv.org/abs/2611.22732
8. **ETSI TR 104 171, 2026 — rapport technique publié** : sources quantiques d'entropie, extracteurs et tests de santé. **Action :** QRNG matériel optionnel seulement après validation ; jamais remplacer le générateur cryptographique système par une source inconnue. https://www.etsi.org/newsroom/press-releases/etsis-identifies-limitations-of-quantum-random-number-generators/
9. **BCE, questions-réponses du pilote euro numérique, 2026 — source officielle** : infrastructure NFC et éléments sécurisés pour certains paiements hors ligne. **Action :** parcours Pay interopérable via prestataires autorisés ; aucune compatibilité ou certification BCE revendiquée. https://www.ecb.europa.eu/euro/digital_euro/pilot/html/ecb.faq-digital-euro-pilot.en.html

## Expérience immédiatement ajoutée : distingueur passif Scattering

**Question falsifiable :** sur des traces locales synthétiques annotées « real » et « cover », un observateur disposant uniquement de la taille exacte des paquets, de l'intervalle entre paquets et de la direction peut-il prédire le type mieux que le hasard sur un jeu d'évaluation tenu à l'écart de l'entraînement ?

**Fichiers :**
- `labs/quantic-native/scattering/traffic-privacy-lab.mjs`
- `tests/scattering-traffic-privacy-lab.test.mjs`

**Exécution, Node 22+ :**

```sh
node --test tests/scattering-traffic-privacy-lab.test.mjs
node labs/quantic-native/scattering/traffic-privacy-lab.mjs --input /chemin/vers/traces-laboratoire.json
```

L'entrée est un tableau JSON de 32 observations « real » et 32 « cover » au minimum, et **ne peut contenir que** ces quatre champs :

```json
{"kind":"cover","packetBytes":168,"gapMs":20,"direction":"out"}
```

L'outil refuse les champs supplémentaires pour éviter les secrets, IP, identités, tokens, identifiants de message et contenus. Les données ne quittent pas le processus local ; seul un rapport agrégé est émis. Les échantillons sont séparés par catégorie ; un classificateur discret est entraîné sur 75 % environ des observations et testé sur des classes d'effectifs égaux. Un test de permutation des étiquettes fournit une valeur p expérimentale.

**Limite cruciale :** un classificateur incapable de distinguer les paquets dans ces champs n'est PAS une preuve que Scattering résiste à un adversaire réel. Il faudrait tester rafales, destinations, synchronisation des relais, retransmissions, charges, machines physiques, observateur global et adversaire actif. Le seuil d'alarme (écart de 10 points et p < 0,05) est uniquement un indicateur de recherche. Le pseudo-hasard utilisé pour la séparation des jeux de données est reproductible et **inadapté** à la cryptographie.

## Hypothèses d'innovation à confronter à la réalité

- **H1 :** ordonnancement externe à cadence fixe + mélange/batching ; chercher le meilleur triplet anonymat, délai, bande passante, sans masquer les frais réseau.
- **H2 :** retransmissions et accusés de réception rendus statistiquement similaires au trafic ordinaire ; vérifier sous pertes/rejeu actifs et surcharge CPU.
- **H3 :** continuité de la racine post-quantique native avec migration transactionnelle et contrôles externes ; protéger les futurs secrets sans prétendre effacer les compromissions historiques.
- **H4 :** Quantic ID/Pay : divulgation sélective plus confidentialité post-quantique, à comparer aux portefeuilles et normes EUDI avant toute revendication d'originalité.

Ces hypothèses demandent des jeux de données indépendants, des tests adversariaux, la recherche d'antériorités et, pour les protocoles, une analyse cryptographique extérieure.

## Barrières de sécurité maintenues

La branche de migration contient déjà des expériences de copie par blocs, journal, stockage Windows et coordination de relais de laboratoire. Elles ne prouvent pas la migration complète des vraies identités. Les secrets historiques exportables du Web, la résistance aux écritures concurrentes, la cohérence entre relais et la capacité de retour arrière nécessitent encore des validations. **Ni bascule d'un vrai compte, ni suppression de clé, ni activation de paiement ou chiffrement propriétaire n'est autorisée par ce travail.**
