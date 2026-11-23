# Quantic Scattering — preuve conditionnelle de confidentialité, V0.7 (23 novembre 2026)

**Démonstration mathématique sous hypothèses + vérification exhaustive sur un petit corps fini.**
**Ce document NE prouve PAS une sécurité de bout en bout, un taux de 99,99999 %, une superposition quantique, ni une distorsion relativiste réelle.**

## Énoncé précis

Soit un secret S dans un corps fini F_p, p premier supérieur au nombre de relais. Pour chaque époque e, on tire indépendamment et uniformément les coefficients a_(e,1), ..., a_(e,t-1), sans dépendance envers S. On définit f_e(X) = S + a_(e,1) X + ... + a_(e,t-1) X^(t-1) mod p, et chaque relais reçoit au plus une évaluation distincte, à un x non nul.

**Propriété :** si l'adversaire apprend strictement moins de t parts de CHAQUE époque, ne récupère aucun coefficient interne, ne lit aucune copie ancienne autrement que celles comptabilisées et ne possède pas de canal auxiliaire, alors la distribution conjointe de ses parts observées est identique pour tout secret S. Formellement, pour tout s,s' et toute observation admissible v, Pr[V=v | S=s] = Pr[V=v | S=s']. La fuite d'information de Shannon est I(S;V)=0.

**Démonstration :** pour k<t positions non nulles distinctes x_1,...,x_k, les évaluations observées vérifient Y = S*1 + V*A, où V est une matrice de Vandermonde tronquée de dimensions k × (t-1). Sur F_p, V possède rang k, donc avec A uniformément tiré sur F_p^(t-1), Y est uniforme sur F_p^k pour chaque S. La distribution n'est donc pas fonction de S. Les polynômes des époques étant tirés indépendamment (sauf la constante S), leur vraisemblance se factorise, et la distribution conjointe reste indépendante de S. Pour t positions d'une même époque, l'interpolation de Lagrange retrouve exactement S.

Cette démonstration est une propriété de **partage parfait de type Shamir et de tirages indépendants**, pas d'une innovation cryptographique exclusive de Quantic. Les propriétés correspondantes ont été étudiées par Shamir (1979) puis par les protocoles de partage proactif, Herzberg et al. (1995).

Références :
- https://people.cs.pitt.edu/~litman/courses/cs2001/lectures/lecture-02-p612-shamir.pdf
- https://cris.biu.ac.il/en/publications/proactive-secret-sharing-or-how-to-cope-with-perpetual-leakage/
- https://crypto.stanford.edu/cs359c/17sp/notes/lec8a.pdf

## Vérification exhaustive exécutable

Le programme indépendant est labs/quantic-native/scattering/threshold-secrecy-proof-v07.mjs avec corps F_17, n=5, t=3, et f(x)=s+a*x+b*x*x (mod 17).

1. Il énumère les **10 paires** de positions parmi 5, les **17 secrets** possibles, les **289 couples** de coefficients par secret : **49 130** expériences exhaustives de confidentialité à deux parts. Pour chaque secret, les **289 valeurs possibles** d'une paire de parts surviennent chacune exactement une fois : la distribution est la même quel que soit le secret.
2. Il énumère les **10 triplets** de positions parmi 5, les **17 secrets** et les **289 polynômes** : **49 130** reconstructions exhaustives. Chaque triplet d'une même époque retrouve le secret exact.
3. Il confronte une capture de deux parts anciennes et de deux parts nouvelles, avec les coefficients renouvelés et indépendants : **les 17 secrets restent également compatibles**.
4. **Contrôle négatif** : trois parts d'une même époque reconstruisent le secret. Réutiliser les parts sans les renouveler permet à un adversaire cumulant ses découvertes de retrouver le secret.
5. Les tests refusent les positions dupliquées, valeurs hors champ et champs sensibles inattendus.

Ces chiffres sont des **dénombrements exhaustifs d'un petit modèle**, PAS des tests de sécurité sur 49 130 attaques réelles ni des estimations de probabilité de piratage.

Exécuter avec Node 22+ :

    node --test tests/scattering-threshold-secrecy-proof-v07.test.mjs
    node labs/quantic-native/scattering/threshold-secrecy-proof-v07.mjs

## Le taux de 99,99999 % : où se situe la frontière ?

Si S est une clé **parfaitement uniforme de 256 bits**, si le partage idéal ne révèle aucune information sur elle, et si l'adversaire ne peut effectuer qu'une seule supposition du secret, sa meilleure probabilité de deviner le bon secret est 2^-256 (environ 8,64 × 10^-78). Avec G suppositions distinctes, la probabilité est au plus min(1, G / 2^256). **Cela ne décrit que la devinette de la clé dans ce modèle idéal**, et ne prouve pas une protection du protocole ou du produit de 99,99999 %.

Dans le laboratoire F_17, une seule supposition d'un secret uniforme réussit avec une probabilité 1/17 (environ 5,88 %) malgré une fuite nulle. « Fuite nulle » ne signifie pas « succès adverse nul ».

Un attaquant qui capture t parts valides d'une même époque reconstitue S avec certitude mathématique, sans casser AES, ML-KEM ou une quelconque géométrie temporelle.

## Hypothèses techniques non démontrées pour Quantic Sillage

- Renouvellement de parts sans reconstituer S au mauvais endroit, sans divulguer la nouvelle combinaison des coefficients, même lorsque des relais sont malveillants.
- Authentification et vérification des parts, synchronisation des époques, révocation des anciennes parts et non-réutilisation d'états après redémarrage.
- Protection des messages de rafraîchissement, absence de vol de la racine d'identité, de la mémoire et des métadonnées ; effacement réellement sûr.
- Un maximum de t-1 parts apprises par l'adversaire par époque. Cette hypothèse est un PRÉREQUIS, pas une propriété dérivée.
- Positions de relais distinctes et choix d'époques indépendants du secret.
- Protection contre la corrélation temporelle, changement de destinations, coûts et perturbations de routage. Les modèles « espace-temps » du laboratoire ne représentent pas une distorsion physique et n'offrent aucune preuve d'anonymat supplémentaire.
- Validité d'un protocole distribué proactif face à des intrusions simultanées et à un adversaire adaptatif.

**Attention :** le programme utilise le petit corps F_17, une arithmétique directe et des coefficients déterministes. Il ne peut protéger aucune clé réelle et ne doit jamais être réutilisé dans le client Windows ni sur les relais. Aucun algorithme de rafraîchissement proactif cryptographiquement sûr n'est livré ici.

## Critère de passage vers une preuve système

Définir un modèle adverse précis, un partage de secret proactive vérifiable éprouvé, une preuve de composition avec le chiffrement et le transport, puis réaliser des attaques indépendantes sur des machines physiques. Mesurer la disponibilité et les fuites de métadonnées. Faire auditer les implémentations. Tous les drapeaux de livraison réelle restent à false.
