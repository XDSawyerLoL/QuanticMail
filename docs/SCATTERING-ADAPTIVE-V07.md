# Quantic Scattering V0.7 — laboratoire adaptatif isolé (23 novembre 2026)

**Statut : RECHERCHE, simulation synthétique non cryptographique.** Cette expérience ne prouve ni un anonymat réseau, ni une résistance de 99,99999 %, ni la superposition quantique ou la distorsion physique de l'espace-temps.

## Exécuter

Node 22 ou plus récent :

    node --test tests/scattering-adaptive-v07.test.mjs
    node labs/quantic-native/scattering/scattering-adaptive-v07.mjs --iterations 5000

Ce programme est hors ligne et ne consomme ni comptes, ni identités, ni clés réelles, ni adresse IP, ni messages. Le générateur pseudo-aléatoire est reproductible et impropre à la cryptographie.

## Hypothèses idéalisées

- Un secret est abstraitement réparti en **5 fragments** sur **10 relais distincts** ; 3 fragments de la même génération sont nécessaires à sa reconstruction.
- L'adversaire compromet au maximum **2 relais par génération**, selon une séquence connue ; il peut conserver les fragments volés. Cette limite est une hypothèse, et non une protection du logiciel.
- **static** : positions et fragments restent valides ; les captures s'accumulent.
- **move-only** : les positions changent, mais sans renouveler le matériel secret ; les anciennes captures restent utiles.
- **refresh** : les fragments d'une ancienne génération deviennent inutilisables par hypothèse. Il n'existe PAS d'algorithme de partage proactif ni d'effacement vérifié dans ce prototype.
- **masked-adaptive** : même renouvellement idéalisé, avec exclusion au tour suivant des relais que le détecteur supposé parfait a identifiés. La simulation échoue si les relais de rechange sont insuffisants.
- **Contrôle négatif** : si l'attaquant connaît et compromet 3 emplacements actifs dans une génération, les 4 stratégies échouent à protéger le secret.

Aucune partie de ce code n'implémente Shamir, un partage proactif vérifiable, la gestion des générations dans le transport réel, l'effacement sécurisé, la préservation du quorum, l'authentification des relais ou la tolérance aux terminaux compromis.

## Réactions actives et observables

Le distingueur artificiel n'observe que la taille (168 octets), la direction (sortante) et un délai d'événement. Dans **move-only**, une intrusion provoque une activité à 1 ms : la détection atteint **100 %**, intentionnellement. Dans **masked-adaptive**, le délai reste fixé à 20 ms indépendamment de l'intrusion : le même détecteur tombe à **50 % par construction**.

Ce n'est pas une expérience sur le réseau réel et ne démontre aucune indétectabilité : les destinations, ports, délais matériels, rafales, accusés, charges CPU et réponses applicatives ne sont pas modélisés.

## Modèle des rafales de perte

24 cellules identiques, cadence fixe ; 10 cellules contiennent deux copies de chacun des 5 fragments. Le message est récupérable dès que 3 fragments différents survivent. Les politiques de répartition temporelle sont **uniform**, **random** et **geometry** (courbe mathématique puissance 1,6, pas une géométrie relativiste). Une seule rafale contiguë de 6, 10, 14, 18 ou 20 cellules est perdue.

Cette épreuve permet d'étudier la disponibilité **dans ce modèle de perte seulement**. Elle ne constitue pas une validation de la géométrie sur des réseaux réels. Le classement varie fortement avec la longueur de rafale.

## Résultats initiaux, graine 20261123, 5 000 essais par cas

| Politique | Captures réussies en 8 générations |
| --- | ---: |
| static | 5 000/5 000 (100 %) |
| move-only | 4 896/5 000 (97,92 %) |
| refresh | 0/5 000 (0 %) |
| masked-adaptive | 0/5 000 (0 %) |

**Interprétation :** l'échec de la capture inter-générations dans les deux dernières politiques est largement une conséquence du seuil 3, de la limite de compromission à 2 par génération et du renouvellement idéal supposé. Il n'est pas une estimation de sécurité opérationnelle. Un même attaquant qui détient 3 parts dans une génération reconstitue le secret dans les 4 politiques.

## Travaux nécessaires avant toute intégration native

1. Définir un protocole de **partage proactif vérifiable** fondé sur des constructions auditées, avec protections contre les relais malveillants, l'absence de pièces, les conflits de génération, les écrasements, le vol des terminaux et la perte de quorum.
2. Comparer une couverture réelle à une couverture simulée : observer non seulement les délais et tailles mais également destinations, retransmissions, rafales, dérive et charges, avec adversaires passifs et actifs.
3. Tester indépendamment **deux machines physiques** et plusieurs relais, interruptions, redémarrages et pertes ciblées.
4. Établir une propriété de confidentialité **sous hypothèses formelles**, avec mesure d'avantage d'un adversaire, garanties de disponibilité et coûts.
5. Faire auditer le protocole avant de déplacer des secrets utilisateurs.

Aucune modification des clients Windows, des transporteurs de production, des comptes réels ou des clés existantes. Les anciennes versions restent inchangées. Les champs de sortie confidentialityProven, securityLevel9999999Proven et releaseAuthorized valent toujours false.
