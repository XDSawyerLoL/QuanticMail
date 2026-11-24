# Scattering — laboratoire comparatif de couverture et mélange (23 novembre 2026)

**Laboratoire de simulation uniquement, sans déploiement.** Ce travail s'appuie sur la branche native de la PR #48, le paquet Scattering de 168 octets et les profils de cadence existants. Il ne modifie ni l'émetteur Go, ni les clés, ni la messagerie, ni la réception, ni les utilisateurs.

## Exécution

```bash
node --test tests/scattering-mix-comparison.test.mjs
node scripts/scattering-compare-lab.mjs
node scripts/scattering-compare-lab.mjs --seed=7 --arrivalProbability=0.30
```

Le scénario par défaut est **déterministe** : 12 000 slots de 50 ms (600 secondes), 2 cellules/slot, 168 octets/cellule, 4 cellules par événement avec probabilité 0,15 par slot, files de 512 cellules, mélange par blocs de 8 slots. Le générateur pseudo-aléatoire sert uniquement à reproduire les résultats et n'est **pas** une source cryptographique.

Trois variantes, mêmes arrivées synthétiques et même budget de service **moyen** :

1. **Couverture constante :** envoie 2 cellules à chaque slot (messages utiles ou couverture).
2. **Lots sans couverture :** publie au maximum 16 cellules réelles toutes les 8 périodes ; les périodes sans messages n'émettent rien. Son débit **instantané** est donc supérieur à celui des autres solutions.
3. **Hybride couverture + lots :** rassemble et réordonne des cellules synthétiques par lots puis les transmet à cadence constante, complétées par de la couverture. Ce réordonnancement n'est pas un mixnet cryptographique.

## Résultats locaux du scénario par défaut

| Profil | Cellules émises / 600 s | Go/j, un sens | p95 de délai | Perdues | Restantes en file |
|---|---:|---:|---:|---:|---:|
| Couverture constante | 24 000 | 0,580608 | 100 ms | 0 | 0 |
| Lots sans couverture | 7 268 | 0,175827 | 350 ms | 0 | 0 |
| Hybride | 24 000 | 0,580608 | 500 ms | 0 | 2 |

Ces résultats sont ceux d'un **modèle de file idéal** ; ils ne proviennent pas d'une capture réseau physique. Le chiffre « Go/j » est une extrapolation d'émission **unidirectionnelle**, excluant les en-têtes IP/UDP, les accusés de réception et les réémissions. Les cellules « restantes en file » ne sont pas perdues.

Le mode sans couverture économise ici environ 69,7 % de bande passante mais expose fortement les périodes de trafic. **L'hybride ne réduit pas la bande passante face au flux constant et augmente les délais dans ce scénario.** Cette mesure interdit de prétendre à un progrès d'indécelabilité ou d'efficacité à ce stade.

## Limites du modèle d'attaquant

L'observateur simulé ne voit **que le nombre de cellules sortantes par slot** et compare une séquence active à une séquence inactive. Les deux solutions à cadence constante ont le même profil de comptes de paquets ; les lots sans couverture diffèrent. Cela ne constitue **aucune preuve d'anonymat**, d'indistinguabilité globale, de résistance à la corrélation, de confidentialité du destinataire ou de résistance à la compromission.

Hors du modèle : temps d'arrivée et IP d'entrée, IP de sortie, relais compromis, plusieurs utilisateurs, pertes, congestion, horloge, CPU, signatures des en-têtes, injection adversaire, redémarrages, fiabilité réelle, clés, et routage multi-sauts.

## Conditions minimales avant toute évolution du vrai transport

1. Garder les tests de cadence, d'authenticité, d'anti-rejeu, de perte, de retransmission et de reprise Windows/Linux existants.
2. Définir **avant** implémentation un jeu d'anonymat, l'observateur et les métriques d'avantage de l'adversaire, avec plusieurs utilisateurs et relais dont certains compromis.
3. Comparer à trafic et capacité comparables les captures indépendantes de plusieurs machines physiques : flux réel et inactif, surtension CPU, pertes, redémarrage, délai et volume. Quantifier les intervalles de confiance.
4. Ne proposer un changement de protocole que si les objectifs conjoints de fiabilité, confidentialité **et** économie de bande passante sont démontrés et vérifiés par un audit indépendant.

**Ne pas déployer et ne pas migrer d'identité sur la base de ce laboratoire.**


## Deuxième étape : attribution des émetteurs par un observateur

```bash
node --test tests/scattering-multiplex-linkability.test.mjs tests/scattering-batch-observer.test.mjs
node scripts/scattering-observer-lab.mjs
```

### Fait vérifié dans le multiplexeur de laboratoire existant

Dans `lib/quantic/scattering-multiplex-lab.mjs`, le format de la cellule multiplexée préfixe un identifiant pseudonyme de 16 octets, dérivé pour chaque membre et pour une époque donnée. Cet identifiant est **constant pour les cellules du même membre pendant cette époque** : un observateur extérieur peut donc regrouper ces cellules sans les déchiffrer. Le passage à une époque différente change l'identifiant. **Sans autre information, cela ne donne pas automatiquement le nom réel de l'émetteur.** Un relais connaissant la correspondance, ou un adversaire disposant d'une liaison externe, pourrait toutefois attribuer les cellules à leur source. Le code existant se présente explicitement comme laboratoire avec passerelle de confiance, pas comme mixnet anonyme.

`tests/scattering-multiplex-linkability.test.mjs` introduit cette **contre-épreuve de traçabilité** : même longueur de cellule et corps chiffré ne suffisent pas à éliminer le regroupement par métadonnée visible. Ne pas annoncer d'anonymat du multiplexeur existant.

### Hypothèse mathématique : fenêtre de mélange parfaite à plusieurs utilisateurs

`lib/quantic/scattering-batch-observer-lab.mjs` mesure une **attribution de source conditionnelle** par un observateur qui connaît les décomptes d'entrée de chaque utilisateur par fenêtre. Les cellules seraient ensuite parfaitement et secrètement permutées au sein d'une fenêtre, sans identifiant de routage ni autre fuite. La meilleure décision pour un paquet de cette fenêtre est alors d'attribuer le paquet à l'émetteur le plus fréquent. Cette mesure ne modélise ni le routage réel ni un adversaire Internet complet. Elle n'est **pas une preuve cryptographique**.

Paramètres reproductibles par défaut : 12 émetteurs, 6 400 périodes, 24 répétitions indépendantes, fenêtres de 1/8/32 périodes. Arrivées Bernoulli par émetteur et période ; charges équilibrées faibles (0,005), élevées (0,06) et charge déséquilibrée (0,03, un émetteur multiplié par 8). Le générateur synthétique ne sert jamais à la cryptographie. Les intervalles à 95 % sont des estimations normales de dispersion entre graines de simulation, et **non** des intervalles de sécurité réelle.

Pour une fenêtre de 8 périodes, mesures locales dans le modèle idéal :

| Scénario | Taux moyen de meilleure attribution à un émetteur |
|---|---:|
| Faible activité, équilibrée | 80,96 % |
| Forte activité, équilibrée | 30,33 % |
| Forte activité, émetteur dominant | 46,43 % |

Ces pourcentages sont des taux de réussite **dans le modèle d'observation inventé**, pas les probabilités de piratage de Quantic Sillage. Une correspondance connue entre pseudonyme visible et identité supprime le bénéfice de permutation ; un pseudonyme sans correspondance connue autorise déjà le regroupement, mais pas nécessairement l'identification nominative.

**Conséquence technique :** un mélange par lots n'est potentiellement utile que s'il existe un véritable ensemble d'utilisateurs partageant le trajet, que les étiquettes de source/routage ne survivent pas au mélange observable et que la fiabilité et le trafic de couverture restent acceptables. La priorité suivante est un essai à deux hôtes avec capture réseau indépendante et une spécification de l'adversaire, avant tout changement de protocole.
