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
