# Scattering — première borne mathématique conditionnelle (2026-11-23)

**Statut : résultat mathématique élémentaire sous hypothèses de laboratoire, pas preuve d'anonymat du réseau.** Aucune autorisation de diffusion, sécurité revendiquée ou activation d'utilisateurs réels.

## Question très limitée

Un adversaire reçoit **un seul paquet** échantillonné indépendamment dans une des deux classes équiprobables : trafic réel ou trafic de couverture. Il ne voit que trois attributs publics regroupés en 24 catégories préétablies :

- `packetBytes` : inférieur à 168 / exactement 168 / supérieur à 168 ;
- `gapMs` : inférieur à 10 / [10,50[ / [50,200[ / supérieur ou égal à 200 ;
- `direction` : entrant / sortant.

Il **ne voit pas** les IP, destinataires, horaires absolus, rafales, paquets précédents ou suivants, contenu chiffré, résultats ACK, échecs de réseau ou actions d'adversaire. Des différences de taille *au sein* d'une même catégorie ne sont pas détectées par cette analyse. Les échantillons de chaque classe doivent être IID, collectés sans biais selon le même modèle. Ces hypothèses sont généralement difficiles à justifier sur un vrai réseau.

## Borne statistique

Soient `P` et `Q` les lois inconnues de ces 24 catégories, et `P_hat`, `Q_hat` les fréquences calculées sur `n_real` et `n_cover` observations indépendantes. Leur distance en variation totale est :

`TV(P,Q) = 1/2 * sum_i |P_i - Q_i|`

Pour chaque classe, Hoeffding et une borne de l'union donnent, avec un risque total `alpha` :

`eps_X = sqrt(log(4*k/alpha)/(2*n_X))`, `k=24`.

Par l'inégalité triangulaire, avec une probabilité au moins `1-alpha` sur les échantillons :

`TV(P,Q) <= min(1, TV(P_hat,Q_hat) + k/2*(eps_real + eps_cover))`.

Pour un test de Neyman–Pearson optimal et des prioris égaux sur ces **seules** catégories, le taux de classification maximal vaut `(1 + TV(P,Q))/2`, donc la borne supérieure de confiance sur ce taux vaut `(1 + upperTV)/2`.

Cette dérivation ne nécessite aucune hypothèse de normalité, mais suppose l'IID et la complétude de l'alphabet observé ; elle n'implique aucune résistance post-quantique ni indistinguabilité cryptographique du transport.

## Exploitation

`labs/quantic-native/scattering/statistical-bound.mjs` accepte des comptages agrégés :

```json
{
  "real": [0,0,0,0,0,0,0,0,0,0,0,1000000,0,0,0,0,0,0,0,0,0,0,0,0],
  "cover": [0,0,0,0,0,0,0,0,0,0,0,1000000,0,0,0,0,0,0,0,0,0,0,0,0]
}
```

La fonction exportée `countLabMetadata(records)` transforme exclusivement des tableaux de métadonnées locales annotées `kind`, taille, gap et direction en 24 compteurs. Les adresses, contenus et jetons sont refusés. L'analyse agrégée ne lit pas de secrets.

```sh
node --test tests/scattering-statistical-bound.test.mjs
node labs/quantic-native/scattering/statistical-bound.mjs --input /path/to/local-aggregate.json
```

Avec un petit nombre d'observations, la borne peut être `1`, c'est-à-dire **aucune information utile** sur l'anonymat ; il ne faut pas conclure à la sécurité sur la base d'un bon score empirique. Inversement, une forte variation totale empirique révèle une fuite possible dans ce modèle.

## Invariants de prudence

- `endToEndAnonymityProven = false` et `releaseAuthorized = false` **toujours**.
- Aucun échantillon de laboratoire ne prouve l'IID d'un réseau physique.
- Un observateur actif, un observateur global, un adversaire voyant des sessions entières ou un dispositif de corrélation peut être **beaucoup** plus puissant.
- Avant toute revendication réelle : modèle formel de protocole, adversaires distincts, preuve et revue indépendantes, capture physique, hypothèses de charge et mesure des compromis bande passante / latence / disponibilité.

Le travail ouvre une piste mesurable pour Scattering ; il n'est pas un nouveau théorème d'anonymat.
