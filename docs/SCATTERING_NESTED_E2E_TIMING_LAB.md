# Scattering : double enveloppe chiffrée, relais et observateur temporel

**État : laboratoire isolé sur GitHub, 24 novembre 2026 ; PR #63 en brouillon.**

## Objectif de l'expérience

Conserver des cellules UDP de **168 octets** et une émission régulière tout en empêchant qu'un relais déchiffrant **sa couche de transport** ne découvre le contenu d'application transporté.

La nouvelle enveloppe interne est indépendante des clés de relais :

- **Contenu synthétique :** 59 octets, plus un octet d'émetteur et quatre octets de séquence, tous chiffrés par AES-256-GCM avec un nonce aléatoire (12 octets) et un tag (16 octets). Résultat : 92 octets.
- **Enveloppe du premier saut :** le contenu interne de 92 octets est déposé dans la cellule RC2 AES-256-GCM de 168 octets.
- **Relais :** il ouvre uniquement la couche extérieure avec la clé de saut entrée, transfère les **92 octets toujours chiffrés**, puis crée une nouvelle couche extérieure avec une clé indépendante vers le destinataire. Il n'a **aucun besoin de la clé interne** pour transférer le paquet.
- **Destinataire :** il ouvre la couche extérieure, puis l'enveloppe interne avec la clé de laboratoire réservée aux terminaux ; il décompte l'authenticité et les messages de chaque émetteur, sans exporter leurs données.

**Important :** ce n'est pas une conception de mixnet validée ni un protocole de messagerie complet. Un relais connaît les adresses de son entrée et de sa sortie, peut supprimer des données et observer des métadonnées. Le contenu interne ne reste confidentiel que si la clé interne n'est pas compromise. Les deux émetteurs partagent ici une même clé de laboratoire, et tous les espaces réseau utilisent un système de fichiers Linux commun : un attaquant contrôlant le système de test avec des privilèges suffisants pourrait retrouver cette clé. Le test **ne valide donc pas une isolation forte des clés**. AES-256-GCM n'est pas, à lui seul, une construction post-quantique.

## Résultats mesurés

[Exécution GitHub du parcours complet](https://github.com/XDSawyerLoL/QuanticMail/actions/runs/45353401925) : les cinq jobs du laboratoire multi-utilisateur ont réussi, dont le nouveau mode `recipient-only-nested-e2e`.

- 100 paquets préparés/émis par l'émetteur A, 100 par B, et 200/200 cellules acceptées par le relais (pour le test considéré).
- 550 cellules de sortie émises par le pacer natif, 168 octets chacune ; zéro échéance native manquée.
- 200/200 cellules d'application récupérées et authentifiées **par les deux couches** à destination ; 100 attribuées à A et 100 à B, zéro répétition détectée dans l'essai.
- 0/200 cellule reliée à son entrée par **égalité directe de contenu chiffré** ; 350 cellules restantes sont des paquets de couverture produits par le pacer Go.
- Ces résultats proviennent de **quatre espaces réseau sur un seul hôte physique**, pas d'un WAN indépendant.

[Exécution GitHub de l'observateur temporel](https://github.com/XDSawyerLoL/QuanticMail/actions/runs/45353863232) : les cinq jobs ont réussi.

L'attaque testée prend **uniquement les horaires** des paquets entrants (A/B) et sortants ; pour chaque sortie, elle choisit le dernier paquet entrant observé dans une fenêtre fixe de 250 ms (égalité en faveur de A). **Aucune clé ni étiquette de message ne lui est fournie.** Après la prédiction, un évaluateur indépendant, qui connaît les clés de laboratoire, déchiffre les cellules pour déterminer l'émetteur réel *à des fins de mesure seulement*.

| Métrique, un essai | Résultat |
|---|---:|
| Messages authentifiés dont on connaît la source | 200 (100 A + 100 B) |
| Attributions temporelles correctes | 100/200 = 50 % |
| Attributions temporelles incorrectes | 100/200 |
| Référence majoritaire sur ce trafic parfaitement équilibré | 50 % |
| Couverture ne portant aucun message interne | 350 cellules |
| Couvertures faussement attribuées à une source | 60/350 (17,14 %) |

**Interprétation limitée :** un classificateur temporel élémentaire n'a fait ici **pas mieux que le hasard**, en présence de deux sources parfaitement équilibrées et simultanément actives. Cela ne donne **aucune borne de sécurité** et ne démontre pas que des modèles plus puissants ou davantage de données échoueraient. L'observateur reçoit une étiquette oracle *pour le calcul de la précision sur les vrais messages*, ce qui favorise sa mesure ; en situation réelle, il ne peut pas séparer directement les vrais messages des couvertures. Aucun intervalle de confiance n'est établi.

## Code reproductible

- `lib/quantic/scattering-e2e-envelope-lab.mjs` : double enveloppe et vérification AES-GCM.
- `tests/scattering-e2e-envelope.test.mjs` : rotation des nonces, séparation des clés, refus de clés erronées et paquets corrompus.
- `scripts/scattering-e2e-sender-lab.mjs` / `scripts/scattering-e2e-receiver-lab.mjs` : démonstration entre vrais processus réseau Go et terminal de vérification.
- `lib/quantic/scattering-temporal-correlation-lab.mjs` : attaque temporelle sans clé et évaluateur hors ligne avec vérité issue du chiffrement.
- `tests/scattering-temporal-correlation.test.mjs` : détecteur reproductible, faux positifs de couverture et refus d'évaluer avec une mauvaise clé.
- `scripts/scattering-multihop-netns-lab.sh` : montage de quatre espaces réseau, suppression de la topologie, des captures et des clés après l'expérience.

Sous Linux avec Go 1.23+, Node 22+, `iproute2`, `tcpdump` et un droit `sudo` de laboratoire :

```bash
cd labs/quantic-native/scattering/native
go build -trimpath -o /tmp/Quantic-Pacer .
cd ../../../..
node --test tests/scattering-e2e-envelope.test.mjs tests/scattering-temporal-correlation.test.mjs
SCATTERING_MULTIHOP_RESEAL=1 SCATTERING_MULTIHOP_E2E=1 \
  bash scripts/scattering-multihop-netns-lab.sh /tmp/Quantic-Pacer
```

**Pas d'exécution sur un ordinateur contenant des clés de production**, pas de modification des comptes Quantic Mail ou Identity Vault. Le relais et le destinataire sont des composants jetables de laboratoire, et ce code ne doit pas être déployé comme produit.

## Verrous résiduels (non résolus)

1. Vraie séparation de privilèges entre machines et entre coffres : impossible de déduire l'isolation des clés d'un simple namespace réseau partageant le système de fichiers.
2. Protocoles **multiples relais et cryptographie multicouche** à étudier, avec un modèle de confiance et de compromission explicite.
3. Analyse temporelle préenregistrée, répétée, avec **sources déséquilibrées, périodes inactives, relais compromis et adversaires entraînés**. Résultat ci-dessus insuffisant pour une revendication d'anonymat.
4. Couverture durable, gestion des clés, rotation, suppression, préclés, authentification, résistance au rejeu complet, retransmission et récupération fiables sous véritable perte de réseau.
5. Essais sur deux machines physiques puis sur plusieurs sites indépendants, en mesurant le coût mémoire/CPU, débit, latence et débits de couverture.

**Aucune confidentialité ou supériorité globale n'est démontrée au-delà de la fonction locale d'enveloppe et des attaques précises testées.**
