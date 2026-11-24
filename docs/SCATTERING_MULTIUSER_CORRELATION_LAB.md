# Scattering — corrélation entre deux émetteurs et un relais (24 novembre 2026)

> **Recherche uniquement, PR #63 non fusionnée.** Deux émetteurs Go natifs, un relais applicatif expérimental, un émetteur Go natif en sortie, un récepteur et trois captures `tcpdump` **passives**. Le laboratoire utilise quatre espaces réseau virtuels, sur **un seul ordinateur physique Linux**. Aucun message ou coffre utilisateur, aucune connexion à Internet, aucun déploiement.

## Modèle adversarial explicite

L'observateur peut capturer les paquets sur **les deux interfaces d'entrée** du relais et **son interface de sortie**, connaître à quel émetteur de laboratoire appartient chaque lien et comparer les 168 octets d'une cellule par égalité SHA-256. Il ne possède pas de clé de déchiffrement. Il ne cherche ni l'identité civile d'un utilisateur ni à déchiffrer le corps. La comparaison **d'octets à octets** ne couvre pas les attaques de corrélation temporelle lorsque les contenus changent.

Le protocole d'essai est volontairement **négatif** dans sa première variante : le relais transfère les cellules identiques vers une file de l'émetteur natif, avec une cadence de sortie fixe (20 ms). Ce relais n'est **pas** un mixnet anonyme. Les deux pacers sources ont chacun une cadence fixe de 50 ms. Une cellule retransmise garde exactement les mêmes octets : c'est un signal de corrélation trivial malgré le remplissage par couverture.

## Exécution CI indépendante

[Workflow multi-utilisateur](https://github.com/XDSawyerLoL/QuanticMail/actions/runs/45350120763) : quatre jobs **réussis**. Capture des deux interfaces d'entrée et de l'interface de sortie ; les fichiers PCAP synthétiques et les clés éphémères sont détruits par le script, jamais publiés comme artefacts.

| Essai (une exécution) | Cellules entrée A+B | Sortie Go | Paquets sortie capturés | Cellules entrée reconnues par égalité | Réception authentifiée |
|---|---:|---:|---:|---:|---:|
| Relais opaque, sans perturbation | 100+100 | 550 | 550 | **200/200** | non applicable |
| Relais opaque, charge CPU concurrente (4 tâches) | 100+100 | 550 | 550 | **200/200** | non applicable |
| Relais opaque, perte 6 % + 25 ± 6 ms sur lien sortant | 100+100 | 550 | 512 | **185/200** | non applicable |
| Relais de confiance, déchiffrement puis AES-256-GCM avec nouvelle clé de saut | 100+100 | 550 | 550 | **0/200** | **200/200** |

Le taux de perte de 6 % est **paramétré**, non mesuré comme exactement 6 %. Le scénario CPU ajoute quatre tâches concurrentes mais n'établit pas une saturation matérielle. Le compteur `sent` de Go reflète l'émission acceptée par le socket, pas la livraison sur Internet. La source des mesures est le journal GitHub de chaque job, pas une simulation mathématique.

## Ce que le rechiffrement montre réellement

Le fichier `lib/quantic/scattering-hop-reseal-lab.mjs` vérifie l'authenticité des paquets entrants à l'aide des clés de saut de laboratoire, puis recrée une cellule de 168 octets avec un nouveau nonce et une **autre clé de saut**, sans conserver le texte chiffré visible à l'entrée. Le récepteur authentifie 200 cellules, avec 0 rejeu ; les 350 autres cellules en sortie sont la couverture native, normale et sans authentification du laboratoire. `tests/scattering-hop-reseal.test.mjs` vérifie le roundtrip, la non-égalité du chiffré, le refus de clés incorrectes, d'altérations et de cellules de couverture.

**Mais le relais possède les clés permettant de déchiffrer le contenu utile intermédiaire.** Cette architecture de preuve n'est donc **pas** une solution à la compromission d'un relais ni une protection de bout en bout. La disparition du lien par comparaison directe ne prouve **aucun anonymat** contre les attaques statistiques ou les corrélations temporelles d'un observateur global.

## Exécuter localement sur Linux de laboratoire

```bash
cd labs/quantic-native/scattering/native
go build -trimpath -o /tmp/Quantic-Pacer .
cd ../../../..
node --test tests/scattering-multihop-observer.test.mjs tests/scattering-hop-reseal.test.mjs
bash scripts/scattering-multihop-netns-lab.sh /tmp/Quantic-Pacer
SCATTERING_MULTIHOP_IMPAIRMENT=1 bash scripts/scattering-multihop-netns-lab.sh /tmp/Quantic-Pacer
SCATTERING_MULTIHOP_CPU_LOAD=1 bash scripts/scattering-multihop-netns-lab.sh /tmp/Quantic-Pacer
SCATTERING_MULTIHOP_RESEAL=1 bash scripts/scattering-multihop-netns-lab.sh /tmp/Quantic-Pacer
```

Ces commandes nécessitent `iproute2`, `tcpdump`, `sudo`, Go 1.23+, Node 22+, les permissions de création d'espaces réseau et une **machine de test uniquement**. Le script supprime les namespaces, captures et clés de laboratoire en sortie.

## Exigences avant une éventuelle architecture transport

1. Construire un **véritable protocole multicouche cryptographique** où aucun relais individuel ne détient de secrets de bout en bout et où la liaison entrée/sortie n'est pas exposée par les identifiants ou les tailles.
2. Mesurer la corrélation **temporelle** malgré le rechiffrement : fenêtres d'activité, populations déséquilibrées, répétitions à plusieurs dizaines d'émetteurs et relais compromis. Comparer avec trafic de couverture équivalent et intervalles de confiance.
3. Confronter les résultats aux pertes, au réordonnancement, aux retransmissions, à l'emballement CPU, aux pannes de relais et à un **vrai réseau entre machines physiques indépendantes**.
4. Auditer la protection des clés, le secret futur, les risques de compromission, la livraison durable et la récupération d'identité avant toute bascule d'un utilisateur.

**Bilan : l'égalité directe entre cellules est éliminée par la transformation testée ; l'anonymat global, la sécurité d'un relais compromis et la robustesse WAN ne sont pas démontrés.** Aucune fonction en production ne dépend de ce laboratoire.
