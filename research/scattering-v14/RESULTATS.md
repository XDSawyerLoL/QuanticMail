# Résultats de recherche Scattering V1.4 — 23 novembre 2026

**Conditions** : 5 000 répétitions synthétiques par attaque ; paquet fixe 168 octets ; 28 paquets par fenêtre ; 16 fragments Reed–Solomon, huit suffisent ; clés de banc de test non secrètes ; une seule fenêtre et un seul message utile au maximum. Les comparaisons sont exploratoires (aucune validation terrain ou brevetabilité établie).

| Attaque simulée | Stratifié public | Stratifié à clé | Uniforme à clé | Antipodal à clé |
|---|---:|---:|---:|---:|
| Pertes indépendantes 2 % | 100,00 % | 100,00 % | 100,00 % | 100,00 % |
| Rafale continue 14 | 100,00 % | 90,10 % | 65,24 % | 100,00 % |
| Deux rafales 7+7 (possibles recouvrements) | 100,00 % | 82,60 % | 65,10 % | 70,48 % |
| Suppression des 14 premiers | 100,00 % | 100,00 % | 66,14 % | 100,00 % |
| Suppression des 14 derniers | 100,00 % | 100,00 % | 64,12 % | 100,00 % |
| 14 suppressions aléatoires | 66,02 % | 65,38 % | 65,60 % | 65,88 % |
| 9 positions publiques connues ciblées | 0,00 % | 98,48 % | 99,78 % | 99,98 % |
| 9 positions formant quatre paires antipodales + une | 100,00 % | 100,00 % | 99,82 % | 96,62 % |
| 14 positions formant sept paires antipodales | 100,00 % | 100,00 % | 64,56 % | 70,76 % |

## Garantie démontrable mais circonscrite

Chaque paire antipodale se compose de deux créneaux distants de 14 positions dans un anneau de 28 créneaux. Toute séquence continue de 14 créneaux contient exactement l'un des deux éléments de chaque paire. Si 8 paires sont choisies, exactement huit fragments survivent à une unique rafale de 14 pertes ; le Reed–Solomon 8/16 retrouve le message. Ce n'est pas une garantie si d'autres pertes se produisent dans la même fenêtre.

## Échec et incertitude

Le placement antipodal est loin d'être universel : une attaque de 14 suppressions visant sept paires antipodales fait tomber le taux de récupération autour de 70,76 % dans l'échantillon. La clé compromise permet à l'adversaire de cibler neuf fragments authentiques et de faire échouer systématiquement la reconstruction.

L'indécelabilité du message a été modélisée au seul niveau du nombre et de la taille des paquets : le débit extérieur est strictement identique dans les deux hypothèses, **par construction**. L'anonymat de bout en bout, les traces TCP/UDP, la dérive temporelle, les en-têtes IP, les adresses et les signatures d'OS ne sont pas masqués par le laboratoire.

**Décision** : recherche isolée avec vérification de chiffrement, anti-rejeu et reconstruction, sans intégration à la production. Le nom « antipodal à clé » est une désignation de prototype, pas une revendication d'invention ou de priorité scientifique.
