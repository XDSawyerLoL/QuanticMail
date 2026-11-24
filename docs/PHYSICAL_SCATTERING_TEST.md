# Essai physique Scattering — couverture UDP uniquement

Le paquet Windows contient désormais le véritable pacer/sink Go. Le script de diagnostic n'utilise aucun compte ni clé et ne transmet que des paquets aléatoires de 168 octets. Le test local automatisé n'est pas une preuve WAN.

Préparation : deux ordinateurs distincts, Windows ou Linux (binaire compilé pour l'OS), Node 24, réseau autorisé, une adresse IPv4 joignable du récepteur et un port UDP explicitement autorisé. Ne modifiez pas automatiquement pare-feu, routeur ou NAT ; si aucun chemin direct n'existe, noter le blocage. Un VPN change l'observateur et ne vaut pas un test Internet direct.

## Parcours graphique Windows (LAN prive)

Installer le meme build sur deux PC du meme reseau prive autorise. Sur B,
choisir "Scattering - tester la reception sur ce PC", selectionner son
IPv4 locale et confirmer. Sur A, choisir "Scattering - tester l'envoi vers
un autre PC", saisir l'IPv4 de B et confirmer pendant la fenetre de
reception de 60 secondes. Les deux fenetres s'executent sans console.
Relever le nombre de paquets et le P95 affiche par B, puis inverser
les roles. Aucun changement automatique du pare-feu ; UDP 49001 doit
etre autorise sur le reseau de test. Les adresses publiques, loopback
et multicast sont refusees dans ce parcours. Ce test de couverture
n'est pas un test de messagerie ni une preuve d'indistinguabilite.

## Parcours technique existant

Sur B, lancer : node scripts/scattering-physical-probe.mjs receive C:\chemin\Scattering-Pacer.exe IP_LOCALE_B 49001 60

Sur A, immédiatement après : node scripts/scattering-physical-probe.mjs send C:\chemin\Scattering-Pacer.exe IP_JOIGNABLE_B 49001 30

Refaire dans l'autre sens. Conserver les sorties JSON locales, le nombre de paquets envoyés et reçus et les intervalles médian, p95 et maximum. Ne publier aucune adresse réseau personnelle. Comparer à l'objectif de 50 paquets/s ; les pertes, les paquets malformés et le retard doivent être rapportés. Une réception non nulle établit seulement une connectivité, pas l'absence de pertes ni l'identité de l'expéditeur. Les paquets ne sont pas authentifiés dans ce test : une injection peut fausser les résultats. Le réseau de test doit être sous contrôle.

Étape suivante : exécuter le pont de messagerie Scattering avec les vraies enveloppes synthétiques authentifiées et mesures indépendantes, tester arrêt du consommateur et reprise, puis comparer couverture et trafic réel via capture externe. Le pont complet distant reste Linux uniquement à ce stade. Ce diagnostic ne constitue ni une migration ni une validation intégrale du produit.
