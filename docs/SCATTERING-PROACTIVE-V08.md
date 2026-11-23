# Quantic Scattering V0.8 — Proactive Secret Sharing (LAB ONLY)

**Statut : démonstrateur cryptographique sur cinq processus Node.js indépendants, hors production.**

Ce n'est ni une preuve d'anonymat de bout en bout, ni une certification post-quantique, ni une protection démontrée à 99,99999 %. **Ne pas connecter ce prototype à Identity Vault, Quantic ID, Quantic Mail, Quantic Pay, un coffre réel ou un transport public.**

## Architecture vérifiable

- Cinq processus enfants, cinq identités Ed25519 distinctes, cinq clés temporaires X25519 signées pour chaque époque. Coordination par IPC local et non par réseau physique.
- Seuil 3/5 : chaque processus crée un polynôme aléatoire de degré 2 dans un corps premier de 3071 bits (sous-groupe de RFC 3526 MODP15). Initialisation distribuée : le secret est la somme des constantes des cinq polynômes ; le coordinateur ne reçoit que signatures, engagements et ciphertexts.
- Les engagements Pedersen sur les coefficients sont C_j=g^(a_j) h^(b_j) (mod p), dans un sous-groupe d'ordre premier q. Le générateur h est dérivé d'une chaîne publique par hachage SHAKE256 et mise au carré dans le groupe. La liaison des engagements dépend de la difficulté du logarithme discret et de l'absence de relation connue entre g et h. L'aveuglement aléatoire donne une propriété de confidentialité informationnelle sous hypothèses.
- Chaque fragment et son aveuglement sont chiffrés dans une enveloppe X25519 + HKDF-SHA256 + AES-256-GCM, liée au destinataire, à l'époque, au dealer, aux manifestes et aux engagements. Le dealer signe l'enveloppe ; le destinataire vérifie la signature, l'AEAD et l'engagement Pedersen.
- Pour chaque renouvellement, **chacun des cinq dealers** propose un polynôme de modification de constante **zéro**, avec engagement de la constante et ouverture de son facteur aveuglant. Les autres coefficients sont nouveaux et indépendants. Les destinataires additionnent leurs nouvelles parts à l'ancien partage sans reconstruire le secret.
- Les cinq destinataires signent leur approbation du même engagement global. Le coordinateur ne déclenche la mise à jour en mémoire que lorsqu'il possède les cinq approbations valides. Aucun vrai consensus atomique entre machines n'est implémenté.
- La commande de récupération de parts est délibérément accessible en mode **laboratoire uniquement** afin de valider la reconstruction. Elle **ne doit jamais être conservée** dans une implémentation de production.

## Vérifications et contrôles négatifs

Les tests couvrent :
- initialisation, renouvellement sur deux époques et reconstruction correcte avec 3 fragments malgré changement des parts ;
- deux fragments insuffisants : un secret distinct peut produire les mêmes observations ;
- signature ou ciphertext modifié, paquet rejoué depuis une génération précédente, paquet manquant et engagement substitué : refus avant validation de la génération ;
- preuve d'une constante nulle à chaque renouvellement ; rejet d'une constante non nulle correctement signée ;
- liaison du ciphertext aux métadonnées, rejet AEAD en cas de modification.

**Ce que la preuve mathématique dit :** si les polynômes de chaque génération utilisent des coefficients indépendants, si moins de 3 parts valides sont compromises par génération et si les détails de renouvellement sont confidentiels, les observations de parts ne révèlent aucune information sur le secret. Les engagements Pedersen et le chiffrement des échanges sont des mécanismes supplémentaires, sous leurs hypothèses propres.

**Ce que ces tests ne démontrent pas :** absence de fuites mémoire, indépendance physique, résistance de l'implémentation à un adversaire adaptatif, transport réseau indécelable, protection des adresses IP, confidentialité des métadonnées, disponibilité face à un dealer malveillant, sécurité sous compromis de la machine hôte, ou probabilité universelle de 10^-7.

## Limites bloquantes avant une production

1. **Pas encore post-quantique :** Ed25519, X25519 et la liaison des engagements Pedersen reposent sur des hypothèses vulnérables à un ordinateur quantique suffisamment puissant. Les standards hybrides/PQ et une construction VSS auditée adéquate sont nécessaires.
2. **Pas de garantie durable** : mémoires de processus uniquement ; aucune écriture atomique multi-relai, aucun journal transactionnel, aucune restauration, aucun certificat de consensus entre nœuds physiques. Après une panne au mauvais moment, les processus peuvent diverger.
3. **Pas de garantie d'effacement** : les objets BigInt et les clés privées gérés par Node.js ne sont pas garantis effacés de RAM, même si les anciennes références sont abandonnées. L'observation de clés de transport anciennes ou de la mémoire peut casser les hypothèses proactives.
4. **Aucune tolérance au dealer absent ou malveillant** : le protocole exige 5 approbations sur 5. Un seul participant peut bloquer la progression. Cette stratégie est volontairement restrictive pour le laboratoire.
5. **Données et métadonnées de transport identifiables** : 25 transmissions chiffrées par génération, taille de ciphertext constante (768 octets), mais taille totale des paquets et schéma d'activité différents suivant la phase. Les destinations sont exposées au coordinateur. Ce n'est pas une protection contre l'analyse du trafic ou l'effet espace-temps.
6. **Pas de vraie démonstration sur le réseau** : les cinq relais communiquent à travers le coordinateur local via IPC. Il faut deux machines physiques au minimum, une capture indépendante de trafic, des essais de perte, rejeu, dérive, charge CPU, redémarrage et corruption pendant un commit.
7. **Revue cryptographique externe indispensable** : implémentation illustrative et non bibliothèque auditée, ce qui interdit toute donnée utilisateur réelle et toute diffusion en tant qu'outil de sécurité.

## Reproduction

Avec Node 22+ à la racine du dépôt :

    node --test tests/scattering-proactive-v08.test.mjs

Le processus lance cinq sous-processus et ne requiert aucune API, domaine, connexion Internet ni secret utilisateur. L'état est détruit lorsque le laboratoire se termine. Les tests cryptographiques consomment plusieurs dizaines de secondes ; utiliser le workflow dédié GitHub Actions pour la répétabilité.

Références scientifiques : A. Shamir (1979), T. P. Pedersen (CRYPTO 1991), Herzberg et al. (CRYPTO 1995). Pour les limites de transparence et de liaisons des engagements : https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/ ; https://www.cs.cornell.edu/courses/cs754/2001fa/339.PDF

**Drapeaux de confiance :** `prodIntegrationAuthorized=false`, `endToEndAnonymityProven=false`, `protection9999999Proven=false`, `postQuantumEndToEnd=false`, `independentSecurityAudit=false`.
