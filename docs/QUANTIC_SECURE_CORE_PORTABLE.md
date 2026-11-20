# Quantic Secure Core — stockage cryptographique portable

## Décision du 20 novembre 2026

Quantic ID et Quantic Mail utilisent un format de coffre ouvert, indépendant du système d'exploitation et du réseau de transport. Quantic Network n'est **ni requis ni présumé disponible** ; aucun projet Quantic OS n'est une condition de cette architecture. Aucun composant Microsoft DPAPI, Apple Keychain, Google Play Services ni compte GAFAM n'est une condition de déchiffrement. Les stockages système restent des adaptateurs facultatifs.

## Prototype QSC1

Le fichier .qsc est binaire, non un fichier JSON d'identité en clair. En-tête de 40 octets : marqueur QSC1 (4), version (1), suite (1), réserve (2), sel HKDF (16), nonce AES-GCM (12) et longueur de charge chiffrée big-endian (4). La charge chiffrée inclut une étiquette de 16 octets.

Primitives standards : AES-256-GCM, HKDF-SHA-256, sel et nonce nouveaux pour chaque écriture. La clé d'enregistrement dépend de la racine et du contexte Quantic ID, espace applicatif et identifiant de l'enregistrement. Ce contexte et l'en-tête sont authentifiés. Implémentation Web Crypto standard, sans dépendance d'OS.

Ce composant est une bibliothèque cryptographique et des tests : **il n'est pas encore connecté au stockage réel d'Identity Vault ni de Mail**.

## Protection et possession des clés

La racine de 256 bits doit venir d'une autorisation Quantic ID indépendante du fichier. Le module expose une fonction d'importation de clé temporaire **destinée aux essais et adaptateurs contrôlés**. Une CryptoKey marquée non exportable par Web Crypto ne garantit pas qu'elle réside dans le matériel : cette distinction est impérative.

Architecture cible : service Quantic ID Secure Core isolé qui conserve la racine et exécute les opérations de signature, chiffrement et déchiffrement pour les applications autorisées. Quantic Mail ne reçoit ni les clés privées principales, ni un deuxième mot de passe de compte.

Déverrouillage sans second mot de passe Mail : authentificateur FIDO2 compatible PRF ou hmac-secret avec présence utilisateur, ou adaptateur optionnel de matériel sécurisé (TPM2, Secure Element, etc.). La prise en charge réelle doit être vérifiée. Une identité uniquement liée à un secret stocké sur le même disque ne résiste pas à sa copie ; si aucun facteur indépendant n'existe, ne pas promettre cette protection.

Récupération facultative : phrase détenue par l'utilisateur et dérivation Argon2id selon RFC 9106 avec paramètres calibrés par matériel. Argon2id et les mécanismes de récupération ne sont **pas implémentés dans ce prototype**.

## Indépendance de Quantic Network

Quantic Network est **facultatif** : aucune clé privée, identité, dérivation cryptographique, récupération ou ouverture du coffre ne doit dépendre d'un service Quantic Network, d'un relais propriétaire ou d'un serveur central. Le coeur QSC1 fonctionne hors ligne pour les opérations locales.

Quantic Mail doit disposer d'une interface de transport interchangeable : livraison via relais Quantic indépendants, relais autohébergés, fédération ouverte ou P2P lorsqu'il est techniquement disponible. Le réseau Internet est nécessaire à la livraison entre machines distantes, mais un produit nommé Quantic Network ne l'est pas.

Séparer strictement la sécurité de l'identité du transport : un relais voit les seules informations indispensables au routage et ne doit ni détenir la clé privée de l'utilisateur, ni décider à lui seul de son identité. La livraison entre deux réseaux avec NAT, la découverte de pairs, les métadonnées et la tolérance aux pannes restent à valider par des tests réels. Aucune indépendance totale n'est encore démontrée par ce prototype.

## Transition depuis l'existant

Le fichier Identity Vault PC chiffré aujourd'hui par Electron safeStorage / Windows DPAPI ne peut pas être simplement copié et déchiffré dans un autre système d'exploitation. Il doit être ouvert une dernière fois dans son environnement d'origine, re-chiffré dans QSC1, et vérifié avant bascule. Ne jamais effacer l'ancien coffre avant validation et sauvegarde.

Les clés Mail JWK exportables en IndexedDB, les préclés, le mode portable avec fichier de jeton adjacent, ainsi que relay-identity.json contenant une clé PEM demandent des migrations séparées. Ces données **ne sont pas encore protégées par QSC1**. L'historique des messages, la confidentialité des métadonnées et les sauvegardes sont des chantiers distincts.

## Menaces et critères d'acceptation

La copie de fichiers ne doit pas suffire à déchiffrer ; mauvais Quantic ID, mauvais contexte, altération et mauvaise clé doivent être rejetés. Tester Windows et Linux avec le même fichier et différents adaptateurs de déverrouillage ; valider le déverrouillage réel, la révocation, les écritures atomiques et la migration non destructive.

Un logiciel malveillant exécuté dans une session déverrouillée, une injection de code, un périphérique détourné ou la capture de l'écran ne sont pas résolus par le seul format QSC1. Audit cryptographique indépendant requis avant déploiement stable.