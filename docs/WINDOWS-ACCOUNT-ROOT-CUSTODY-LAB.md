# Secure Core V2 — coffre Windows expérimental pour racine ML-DSA-65

**Date : 23 novembre 2026.** Limite essentielle : ce composant est destiné à des **identités synthétiques non enrôlées**. Il n'autorise ni migration réelle, ni révocation, ni nettoyage de l'ancien IndexedDB, ni paiements. Il est distinct de la clé post-quantique d'appareil (ML-KEM + ML-DSA) existante.

## Implémentation

Fichier `labs/quantic-native/vault/windows_account_root.go` (Windows x64, CGO, OpenSSL 3 récent avec ML-DSA-65, système NTFS local).

- Crée une **racine de compte ML-DSA-65 distincte** des clés de signature et de chiffrement de l'appareil. La clé privée est générée par le fournisseur OpenSSL, puis encodée en PKCS#8 pour être chiffrée. Elle n'est **pas** non exportable et peut se retrouver en mémoire du processus après déchiffrement.
- Stocke l'archive dans `account-root.pq.vault`, AES-256-GCM, PBKDF2-HMAC-SHA-256 (600 000 itérations, sel aléatoire 16 octets, nonce 12 octets), en utilisant les primitives existantes du laboratoire. Le domaine authentifié lie l'application, le quorum, l'adresse, l'ID appareil, les pins P-256 et les pins ML-KEM/ML-DSA de l'appareil.
- Crée le fichier exclusivement (`CREATE_NEW`), sur NTFS fixe, avec contrôle DACL propriétaire/SYSTEM, absence de point de réanalyse/hardlink et `FILE_FLAG_WRITE_THROUGH` ; refuse une seconde création et ne répare pas automatiquement un état partiel.
- À la réouverture, exige une **empreinte SHA-256 externe et préalablement conservée** de la clé publique SPKI ML-DSA. Teste la possession de la racine par une signature ML-DSA sur un nouveau challenge aléatoire de 32 octets lié au contexte. Une substitution d'archive avec une autre racine, une altération AES-GCM ou une phrase secrète incorrecte sont refusées.
- Ne propose que deux commandes locales avec consentement Windows explicite. Aucune API Web ou renderer n'est ajoutée. Aucun endpoint de création/révocation sur une vraie identité.
- Le rapport ne contient ni PKCS#8 privé, ni mot de passe, ni challenge, ni signature réutilisable. Il indique `hardwareNonExportable:false`, `nativeAccountEnrolled:false`, `realIdentityMigrationAuthorized:false` et `legacyKeyDeletionAuthorized:false`.

## Opérations locales

Ces commandes supposent un coffre Windows **neuf, synthétique, déjà provisionné** et les empreintes connues par une voie indépendante :

```text
Vault.exe --provision-windows-account-root-lab <private-directory> <app-public> <quorum-pin> <canonical-address> <device-id> <classical-sign-pin> <classical-encryption-pin> <device-kem-pin> <device-dsa-pin>

Vault.exe --verify-windows-account-root-lab <private-directory> <app-public> <quorum-pin> <canonical-address> <device-id> <classical-sign-pin> <classical-encryption-pin> <device-kem-pin> <device-dsa-pin> <EXPECTED-ACCOUNT-ROOT-PIN>
```

Ces commandes sont refusées sans le fournisseur Windows PQ et les invites exigent une phrase secrète forte **saisie localement**. Le pin public de sortie de la première commande **doit être conservé indépendamment du coffre et du terminal** ; le relire depuis le même disque compromis ne permettrait pas de détecter sa substitution.

## Tests sur un véritable runner Windows

`go test -tags pqopenssl -run '^TestWindowsAccountRoot' -v .`

- Création de deux clés distinctes (racine de compte et ML-DSA d'appareil), non réutilisation de la racine.
- Relecture et signature de possession après fermeture des handles, **dans un deuxième processus système** sans clé privée héritée.
- Refus du mauvais mot de passe, d'une racine de substitution, d'un autre contexte cryptographique, d'un fichier chiffré altéré et de la création par-dessus un fichier existant.
- Refus d'un dossier privé non provisionné.

Les tests **ne représentent pas un redémarrage de la machine**, ni une coupure électrique. Il faut encore réaliser ces essais sur une machine Windows physique hors GitHub Actions, avec verrouillage, extinction brutale et récupération.

## Limites de sécurité et ordre des prochains travaux

**Ce n'est pas encore une racine matérielle souveraine.** Sans TPM obligatoire, une clé logicielle persistante peut être exfiltrée après compromission du processus, récupération de la phrase secrète, accès mémoire ou déchiffrement sur un poste contrôlé par l'attaquant. Le durcissement NTFS limite certaines attaques locales mais n'arrête pas un administrateur malveillant ni un malware exécuté sous le compte propriétaire.

Pour protéger efficacement la racine : concevoir une **custody multi-facteur optionnelle et indépendante de l'OS**, éventuellement avec deux supports physiques distincts ou un module matériel portable, audit de la collecte de phrase secrète, résistance aux sauvegardes/restaurations abusives, journal externe de non-rollback et mécanisme de récupération quorumaire. Ne jamais présenter un simple contrôle ACL ou un test de signature comme une preuve de protection contre l'exfiltration.

L'étape suivante est de relier ce pin de racine **conservé indépendamment** à la vérification de filiation de la PR #51 et à un registre de confiance protégé, avant toute inscription réelle. Le présent composant n'émet aucune autorisation de migration ni de révocation.
