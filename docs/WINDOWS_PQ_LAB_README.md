# QuanticMail Windows PQ — unsigned portable laboratory
Synthetic identities only. No production release or installer. Requires local fixed NTFS, a trusted installation directory, an attached Windows console and the bundled Node 24 runtime (pinned laboratory build; not a production security baseline). No separately installed Node, Go or OpenSSL is required by this package if its smoke tests pass. No passwords or account configuration included. SHA256SUMS is a build inventory, not an independently authenticated publisher signature.

Native executable: bin/Vault-PQ-lab.exe. The existing --provision-windows-pq-storage-lab command creates a new local encrypted identity, requires two passphrases, and refuses an existing directory. Before use, independently provisioned, ACL-validated desktop.json, controller.pem, quorum.json, contacts.json, peer TLS key/certificate files and valid classical/PQ authority grants must exist. No automatic enrollment or migration is provided. Do not copy real credentials into this test build.

Node command: .\runtime\node.exe --experimental-transform-types scripts/native-vault-windows-local.mjs ABSOLUTE_EXE_PATH TRUSTED_SHA256 PRIVATE_DIRECTORY open ABSOLUTE_WIRE_FILE. Other operations: recover-open, seal, recover-seal (last two require new wire output path). Independently establish the binary pin and installation integrity. A sealed result is saved locally, never automatically sent. The separate explicit terminal mailbox workflow is documented in AUDIT_WINDOWS_SCATTERING_MAIL_FLOW.md; it is not a feature of the file-only client. Existing Electron 38 is not a supported runtime for PQ; the future Node 24 desktop UI is not packaged here.

No power-loss, WAN or physical-machine validation is implied. Do not install as a production identity provider.

The runtime and migration-verifier import are covered by the packaged smoke test. Do not trust SHA256SUMS alone: obtain an independent authenticated expected manifest hash and publisher identity. This is not an Authenticode-signed installer, not an automatic enrollment tool, and does not authorize real account migration.

New synthetic vault provisioning generates a separate random receipt.key and completion marker. Explicit --windows-import-lab-file ABS_VAULT_DIR BASENAME INDEPENDENT_SHA256 reads bounded bytes from stdin, then requires a real console APPROVE; the native file is created with strict ACL and never overwritten. Controller PKCS8 Ed25519 PEM must match the provisioned public key. JSON/PEM import only stages input; broker still validates all authority, contact and peer data. Older incomplete directories are refused. No import of vault, journal, receipt key or historical identity; no live migration.

Before execution, use a separately trusted copy of Test-Windows-PQ-Package.ps1 and an independently authenticated SHA256 of the exact SHA256SUMS.txt. The verifier rejects modified, missing or extra files, aliases, duplicate inventory entries and reparse points. The launcher now requires ExpectedManifestSha256 as well. CI tests extra DLL and modified README refusal. Package and installation directory must remain trusted against concurrent changes; this is not an OS-enforced immutable install or Authenticode signature. A hash printed by the same untrusted package does not authenticate its publisher.

The manifest generator explicitly uses GNU sha256sum --binary. Both strict launcher and external verifier require the binary marker (space + asterisk) and exact relative paths. CI 44940681300 previously refused the noncanonical record format; no validation bypass was added.

Unified laboratory operator dashboard: after independent whole-package verification, call Start-Windows-PQ-Lab.ps1 -Operation Dashboard -ExpectedManifestSha256 EXPECTED_MANIFEST_HASH -TrustedBinarySha256 EXPECTED_VAULT_HASH from a local Windows console. Graphical action selection uses existing terminal approval tools. Synthetic identity/authority/relay configuration and independent native carrier processes are still prerequisites. This is not a signed single-file installer.

The dashboard now generates its own local Ed25519 controller key inside a new ACL-guarded vault, without an externally supplied controller secret. Public identity address and independently obtained quorum pin are still required; this does not create a remotely enrolled account. The generated controller is written before the final local completion marker; no overwrite, no legacy key import. Existing controller custody is owner/SYSTEM ACL only (same-user compromise not protected). CI tests generated key/marker/journal binding and overwrite refusal.

## Démonstration synthétique Windows (une commande)

Dans le paquet Windows vérifié, lancer depuis PowerShell :

```powershell
.\Start-Windows-PQ-Lab.ps1 -Operation MigrationSmoke `
  -ExpectedManifestSha256 VOTRE_MANIFEST_SHA256_VERIFIE `
  -TrustedBinarySha256 VOTRE_SHA256_BINAIRE_VERIFIE `
  -PrivateDirectory "C:\QuanticMigrationLab\Essai01"
```

Le dossier indiqué doit être nouveau, local et sur NTFS. Le lanceur exige les empreintes obtenues indépendamment de l'archive, vérifie le paquet puis crée uniquement des enregistrements fictifs. Les quatre collections sont chiffrées par AES-256-GCM, stockées sans écrasement par le composant Windows natif, relues dans un second processus et comparées intégralement. Le résultat attendu est `synthetic-windows-migration-smoke-passed`, sans aucune autorisation de migration ou de suppression réelle. Le laboratoire garde les fichiers pour inspection et refuse une seconde exécution dans le même dossier. Ce scénario ne vérifie ni les comptes réels, ni la continuité des relais distants, ni les coupures électriques, ni les archives supérieures à 96 Ko.

## Copie de 16 Mio interrompue et journal natif — laboratoire

Après vérification indépendante du paquet, utiliser sur Windows :
```powershell
.\Start-Windows-PQ-Lab.ps1 -Operation MigrationFullSmoke `
  -ExpectedManifestSha256 VOTRE_MANIFEST_SHA256_VERIFIE `
  -TrustedBinarySha256 VOTRE_SHA256_BINAIRE_VERIFIE `
  -PrivateDirectory "C:\QuanticMigrationLab\Essai16Mio01"
```

Le dossier cible **doit être absent**. Le lanceur prépare des
collections fictives représentant presque 16 Mio, crée une copie
source et interrompt volontairement la cible après trois blocs
chiffrés. Un autre processus reprend uniquement les blocs manquants,
relit les deux copies via l'exécutable natif Windows et compare les
quatre catégories. Deux étapes d'audit sont écrites dans des fichiers
chiffrés NTFS non réinscriptibles, vérifiés par chaîne d'empreintes.
Le verdict attendu comprend
`status:synthetic-16mib-windows-restart-passed`,
`localAuditJournalVerified:true`,
`liveRestoreAuthorized:false` et
`legacyDeletionAuthorized:false`.

Le processus n'utilise ni compte ni clé réelle, n'acquitte aucun
message distant et ne restaure aucune session. La reprise n'est pas
garantie après panne d'alimentation et le journal n'est **pas**
un commit transactionnel de production. Le contrôle séparé de la file
du relais n'examine que deux fenêtres de 100 éléments maximum et
n'atteste pas l'exhaustivité de la messagerie. Le programme et
l'installateur demeurent des laboratoires **non signés**.

## Envoi intégré depuis un brouillon déjà préparé (laboratoire)

Le lanceur vérifié propose maintenant `SealAndSend` et `RecoverSealAndSend`
avec les paramètres `PrivateDirectory`, `InputFile` (`draft-*.json`) et
`OutputFile` (`wire-*.json` nouveau), en plus des empreintes vérifiées.
L'identité synthétique, les deux autorités, les contacts et le relais
Scattering doivent être provisionnés indépendamment avant l'opération.
Le terminal demande deux approbations : chiffrer puis déposer.

Le coffre natif scelle, le stockage NTFS sauvegarde sans écraser, les
contenus chiffrés sont relus et authentifiés, **puis seulement** le relais
reçoit un unique dépôt. Le fichier signé est conservé si l'utilisateur
refuse le dépôt ou si le réseau échoue. En cas de transmission incertaine,
utiliser `Send` avec le même fichier plutôt que re-sceller le brouillon.
Aucun compte réel n'est migré ni activé par ces opérations.

Détails et exemple de commande : `AUDIT_WINDOWS_SCATTERING_MAIL_FLOW.md`.
Les tests unitaires injectent un coffre et un relais simulés ; ils ne
prouvent pas encore l'envoi entre deux PC physiques distincts.

## Deux identités PQ fictives en une opération locale

L'action **Creer deux coffres de test PQ** du tableau de bord appelle
`ProvisionPair` (ou la même opération depuis PowerShell). Elle est destinée
au **test de deux personnes sur un seul PC Windows**, pas à une installation
automatique de comptes réels ou à un réseau de production.

Avant l'opération, créer un **dossier parent de laboratoire** sur disque
fixe NTFS, **sans** sous-dossiers `participant-a` et `participant-b`.
Obtenir depuis des canaux authentifiés **deux adresses synthétiques
distinctes** et les empreintes de confiance des quorums d'autorité.
Ne pas inventer une empreinte de quorum et ne pas reprendre une identité
Web réelle. Le vérificateur de paquet et les deux empreintes du paquet
et de l'exécutable demeurent obligatoires.

Exemple de commande (remplacer chaque champ par sa vraie valeur vérifiée) :

```powershell
.\Start-Windows-PQ-Lab.ps1 -Operation ProvisionPair `
  -ExpectedManifestSha256 MANIFEST_SHA256_INDEPENDANT `
  -TrustedBinarySha256 BINAIRE_SHA256_INDEPENDANT `
  -PrivateDirectory "C:\QuanticLab\Pair" `
  -CanonicalAddress "alice~32_HEX_A@quantic" `
  -QuorumPin QUORUM_A_SHA256 `
  -SecondCanonicalAddress "bobby~32_HEX_B@quantic" `
  -SecondQuorumPin QUORUM_B_SHA256
```

Le moteur natif crée séparément `participant-a` et `participant-b`.
Pour **chaque coffre** il exige son propre accord local et **deux phrases
secrètes différentes**, directement sur la console native. Le processus
Node ne lit et ne conserve aucune de ces phrases secrètes. Il vérifie
l'identité d'appareil dérivée de la clé P-256 et les empreintes des clés
publiques P-256, ML-KEM et ML-DSA renvoyées par l'exécutable. Il ne
publie que les adresses, identifiants d'appareil et empreintes publiques
nécessaires à la suite du laboratoire. Si le premier coffre échoue, le
second n'est pas lancé.

Toute tentative d'écraser un coffre existant est refusée. Une erreur
durant la création du second peut laisser le premier correctement
provisionné : **ne pas supprimer ou réinitialiser automatiquement** les
dossiers partiels. Aucune ancienne clé n'est effacée.

Ce qu'il reste à préparer **indépendamment** avant de lancer deux PC :
les quatre autorités mTLS et leurs attestations fraîches, les contacts
et manifestes signés, l'inscription distante, les transports Scattering
et les relais des deux machines. Aucun de ces éléments n'est généré par
ce provisionneur, et le résultat signale
`remoteAuthoritiesConfigured:false`,
`nativeMailRelayConfigured:false` et
`liveAccountEnrollmentAuthorized:false`.
La commande **n'est donc pas encore une démonstration inter-PC de bout
en bout**. Les tests unitaires simulent les réponses de l'exécutable Go
et contrôlent les empreintes et les refus ; le workflow Windows valide
séparément la compilation native et l'emballage.

## Précontrôle des quatre autorités et de Scattering avant essai sur deux PC

Le tableau de bord propose `MailPreflight` (hors ligne) et `MailAttest`
(attestation mTLS fraîche de trois autorités parmi quatre). Les deux
opérations sont **strictement en lecture seule** et exigent un fichier
public de confiance dont l'empreinte SHA256 est obtenue hors bande,
ainsi que les dossiers privés distincts du coffre et du transport.

Le contrôle vérifie les racines et identités épinglées, les clés
publiques canoniques des contacts, les quatre clés Ed25519 des autorités
et leurs certificats TLS, le rôle client/relais et les ports de loopback.
Il n'affiche aucun secret, ne génère aucune attestation et ne connecte
aucun compte réel. Une réponse de laboratoire positive n'est pas
une preuve de livraison WAN ou inter-PC. Les conditions et commandes
complètes figurent dans `WINDOWS_TWO_HOST_MAIL_READINESS.md`.

## Application native `.exe` Windows — parcours d'installation Alpha

Le livrable `Quantic-Sillage-Alpha-UNSIGNED.exe` est **l'installateur**
monofichier Windows de laboratoire, et non un exécutable de messagerie
prêt pour un déploiement public. Il fonctionne sans navigateur Web
obligatoire et installe, dans le profil local de Windows, un second
programme directement lançable :

```text
%LOCALAPPDATA%\QuanticSillage\Alpha-<IDENTIFIANT_BUILD>\Quantic-Sillage-Alpha.exe
```

Ce **second fichier est une véritable application native Go/Windows**
qui s'ouvre par double-clic depuis le bureau ou le menu Démarrer.
Il vérifie d'abord les SHA-256 attendus du manifeste intégral et du
binaire de coffre post-quantique, dont les valeurs sont **incorporées
dans l'exécutable après la construction du paquet**. Le programme
lance ensuite le tableau de bord local Windows et délègue les
opérations cryptographiques aux composants natifs protégés. Il ne
tente aucune connexion au client Web supprimable et ne réactive
aucun ancien compte. Aucune empreinte modifiable n'est requise
dans les arguments du raccourci.

L'installation crée un nouveau répertoire versionné. Elle
**refuse d'écraser** une version déjà installée, un coffre,
des courriers historiques ou une sauvegarde. Le raccourci du
bureau n'est pas remplacé s'il existe déjà. Le mode de
vérification silencieuse `Quantic-Sillage-Alpha.exe --self-test`
est exercé dans GitHub Actions depuis le **dossier réellement
installé**. Ce test vérifie le démarrage et l'intégrité, pas une
connexion WAN ni la livraison d'un courriel réel.

### Conditions pour diffuser un `.exe` à d'autres utilisateurs

Le build automatique fournit actuellement **deux exécutables non
signés** : l'installateur et le programme installé. Un futur
package distribuable devra impérativement :

1. Disposer d'un certificat de signature de code au nom de
   l'éditeur légal et d'un service d'horodatage HTTPS de confiance.
   Signer le **lanceur natif avant de le placer dans l'installateur**,
   puis signer l'installateur final. Le signataire doit être le même
   et son certificat SHA-256 connu hors bande.
2. Construire l'installateur à partir du package figé, avec le
   lanceur déjà signé, puis vérifier les signatures Authenticode
   horodatées, l'intégrité des fichiers installés et le test
   `--self-test`. Le script opérateur
   `scripts/Test-Quantic-Sillage-Signed-Alpha.ps1` bloque les
   versions non signées et vérifie les deux exécutables.
3. Réaliser un vrai parcours de messagerie chiffrée sur **deux
   ordinateurs physiques**, avec les quatre autorités
   indépendantes, les connexions Scattering, le redémarrage,
   les reçus et la récupération. Les tests CI ne remplacent pas
   cette campagne.
4. Terminer la migration sans perte et l'audit indépendant avant
   toute activation de comptes réels ou diffusion de production.

**Ne pas confondre le code vert de CI avec une autorisation de
déploiement public.** Le site ou le navigateur ne constituent pas
la future application Quantic Mail : le logiciel natif est
la cible de déploiement.
