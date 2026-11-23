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
