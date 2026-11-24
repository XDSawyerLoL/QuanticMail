# Windows Scattering mail client (laboratory)
Separate terminal entry point scripts/native-vault-windows-mailbox.mjs takes binary, independently trusted SHA256, private vault directory, operation, private file path. Only explicit windowsScattering configuration with enabled:true, address/deviceId matching PQ account, loopback HTTP endpoint, token, and receiptKeyFile equal to vault/receipt.key. The local loopback bridge is separately started and trusted; loopback itself does not authenticate the process or prove remote carrier usage. No direct remote HTTP fallback. The 32-byte independent receipt key and configuration must be provisioned out of band with strict NTFS ACLs; no enrollment or production migration.
send reads an existing signed wire, explicitly deposits it; no automatic resend. receive and recover-receive pull, ask local approval, use the native broker, encrypt receipt, write exclusively with native write-through, reread and authenticate before acknowledging. confirm-receipt uses stored authenticated receipt and exact relay recover before acknowledgement. Failed write or reread prevents ACK. Tests mock the controller and relay separately, not end-to-end. Physical power loss and actual authorities plus WAN not verified. Private normal-mode Electron UI remains unchanged. No account keys moved.

## Chaîne intégrée Windows — rédaction, scellement, dépôt

Une nouvelle opération de terminal relie le coffre postquantique local et le
client du relais Scattering : `SealAndSend`. Après vérification **indépendante**
du manifeste du paquet et de l'empreinte du binaire natif :

```powershell
.\Start-Windows-PQ-Lab.ps1 -Operation SealAndSend `
  -ExpectedManifestSha256 EMPREINTE_MANIFEST_VERIFIEE `
  -TrustedBinarySha256 EMPREINTE_BINAIRE_VERIFIEE `
  -PrivateDirectory "C:\Quantic\private" `
  -InputFile "C:\Quantic\private\draft-exemple.json" `
  -OutputFile "C:\Quantic\private\wire-exemple.json"
```

Ce parcours exige toujours une identité **synthétique déjà provisionnée**,
les contacts attestés par deux autorités et un transport local
`windowsScattering` explicitement configuré. Il n'autoprovisionne pas les
certificats, les relais ni un compte Quantic ID réel.

1. Lit le brouillon privé et refuse toute identité expéditrice différente
   du coffre ou toute destination invalide.
2. Affiche l'objet, le texte et le destinataire dans le terminal et exige une
   première confirmation locale.
3. Demande au **broker natif** de chiffrer et signer en hybride P-256 /
   ML-KEM-768 / ML-DSA-65, sans exporter de clé privée.
4. Crée le fichier `wire-*.json` **sans écraser** d'ancien résultat, via
   l'écriture exclusive et synchronisée du stockage natif Windows ; ferme le
   contrôleur puis relit les octets depuis le stockage et vérifie exactement
   l'empreinte et le contenu chiffré.
5. Exige une seconde confirmation explicite avant **un seul** appel de
   dépôt au relais. Le résultat renvoie uniquement identifiant et empreinte
   du message, sans contenu clair.

Si la sauvegarde ou sa relecture échoue, **aucun dépôt n'est lancé**.
Si la dernière confirmation est refusée, le fichier signé demeure
disponible pour `Send`. Si la connexion échoue après transmission, il
n'existe **aucun réessai automatique** : le même `wire-*.json` doit
être conservé et, après vérification, retransmis avec l'opération `Send`
existante, qui utilise la déduplication exacte du relais.

`RecoverSealAndSend` impose le même processus mais demande au broker
natif la récupération exacte d'un scellement interrompu ; elle ne crée
pas volontairement une nouvelle opération cryptographique. Un
fichier `wire-*.json` déjà présent ne peut jamais être écrasé.

Le test `tests/native-windows-integrated-mail.test.mjs` vérifie
les deux confirmations, la persistance avant réseau, le refus d'écraser,
les brouillons incohérents, les écritures échouées, les fichiers altérés,
la conservation du résultat en cas de transport ambigu et l'absence
d'envoi automatique. Il injecte un faux broker et un faux relais ;
la CI valide séparément les véritables briques cryptographiques
et la messagerie native. La chaîne complète sur deux ordinateurs
physiques, la continuité des comptes Web existants et le lancement
commercial restent non démontrés.

**Les nouvelles opérations n'activent jamais la migration de vraies
identités ni la suppression d'anciennes clés.**
