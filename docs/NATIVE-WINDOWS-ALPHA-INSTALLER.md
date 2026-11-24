# Quantic Sillage Alpha — installer natif Windows

État au 23 novembre 2026. **Laboratoire uniquement — aucune identité réelle, migration ou transaction.**

## État du parcours graphique de test — 23 novembre 2026

Sur la branche UX de la PR #57, le lanceur ouvre le tableau de bord **sans console PowerShell en arrière-plan**.
Le premier parcours Quantic Mail est **« Rédiger un message (sans terminal) »** : choix d'un coffre **de test déjà provisionné**, sélection d'un contact présent dans le carnet local, objet et texte. Aucun nom `draft-nom.json` n'est demandé ; le nom technique est choisi automatiquement, avec refus de tout écrasement et relecture du fichier.

**Protection de stockage de la PR #58 : le brouillon est maintenant chiffré avant toute écriture sur disque.** Le processus natif Go utilise Windows DPAPI en mode utilisateur courant, sans sauvegarde en clair, avec une entropie supplémentaire liée au chemin et une enveloppe versionnée `QSD2`. Le stockage NTFS conserve la création exclusive et les ACL. Le lecteur natif refuse les brouillons JSON historiques en clair, les modifications de ciphertext, les déplacements vers un autre nom et les accès avec un autre profil non autorisé. Le déchiffrement est effectué uniquement par le processus Go vérifié et transmis via un pipe local au contrôleur de laboratoire. **Ce n'est pas un chiffrement post-quantique ni une solution portable entre OS ou utilisateurs**, et un malware agissant avec les droits du même utilisateur ou un poste compromis restent des menaces. Cette protection **ne remplace pas** le futur coffre Quantic natif indépendant du système. Aucun compte réel ni envoi n'est autorisé. L'interface de signature et d'envoi sans terminal demeure un chantier distinct.

Les opérations historiques de laboratoire restent accessibles après un consentement explicite ouvrant **une console technique distincte**. Elles ne font pas partie du parcours standard. L'installateur demeure non signé.

## Autotest interactif des boites de dialogue Windows — 24 novembre 2026

Depuis le tableau de bord natif, ouvrir **DIAGNOSTIC → Tester les fenêtres de sécurité Windows**. L'essai ne nécessite **aucun coffre** ni mot de passe réel : il déclenche la vraie boite de confirmation native (répondre OUI), un dialogue Windows CredUI masqué pour recopier un code temporaire affiché dans la fenêtre, puis une autorisation OUI et un refus NON. Le résultat est validé dans le processus Go natif déjà épinglé par SHA-256.

La commande `Vault-PQ-lab.exe --windows-gui-operator-check-lab` est **délibérément interactive** ; elle refuse les environnements Windows sans station graphique visible et les arguments supplémentaires. Aucune clé, aucun compte, aucune donnée utilisateur, aucune connexion réseau ou modification de configuration n'est impliqué. Les tests CI couvrent le contrat et la compilation mais **ne prouvent pas** qu'un humain a ouvert et manipulé les dialogues. L'acceptation finale doit être constatée sur un poste Windows réel, avec les clics OUI/OUI/NON et la saisie du code d'essai. Ne jamais entrer une vraie phrase secrète dans le test.

Le test ne remplace ni un audit du poste, ni une preuve de réception du courrier sur un deuxième ordinateur, ni une signature d'éditeur. Tant qu'un certificat de signature de code valide et vérifié n'est pas disponible, l'exécutable d'installation reste une Alpha **non signée** ; ne pas contourner SmartScreen sur un poste sensible.

## Historique des essais locaux — PR #61

Le bouton **« Mes essais locaux »** lit uniquement l'inventaire privé du coffre à travers son binaire Go natif déjà vérifié : les brouillons DPAPI sont authentifiés lors de la lecture, les enveloppes sont simplement recensées sans déduire leur validité cryptographique. Il montre des états **« Brouillon protégé — non envoyé »** ou **« Enveloppe locale présente — livraison inconnue »**. Il ne supprime, ne renvoie et ne déchiffre aucun courrier à l'écran. Les fichiers JSON ne sont jamais demandés à l'utilisateur. Aucune présence de fichier n'est interprétée comme une confirmation de livraison.

## Nouveau mode GUI du coffre — PR #61 (laboratoire uniquement)

Deux boutons sont présents dans l'éditeur de test : **« Enregistrer mon brouillon »** et **« Chiffrer et déposer (test) »**. Le second passe par des confirmations Win32 natives et le fournisseur post-quantique déjà présent. Le coffre ne lit plus les phrases secrètes dans un terminal lorsqu'il est lancé explicitement avec le mode `--broker-windows-pq-quorum-gui-lab` ; le mode terminal reste disponible séparément pour l'ingénierie. Les phrases secrètes sont saisies directement dans une fenêtre Windows CredUI avec persistance interdite. Les autorisations par opération exigent un consentement explicite dont le choix par défaut est le refus.

Le dépôt sur **relais local** ne signifie pas livraison sur un autre poste, ni lecture. Toute erreur incertaine conserve le brouillon ou l'enveloppe qui peut déjà exister ; il n'y a aucun renvoi automatique. La validation ne peut fonctionner qu'avec un coffre, un contact et les attestations de confiance fictifs déjà configurés ; aucune identité réelle ni clé historique n'est reprise. Le mode graphique d'essai refuse les grands messages tant que sa fenêtre de confirmation ne peut pas présenter le texte intégral. La signature de l'installateur, la migration native, les essais indépendants sur deux ordinateurs et les essais GUI réellement interactifs restent bloquants.

**Dépendance transitoire :** les brouillons utilisent Windows DPAPI CurrentUser, pas une clé Quantic post-quantique indépendante de l'OS. Le mécanisme est propre à ce laboratoire Windows ; il ne satisfait pas encore l'objectif final de portabilité Quantic Sillage.

## Fichier installable

Le workflow `.github/workflows/native-vault-lab.yml` compile le coffre Go/OpenSSL ML-KEM-768/ML-DSA-65, le pacer Scattering natif, les scripts du contrôleur et l'interface Windows Forms. Il assemble d'abord un paquet local vérifiable par `SHA256SUMS.txt`, puis fabrique un installateur NSIS unique :

`Quantic-Sillage-Alpha-UNSIGNED.exe`

Cet installateur **n'est pas signé**. Il est volontairement publié uniquement dans les **artefacts temporaires GitHub Actions**, nommés `Quantic-Sillage-Alpha-UNSIGNED-Installer` (durée de conservation : 7 jours), avec le fichier d'empreinte SHA-256. Il ne doit **pas** être présenté comme une version prête au déploiement public ni exécuté sur un poste contenant de vraies identités Quantic.

Pour récupérer l'artefact de test : ouvrir la dernière exécution réussie du workflow *Native Vault laboratory* sur la branche de développement, section **Artifacts**. Le ZIP Actions contient l'exécutable et son fichier `.sha256`. Vérifier indépendamment la provenance du commit et l'empreinte du téléchargement. **SmartScreen peut avertir à cause de l'absence de signature éditeur ; ne contournez pas les avertissements sur un poste sensible.**

## Fonctionnement

- Installation **par utilisateur** sous `%LOCALAPPDATA%\QuanticSillage\Alpha-<commit>`, sans droits administrateur et sans installer de composants dans le navigateur.
- **Une version ne remplace jamais une version précédente** : si le dossier de ce commit existe, l'installation échoue plutôt que d'écraser les fichiers. Les coffres utilisateurs sont provisionnés dans leurs propres répertoires privés, en dehors du paquet.
- Raccourcis **Menu Démarrer** et **Bureau** vers la même interface locale Windows Forms, avec les empreintes SHA-256 attendues du manifeste et du binaire Go gravées à la compilation.
- Lors du lancement, `Start-Windows-PQ-Lab.ps1` vérifie d'abord l'empreinte du manifeste et l'inventaire complet des fichiers (`Test-Windows-PQ-Package.ps1`), puis le binaire Go. Aucune URL Web n'est chargée comme client.
- Interface regroupée dans six sections : **Quantic Mail**, **Quantic ID**, **Identity Vault**, **Scattering**, **Quantic Pay — lab**, **Diagnostic**. Toutes les opérations existantes restent en mode test. Les phrases secrètes continuent d'être saisies dans le terminal local du coffre ; elles ne passent pas par une page Web.
- Les opérations Mail requièrent encore la configuration et les attestations de confiance du laboratoire. Les fonctions Pay sont des simulations. L'absence de configuration valide doit produire un refus, non une création automatique de compte ou une opération réelle.

## Validations réalisées dans les GitHub Actions

1. Tests Go et OpenSSL du coffre Windows natif : création et déchiffrement ML-KEM, signature ML-DSA, fichiers NTFS privés, reprise du journal, quarantaine des erreurs.
2. Test PowerShell `DashboardCheck`, exécution **réelle** de Windows Forms en mode auto-test : affectation et sélection de chacun des six modules, contrôle des champs, protection contre traversée de chemins.
3. Test NSIS réel : compilation de l'exécutable, installation silencieuse sur un runner Windows, vérification de l'intégralité des fichiers installés, refus d'une réinstallation sur le même dossier, contrôle des raccourcis Bureau/Menu Démarrer, lecture des empreintes intégrées et lancement du diagnostic cryptographique natif **depuis les fichiers installés**.
4. Contrôle négatif de signature : l'installateur **non signé doit être refusé** par `Test-Native-Installer-Signature.ps1`.

## Désinstallation Alpha propre (build isolé)

Le paquet installe `Uninstall-Quantic-Sillage-Alpha.exe` dans son dossier de build et un raccourci **Désinstaller Alpha** dans le menu Démarrer. Ce désinstallateur n'est pas un nettoyeur général de profil utilisateur.

- À la compilation, `build-alpha-uninstall-inventory.mjs` énumère les **fichiers effectivement inclus** et génère des instructions NSIS de suppression explicites ; aucun `RMDir /r` n'est autorisé.
- Avant toute suppression, chaque répertoire connu est contrôlé pour refuser les jonctions NTFS et points de réanalyse afin d'éviter une redirection vers des données privées.
- Le dossier `%LOCALAPPDATA%\\QuanticSillage\\Alpha-<commit>` est fixe, sans chemin de désinstallation fourni par l'appelant. Les fichiers inconnus et les dossiers non vides restent en place.
- Les coffres privés hors paquet, les identités existantes et les autres builds Alpha ne sont **pas** visés. Aucune purge de données utilisateur n'est proposée.
- La CI Windows doit vérifier installation, refus d'écrasement, désinstallation silencieuse et survie d'un fichier étranger dans le dossier installé ainsi que d'un coffre synthétique privé. Tant que ce test n'est pas vert, la fonctionnalité reste **non validée**.

## Publication et mises à jour

La chaîne de signature existe dans `scripts/Sign-Native-Lab-Installer.ps1` mais requiert un **véritable certificat de signature de code** autorisé, sa clé privée conservée hors du dépôt, une empreinte publique d'éditeur approuvée indépendamment, Windows SDK SignTool et un service d'horodatage HTTPS. Ni certificat ni signature ne sont générés fictivement dans la CI. Pas de mise à jour automatique d'un binaire non signé.

L'étape de distribution suivante doit fournir un flux **version signée → téléchargement vérifié → installation dans un nouveau dossier → nouvelle vérification des empreintes et de la signature**. Il ne doit jamais écraser le coffre ni désinstaller automatiquement les anciens secrets.

## Blocages avant ouverture réelle

Le chemin Windows natif reste une **Alpha** : pas de véritable enrôlement de compte, pas de migration définitive, pas de continuité de racine installée partout, pas de paiement réel, pas de validation d'indistinguabilité Scattering à deux postes physiques. Les travaux de filiation PQ de la PR #51 et de racine de compte isolée de la PR #52 ne sont pas implicitement inclus dans cette branche. Une revue de sécurité, la signature de l'installateur et la migration avec retour arrière sont encore indispensables.

Le client Web historique reste disponible pour les besoins des **comptes existants** jusqu'à ce que la continuité et la restitution native soient prouvées. L'ancienne enveloppe Electron Web, elle, est explicitement bloquée par la PR #53.
