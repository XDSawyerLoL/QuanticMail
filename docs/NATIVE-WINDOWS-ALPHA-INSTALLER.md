# Quantic Sillage Alpha — installer natif Windows

État au 23 novembre 2026. **Laboratoire uniquement — aucune identité réelle, migration ou transaction.**

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
