# Quantic Sillage Alpha — installer natif Windows

État au 23 novembre 2026. **Laboratoire uniquement — aucune identité réelle, migration ou transaction.**

## État du parcours graphique de test — 23 novembre 2026

Sur la branche UX de la PR #57, le lanceur ouvre le tableau de bord **sans console PowerShell en arrière-plan**.
Le premier parcours Quantic Mail est **« Rédiger un message (sans terminal) »** : choix d'un coffre **de test déjà provisionné**, sélection d'un contact présent dans le carnet local, objet et texte. Aucun nom `draft-nom.json` n'est demandé ; le nom technique est choisi automatiquement, avec refus de tout écrasement et relecture du fichier.

**Limite critique : le brouillon enregistré est en clair dans un dossier privé NTFS.** Ses ACL protègent contre des comptes non autorisés dans le modèle de test, mais pas contre un malware opérant sous le même compte. Le logiciel demande un accord explicite et interdit de considérer cette fonction comme adaptée à de vrais messages ou à un déploiement. Le chiffrement des brouillons au repos et la signature/envoi sans console nécessitent un futur dialogue natif de secrets et d'approbations, sans contournement du coffre. Aucune transmission ni création d'identité réelle n'est effectuée par le composeur.

Les opérations historiques de laboratoire restent accessibles après un consentement explicite ouvrant **une console technique distincte**. Elles ne font pas partie du parcours standard. L'installateur demeure non signé.

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

## Vérifier les véritables fenêtres de sécurité Windows

Dans l'Alpha Windows, ouvrir **Quantic Mail → Rédiger un message** puis choisir **Tester les fenêtres de sécurité Windows**. Ce diagnostic ne demande ni coffre, ni contact, ni fichier technique, ni accès réseau.

1. Accepter le dialogue d'autorisation Windows. Un refus est considéré comme un test non validé.
2. Dans la fenêtre Windows de saisie, taper exclusivement la phrase **`ALPHA-TEST-ONLY`**, jamais une vraie phrase secrète. L'application doit confirmer que les deux fenêtres fonctionnent.
3. Aucune clé ou identité n'est chargée : l'exécutable natif renvoie uniquement un état constant `windows-native-credential-dialogs-verified`, `labOnly=true`, `vaultOpened=false`, `networkUsed=false`. Le mot de passe fictif est effacé de la mémoire native après vérification.

Une annulation, un mauvais texte, un terminal sans dialogue graphique ou un processus bloqué donnent **échec**. Une compilation CI réussie ne remplace pas ce test sur un poste Windows disposant d'un bureau interactif. Cette vérification ne démontre pas l'envoi ni la réception entre deux ordinateurs.

## Essai d'envoi chiffré sans terminal (branche de laboratoire)

Le composeur Windows propose désormais, en plus de l'enregistrement du brouillon, une action **Chiffrer et déposer (test uniquement)**. C'est un prototype, **pas** une messagerie générale déployable.

- Le coffre de test et le destinataire sont sélectionnés graphiquement. Le sujet et le contenu passent seulement par un pipe local privé vers Node ; aucune phrase secrète n'est transmise à Node, PowerShell, une ligne de commande, un fichier de configuration ou une URL.
- Le broker Go utilise le dialogue de credentials natif Windows avec persistance interdite, et exige une approbation explicite locale. Le mode console historique reste séparé.
- Le brouillon en clair est conservé dans le dossier NTFS privé de laboratoire. L'enveloppe signée et chiffrée PQ est écrite une seule fois, synchronisée, relue et vérifiée **avant** d'autoriser un dépôt sur le relais Scattering déjà configuré.
- Une deuxième confirmation graphique est exigée avant le dépôt, sans nouvel essai automatique si le résultat réseau est incertain. Un dépôt local confirmé **ne prouve pas** une réception, une lecture ni une livraison sur un deuxième ordinateur.
- Cette nouvelle voie doit encore subir la compilation Windows, les tests de paquet, un test interactif sur deux vrais PC et une revue des dialogues et de la gestion des secrets. L'absence de console dans le test CI n'est pas une preuve de sécurité face à un PC compromis. Elle demeure interdite pour les comptes réels.
- Les anciennes identités, messages et sauvegardes sont conservés. Aucune suppression, migration définitive ni paiement réel n'est autorisé.

## Publication et mises à jour

La chaîne de signature existe dans `scripts/Sign-Native-Lab-Installer.ps1` mais requiert un **véritable certificat de signature de code** autorisé, sa clé privée conservée hors du dépôt, une empreinte publique d'éditeur approuvée indépendamment, Windows SDK SignTool et un service d'horodatage HTTPS. Ni certificat ni signature ne sont générés fictivement dans la CI. Pas de mise à jour automatique d'un binaire non signé.

L'étape de distribution suivante doit fournir un flux **version signée → téléchargement vérifié → installation dans un nouveau dossier → nouvelle vérification des empreintes et de la signature**. Il ne doit jamais écraser le coffre ni désinstaller automatiquement les anciens secrets.

## Blocages avant ouverture réelle

Le chemin Windows natif reste une **Alpha** : pas de véritable enrôlement de compte, pas de migration définitive, pas de continuité de racine installée partout, pas de paiement réel, pas de validation d'indistinguabilité Scattering à deux postes physiques. Les travaux de filiation PQ de la PR #51 et de racine de compte isolée de la PR #52 ne sont pas implicitement inclus dans cette branche. Une revue de sécurité, la signature de l'installateur et la migration avec retour arrière sont encore indispensables.

Le client Web historique reste disponible pour les besoins des **comptes existants** jusqu'à ce que la continuité et la restitution native soient prouvées. L'ancienne enveloppe Electron Web, elle, est explicitement bloquée par la PR #53.
