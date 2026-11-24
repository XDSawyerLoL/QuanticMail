# Quantic Sillage Alpha — installer natif Windows

État au 23 novembre 2026. **Laboratoire uniquement — aucune identité réelle, migration ou transaction.**

## État du parcours graphique de test — 23 novembre 2026

Sur la branche UX de la PR #57, le lanceur ouvre le tableau de bord **sans console PowerShell en arrière-plan**.
Le premier parcours Quantic Mail est **« Rédiger un message (sans terminal) »** : choix d'un coffre **de test déjà provisionné**, sélection d'un contact présent dans le carnet local, objet et texte. Aucun nom `draft-nom.json` n'est demandé ; le nom technique est choisi automatiquement, avec refus de tout écrasement et relecture du fichier.

**Protection des nouveaux brouillons :** DPAPI Windows liée au compte utilisateur, avec entropie de domaine et de chemin, refus de l'écrasement et ACL NTFS privées. Les anciens brouillons en clair restent intacts et ne sont plus ouverts par le nouveau lecteur : une migration explicite reste nécessaire. DPAPI ne protège pas contre un malware sous le même compte. Aucune utilisation réelle ni déploiement autorisé.

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

## Première utilisation : identité de test sans terminal

Dans **Quantic Sillage Alpha**, les deux boutons principaux permettent désormais les opérations locales suivantes :

1. **Créer mon identité de test** : utilise un nouveau sous-dossier privé de `%LOCALAPPDATA%` sur un volume Windows **NTFS** ; ouvre un consentement natif et deux saisies avec confirmation. Les secrets ASCII doivent comporter au moins 20 caractères et **être différents**. Aucune phrase secrète n'est communiquée à PowerShell, à Node, à un fichier JSON ou aux arguments d'un processus.
2. **Ouvrir mon coffre de test** : vérifie par le fournisseur Go natif les deux déchiffrements P-256 et PQ et la correspondance des clés avec les métadonnées publiques du laboratoire. Après redémarrage, l'utilisateur choisit le dossier du coffre existant (aucun fichier JSON à rechercher).

La création est **localement réelle** : clés P-256 et ML-KEM-768 / ML-DSA-65 générées, coffres et contrôleur chiffrés/protégés par ACL NTFS ; fichier d'identification **synthétique**, et jamais d'inscription sur un serveur. Le `quorumPin` local est un *marqueur aléatoire fictif*, **pas** une autorité indépendante. Aucun carnet de contacts attesté ni relais n'est fabriqué. Une ouverture réussie est une **vérification de secrets et de clés locales**, pas une session Quantic ID distante, pas une première connexion à SWAPP, pas une preuve de livraison et pas une messagerie utilisable avec un autre compte.

L'ouverture d'un coffre existant refuse une identité altérée, un mauvais secret ou un chemin non canonique. Une création interrompue conserve son dossier partiel ; **aucun écrasement, effacement ou reprise implicite**. Le chemin de profil Windows doit actuellement se limiter aux caractères ASCII prévus par le garde-fou de stockage natif : les profils contenant des caractères non pris en charge sont refusés plutôt que déplacés sans autorisation.

Tests automatisés : `TestSyntheticFirstRunMetadataNeverBecomesEnrollment`, `TestSyntheticGUICommandsRejectUnexpectedArgumentsWithoutDialogs`, et auto-test de l'interface WinForms. Le **parcours interactif complet** (dialogues Win32, saisie réelle, annulation, redémarrage) exige encore une validation sur PC Windows physique avant distribution, ainsi qu'un installateur dont le nouveau moteur est attesté par la CI.

## Identités retrouvées et codes de contact (laboratoire, 24/11/2026)

L'interface **Ouvrir mon coffre de test** retrouve désormais les identités fictives déjà créées sous `%LOCALAPPDATA%`, sans demander de dossier ni de fichier JSON. Lorsqu'il n'y a qu'une identité, elle est proposée directement. S'il y en a plusieurs, une liste graphique permet de choisir. Le registre ne présente que des coffres dont le répertoire et le fichier public passent les contrôles de type, ACL NTFS et absence de reparse point. Une génération interrompue n'est pas affichée comme un coffre prêt. Le registre est **en lecture seule** : aucune restauration ou réparation silencieuse.

Le nouveau bouton **Inviter un contact de test (en attente)** permet deux opérations :

1. **Partager mon code de test** : les deux secrets du coffre sont revérifiés dans les fenêtres natives Windows, puis une carte publique à durée limitée (24 heures) est signée par le contrôleur local Ed25519. Le texte public peut être copié pour le transmettre sur un autre poste, sans fichier JSON ni terminal. L'empreinte courte de la clé du contrôleur doit être comparée par un second canal convenu avec le correspondant.
2. **Entrer le code reçu d'un autre PC** : la signature, le domaine cryptographique, les empreintes et identifiants, la date d'expiration et le refus de son propre compte sont vérifiés par le processus natif. Après comparaison de l'empreinte et autorisation graphique, le code est sauvegardé en **candidat en attente**, dans un nouveau fichier privé à création exclusive ; aucun écrasement.

**Frontière de confiance impérative :** cette carte n'est qu'une **auto-attestation** de clé locale, pas une attestation indépendante des autorités Quantic, une preuve de l'identité humaine, ni une garantie contre la substitution initiale. Le contrôleur Ed25519 de ce laboratoire est toujours stocké dans un fichier privé NTFS, mais n'est pas un module matériel anti-extraction. Les contacts ainsi importés **ne sont jamais insérés dans `contacts.json`** et **ne donnent aucun droit d'envoi/déchiffrement**. Le passage en contact autorisé devra exiger des attestations mTLS/quorum réellement indépendantes, puis une activation explicite séparée.

Tests : `TestSyntheticContactCardSignedButNeverAuthorized`, `TestNativeSyntheticRegistryAndContactCommandsFailClosed` et auto-test de l'interface Windows. Une exécution humaine entre deux PC reste indispensable pour vérifier l'expérience Win32 et la comparaison hors bande des empreintes. La messagerie distante ne fonctionne pas automatiquement à ce stade.

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
- Le nouveau brouillon est conservé sous forme DPAPI dans le dossier NTFS privé de laboratoire. L'enveloppe signée et chiffrée PQ est écrite une seule fois, synchronisée, relue et vérifiée **avant** d'autoriser un dépôt sur le relais Scattering déjà configuré.
- Une deuxième confirmation graphique est exigée avant le dépôt, sans nouvel essai automatique si le résultat réseau est incertain. Un dépôt local confirmé **ne prouve pas** une réception, une lecture ni une livraison sur un deuxième ordinateur.
- Cette nouvelle voie doit encore subir la compilation Windows, les tests de paquet, un test interactif sur deux vrais PC et une revue des dialogues et de la gestion des secrets. L'absence de console dans le test CI n'est pas une preuve de sécurité face à un PC compromis. Elle demeure interdite pour les comptes réels.
- Les anciennes identités, messages et sauvegardes sont conservés. Aucune suppression, migration définitive ni paiement réel n'est autorisé.

## Réception chiffrée sans terminal (deuxième poste de laboratoire)

Dans **Quantic Mail → Rédiger un message**, sélectionner un coffre de test disposant d'un contact signé et d'un relais Scattering **déjà préparé**, puis choisir **Recevoir un message chiffré (test)**.

- Si la file est vide, le logiciel affiche **Aucun message**. Rien n'est acquitté.
- Si un message est en attente, la fenêtre demande une approbation `OPEN` explicite pour ouvrir et vérifier son enveloppe. Les phrases secrètes sont demandées par le coffre natif dans les fenêtres Windows, pas par une console.
- Le moteur existant vérifie le destinataire, les clés et la signature hybride. Il crée un **nouveau reçu chiffré privé**, le synchronise, le relit et vérifie le résultat avant de confirmer au relais local. Le contenu en clair apparaît uniquement dans la fenêtre locale en lecture seule.
- Si le disque, la vérification ou l'accusé échoue, le résultat reste **non confirmé**. Un reçu peut subsister ; **aucune relance automatique**. La récupération explicite doit préserver l'ancien reçu.
- L'affichage d'un message reçu sur un poste et l'acquittement du relais local **ne sont pas encore une preuve indépendante** du transport physique entre deux postes. Un essai de bout en bout avec deux PC, quatre autorités mTLS indépendantes et une observation réseau externe reste obligatoire avant tout usage réel.

Les tests automatisés sont dans `tests/native-windows-gui-receive.test.mjs` et `tests/native-windows-mail-flow.test.mjs`. Ils vérifient le refus des résultats non authentifiés, les limites de réception et l'ordre écriture-vérification-ACK, mais ne remplacent pas le test interactif à deux machines.

## Publication et mises à jour

La chaîne de signature existe dans `scripts/Sign-Native-Lab-Installer.ps1` mais requiert un **véritable certificat de signature de code** autorisé, sa clé privée conservée hors du dépôt, une empreinte publique d'éditeur approuvée indépendamment, Windows SDK SignTool et un service d'horodatage HTTPS. Ni certificat ni signature ne sont générés fictivement dans la CI. Pas de mise à jour automatique d'un binaire non signé.

L'étape de distribution suivante doit fournir un flux **version signée → téléchargement vérifié → installation dans un nouveau dossier → nouvelle vérification des empreintes et de la signature**. Il ne doit jamais écraser le coffre ni désinstaller automatiquement les anciens secrets.

## Blocages avant ouverture réelle

Le chemin Windows natif reste une **Alpha** : pas de véritable enrôlement de compte, pas de migration définitive, pas de continuité de racine installée partout, pas de paiement réel, pas de validation d'indistinguabilité Scattering à deux postes physiques. Les travaux de filiation PQ de la PR #51 et de racine de compte isolée de la PR #52 ne sont pas implicitement inclus dans cette branche. Une revue de sécurité, la signature de l'installateur et la migration avec retour arrière sont encore indispensables.

Le client Web historique reste disponible pour les besoins des **comptes existants** jusqu'à ce que la continuité et la restitution native soient prouvées. L'ancienne enveloppe Electron Web, elle, est explicitement bloquée par la PR #53.

## Protection complémentaire des nouveaux secrets locaux

Le contrôleur Ed25519 et la clé des reçus des nouveaux coffres synthétiques sont désormais protégés au repos par DPAPI utilisateur, avec séparation de domaine et liaison au chemin. Les lecteurs refusent les anciennes clés en clair sans les modifier. La migration explicite des anciens coffres reste à réaliser. Les clés TLS et configurations de transport ne sont pas couvertes par ce changement. Cette protection ne constitue pas une isolation entre processus sous le même utilisateur Windows ; les opérations existantes peuvent encore déchiffrer les secrets dans le processus de confiance. Aucun compte réel ni déploiement autorisé.

## Durée de vie des secrets en mémoire (laboratoire)

La clé TLS du client est chargée pour chaque interrogation du quorum, puis son tampon est effacé dans un bloc finally. Les tampons IPC sont effacés après lecture ou écriture et lors des erreurs ; une session défaillante est fermée sans reprise implicite. Les références aux objets de clés du contrôleur sont abandonnées à la fermeture. Les chaînes JavaScript immuables, copies internes de Node/OpenSSL, mémoire paginée et processus du même utilisateur ne sont pas couverts par une garantie d'effacement. Cette mesure ne remplace ni l'isolation OS, ni la garde non exportable des clés, ni un audit indépendant.

## Restriction des nouveaux accès au processus Windows

Le courtier cryptographique et l'assistant de signature du contrôleur appliquent une DACL de processus avant de déchiffrer des clés. Les nouveaux handles ordinaires du même utilisateur sont limités à la consultation minimale, l'attente et l'arrêt. Une entrée OWNER RIGHTS retire le droit implicite de modifier la DACL. Le test lance un second processus synthétique et exige le refus des accès mémoire, duplication de handles, création de thread et modification des droits. Le processus créateur possède déjà un handle ; les threads, privilèges administrateur/debug, injection préalable, DPAPI et compromission du compte ou du noyau ne sont pas isolés. Aucun TPM obligatoire, aucun changement global de Windows.
