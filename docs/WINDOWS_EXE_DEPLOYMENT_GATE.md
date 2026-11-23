# Quantic Sillage — livrable Windows EXE et critères de déploiement

État : **Alpha de laboratoire téléchargeable**, **pas de diffusion publique**.
Ce document concerne l'application native Windows : aucun compte Web ou
navigateur n'est requis par l'installateur de laboratoire.

## Le fichier exécutable existe déjà

Le workflow GitHub **Native Vault laboratory** construit deux artefacts :

- `Quantic-Sillage-Alpha-UNSIGNED-Installer`, contenant
  `Quantic-Sillage-Alpha-UNSIGNED.exe` et son fichier `.sha256` :
  **installateur Windows monofichier**.
- `QuanticMail-Windows-PQ-Lab-unsigned` : paquet portable permettant
  l'inspection des fichiers et le diagnostic des composants.

Le fichier `.exe` installe l'application
`%LOCALAPPDATA%\QuanticSillage\Alpha-<COMMIT12>\Quantic-Sillage-Alpha.exe`,
le moteur PQ, Scattering et le runtime local Node 24. L'installation est
limitée au profil utilisateur, sans privilèges administrateur ni
modification d'identité existante. Chaque build utilise son propre
dossier, et l'installateur refuse de remplacer un dossier préexistant.

La version Alpha ajoute désormais une entrée par build dans
**Paramètres Windows → Applications installées**, avec un
`Uninstall-Quantic-Sillage-Alpha.exe` autonome. La désinstallation
supprime exclusivement les fichiers déclarés dans l'inventaire
SHA256 vérifié à la construction et seulement les dossiers redevenus
vides : **aucune suppression récursive**, aucun nettoyage de coffre.
La présence d'un fichier inconnu dans le dossier `app` entraîne
un refus et laisse les données restantes pour vérification manuelle.
Les autres builds `Alpha-*` et les coffres conservés ailleurs ne
sont pas affectés. Une nouvelle installation est juxtaposée à
l'ancienne, **sans migration ni mise à niveau automatique**.

Les artefacts issus de la branche sont conservés **30 jours** par
GitHub Actions ; l'accès au dépôt et à ses artefacts GitHub est requis.
Un artefact GitHub Actions n'est pas une release publique ni un lien
permanent et n'est pas une preuve d'authenticité indépendante.

## Récupérer et essayer l'exécutable

1. Ouvrir GitHub → Actions → **Native Vault laboratory**.
2. Sélectionner une exécution avec résultat **Success**, associée
   au commit souhaité.
3. Télécharger `Quantic-Sillage-Alpha-UNSIGNED-Installer` dans
   la section **Artifacts**, puis extraire
   `Quantic-Sillage-Alpha-UNSIGNED.exe` et son SHA256.
4. Contrôler l'empreinte attendue auprès d'une source
   **indépendante et authentifiée** (le fichier `.sha256`
   téléchargé depuis la même archive ne constitue pas une preuve
   d'authenticité à lui seul).
5. Installer sur **Windows 11 x64 de test**, idéalement sur
   une machine dédiée et sans identité réelle. Lancer
   `Quantic-Sillage-Alpha.exe` depuis le menu Démarrer.

**Ne pas contourner les avertissements Windows pour un usage réel :
l'installateur est actuellement NON SIGNÉ.** L'exécution reste réservée
à un environnement de laboratoire contrôlé et ne doit pas transporter
d'identité ou de courrier de production.

La CI vérifie sur un runner Windows :
installation silencieuse, présence du lanceur natif, auto-test du
lanceur, intégrité du paquet installé, non-écrasement à la
réinstallation, refus de la publication non signée et compilation
du fournisseur cryptographique. Ceci **ne prouve pas** la sécurité
ou la connectivité entre deux machines de l'utilisateur.

## Critères bloquants avant déploiement public

| Condition | Situation actuelle | Critère de sortie |
|---|---|---|
| Installation Windows `.exe` | **Réalisée en Alpha** | Réinstallation, désinstallation et mise à niveau sans perte de données validées |
| Signature de l'éditeur | **Bloquante** | Certificat de signature de code légitime, Authenticode horodaté et identité de l'éditeur vérifiée sur l'installateur **et** le lanceur intérieur |
| Parcours utilisateur | **Laboratoire** | Création, invitation, contact, envoi, réception et récupération accessibles sans paramétrage manuel de plusieurs services |
| Échange de courrier | **Tests locaux/synthétiques** | Envoi chiffré PC A → PC B sur un réseau indépendant, réception, accusé, reprise et redémarrage vérifiés |
| Autorités mTLS | **Quorum local testé** | Quatre opérateurs indépendants, distribution de confiance, politique et renouvellement contrôlés en conditions réelles |
| Identités existantes | **Migration réelle non validée** | Réconciliation des clés, contacts, préclés, courriers et sauvegardes, sans suppression avant contrôle |
| Chaîne de publication | **CI de laboratoire** | Build figé, signature indépendante, publication à accès contrôlé, test sur Windows propre et stratégie de révocation/rollback |
| Sécurité | **Tests automatisés** | Audit indépendant, revue des frontières de confiance et tests adversariaux avant public |

**Priorité de livraison :** une Alpha installable entre deux PC, avec
des identités **strictement fictives** et un aller-retour chiffré
reproductible, puis une bêta signée et distribuée en cercle fermé.
Ne pas annoncer une date de mise en production tant que les tests
physiques, l'audit et la signature de l'éditeur ne sont pas obtenus.

## Chaîne de signature existante

`scripts/Sign-Native-Lab-Installer.ps1` et
`scripts/Test-Quantic-Sillage-Signed-Alpha.ps1` fournissent des
contrôles côté opérateur. Le second exige **deux signatures
Authenticode valides, avec le même certificat éditeur épinglé et un
horodatage**, sur l'installateur extérieur et l'application
`Quantic-Sillage-Alpha.exe` installée. Signer seulement le fichier
`Quantic-Sillage-Alpha-UNSIGNED.exe` ne suffit pas. Une nouvelle
construction de l'installateur contenant le lanceur signé, puis sa
signature, est nécessaire.

Il ne faut jamais inventer de certificat ni publier une archive
non signée comme release de production pour satisfaire ce contrôle.
