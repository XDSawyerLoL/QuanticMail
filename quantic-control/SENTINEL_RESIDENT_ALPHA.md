# Quantic Sentinel — agent résident Windows par utilisateur (Alpha)

## Fonctionnel

L'application Win32 reste une **seule application native** `quantic-sentinel-alpha.exe`, sans console ni navigateur. Depuis sa fenêtre :

1. Cliquer sur **Surveiller un dossier** et choisir un dossier de test, avec consentement explicite.
2. Cliquer sur **Installer pour ma session Windows** pour copier ce même programme vers `%LOCALAPPDATA%\QuanticSillage\Sentinel\quantic-sentinel.exe`.
3. Seul le compte Windows actuel reçoit une entrée de démarrage automatique sous `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\QuanticSentinelUserAgent`, pointant vers **`"…\quantic-sentinel.exe" --resident`**.
4. Le programme démarre un agent séparé, sans fenêtre ni droits d'administrateur. Il continue la surveillance pendant que la fenêtre principale est fermée et redémarre à la prochaine **ouverture de session utilisateur**.
5. L'agent inspecte les métadonnées des fichiers sélectionnés toutes les deux secondes, rapporte les rafales de modifications/suppressions et écrit des alertes dans `%LOCALAPPDATA%\QuanticSillage\Sentinel\events.jsonl`. Les événements sont lisibles via **Historique local**.
6. **Désinstaller** retire l'entrée HKCU, signale l'arrêt et efface seulement l'exécutable et le manifeste connus, après vérification de l'empreinte de l'exécutable. Les journaux d'alerte et fichiers inconnus sont conservés.

Le journal est limité à 4 Mio. Chaque événement significatif, cycle de vie et battement périodique est synchronisé sur disque. Un journal saturé/interdit provoque l'arrêt de la surveillance, sans suppression automatique silencieuse.

## Lien vers la protection réellement bloquante de Windows

Le bouton **Protection antirançongiciel Windows** ouvre uniquement l'application Sécurité Windows sur les paramètres d'accès contrôlé aux dossiers. Si ce mécanisme Microsoft Defender est disponible et activé par l'utilisateur, **c'est Windows Defender qui bloque** les modifications de fichiers par des applications non fiables, pas Quantic Sentinel. L'application ne peut ni garantir qu'il est activé, ni changer les réglages sans action de l'utilisateur, ni désactiver une protection existante. Les entreprises peuvent imposer leurs propres politiques.

## Ce que ce n'est PAS

- **Pas de service Windows SCM**, ni agent au démarrage avant connexion. L'agent fonctionne seulement dans la session du compte utilisateur et s'arrête à la déconnexion, sans privilèges système.
- Pas d'antivirus, de moteur EDR, de suppression de virus, d'auto-quarantaine ni de protection contre les rançongiciels. Il s'agit d'un outil d'**observation et de diagnostic**, susceptible de faux négatifs et de faux positifs.
- Pas de contrôle distant, pas de remontée réseau, aucun transfert de fichiers ou de secrets, pas d'Identity Vault connecté à l'agent.
- Pas de preuve d'intégrité inviolable du journal : un programme malveillant exécuté sous le même compte peut modifier les fichiers de l'utilisateur ou arrêter cet agent.
- Pas d'exécutable signé, pas de validation utilisateur sur un véritable PC, pas d'essais indépendants ni d'audit de sécurité. Windows SmartScreen peut avertir lors de l'ouverture du binaire.
- Le registre HKCU Run ne garantit pas la relance immédiate après un crash pendant la session. La résilience à un crash et le suivi d'état depuis l'UI sont des prochains verrous.
- Un agent déjà installé doit être désinstallé puis remplacé par l'utilisateur ; aucune mise à jour autonome ni écrasement silencieux n'est permis.
- L'installation demande une **action explicite**, et le dossier surveillé doit être choisi par l'utilisateur.

## Tests

La CI vérifie les règles de détection, le scanner et sa boucle résidente, l'écriture/relecture durable des alertes, les fichiers corrompus/refusés et la compilation native Windows GUI. Sur Windows, elle vérifie également le sous-système PE graphique (2) et la compilation de l'agent incorporé dans le même exécutable.

Les tests CI ne modifient pas le registre ni le démarrage de l'ordinateur du runner. Un test d'installation/désinstallation et de continuité après déconnexion/reconnexion **sur une VM Windows de laboratoire** reste obligatoire avant commercialisation.

## Pour une capacité de protection réelle

Microsoft Defender **Controlled Folder Access** peut bloquer des écritures non autorisées sur les dossiers protégés, si cette fonctionnalité est disponible et configurée par l'utilisateur. Quantic Sentinel ne l'active pas automatiquement et ne désactive aucune protection existante. Voir [la documentation Microsoft](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview).

Un agent Windows réellement défensif devra corréler les alertes aux événements Defender et aux processus responsables, auditer les faux positifs, proposer des actions de confinement réversibles et implémenter une politique signée liée à Quantic ID / Identity Vault.
