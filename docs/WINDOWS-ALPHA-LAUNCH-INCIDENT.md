# Incident Alpha Windows — fermeture après message rouge (23 novembre 2026)

## État et constat

L'installateur précédent (`Quantic-Sillage-Alpha-UNSIGNED.exe`) était intègre au téléchargement : son SHA-256 correspondait à son manifeste de livraison. Les tests GitHub Actions validaient l'installation et le diagnostic du coffre, **mais ne lançaient pas le tableau de bord par le raccourci utilisateur**. Le raccourci ouvrait directement `powershell.exe -File Start-Windows-PQ-Lab.ps1` : une erreur PowerShell (politique d'exécution, refus du paquet, environnement local ou exception d'interface) apparaissait en rouge et le terminal pouvait se fermer avant d'être lu.

**La cause exacte de l'incident utilisateur n'est pas établie sans le message d'erreur.** Cette correction traite le défaut de lancement et de diagnostic et introduit un test de bout en bout du bootstrap ; elle ne prétend pas corriger toutes les incompatibilités possibles.

## Correction

- Nouveau `bin/Quantic-Sillage-Launcher.exe` en Go, compilé **Windows GUI** : le raccourci Bureau/Menu Démarrer n'exécute plus directement PowerShell.
- Le bootstrap vérifie l'empreinte SHA-256 du manifeste **fournie par l'installateur**, les hashes des trois scripts critiques contre ce manifeste, ainsi que l'empreinte attendue du coffre natif. Il refuse les substitutions et ne charge aucun client Web.
- Après contrôle des fichiers, le bootstrap lance le PowerShell **système** (`System32\WindowsPowerShell\v1.0\powershell.exe`) sans profil, dans un nouveau terminal interactif pour conserver la saisie locale des phrases secrètes.
- La politique d'exécution `Bypass` est appliquée **seulement à ce processus enfant après vérification des scripts**, sans modifier les stratégies Windows globales. Une stratégie de groupe imposée par l'administrateur continue de primer ; elle ne doit pas être contournée sur un PC professionnel.
- Si la commande échoue ou se ferme avec un statut d'erreur, la fenêtre principale affiche **un dialogue Windows persistant avec le code de sortie**. Le message n'inclut aucun contenu de courriel ni secret. Les erreurs de confiance sont refusées avant tout démarrage des scripts.
- Deux modes sans secrets pour la CI : `--self-test` vérifie les fichiers, `--smoke-ui` démarre le **vrai** chemin `Launcher.exe -> PowerShell -> Start-Windows-PQ-Lab.ps1 -> Quantic-Sillage-Alpha.ps1 -SelfTest`.
- Le vérificateur de paquet exige désormais le nouveau binaire dans son inventaire signé par hash.

## Limites

La version reste un laboratoire **NON SIGNÉ** ; aucune protection contre malware du même utilisateur ni contre une compromission de l'OS n'est prétendue. L'usage sur un poste contenant des identités réelles n'est pas autorisé. Les tests CI sont réalisés en environnement Windows runner ; ils ne prouvent pas le fonctionnement de toutes les éditions Windows et politiques entreprise.

Une correction de lancement ne doit pas réinitialiser, écraser ou nettoyer le stockage des identités Web historiques : l'installateur utilise un dossier distinct par commit.

## Tester

Sur le dernier artefact `Quantic-Sillage-Alpha-UNSIGNED-Installer` de la **branche de correctif**, et non sur l'exécutable de la version précédente :
1. Vérifier la provenance (workflow, branche, SHA-256 indépendant).
2. Installer uniquement sur une machine de test sous Windows.
3. Lancer le **nouveau raccourci correspondant au commit de correction**. Si le coffre ou PowerShell est indisponible, une boîte de diagnostic restera affichée : noter le code d'erreur sans communiquer de clés.
4. Ne pas supprimer les anciennes archives ou clés en réponse à un échec d'ouverture.

Avant toute distribution publique, la signature éditeur Authenticode horodatée et vérifiée indépendamment reste obligatoire.
