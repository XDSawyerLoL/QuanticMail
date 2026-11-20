# Quantic Mail Windows — protection locale des clés

## Constat vérifié au 20 novembre 2026
- Quantic ID / Identity Vault PC chiffre déjà son fichier `identity-vault.json` via Electron `safeStorage` (DPAPI sous Windows).
- Quantic Mail utilisait IndexedDB avec des JWK privées et des jetons exportables en clair au niveau de l'application.
- Le relais possède encore une identité de relais persistante `relay-identity.json` avec une clé privée PEM : **hors de la portée de ce correctif**, à traiter avant la sortie stable.
- Les messages locaux peuvent conserver leur sujet et leur corps en clair dans IndexedDB : **autre chantier distinct**.

## Nouveau périmètre
Uniquement la construction Windows `NEXT_PUBLIC_QUANTIC_DESKTOP=true` :
- Le processus principal Electron applique `safeStorage.encryptString/decryptString` pour sceller les enregistrements d'identité, l'appairage d'appareil et les préclés privées.
- Les appels IPC sont limités à la fenêtre principale et au cadre de premier niveau dont l'URL est `http://127.0.0.1:18787/mail/...`.
- Le rendu conserve seulement une API `seal/unseal` ; aucune API de fichier arbitraire n'est exposée par le preload.
- Les enregistrements anciens sont migrés en place, après une écriture chiffrée réussie et seulement si l'enregistrement d'origine est inchangé.
- En cas de problème de chiffrement, l'opération échoue et les données existantes ne sont ni supprimées ni remplacées.
- Les entrées de préclés gardent seulement `preKeyId`, `expiresAt` et `state` non chiffrés pour les index de la base.
- Le site Web n'est pas changé.

## Limites
- DPAPI protège essentiellement contre la copie hors ligne de fichiers et certains vols de profil. Il ne bloque pas un logiciel malveillant exécuté dans la session Windows ouverte, un processus Electron compromis ou une injection dans la page Mail.
- La clé matérielle/TPM non exportable, l'authentification Windows Hello et une véritable séparation du service de signature exigent une évolution majeure séparée.
- Ne pas supprimer les profils précédents et ne pas modifier la compatibilité de récupération avant une sauvegarde vérifiée et un test sur Windows réel.
- Le nouveau binaire doit réussir les tests CI, l'exécution et la migration réelles avant déploiement stable.
