# Quantic Mail pour Windows

Cette version installe Quantic Mail comme application Windows 64 bits : fenêtre dédiée, raccourci Bureau, menu Démarrer et désinstallation via Windows.

## Pour installer (sans Node.js)

1. Ouvrir l'onglet **Actions** du dépôt GitHub et sélectionner **Installer Windows QuanticMail**.
2. Ouvrir la dernière exécution réussie ; télécharger l'artefact **quanticmail-windows-installer**.
3. Extraire le ZIP puis lancer `QuanticMail-Setup-1.3.1.exe`.
4. Dans Quantic Mail, utiliser **Identity Vault** pour importer le coffre `.quantic-vault` chiffré, ou associer ce poste comme nouvel appareil depuis le dispositif maître.

**Important :** l'installation ne récupère pas automatiquement le coffre ou les messages stockés dans IndexedDB du navigateur, car les profils navigateur et Electron sont séparés. Exporter le coffre depuis l'ordinateur d'origine AVANT de réinitialiser quoi que ce soit. Ne jamais transmettre ce fichier ou son mot de passe à un tiers.

## Pour compiler soi-même

Avec Node.js 22 sur Windows :

```powershell
npm install
npm run desktop:dist
```

L'installateur est généré dans `desktop-dist/`. L'icône Windows est construite localement par `scripts/generate-desktop-icon.mjs` sans dépendance supplémentaire.

## Limites actuelles

- Cette première édition est un client de bureau sécurisé de la surface Quantic Mail hébergée sur Hostinger. Elle **a besoin d'une connexion Internet** pour charger l'interface ; elle ne contient pas encore le moteur de relais ni un serveur local embarqué.
- Les clés et les messages gérés par le navigateur Electron sont distincts de ceux du navigateur web. La restauration/association est volontaire pour éviter toute copie implicite de clés privées.
- L'installateur CI est **non signé**. Windows SmartScreen peut demander une vérification de réputation. À terme, une signature de code éditeur est recommandée.
- Les communications entre identités Quantic peuvent se passer de SMTP/DNS, mais l'interface hébergée et les relais distants utilisent encore HTTPS/DNS pour leur accès initial.
