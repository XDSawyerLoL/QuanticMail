# Quantic Sillage — stratégie de distribution exclusivement native

## Priorité produit réaffirmée le 24 novembre 2026

Applications installables et fonctionnelles d'abord. Toute compatibilité Web applicative est reportée jusqu'à validation de la suite native, avec une nouvelle décision explicite et un audit de sécurité distinct. Aucun client Web, relais HTTP historique, ni retour automatique vers un service hébergé n'est autorisé dans la distribution native. Les interfaces locales de laboratoire et protocoles réseau authentifiés sont distincts d'un client Web public ; ils ne constituent pas une preuve de maturité. Le paquet Windows exclut le module historique durable-web-relay-route.mjs et vérifie son inventaire avant création du manifeste. Le témoin HTTPS configurable reste un point d'audit ; il ne doit pas être confondu avec le transport Mail Scattering ni considéré comme validé pour la production.

Décision produit du **23 novembre 2026** : Quantic ID, Identity Vault, Quantic Mail, Quantic Scattering et les futurs paiements se présentent comme **logiciels natifs installés**, non comme des comptes et applications exploités depuis un navigateur.

## Contrat de sécurité appliqué dans cette branche

- `desktop/main.cjs` **ne charge plus de domaine distant**. Pas de `BrowserWindow`, `loadURL`, `shell.openExternal`, renderer distant ni bascule implicite vers une session Web. Par défaut, une boîte de dialogue native informe que l'ancien client Web a été désactivé puis l'application se ferme.
- Les deux seuls parcours expérimentaux explicitement acceptés : `--native-vault-windows-lab` avec chemin absolu et SHA-256 préalablement épinglé du binaire, dossier de coffre local, Node 24 intégré ; ou `--native-vault-lab` sous Linux avec terminal local.
- Le parcours Windows utilise déjà `desktop/native-windows-desktop.mjs` et le contrôleur de coffre. Il s'agit d'une **interface native de laboratoire**, sans accès direct aux clés privées par un renderer.
- La distribution historique via `npm run desktop:dist` échoue volontairement. L'ancien workflow `desktop-release.yml` ne possède plus le droit `contents: write`, ne construit plus d'exécutable Electron distant et **ne publie aucune release**.
- La voie retenue pour Windows est le paquet indépendant **Quantic Sillage Alpha** : scripts `package-windows-pq-lab.sh`, `Start-Windows-PQ-Lab.ps1`, `Quantic-Sillage-Alpha.ps1`, installateur `Quantic-Sillage-Alpha.nsi`. Il contient le coffre Go/OpenSSL, un runtime Node local, les modules nécessaires et Scattering ; il n'embarque pas de navigateur client Web. Son manifeste SHA-256 est contrôlé avant lancement. Un véritable déploiement public exige un installateur signé Authenticode, une épingle de certificat éditeur vérifiée indépendamment et une analyse des dépendances.
- Le site public pourra rester une **vitrine informative et une page de téléchargement**. Les interfaces locales et protocoles réseau authentifiés nécessaires aux échanges natifs ne sont pas des interfaces Web applicatives. Aucun relais Web historique ne fait partie de la cible.

## Ce qui est délibérément conservé

Le code Web historique, ses schémas, ses clés et les routes existantes de migration ne sont **pas supprimés dans cette PR** : des identités réelles pourraient encore en dépendre. La suppression matérielle des clés Web ou le retrait des endpoints de récupération avant preuve de continuité peut détruire du courrier, des contacts ou des capacités de déchiffrement.

La PR #48 (coffre Windows), la PR #51 (continuité de racine post-quantique) et la PR #52 (stockage isolé ML-DSA sur Windows) sont toujours des laboratoires, à examiner et intégrer avant une migration.

## Critères avant de retirer le client Web historique du serveur

1. **Inventaire et sauvegarde** : archive complète, vérifiable hors ligne, avec empreintes indépendantes et historique de messages, contacts, préclés, files d'envoi et accusés.
2. **Contrôle de propriété** : possession de l'ancienne identité et filiation post-quantique vérifiées ; procédure formalisée de récupération si la racine ancienne est compromise.
3. **Restitution** : stockage natif Windows durable, résistance à l'interruption, reprise transactionnelle, relecture intégrale après redémarrage physique et comparaisons binaires.
4. **Convergence réseau** : gel cohérent des relais, contrôle des messages en transit, comparaison à un état distant vérifié, pas de suppression avant confirmations croisées.
5. **Sécurité d'exécution** : réduction des privilèges, interfaces locales, réseau strictement borné, signature des installateurs et mises à jour avec politique de rollback.
6. **Transition** : consentement local, migration réversible et observée, anciennes clés conservées de manière contrôlée jusqu'à validation indépendante. Puis désactivation progressive, retrait serveur audité et procédure d'assistance.

**État présent :** la page distant ne s'ouvre plus dans le wrapper Electron de cette branche. Aucun client Web en production n'a été retiré. Aucun compte réel n'est migré. Il n'existe pas encore de distribution commerciale signée et certifiée. Les fonctionnalités de courrier et paiement natives ne sont pas toutes opérationnelles hors laboratoire.

## Exécuter les tests d'architecture

```sh
node --test tests/desktop-native-only.test.mjs
node --experimental-transform-types --test tests/native-windows-desktop.test.mjs tests/native-vault-desktop.test.mjs
```

La CI `native-only-desktop.yml` vérifie ces conditions. L'absence de renderer réduit un risque majeur, **mais ne prouve pas** la sécurité contre un malware local, la compromission du poste ou d'un relais.
