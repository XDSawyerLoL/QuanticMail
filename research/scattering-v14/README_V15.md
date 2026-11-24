# QUANTIC SCATTERING — V1.5 : SESSIONS AUTHENTIFIÉES

Cette version est un **laboratoire de recherche**, indépendant de Quantic Mail et d'Identity Vault.

## Utilisation Windows

Décompressez l'archive, puis double-cliquez sur `REJOUER_V15_WINDOWS.bat` (Node.js 22 ou supérieur). Le programme exécute les tests et une démonstration de communication UDP locale chiffrée et authentifiée.

Vous n'avez pas besoin d'un deuxième PC, de VPS, de compte Quantic, ni d'une clé privée réelle. Les clés utilisées sont créées uniquement pour cette expérience.

## Tests effectués

- Vérification de l'identité par signatures Ed25519 préalablement épinglées.
- Nouveau secret X25519 éphémère à chaque session, dérivation séparée émission/réception.
- Rejet d'une identité falsifiée et de signatures modifiées.
- Rejet d'une ancienne trame après une nouvelle négociation.
- Sauvegarde anti-rejeu avant livraison des paquets, reprise avec un second processus.
- Refus d'état corrompu, d'une seconde instance concurrente, d'un enregistrement impossible.
- Contre-test explicite : un **retour à un ancien état authentique** peut rouvrir une fenêtre de rejeu. La politique sûre reste la création d'une nouvelle session au redémarrage.

**Important :** X25519 et Ed25519 ne résistent pas à un ordinateur quantique cryptographiquement pertinent. La V1.5 n'est pas un protocole post-quantique et n'est pas un déploiement sécurisé prêt à l'emploi.

Détails techniques et limites : `V15_SECURITY.md`.