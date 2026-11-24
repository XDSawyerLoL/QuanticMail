# Quantic Scattering V1.5 — Sessions authentifiées et anti-rejeu durable

**Recherche isolée — non prête pour Quantic Mail / Identity Vault / production.**

## Résultat réellement implémenté

- L'ouverture d'une session repose sur **Ed25519** (signatures d'identité déjà épinglées chez l'autre participant) et **X25519 éphémère**, avec la signature du transcript et confirmation HMAC du secret partagé.
- Aucune identité ni clé publique d'identité n'est envoyée en clair pendant le handshake. Cela **n'empêche pas** un observateur d'identifier le handshake, ses horaires, sa destination et ses volumes.
- Une nouvelle négociation fabrique un identifiant et des secrets de session distincts ; les clés d'émission/réception sont dérivées séparément avec HKDF-SHA256.
- Les anciennes trames AES-256-GCM ne sont plus valides sous une nouvelle session. Les trames de données restent à 168 octets ; **les messages de handshake ne sont pas de taille fixe**.
- `DurableFrameReceiver` enregistre par écriture atomique et synchronisation disque l'état de la fenêtre anti-rejeu, authentifié par HMAC, **avant de remettre la trame** à l'application. Il sérialise les admissions concurrentes.
- En cas de fichier manquant, d'intégrité non vérifiée, de seconde instance utilisant le même fichier, d'écriture impossible ou de profil de session différent, le récepteur refuse ou se verrouille (*fail closed*).
- Un échange complet avec deux sockets UDP sur `127.0.0.1`, huit fragments et redémarrage logique du récepteur est reproductible avec `node scripts/demo-udp-v15.mjs`. Un test supplémentaire relit l'état depuis un **second processus Node.js**.

## Reproduction

Depuis `research/scattering-v14/` :

```sh
node --test tests/v14.test.mjs tests/v15.test.mjs
node scripts/demo-udp-v15.mjs
```

Windows : `REJOUER_V15_WINDOWS.bat` (Node.js 22+). Ne nécessite ni VPS ni seconde machine. La démonstration crée uniquement des clés de test éphémères dans le processus et une copie temporaire de l'état anti-rejeu.

## Hypothèses et limites explicites

1. **Pas de cryptographie post-quantique.** Ed25519 et X25519 sont classiques. Une future intégration ML-DSA / ML-KEM hybride, conforme aux politiques de Quantic ID/Identity Vault, demande un examen distinct, une implémentation native et des tests de migration.
2. **Distribution de clés d'identité non résolue.** Le prototype suppose que chaque extrémité possède déjà la véritable clé publique Ed25519 de l'autre, acquise hors bande en toute sécurité. Il ne vérifie pas à lui seul qu'une clé appartient à une personne, une machine ou un compte.
3. **Anti-rejeu durable sous stockage de confiance.** HMAC détecte des modifications non autorisées, **mais ne détecte pas un retour à une ancienne copie authentique du fichier**. La sécurité face aux restaurations de sauvegarde nécessite une racine monotone protégée indépendante ou une rotation obligatoire de session à chaque reprise.
4. **Crash et verrou.** Une coupure brutale peut laisser `.lock` sur le disque. Le laboratoire refuse alors la réouverture du même état jusqu'à intervention de maintenance. Il ne faut pas supprimer ce verrou sans certifier que l'ancien processus a cessé et que le stockage est fiable. **La politique recommandée est de négocier une nouvelle session après tout redémarrage.**
5. **At-most-once, pas exactly-once.** L'état de replay est validé avant livraison aux couches supérieures : un crash après écriture et avant traitement applicatif peut perdre une trame acceptée. Il manque une boîte de réception durable, des accusés de réception et des retransmissions sans fuite de métadonnées.
6. **Aucun stockage sécurisé des clés privées.** Les tests créent des identités Ed25519 dans la mémoire du processus ; ils ne sont connectés ni au coffre natif ni à un service de confiance. Aucun système de récupération de clé n'est fourni.
7. **Pas de trafic de couverture de bout en bout.** Le handshake est visible ; le pilote UDP n'a pas de cadence fixe, de résistance à la congestion, de routage masquant les adresses, d'analyse de perte sur Internet ou de portage Windows réel validé.
8. **Pas d'audit indépendant ni de production.** Les tests passent sur la machine de développement, mais ne prouvent ni anonymat, ni confidentialité contre un hôte compromis, ni robustesse globale contre un attaquant adaptatif.

## Décision d'intégration

Conserver en branche de recherche. Ne fusionner vers le transport Quantic Mail qu'après mise en place de signatures/échanges post-quantiques, provisionnement authentifié, politique de redémarrage/rotation, persistance transactionnelle des messages et audits externes. Ne jamais réutiliser des clés privées d'utilisateur dans le laboratoire.