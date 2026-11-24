# Custody locale des secrets — nouvelles inscriptions uniquement

Le nouveau coffre écrit controller.vault et receipt.vault, jamais les fichiers
controller.pem ou receipt.key. Le stockage AES-GCM utilise des domaines séparés
liés à la candidature et les deux phrases secrètes. Chaque secret possède un
sel et un nonce propres. Le jeton réseau ne sert pas à chiffrer ces secrets.
Les anciens candidats ACL-only sont refusés, conservés intacts.

Le contrôleur Node génère une clé Ed25519 éphémère par processus. Après
approbation graphique et déverrouillage des deux coffres, le moteur Go ouvre
la clé de contrôleur persistante et signe une délégation liant nonce de session
et clé publique éphémère. Node vérifie cette signature avec la clé publique
de la candidature ; les trames restent signées, séquencées et bornées.
Le journal et les ancres restent liés au contrôleur persistant. Le choix
d'une clé éphémère par le processus appelant est autorisé uniquement dans
ce mode interactif : les deux secrets et la confirmation native constituent
la frontière de confiance. Ce n'est pas une attestation d'identité du processus
ni une protection contre un OS compromis.

Les reçus sont chiffrés et ouverts par le broker Go sans export de leur clé.
Le format authentifie adresse, appareil, identifiant et digest. Le contrôleur
relit le reçu durable et le fait authentifier avant ACK. Les opérations
historiques conservent leur format pour les tests et ne sont pas utilisables
sur les nouveaux coffres. Les brouillons restent sous ACL NTFS ; leur
chiffrement et la mise en service du transport restent à faire. Aucun compte
réel ni migration destructive.
