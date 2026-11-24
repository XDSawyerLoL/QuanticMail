# Import Windows d'une configuration de messagerie de laboratoire

La nouvelle action « Configurer ma messagerie de test » sélectionne une identité
locale et un unique dossier JSON authentifié, puis demande les deux secrets
dans les dialogues natifs. Elle ne demande aucun chemin de fichier interne.

Le dossier est fourni par un opérateur via un canal privé. Il doit se trouver
dans un répertoire NTFS privé et porter une ACL propriétaire + SYSTEM exacte
comme les autres fichiers du coffre. Le format JSON contient :
`format: "quantic-native-windows-activation-lab/v1"`, `labOnly: true`,
`requestDigest`, `rosterPin`, `approvals` (QSAPPROVAL1 décodé),
`credential` (QSCRED1 décodé), `endpoint` (pont Scattering loopback),
`anchors` (4 objets url HTTPS sans chemin + tlsPin), `checkpoints`
(4 objets url HTTPS /native-checkpoint + pin, publicKey, tlsPin),
`anchorTls` et `checkpointTls` (ca, cert, key : PEM encodés base64 standard),
`contacts` (liste de clés publiques et échéances du format senderContact).
Les empreintes du dossier et du quorum doivent être authentifiées hors bande.

Le moteur valide le dossier entier avant tout import, les votes frais et la
liste, le quorum TLS lié au coffre, les paires de certificats, les contacts et
la preuve du jeton local. Il construit les neuf fichiers privés et relit chacun.
La configuration desktop.json est écrite en dernier. Un import partiel peut
être repris uniquement à octets identiques ; pas de remplacement. Le composeur
peut reprendre l'identité sélectionnée dans la même session du tableau de bord.

Ce dossier contient des clés privées de transport mTLS, distinctes des clés
d'identité, et doit rester confidentiel. La génération de ces clés sur
l'appareil, la fourniture automatique des certificats, le démarrage du pont
Scattering, le renouvellement des contacts et la mise en service physique des
autorités restent à réaliser. L'import ne prouve aucune disponibilité réseau
ni activation distante ; chaque opération continue d'exiger le quorum frais.
Ne pas utiliser de vraies identités ou de secrets de production.
