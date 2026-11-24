# Quantic Mail — infrastructure privée Alpha

**Périmètre : laboratoire, données fictives, réseau privé autorisé.** Ne pas
exposer les ports HTTP locaux à Internet. Aucun remplacement du relais
historique, aucune inscription de comptes réels, aucune promesse d'anonymat.

## Topologie déployable

- Une machine Linux dédiée au relais de messagerie durable. Node 24.8.0
  minimum pour ce build de laboratoire, dépendances du dépôt installées.
- Un processus Scattering par participant, sous un seul superviseur : pont,
  pacer natif et sink natif. Une paire de processus partage exclusivement son
  secret et son epoch préparés hors bande. Le sink écoute sur une adresse
  IPv4 privée explicite du LAN ou du VPN autorisé ; le pont reste en loopback.
- Quatre domaines d'autorité distincts : le broker Go doit accéder à ses
  quatre témoins anchor_server.py et aux preuves de registre signées ; le
  client et le relais ont besoin des quatre services native-checkpoint en
  mTLS et des politiques signées à jour. Les deux mécanismes ne sont pas
  interchangeables. Les services Node de checkpoint restent en loopback ;
  utiliser des tunnels authentifiés séparés préservant la vérification
  du nom TLS, de la CA et de l'empreinte de chaque certificat. Ne pas
  centraliser les quatre clés privées sur le relais.
- Deux clients Windows natifs, avec identité, autorisations, contacts,
  certificats, jeton du relais et transport préparés indépendamment.
  L'interface Windows ne provisionne pas encore automatiquement le transport.

## Démarrage du relais isolé

Depuis une installation de confiance du dépôt et un compte Linux non-root,
préparer deux dossiers distincts (configuration et données durables), mode
0700, appartenant au compte du service. Les fichiers privés sont en 0600.
Ne pas utiliser un stockage temporaire ou le répertoire du relais Web réel.
Le fichier relay.json doit avoir exactement les champs suivants :

- format: quantic-private-native-relay/v1
- labOnly: true
- dataDir: chemin Linux absolu du dossier persistant
- port: port loopback non privilégié
- authority: configuration existante createAttestedPeerSource (authorities,
  caFile, clientCertFile, clientKeyFile)
- tlsFilePins: objet associant caFile, clientCertFile et clientKeyFile à
  leurs empreintes SHA256 indépendamment approuvées.

Les trois fichiers TLS doivent être dans le dossier privé de configuration.
Les quatre attestations doivent provenir des autorités réellement autorisées.
Le jeton d'un client doit correspondre à un appareil inscrit dans le relais
et à son identité attestée. Aucune clé ou inscription fictive n'est ajoutée.

Commande :

    node --experimental-transform-types scripts/run-pinned-native-relay.mjs /CHEMIN/relay.json EMPREINTE_SHA256_APPROUVEE

Le relais reste en 127.0.0.1. Un verrou exclusif dans son dossier de données
interdit deux processus concurrents. Après arrêt propre il est libéré ;
après crash ou démarrage incomplet il reste en place. Réconcilier l'état
et les sauvegardes avant toute levée manuelle. Pas de redémarrage aveugle.

## Démarrage d'une liaison Scattering privée

Compiler le pacer natif depuis les sources vérifiées dans
labs/quantic-native/scattering/native (go build -trimpath).
Préparer un plan privé distinct par côté de chaque liaison. Les champs
exacts du plan sont :

- format: quantic-private-scattering-host/v1
- labOnly: true
- pacerBinary: chemin Linux absolu de l'exécutable vérifié
- pacerSha256: empreinte SHA256 attendue
- listenIP, listenPort: adresse IPv4 privée et port UDP de ce côté
- peerIP, peerPort: adresse IPv4 privée et port UDP de l'autre côté
- periodUs: période fixe de 5000 à 100000 microsecondes
- carrier: configuration native Scattering existante avec labOnly, role,
  secretHex, epochHex, recvPort, httpPort, queueDir, stateDir. En rôle relay,
  httpPort désigne le relais local. En rôle client, le pont local.

Le secret et l'epoch (32 octets aléatoires chacun) ne doivent jamais
transiter en argument, journal, Git ou message non protégé. Les dossiers
queue et state sont privés, distincts et précréés. Le plan entier est en
0600 dans un dossier 0700 ; son empreinte indépendante est requise.

    node scripts/run-native-scattering-host.mjs /CHEMIN/host.json EMPREINTE_SHA256_APPROUVEE

Le superviseur lance les deux processus natifs et le pont, arrête l'ensemble
en cas de panne d'un enfant et ne réutilise jamais un epoch consommé.
Le statut de démarrage n'est pas une preuve de communication distante.
L'opérateur autorise uniquement le pair prévu sur le pare-feu UDP.
Aucun changement automatique de pare-feu ou de routage.

## Exploitation

Lancer chaque autorité, relais et liaison sous un compte dédié, via le
gestionnaire de services de la machine. Pour ces composants de laboratoire,
désactiver les redémarrages automatiques (Restart=no dans systemd) : la
récupération après interruption exige vérification de la persistance et
nouvelle session coordonnée. Garder les secrets hors des fichiers unit et
journaux. Une limite de 16 opérations par epoch existe toujours dans le protocole de
messagerie. La rotation programmée ci-dessous fournit des sessions successives
sans augmenter cette limite. Ce n'est pas une négociation automatique de clés
à la demande et elle ne garantit pas la disponibilité continue.

## Validation

Le test native-scattering-host.test.mjs lance deux vrais processus
superviseurs et leurs pacers/sinks natifs sur UDP. Le test
native-relay-operator.test.mjs vérifie les pins et le verrou de démarrage.
Ils ne remplacent pas un test sur deux hôtes physiques, des autorités
administrativement indépendantes, l'audit de sécurité et un déploiement
autorisé. Aucune instance publique n'est créée par ces scripts.


## Renouvellement automatique préautorisé (Linux Alpha)

Les deux opérateurs préparent **le même calendrier UTC** et des plans locaux
distincts pour chaque session. Chaque paire secret/epoch est indépendante,
transmise par un canal protégé ; ne dériver ni réutiliser les anciennes clés.
Les ports, adresses, rôle, binaire, cadence et dossier d'état restent stables
sur chaque hôte ; chaque session a un nouveau dossier de transit vide. Les
marqueurs d'epoch consommé s'accumulent dans le même dossier d'état.

Le fichier de calendrier (0600, dossier 0700) a exactement ces champs :

- format: quantic-private-scattering-schedule/v1
- labOnly: true
- slots: liste de 2 à 24 objets contenant chacun startMs, endMs (temps UTC
  en millisecondes Unix), file (plan local dans le même dossier) et pin
  (empreinte SHA256 de ce plan approuvée indépendamment).
- Chaque créneau dure de 45 secondes à 1 heure. Les créneaux sont séparés
  de 2 secondes. Le premier doit commencer dans le futur ; horizon de 24 h.
  Les horloges doivent être synchronisées ; un saut de plus d'une seconde
  par rapport à l'horloge monotone interrompt le service.

    node scripts/run-native-scattering-schedule.mjs /CHEMIN/schedule.json EMPREINTE_APPROUVEE

Le superviseur démarre chaque liaison à l'heure prévue et la ferme à la
fin du créneau. L'admission des nouvelles opérations est suspendue 35
secondes avant la fermeture pour permettre la fin des opérations en cours.
Le relais vérifie lui aussi cette échéance. Le client reçoit un refus
explicite après 16 opérations ou durant la fenêtre de drainage ; il ne
renvoie pas automatiquement une opération. Une panne, un saut d'horloge,
un démarrage en retard ou un epoch déjà consommé arrêtent tout le calendrier.
Aucun rattrapage des créneaux manqués et aucune reprise automatique après
redémarrage. Les transitions arrêtent puis relancent les pacers : la
continuité de couverture et l'indécelabilité ne sont pas démontrées.

La CI ajoute un essai avec deux superviseurs sur UDP, seize opérations
acceptées dans le premier epoch, la dix-septième refusée, puis quatre
opérations dans un deuxième epoch, exactement vingt traitements côté
relais. Les résultats restent limités à un runner Linux, un serveur HTTP
de test et un calendrier préparé ; aucune validation physique, ni portage
Windows, ni accord de clé post-compromission ne sont revendiqués.
