# Démarrage supervisé Scattering — laboratoire Windows

Lors de l'import d'activation, le champ facultatif managedCarrier contient
configPin (SHA-256 exact du fichier scattering.json), listen et target
(IPv4 et port explicites). Ce fichier doit être préprovisionné par
l'opérateur dans le sous-répertoire privé carrier du coffre, avec queue
et state créés par le helper Windows existant. L'empreinte est liée au
dossier d'activation authentifié et l'endpoint doit être le même loopback
que celui de la messagerie. Ce champ autorise le démarrage automatique
du trafic UDP de laboratoire à l'ouverture de l'application.

Une seule identité avec ce champ doit exister. Le tableau de bord lance le
superviseur sans console. Le superviseur vérifie la configuration et le
pacer contre le manifeste épinglé, réserve l'époque une seule fois,
démarre le sink et le pacer et attend leurs READY après ouverture des
sockets. Il s'arrête à la fermeture du tableau de bord, à la perte de
l'un des processus ou au plus tard après 30 minutes. Les enfants utilisent
un pipe parent : EOF les arrête si le superviseur est interrompu.
Aucun renvoi, aucune réutilisation d'époque, aucun nettoyage destructif.
Un démarrage partiel peut consommer l'époque : intervention opérateur.

Le statut local ne prouve ni disponibilité du pair ni livraison. Le relais
natif distant et le pair UDP doivent être provisionnés séparément. Le secret
partagé Scattering reste sous ACL NTFS comme dans le laboratoire historique,
pas encore scellé. Pas de renouvellement automatique des époques, de
négociation P2P ni de traversée NAT. Aucun port HTTP public ni modification
de pare-feu.
