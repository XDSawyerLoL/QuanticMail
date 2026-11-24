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

## Interface de signature externe (laboratoire)

La négociation hybride accepte maintenant un signataire asynchrone à la
place des clés privées Node, jamais les deux. Chaque signature retournée
est vérifiée localement contre les deux clés publiques épinglées. Une
fermeture ou un refus avant signature interdit la libération de session.
Le test UDP utilise des signataires fictifs. Le broker Go doit encore
implémenter l'autorisation dédiée (contact, contexte, expiration, anti-rejeu)
avant tout raccordement au dashboard. Aucun renouvellement automatique ni
changement du profil historique n'est introduit par cette interface.

## Native signature bridge (experimental)
The enrolled Windows broker supports scattering-sign-lab only through the authenticated controller pipe, with native approval, a current pinned contact, quorum contact authorization and durable one-shot replay reservation. Go reconstructs the exact hello and response transcripts, including validation of the peer's two signatures on the responder path. The controller supplies only public keys and a signing callback. This is not yet used by the dashboard; no autonomous renewal or migration of old configurations. Local approval and the existing quorum are required for each attempt. No claim of rollback resistance beyond the existing quorum assumptions.

## Bounded renewal authorization (experimental)
One explicit local consent per enrolled broker process grants at most four consecutive signing attempts (generations 0–3), for one pinned contact, role and channel, during at most two hours and never beyond contact expiration. No persistent capability or exported keys. Each signature still validates its complete handshake and reserves its own quorum-anchored replay record. Scope failures, replay or signing failure invalidate delegated use. The grant counts attempts, not proven peer completions; the distributed epoch cutover and dashboard still need integration. No automatic retry of uncertain mail or renewal from an interrupted broker.
