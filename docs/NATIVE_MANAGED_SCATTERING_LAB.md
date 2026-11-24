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

## Fenced cutover experiment
The new explicit supervisor path reserves a generation, negotiates fresh hybrid keys, durably stages its transcript, starts both native processes with mailbox traffic gated, and exchanges role- and transcript-bound authenticated READY/ACK messages over the existing connected UDP bootstrap socket. Only then does it finalize the local fence and enable mailbox traffic. Failed or interrupted staged transitions block further reservations; no automatic resending or rollback. The existing SQLite fence is Linux-only, assumes trusted non-rolled-back storage, and is not yet linked to the Windows vault quorum. An authenticated readiness barrier cannot guarantee simultaneous activation or delivery under arbitrary network failure. The caller must close the old carrier first; dashboard rotation and interrupted-state reconciliation remain separate work.

## Native quorum-backed fence (Windows broker experiment)
The authenticated enrolled broker exposes reserve/stage/finish via the renewal grant. Each phase consumes a distinct durable journal record through the existing quorum CAS. The channel cannot be restarted after a consumed generation-zero reservation, even by reopening the broker or changing the role. Each delegated signature must match the exact current reservation including the previous transcript. The controller passes only public transcript metadata, not transport secrets. Stage/finish require a successful local signature and the same reservation token; finish relies on the trusted controller's assertion of peer readiness, not independently verified UDP evidence in Go. Grant state is volatile; crash recovery intentionally refuses the old channel. No dashboard activation, no automatic recovery or claims of full Windows end-to-end testing.

## Bounded automatic rotation (trusted controller experiment)
The Windows controller exposes a lifecycle abort signal and the rotation driver consumes its existing one-consent native signer/fence. At most four epochs, each at most 25 minutes, and never beyond grant expiry. Fresh queue/state directories are mandatory. At a planned cutover the old endpoint refuses new operations and must be idle, otherwise the entire cycle stops. Loss, expiry, closing the vault, failure of negotiation or unknown delivery stop without replay. The negotiated start observes cancellation during UDP bootstrap and before activation; endpoint cleanup is awaited before reuse. Tests cover budget, loss, expiry, failed retirement and late startup after abort. Both peers still require explicitly provisioned matching settings, socket paths and epoch directories. Relative timers may drift; mismatch fails closed. The driver is not called by the historical dashboard yet and there is no automatic recovery after crash or proof of physical two-host operation.
