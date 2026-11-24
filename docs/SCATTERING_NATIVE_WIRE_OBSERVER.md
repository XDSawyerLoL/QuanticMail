# Scattering — essai UDP natif mesuré, puis essai à deux machines

## État de preuve

Le test exécutable `scripts/scattering-wire-observer-lab.mjs` envoie des paquets UDP avec le **vrai pacer Go** (168 octets, 20 ms). Un socket UDP sur 127.0.0.1 horodate les datagrammes reçus. Les deux états expérimentaux sont (a) couverture seule et (b) file de cellules AES-256-GCM synthétiques et authentifiées, préchargée avant le démarrage. Même exécutable, même destination, même durée et même cadence préconfigurée.

Le récepteur fait aussi office d'observateur des **seuls comptes, tailles et intervalles**. Le contrôle interne connaît les empreintes des cellules préparées pour vérifier que le pacer a réellement consommé la file ; **ces empreintes ne sont pas utilisées pour l'inférence de l'observateur et ne sont pas exportées**.

Ce test est **un essai UDP loopback réel entre processus indépendants sur une seule machine**, pas un essai WAN, deux hôtes, capture passive autonome ou mixnet. Aucun secret utilisateur ni compte Quantic n'est chargé. Aucun trafic Internet n'est créé.

## Exécution reproductible

Sous Linux avec Go >= 1.23 et Node >= 22 :

```bash
cd labs/quantic-native/scattering/native
go build -trimpath -o /tmp/Quantic-Pacer .
cd ../../../..
node --test tests/scattering-wire-metrics.test.mjs
node scripts/scattering-wire-observer-lab.mjs /tmp/Quantic-Pacer 3 2
```

Le dernier nombre représente le nombre de paires (couverture/charge), inversées d'une paire à l'autre pour limiter la dérive. Le test refuse des durées hors de 2 à 8 secondes, plus de six paires, les adresses distantes, les tailles de datagramme non conformes, les compteurs incohérents et l'absence de cellules synthétiques effectivement reçues. Il efface les files temporaires. Les mesures contiennent : paquets prévus/émis/manqués côté pacer, paquets reçus et octets côté observateur, délais médians/p95/p99 entre réceptions et écarts entre conditions.

Le comparatif descriptif n'est **pas** un test statistique indépendant. Une différence n'implique pas nécessairement une faiblesse exploitable ; une absence de différence ne prouve pas l'indécelabilité. Le nombre de paires est trop faible pour fournir un intervalle de confiance de sécurité.

## Validation réseau virtuel indépendante — 24 novembre 2026

Le workflow autonome `.github/workflows/scattering-netns-lab.yml` exécute le **vrai binaire Go** entre deux espaces réseau Linux isolés par un lien `veth` ; un troisième processus `tcpdump` observe le trafic depuis le côté réception. Il ne se limite pas à l'interface loopback, mais reste **une seule machine physique et un seul noyau Linux**. Aucun accès WAN, compte utilisateur ou identité réelle.

- [Exécution 45345781952](https://github.com/XDSawyerLoL/QuanticMail/actions/runs/45345781952) : test UDP/capture indépendant réussi ; couverture et cellules synthétiques ont toutes deux produit 300/300 datagrammes transmis, capturés et reçus, zéro échéance manquée ou taille invalide.
- [Exécution 45346262964](https://github.com/XDSawyerLoL/QuanticMail/actions/runs/45346262964) : ajout du contrôle d'authenticité au récepteur avec clé AES-256-GCM **synthétique éphémère** (32 octets, fichier privé mode 0600, jamais d'identité Quantic) ; 300/300 cellules synthétiques authentifiées, zéro cellule non authentifiée, zéro rejeu, zéro paquet malformé ; 300/300 datagrammes capturés dans les deux conditions.
- Espacements p95 du second essai : **20,055 ms** en couverture seule et **20,055 ms** en transmission synthétique (différence observée de 0,000 ms à la précision des résultats). Ce n'est pas un intervalle de confiance ni une démonstration d'indistinguabilité.
- Le témoin de sécurité vérifie l'authenticité de chaque cellule synthétique et le non-rejeu dans ce parcours déterminé, **pas** la continuité d'un vrai message Quantic Mail ni la récupération après perte.

Commande pour rejouer sur un hôte Linux **dédié au laboratoire**, avec privilèges administrateur pour créer les interfaces `veth` :

```bash
cd labs/quantic-native/scattering/native
go build -trimpath -o /tmp/Quantic-Pacer .
cd ../../../..
node --test tests/scattering-netns-evidence.test.mjs tests/scattering-wire-metrics.test.mjs
bash scripts/scattering-netns-observer-lab.sh /tmp/Quantic-Pacer
```

Le script nettoie les espaces réseau et les fichiers de clé synthétique. La capture et les journaux bruts ne sont pas publiés en artefacts. **Ne pas exécuter sur une machine de production ni sur un compte réel.**

## Protocole deux machines physiques (non exécuté automatiquement)

Sur deux machines qui vous appartiennent, avec le pacer compilé pour leur OS et un port UDP autorisé par l'opérateur :

1. **B, réception :** `node scripts/scattering-physical-probe.mjs receive CHEMIN_ABSOLU_PACER IP_B 49001 60`.
2. **A, envoi couverture seule :** `node scripts/scattering-physical-probe.mjs send CHEMIN_ABSOLU_PACER IP_B 49001 30`.
3. **B, nouvelle réception authentifiée :** préparer un fichier de 32 octets aléatoires en stockage privé (permissions 0600), transmis à A par un canal de laboratoire sécurisé ; puis exécuter `node scripts/scattering-physical-probe.mjs receive-synthetic CHEMIN_ABSOLU_PACER IP_B 49001 60 CHEMIN_ABSOLU_CLE_TEST`.
4. **A, envoi synthétique :** `node scripts/scattering-physical-probe.mjs send-synthetic CHEMIN_ABSOLU_PACER IP_B 49001 30 CHEMIN_ABSOLU_CLE_TEST`. Le compteur `authenticatedSynthetic` côté récepteur certifie les cellules effectivement déchiffrables par le consommateur de test. Ne réutiliser aucune clé de coffre ou de compte.
5. Répéter les deux modes en inversant A et B. Comparer les mesures de B, idéalement avec une capture passive séparée du port de test et plusieurs répétitions en ordre alterné. Supprimer la clé de test après l'expérience.
Capturer **uniquement le port de test**, sans comptes ni conversations réelles. Conserver localement les traces ; ne jamais publier des PCAP contenant des adresses privées/publiques.
Le récepteur Go reste un transport passif sans clés. Le mode `receive-synthetic` ajoute **un consommateur Node de laboratoire distinct** qui déchiffre et authentifie les cellules avec la clé de test. Cela ne valide pas le protocole de messagerie complet ou la confidentialité d'une véritable identité.

Les conditions de passage à une affirmation de sécurité sont plus strictes : sources indépendantes (idéalement au moins trois sites), captures d'entrée et de sortie corrélées, essais de charge CPU, réseau avec pertes et jitter, et hypothèses d'attaquant préenregistrées. Un relais connaissant les expéditeurs et les correspondances de pseudonymes peut annuler un modèle de mélange idéal.

Aucune migration d'identité, aucun déploiement public et aucune réduction automatique de couverture ne découle de ces essais.
