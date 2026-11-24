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

## Protocole deux machines physiques (non exécuté automatiquement)

Sur deux machines qui vous appartiennent, avec le pacer compilé pour leur OS et un port UDP autorisé par l'opérateur :

1. **B, réception :** `node scripts/scattering-physical-probe.mjs receive CHEMIN_ABSOLU_PACER IP_B 49001 60`.
2. **A, envoi couverture seule :** `node scripts/scattering-physical-probe.mjs send CHEMIN_ABSOLU_PACER IP_B 49001 30`.
3. **B, nouvelle réception :** redémarrer la commande de réception avec un journal local distinct.
4. **A, envoi synthétique :** `node scripts/scattering-physical-probe.mjs send-synthetic CHEMIN_ABSOLU_PACER IP_B 49001 30`. Les 1 540 cellules AES-256-GCM synthétiques sont préparées à l'avance et transmises par le pacer natif à cadence identique. Ce chiffre est un nombre préparé, **pas** un nombre reçu et authentifié.
5. Répéter les deux modes en inversant A et B. Comparer les mesures de B, idéalement complétées par une capture passive indépendante du port de test, puis par plusieurs répétitions dans un ordre alterné.
Capturer **uniquement le port de test**, sans comptes ni conversations réelles. Conserver localement les traces ; ne jamais publier des PCAP contenant des adresses privées/publiques.
La sonde peut désormais émettre les cellules synthétiques. En revanche, son récepteur Go transmet les datagrammes sans déchiffrer ni vérifier leur authenticité : il faut ajouter un consommateur authentifié et comparer des captures indépendantes avant toute affirmation sur la confidentialité ou la livraison de contenu.

Les conditions de passage à une affirmation de sécurité sont plus strictes : sources indépendantes (idéalement au moins trois sites), captures d'entrée et de sortie corrélées, essais de charge CPU, réseau avec pertes et jitter, et hypothèses d'attaquant préenregistrées. Un relais connaissant les expéditeurs et les correspondances de pseudonymes peut annuler un modèle de mélange idéal.

Aucune migration d'identité, aucun déploiement public et aucune réduction automatique de couverture ne découle de ces essais.
