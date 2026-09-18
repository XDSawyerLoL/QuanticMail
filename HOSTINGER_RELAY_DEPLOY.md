# Quantic Relay — déploiement Hostinger

Ce service est distinct du frontend QuanticMail. Il doit être déployé comme **Node.js Web App** depuis le dépôt `XDSawyerLoL/QuanticMail`.

## Configuration Hostinger

- Branche : `main`
- Node.js : 22.x
- Installation : `npm install`
- Build : aucun build applicatif requis
- Start : `npm run relay:hostinger`
- Port : fourni automatiquement par Hostinger via `PORT`

## Variables obligatoires

```text
QUANTIC_RELAY_DATABASE_URL=postgresql://...
QUANTIC_RELAY_IDENTITY_SECRET=<32+ caractères, secret unique>
QUANTIC_RELAY_PUBLIC_ENDPOINT=https://<domaine-public-du-relais>
QUANTIC_RELAY_BOOTSTRAP=https://quanticmail-network-relay.onrender.com,https://quantic-network-relay-backup-production.up.railway.app
```

Le service **refuse de démarrer** sans PostgreSQL durable, secret d’identité assez long, endpoint public HTTPS et au moins un bootstrap HTTPS.

## Vérification

```bash
npm run relay:smoke -- https://<domaine-public-du-relais>
```

La route de santé est :

```text
GET /api/quantic/health
```

Une réponse valide contient `ok: true`, `protocol: "quantic-relay/1"`, un `relayId` stable et `federation: "quantic-federation/1"`.

## Continuité

Après mise en ligne, ajouter l’URL du relais Hostinger aux bootstraps du frontend. Render et Railway restent des chemins de secours jusqu’à réussite d’un test réel d’envoi/réception avec le relais Hostinger.
