# Secure Core V2 — filiation de la racine post-quantique (23 novembre 2026)

**Statut : contrôle supplémentaire de laboratoire, exclusivement en lecture seule.** Pas de migration d'une vraie identité, d'importation de clés privées, de révocation, de paiement, de déploiement automatique ou de droit de suppression.

## Pourquoi ce contrôle est nécessaire

L'identité Web historique utilise une racine de propriété P-256 exportable. Une attaque contre l'origine Web ou le stockage peut voler cette clé. Une signature P-256 authentique sur un nouveau profil n'est donc **pas suffisante** pour accepter une nouvelle racine ML-DSA-65 : le propriétaire pourrait être un attaquant.

La vérification existante du Crypto Profile sait déjà vérifier la signature de continuité ML-DSA-65 **si le profil précédent lui est fourni**. Le nouveau préflight `lib/quantic/native-pq-root-transition.mjs` relie cette capacité à une preuve de filiation **indépendamment épinglée** :

1. Refuser sans l'empreinte historique P-256 indépendante, l'empreinte du profil PQ précédent, l'empreinte SPKI de la **racine ML-DSA précédente** et l'empreinte attendue de la racine suivante.
2. Authentifier la signature P-256 du manifeste historique et la signature P-256 du manifeste actuel ; refuser les forks/rollback manifestes.
3. Authentifier l'ancien profil contre son **manifeste historique** (pas un manifeste récent pouvant avoir révoqué un appareil légitime autrefois).
4. Vérifier exactement le contenu canonique de l'ancien profil et que son SPKI ML-DSA vérifie l'empreinte conservée indépendamment ; refuser la réutilisation d'un profil étranger.
5. Vérifier le profil suivant contre le manifeste actuel et l'ancien profil déjà épinglé : signature P-256, auto-signature ML-DSA nouvelle, **signature de continuité de l'ancienne racine ML-DSA** ; séquence strictement croissante, politique `hybrid-required` sans downgrade.
6. Vérifier le SPKI de la nouvelle racine contre un pin attendu indépendant. Retourner un rapport public sans secrets et avec tous les indicateurs de bascule réelle à `false`.

L'appel à `rehearseNativeIdentityMigration` accepte désormais l'argument optionnel `rootTransitionEvidence`. Sans lui, le rapport indique `pqRootLineageVerified:false` et ajoute le bloqueur `previous-pq-root-lineage-not-independently-proven`. Avec des preuves malformées, la répétition échoue immédiatement ; avec une filiation valide, ce **seul** verrou peut être déclaré validé. Les nombreux autres bloqueurs restent inchangés.

## Menaces testées

- Un attaquant ayant la clé P-256 historique crée un nouvel ensemble ML-DSA : **refus**, car il n'a pas la signature de continuité de l'ancienne racine épinglée.
- Ancienne empreinte de profil, ancien pin ML-DSA, nouveau pin ML-DSA ou pin P-256 substitué : refus.
- Profil au même numéro de séquence, régression, fork d'identité ou downgrade `hybrid-required` : refus.
- Auto-signature ou signature de continuité ML-DSA absente ou altérée : refus.
- Filiation non renseignée dans la répétition de migration : résultat explicitement `false`, sans autorisation d'enrôlement.

Les tests utilisent de véritables primitives Node 24 P-256 et ML-DSA-65 avec des clés générées à l'exécution ; les appareils sont fictifs.

## Limites et prochaine étape

- Les **pins historiques doivent provenir d'un mécanisme externe à l'archive et à la réponse de relais** ; le code ne détermine pas automatiquement si leur origine est fiable.
- Une racine ML-DSA précédemment compromise peut signer une fausse continuité ; le système doit alors disposer d'une récupération autorisée hors bande par des autorités indépendantes, avec politique de gouvernance explicite.
- Les clés privées ML-DSA natives et leur résistance à l'exfiltration ne sont pas démontrées par une vérification publique de signature.
- Le protocole ne prouve ni l'exhaustivité des messages, ni la convergence des relais, ni l'absence de split-brain réseau, ni la durabilité du stockage Windows sous coupure électrique.
- Il ne fournit pas une migration effective de l'identité ni un mécanisme de restauration transactionnelle.
- Un ancien compte sans profil PQ fiable ne peut **pas** inventer un ancrage historique : il faut une procédure d'enrôlement initial différente, avec confiance explicitement établie.

**Tests :**

```sh
node --experimental-transform-types --test tests/native-pq-root-transition.test.mjs tests/migration-rehearsal.test.mjs
```

Avant une bascule réelle : établir un référentiel durable et indépendant des pins, tester la rotation sur des dispositifs physiques distincts et bâtir un mécanisme de garde native de la racine, un journal de révocation cohérent et une récupération authentifiée sans remettre en circulation les secrets Web historiques.
