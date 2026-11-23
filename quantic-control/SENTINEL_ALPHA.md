# Quantic Sentinel Alpha — surveillance Windows réelle, locale et volontaire

## Ce que cette version fait

**Quantic Sentinel** est une application Win32 native distincte, sans navigateur ni terminal PowerShell visible. Contrairement au prototype de vérification manuelle d'une empreinte SHA-256, cette version **écoute automatiquement** les notifications `ReadDirectoryChangesW` envoyées par Windows sur un dossier choisi et ses sous-dossiers.

1. Ouvrir `quantic-sentinel-alpha.exe` et choisir « Surveiller un dossier ».
2. Sélectionner un dossier personnel de test, de préférence une copie de fichiers non sensibles.
3. L'application affiche l'activité et une alerte si elle détecte, dans une fenêtre glissante de 15 secondes :
   - 20 fichiers distincts modifiés/créés/renommés ;
   - 8 fichiers distincts supprimés ou renommés ;
   - 4 apparitions/renommages vers des extensions fréquemment associées à des fichiers chiffrés ;
   - ou une perte d'événements du tampon Windows (la surveillance est alors incomplète).
4. Les alertes sont limitées en fréquence (30 s) pour éviter de saturer l'écran.
5. « Arrêter » désactive le watcher. « Effacer le journal » efface uniquement l'affichage de session. Fermer la fenêtre arrête la surveillance.

Le watcher utilise un handle de dossier avec `FILE_LIST_DIRECTORY` et `FILE_FLAG_OVERLAPPED`, un tampon borné et `CancelIoEx` pour un arrêt propre. Aucun contenu de fichier n'est lu par le watcher ; seuls noms, opérations et horodatages transitent en mémoire dans le processus. Les événements sont bornés et les alertes n'enregistrent pas de contenu privé.

### Vérifications

- Tests pure Go de seuils de détection, expiration de fenêtre, anti-spam, fichiers distincts, extensions suspectes et notification d'événements perdus.
- Test d'intégration Windows : création d'un fichier temporaire, réception effective d'un événement `ReadDirectoryChangesW`, annulation du contexte et arrêt propre dans un délai borné.
- Workflow GitHub Windows/Ubuntu : `go test ./...` ; Linux `go test -race ./...` ; compilation de l'exécutable Windows GUI sans console et validation de son sous-système PE.

### Limites importantes

**Ce n'est pas un antivirus, ni une défense opérationnelle contre un rançongiciel.**

- `ReadDirectoryChangesW` ne fournit **pas l'identité/PID du processus** ayant modifié le fichier. Il n'y a **aucun blocage** d'exécution, restauration automatique, isolation réseau ou quarantaine.
- Une attaque peut chiffrer les fichiers **avant** qu'une alerte ne s'affiche ; des activités bénignes (copie de nombreux fichiers, synchronisation) peuvent déclencher de faux positifs. Un malware peut aussi ralentir ou contourner cette surveillance.
- Il ne s'agit pas d'un service Windows résident : la surveillance s'arrête quand la fenêtre est fermée, quand le PC redémarre ou si le processus est interrompu.
- Aucun lien fonctionnel avec la sécurité post-quantique ou Identity Vault n'est activé dans l'interface. Quantic ID et le coffre demeurent des interfaces expérimentales séparées.
- Le binaire Windows est non signé, non installé et non audité. Ne pas l'utiliser comme système de protection principal ni désactiver Microsoft Defender.
- Les interactions graphiques ne sont pas entièrement automatisées sur un poste Windows physique ; seuls l'intégration API native et le lancement/format d'exécutable sont validés par CI.

## Prochain vrai jalon de protection

Construire **un agent Windows installé avec consentement explicite**, qui démarre avec le système, journalise durablement les détections et corrèle les événements à un processus via une API d'audit Windows adaptée. Prévoir une réaction à déclenchement manuel, réversible et testée (sans tuer arbitrairement des processus), et intégrer un contrôle de politiques signé. Il faudra des simulations de rançongiciel en environnement isolé et des essais de faux positifs avant toute protection active.
