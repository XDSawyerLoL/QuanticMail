# Brouillons chiffrés — nouvelles inscriptions Windows

Une clé AES-256 aléatoire indépendante, draft.vault, est scellée à la création
du coffre avec les deux secrets et un domaine distinct des reçus et du
contrôleur. Le helper graphique hors ligne ouvre uniquement cette clé et
vérifie le contact local, chiffre le brouillon par AES-GCM, écrit en mode
exclusif NTFS, synchronise puis relit et authentifie le contenu exact.
Le sujet, le corps et le destinataire ne sont pas persistés en clair.
Le nom aléatoire, la taille et la date restent observables localement.
L'enregistrement ne contacte aucune autorité ni serveur.

L'envoi ouvre le brouillon dans la session Go autorisée, vérifie les champs,
puis suit le chemin hybride et les approbations existantes. Le texte est
présent dans la mémoire des composants d'interface de confiance pour
affichage ; aucune garantie contre un OS compromis. Un second déverrouillage
est nécessaire pour l'envoi après l'enregistrement hors ligne. Les fichiers
historiques restent intacts et les nouveaux coffres refusent les anciens
brouillons en clair ainsi que les imports historiques. Une ancienne
candidature sans draft.vault n'est pas migrée automatiquement.
Aucune mise en service physique de Scattering ou livraison réelle prouvée.
