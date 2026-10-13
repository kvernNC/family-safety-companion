# Contrôle parental pour Windows 11

Console PowerShell (WPF) pour préparer et administrer le PC Windows d'un enfant (compte standard géré par
Microsoft Family Safety) : un interrupteur et une description par protection locale, plus une fenêtre qui pilote
Family Safety (sites autorisés, applications, temps d'écran).

> ⚠️ **API non officielle.** La partie « Family Safety (cloud) » utilise l'API mobile non documentée de
> Microsoft Family Safety, en se présentant comme l'application Android officielle (méthode reprise de
> [pyfamilysafety](https://github.com/pantherale0/pyfamilysafety)). Cet usage est probablement contraire aux
> conditions d'utilisation de Microsoft, l'API peut changer sans préavis, et ton compte familial est exposé.
> À utiliser en connaissance de cause.

## Aperçu

La console : une carte par protection, avec sa description et son interrupteur. Une protection levée se réactive
d'elle-même après le délai choisi.

![Console principale : protections locales avec interrupteurs](docs/console.png)

La fenêtre Family Safety, onglet Sites web : réglages du filtre, ajout de sites en masse, tentatives bloquées.

![Fenêtre Family Safety : ajout de sites en masse](docs/family-safety.png)

*Captures réalisées avec des données fictives.*

## Fonctions

### Protections locales (25, réversibles)
- **Edge** : extensions bloquées, pas de navigation privée ni de profil invité, outils de développement bloqués,
  historique non effaçable, téléchargements dangereux bloqués, SmartScreen imposé, SafeSearch et YouTube restreint
  forcés, proxy verrouillé, DNS sécurisé (DoH) désactivé…
- **Réseau** : DNS filtrant Cloudflare Family (1.1.1.3) imposé, pare-feu bloquant tout autre DNS (ports 53 et 853).
- **Windows** : SmartScreen en mode « Bloquer », widgets et suggestions web désactivés ; en option : applications du
  Store uniquement, stockage USB désactivé, élévation refusée aux comptes standard, historique d'activités et
  localisation désactivés, maintenance hebdomadaire (fichiers temporaires, `winget upgrade`).
- **Démarrage élevé (SYSTEM)** : menu pour lancer un programme choisi EN SYSTEM dans la session de l'enfant à
  l'ouverture de session, et pour (re)démarrer un service en l'élevant au compte LocalSystem (voir plus bas).
- Réactivation automatique après un délai quand tu lèves une protection (tâche planifiée SYSTEM),
  sauvegarde du registre avant chaque modification, diagnostic (comptes, navigateurs ou VPN en trop, démarrage).

### Family Safety (cloud)
- Connexion automatique : une fenêtre Edge séparée s'ouvre, tu te connectes, le jeton est stocké chiffré (DPAPI)
  dans un dossier réservé aux administrateurs.
- **Sites web** : lecture des réglages du filtre ; **ajout de sites en masse** (liste collée ou fichier, progression,
  reprise, mémoire des sites déjà envoyés, journal) ; fenêtre « Tentatives bloquées » qui lit le rapport d'activité
  pour autoriser les domaines manquants. Les listes existantes ne sont pas lisibles par cette API : elles se
  consultent et se suppriment sur [account.microsoft.com/family](https://account.microsoft.com/family/).
- **Applications** : blocage, déblocage, déblocage temporaire avec reblocage automatique.
- **Appareil** : blocage temporaire d'une plateforme, limites quotidiennes de temps d'écran.
- **Activité** : temps d'écran du jour, historique web et recherches (affichage brut), appareils.

## État (octobre 2026)
| Fonction | État |
|---|---|
| Interface, connexion Family Safety, lecture des membres et des réglages du filtre | Vérifié |
| Ajout de sites (unitaire et en masse) | Vérifié : les sites apparaissent sur le site officiel |
| Tentatives bloquées, historique web et recherches | Format des réponses non confirmé |
| Blocage d'applications, blocage d'appareil, limites de temps d'écran | Non testé en réel (gestion du fuseau horaire non confirmée) |
| Protections locales | Code vérifié, pas encore éprouvé sur un PC d'enfant : teste chacune avant de t'y fier |
| Démarrage élevé (SYSTEM), élévation de service | Non testé sur un appareil réel : vérifie `elevate-launch.log` et l'écran de l'enfant |

## Prérequis
- Windows 10 ou 11 (Home compris), Windows PowerShell 5.1, Microsoft Edge.
- Un compte administrateur (parent) ; l'enfant utilise un compte **standard**.
- Les fichiers `.ps1` et `.psm1` doivent rester encodés en **UTF-8 avec BOM** (accents de l'interface).

## Utilisation
Place `ControleParental.ps1` et `FamilySafety.psm1` dans le même dossier, puis :

```powershell
powershell -ExecutionPolicy Bypass -File .\ControleParental.ps1
```

Le script demande l'élévation (UAC). En ligne de commande (administrateur) :

```powershell
.\ControleParental.ps1 -Status                                  # état des protections
.\ControleParental.ps1 -Apply recommended                       # active les protections recommandées
.\ControleParental.ps1 -Revert edge-downloads                   # lève une protection
.\ControleParental.ps1 -Diagnostic                              # rapport de diagnostic
.\ControleParental.ps1 -FsImport liste.txt -FsChild Prenom      # ajout en masse de sites autorisés (-FsBlock pour bloquer)
```

## Démarrage élevé (SYSTEM) — menu « Démarrage élevé »
Sur un compte standard, certaines applications n'ont pas les droits d'agir sur le matériel. Cas typique : sur une
**ROG Ally**, Armoury Crate ne peut pas appliquer le mode de puissance depuis le compte de l'enfant, et la
consommation reste au maximum. Donner à l'enfant un accès administrateur (compte admin, `runas /savecred`)
réglerait le symptôme mais annulerait Family Safety et toutes les protections : il pourrait tout élever.

Le menu **Démarrage élevé (SYSTEM)** fait ce travail sans donner de droits à l'enfant. C'est toi, admin, qui
choisis les cibles dans la console (elle-même protégée par l'UAC) ; chaque cible est **figée dans une tâche
planifiée SYSTEM** que l'enfant ne peut ni voir ni modifier. Il déclenche l'ouverture de session, mais ne choisit
jamais ce qui est élevé.

- **Programmes au démarrage de session** : tu ajoutes un `.exe` (et, au besoin, des arguments et une liste de
  processus à tuer d'abord). La console crée une tâche SYSTEM déclenchée à l'ouverture de session, qui lance le
  programme **en SYSTEM, dans la session interactive de l'enfant** (même principe que `PsExec -s -i` : jeton SYSTEM
  injecté dans la session active). Le bouton « Tester maintenant » le lance tout de suite.
- **Services** : tu passes un service au compte **LocalSystem** + démarrage automatique, puis la console le
  redémarre. La liste propose les services ASUS / Armoury Crate détectés.

Pour une ROG Ally : laisse les arguments vides, mets les processus Armoury Crate dans « tuer d'abord » (par ex.
`ArmouryCrate.UserSessionHelper`, `ArmouryCrateSE`) et pointe la cible sur l'exécutable d'Armoury Crate. Ta tâche
qui lance le mode Xbox reste utile pour l'interface manette. **À tester** : certains programmes se comportent mal
lancés en SYSTEM ; si c'est le cas, l'autre piste est d'élever le ou les services d'Armoury Crate dans l'onglet
Services. Journal : `C:\ProgramData\ControleParental\elevate-launch.log` ; le diagnostic affiche aussi les
entrées configurées et l'état des services ASUS.

```powershell
.\ControleParental.ps1 -ElevList                 # liste les programmes configurés
.\ControleParental.ps1 -ElevTest "ArmouryCrate"  # lance maintenant l'entrée nommée ainsi
.\ControleParental.ps1 -SvcElevate ArmouryCrateService   # élève + redémarre un service
```

> ⚠️ Lancer un programme en SYSTEM lui donne les droits maximaux de la machine. N'ajoute que des programmes de
> confiance (Armoury Crate et autres outils constructeur). Ce menu ne crée aucun champ où l'enfant fournirait
> lui-même une cible : il ne peut pas s'en servir pour élever autre chose.

## Liste blanche
`exemple-liste-blanche.txt` est une proposition pour un enfant de 11 ans (collège, francophone), à adapter.
Format : un site par ligne (`site.com`, adresse complète, ou `@@||site.com^` / `||site.com^`), commentaires
avec `!` ou `#`. Après un envoi, recharge la page officielle (Ctrl+F5) pour voir les sites.

## Données locales
Tout est rangé dans `C:\ProgramData\ControleParental` : copie installée du script, sauvegardes du registre,
journaux, `secrets\` (jeton chiffré, réservé à SYSTEM et aux administrateurs).

## Crédits et licence
- Conçu par [kvernNC](https://github.com/kvernNC) et développé avec
  [Claude](https://www.anthropic.com/claude) (Anthropic), via Claude Code : code, interface, analyse de l'API et tests.
- Méthode d'authentification et points d'accès de l'API mobile repris de
  [pyfamilysafety](https://github.com/pantherale0/pyfamilysafety) (MIT, © 2023 Jordan H) ; la notice figure
  dans `FamilySafety.psm1`.
- Projet sous licence MIT (voir `LICENSE`). Aucune garantie : teste chaque protection avant de t'y fier.
