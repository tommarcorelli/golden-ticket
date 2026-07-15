# 🎫 Golden Ticket — Feuille de route

Statut au 11 juillet 2026 : **3 scénarios + mode libre multi-chemins + 1 chapitre final épique** (Kerberoasting, Pass-the-Hash, Abus d'ACL, Mode libre combinant les trois avec plusieurs chemins valides, puis Chapitre Final qui enchaîne tout jusqu'au vrai Golden Ticket), moteur générique data-driven, leçon + glossaire + page d'analyse défense + progression persistante + classement des meilleurs temps + indices à paliers + confettis/fanfare sur le final.

---

## 🟢 Petits chantiers (quelques lignes, rapide à livrer)

- [x] Bouton "Recommencer" sur l'écran de jeu
- [x] Historique de commandes (↑ / ↓)
- [x] Auto-complétion partielle (Tab)
- [x] Récap de fin de mission (temps, commandes, indices utilisés)
- [x] Effet visuel à la victoire (glow doré sur le terminal)
- [x] Messages d'erreur pédagogiques (expliquer pourquoi, pas juste "refusé")
- [x] Easter eggs (`sudo`, `ls`, `cat`...)
- [x] Favicon + titre d'onglet dynamique selon l'écran
- [x] Bouton "copier le flag"
- [x] Son ou vibration légère au flag trouvé

## 🟡 Chantiers moyens (une session de travail)

- [x] Écran de fin de mission dédié (récap visuel de la chaîne d'attaque, pas juste du texte terminal)
- [x] Glossaire AD consultable hors mission (SPN, ACL, Kerberos, Domain Admin, GPO...)
- [x] Système d'indices à paliers plus progressif (vague → quasi-solution)
- [x] Page "Explication complète" après le flag : comment se protéger en vrai (gMSA, rotation de mot de passe...)
- [x] Mode "chrono" avec classement des meilleurs temps (au-delà du simple record personnel affiché sur l'accueil)
- [x] Responsive mobile propre
- [x] Progression visuelle sur l'accueil (scénario complété = badge, persistant en localStorage)

## 🟠 Gros chantiers (nouveau contenu substantiel)

- [x] **Scénario 02 — Pass-the-Hash**
- [x] **Scénario 03 — Abus d'ACL**
- [x] Mode "libre" : un domaine plus grand avec plusieurs chemins d'attaque valides au lieu d'une seule chaîne imposée
- [x] Scénario "Golden Ticket" littéral — **Chapitre Final**, enchaîne les 3 techniques jusqu'au forgeage d'un ticket krbtgt

## 🔴 Chantiers d'architecture (fondations, avant d'empiler trop de contenu)

- [x] Moteur de scénarios data-driven (`terminal.js` générique + `scenarios.js` pour les données/logique par scénario)
- [x] Séparer commandes génériques du moteur (help/man/clear/easter eggs) des commandes spécifiques au scénario
- [x] Vraie sauvegarde de progression — le projet vit hors des artifacts Claude.ai (dépôt git avec remote), donc `localStorage` fonctionne : scénarios terminés + meilleurs temps persistent entre sessions (`js/main.js`, clé `goldenticket_progress_v1`), avec réinitialisation manuelle possible depuis l'accueil.
- [x] Mode "chapitre final" combinant plusieurs techniques enchaînées (façon boss fight de LinuxDojo) : Kerberoasting → Pass-the-Hash → abus d'ACL → Golden Ticket, à la suite

---

## Recommandation d'ordre

1. ~~Finir les petits chantiers restants~~ ✅
2. ~~Glossaire AD + explication post-flag~~ ✅
3. ~~Scénario 02 (Pass-the-Hash)~~ ✅
4. ~~Moteur data-driven~~ ✅
5. ~~Scénario 03 (Abus d'ACL)~~ ✅
6. ~~Chapitre final (enchaînement des 3 techniques)~~ ✅
7. ~~Peaufinage : progression persistante, responsive mobile, écran de fin dédié, page d'explication post-flag~~ ✅
8. ~~Système d'indices à paliers progressifs~~ ✅
9. ~~Mode chrono / classement des meilleurs temps~~ ✅
10. ~~Mode libre (domaine plus grand, chemins d'attaque multiples : ACL via groupe ou Pass-the-Hash direct)~~ ✅
11. **Prochaine étape suggérée** : tous les chantiers identifiés sont faits. Voir le backlog d'idées ci-dessous — non priorisé, à trier selon l'envie du moment.

---

## 💡 Backlog d'idées (pas encore priorisées)

Idées non validées, à piocher selon l'envie. Pas d'ordre de priorité — c'est un vivier, pas un plan.

**Périmètre du projet : un jeu solo pour apprendre, pas une plateforme.** Pas de comptes utilisateurs, pas de backend, pas de suivi de qui que ce soit. Toute idée qui demanderait un serveur ou une notion de "compte formateur / plusieurs joueurs suivis" est hors périmètre — à écarter si elle revient.

### 🟢 Petites (rapides, fun)
- [x] Konami code ou easter egg caché supplémentaire (ex: taper `matrix` déclenche une pluie de caractères verts sur le terminal)
- [x] Export/import de la progression en JSON téléchargeable — filet de sécurité vu que tout est en `localStorage` (changement de navigateur = tout perdu sinon)
- [x] Badge/"succès" fun et discrets : 6 succès (Sans indice, Éclair, Curieux, Les deux routes, Golden Ticket, Maître du domaine), visibles dans le classement, débloqués en toast à la fin d'une mission
- [x] Bouton "partager mon temps" qui génère une image ou un texte à copier-coller (façon Wordle)
- [x] Effet sonore distinct pour une commande refusée (petit "buzz" discret, toggle activable/désactivable)
- [x] Mode clair en plus du thème sombre actuel (toggle, si le style s'y prête sans dénaturer l'identité visuelle)

### 🟡 Moyennes (une session)
- [x] Mode "Expert" : indices désactivés, chrono plus visible pendant la mission (pas juste au récap), classement séparé de celui du mode normal
- [x] Certificat de fin (image téléchargeable) après le Chapitre Final — sympa pour un contexte formation/sensibilisation en entreprise
- [x] PWA installable (manifest + service worker) : le jeu s'installe et fonctionne hors-ligne sur mobile/desktop — ⚠️ le service worker ne s'enregistre que servi en HTTPS (ou `localhost` en local) ; ouvrir `index.html` directement en `file://` ne l'active pas, mais le jeu reste jouable normalement
- [x] Étendre le mode libre à 3-4 chemins d'attaque au lieu de 2, avec un compte supplémentaire "piège" plus subtil (ACL qui semble exploitable mais mène à une impasse) — 3e chemin via `svc_backup` (ajouté par erreur au groupe Server Admins) + piège `k.morel` (ACL Comptabilité alléchante mais sans aucun privilège réel)
- [ ] Accessibilité clavier complète + support lecteur d'écran sur les écrans hors-terminal (accueil, glossaire, indices)

### 🟠 Grosses (nouveau système)
- [ ] **Notion de furtivité (OPSEC)** : certaines actions "bruyantes" (trop de tickets Kerberoast demandés d'un coup, essais de mot de passe répétés) font monter une jauge d'alerte SOC simulée ; au-delà d'un seuil, un message "l'équipe sécurité a été notifiée" change la fin de mission (pas un échec, mais un score/évaluation différent — introduit la notion réelle de détection, pas juste d'exploitation)
- [ ] **Mode Blue Team** : le joueur devient l'analyste SOC, reçoit des logs (fictifs) d'une attaque déjà en cours, et doit identifier la technique utilisée et la chronologie — pédagogiquement complémentaire au mode attaque existant
- [ ] **Carte d'attaque façon BloodHound** : graphe SVG qui se dessine en direct au fil de l'énumération (comptes découverts = nœuds, ACL/droits trouvés = arêtes), très parlant visuellement et cohérent avec le thème du jeu
- [ ] Scénario **Cloud/Azure AD (Entra ID)** : secrets d'App Registration exposés, abus de rôles Conditional Access — même logique pédagogique mais univers différent (extension naturelle après le tout-AD on-prem)

### 🤯 Trucs de fous (ambitieux, pas nécessairement raisonnables)
- [ ] **Générateur de domaine aléatoire** : à chaque partie du mode libre, les comptes, mots de passe faibles et ACL vulnérables sont re-tirés aléatoirement (seed) — rejouabilité infinie, mais demande de repenser toute la logique de scénario en règles génériques plutôt qu'en données fixes
- [ ] **Rejeu/replay partageable** : enregistrer la séquence de commandes d'une run et pouvoir la "rejouer" comme une vidéo (façon asciinema) pour la partager ou l'analyser après coup, en local (fichier exporté, pas de serveur)
