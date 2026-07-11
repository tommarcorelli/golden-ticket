# 🎫 Golden Ticket — Feuille de route

Statut au 11 juillet 2026 : **4 scénarios jouables** (Kerberoasting, Pass-the-Hash, Abus d'ACL, Golden Ticket — chapitre final), moteur générique data-driven partagé, leçon + glossaire + écran de fin dédié + page d'analyse post-flag + progression visuelle sur l'accueil.

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
- [x] Son à la victoire (mélodie web-audio + fanfare distincte pour le chapitre final)

## 🟡 Chantiers moyens (une session de travail)

- [x] Écran de fin de mission dédié (récap visuel de la chaîne d'attaque, pas juste du texte terminal)
- [x] Glossaire AD consultable hors mission (SPN, ACL, Kerberos, Domain Admin, GPO...)
- [ ] Système d'indices à paliers plus progressif (vague → quasi-solution)
- [x] Page "Explication complète" après le flag : pourquoi ça marche + comment se protéger (bouton "🛡️ Analyse" sur l'écran de victoire)
- [ ] Mode "chrono" avec classement des meilleurs temps (stockage local)
- [ ] Responsive mobile propre (des media queries existent déjà — à repasser en revue sur device réel)
- [x] Progression visuelle sur l'accueil (badge "✓ Terminé" par scénario + compteur de session)

## 🟠 Gros chantiers (nouveau contenu substantiel)

- [x] **Scénario 02 — Pass-the-Hash**
- [x] **Scénario 03 — Abus d'ACL**
- [ ] Mode "libre" : un domaine plus grand avec plusieurs chemins d'attaque valides au lieu d'une seule chaîne imposée
- [x] **Scénario "Golden Ticket" littéral** (forger un ticket Kerberos après avoir compromis le compte krbtgt) — accessible via la bannière dédiée sur l'accueil

## 🔴 Chantiers d'architecture (fondations, avant d'empiler trop de contenu)

- [x] Moteur de scénarios data-driven (`terminal.js` générique + `scenarios.js` pour les données/logique par scénario)
- [x] Séparer commandes génériques du moteur (help/man/clear/easter eggs) des commandes spécifiques au scénario
- [ ] Vraie sauvegarde de progression (nécessite un stockage persistant réel, pas possible dans les artifacts Claude.ai — à prévoir une fois le projet hors de cet environnement)
- [x] Mode "chapitre final" combinant plusieurs techniques enchaînées (façon boss fight de LinuxDojo) : Kerberoasting → abus d'ACL → krbtgt → Golden Ticket, à la suite

---

## Recommandation d'ordre

1. ~~Finir les petits chantiers restants~~ ✅
2. ~~Glossaire AD + explication post-flag~~ ✅
3. ~~Scénario 02 (Pass-the-Hash)~~ ✅
4. ~~Moteur data-driven~~ ✅
5. ~~Scénario 03 (Abus d'ACL)~~ ✅
6. ~~Chapitre final (Golden Ticket) + branchement UI (badges, bannière, page d'analyse)~~ ✅
7. **Prochaine étape suggérée** : indices à paliers progressifs, passage responsive mobile sur device réel, puis mode "chrono" avec meilleurs temps.

---

## 🐛 Session du 11 juillet 2026 — bugs corrigés

Le zip fourni ne contenait pas `index.html` (présent uniquement dans l'historique git, récupéré depuis l'objet blob). Cette version HTML était une ancienne version committée, désynchronisée du JS/CSS de travail plus récent. Résultat : plusieurs fonctionnalités existaient en JS/CSS mais étaient invisibles/inatteignables faute de markup :

- **Scénario "Golden Ticket" (chapitre final)** : entièrement codé dans `scenarios.js` (objectifs, indices, dialogue, `deepDive`) mais aucun bouton ni carte sur l'accueil n'y menait. → Ajout d'une bannière dédiée `.epic-banner`.
- **`showExplain()`** : fonction définie dans `main.js`, jamais appelée nulle part, et la section `#view-explain` qu'elle cible n'existait pas dans le HTML. → Section ajoutée + bouton "🛡️ Analyse" sur l'écran de victoire.
- **`#confetti-host`** : référencé par `terminal.js` pour l'animation de victoire, absent du HTML → les confettis du chapitre final ne s'affichaient jamais. → Ajouté dans l'overlay de fin de mission.
- **`#progress-track`** et **`badge-<scenarioId>`** : référencés par `updateHomeBadges()` dans `main.js`, absents du HTML → la progression ne s'affichait jamais sur l'accueil. → Ajoutés sur chaque carte + bannière, plus le compteur de session.

Vérifications effectuées : pas de fonction/variable dupliquée entre fichiers JS, tous les `onclick` du HTML pointent vers des fonctions réellement définies, chaque scénario a un objectif complétable pour chaque `id` déclaré, chaque scénario appelle bien `finishMission()` une fois, balises HTML équilibrées.
