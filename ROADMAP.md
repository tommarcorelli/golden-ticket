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
11. **Prochaine étape suggérée** : tous les chantiers identifiés sont faits. Pistes pour la suite : plus de comptes/chemins dans le mode libre (aujourd'hui 2 chemins, pourrait monter à 3-4), un mode difficulté ("dur" = indices désactivés), ou sortir le projet de cet environnement pour un vrai déploiement (le ROADMAP notait déjà que la sauvegarde ne pouvait pas être "vraie" avant — c'est fait, `localStorage` fonctionne dès que le site est servi normalement).
