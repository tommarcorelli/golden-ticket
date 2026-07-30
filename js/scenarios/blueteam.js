
// ---------------------------------------------------------
// MODE BLUE TEAM — CÔTÉ DÉFENSE : ANALYSTE SOC
// Complément pédagogique du mode attaque : le joueur ne compromet
// rien, il enquête sur une compromission déjà survenue à partir de
// journaux (fictifs), doit identifier la technique, le compte
// touché, et reconstituer la chronologie des événements.
// ---------------------------------------------------------
SCENARIOS.blueteam = {
  id:'blueteam',
  tag:'🛰️ MODE BLUE TEAM · ANALYSTE SOC',
  lessonTag:'📘 LEÇON · MODE BLUE TEAM',
  opsecEnabled:false,
  noiseRules:[],
  startUser:'t.leroux',

  identities:{
    't.leroux': { label:'SOC\\t.leroux', priv:'Analyste sécurité', groups:['SOC Tier 1'], desc:'Analyste SOC — équipe de garde' }
  },

  // Deux dossiers d'incident possibles — un est tiré au hasard à chaque
  // entrée dans le Mode Blue Team (ou forcé par un replay importé, voir
  // sc.forcedCase). Vérité terrain des événements — clé = identifiant
  // affiché (EVT-X). L'ordre chronologique réel se lit uniquement à
  // l'horodatage, pas à l'ordre d'affichage (volontairement mélangé).
  CASES:[
    {
      id:'kerberoast',
      ticket:'INC-2024-0417',
      alertLine:'pic anormal de demandes de tickets Kerberos cette nuit',
      readmeText:`<span class="out-dim">"Alerte SIEM déclenchée à 03:12 : pic anormal de demandes de tickets Kerberos sur CORP.LOCAL. Détermine s'il s'agit d'une attaque, laquelle, quel compte est concerné, et reconstitue la chronologie complète avant de clôturer le ticket." — Notes d'astreinte</span>`,
      techniqueLabel:'Kerberoasting',
      CORRECT_TECHNIQUE:['kerberoasting','kerberoast'],
      CORRECT_ACCOUNT:'svc_backup',
      CORRECT_ORDER:'a,b,c,d',
      EVENTS:{
        A:{ time:'02:50:10', text:'EventID 4769 (Ticket de service demandé) — Compte demandeur : k.morel — SPN visé : MSSQLSvc/sql-report.corp.local:1433 — Chiffrement : AES256-CTS-HMAC-SHA1' },
        B:{ time:'03:12:04', text:'EventID 4769 (Ticket de service demandé) — Compte demandeur : j.dupont — SPN visé : MSSQLSvc/sql01.corp.local:1433 (svc_backup) — Chiffrement : RC4-HMAC ⚠ legacy' },
        C:{ time:'03:14:47', text:"EventID 4624 (Ouverture de session réussie) — Compte : svc_backup — Poste source : WKS-042 — Type d'ouverture : 3 (réseau)" },
        D:{ time:'03:15:02', text:"EventID 4663 (Tentative d'accès à un objet) — Compte : svc_backup — Objet : C:\\Users\\Administrator\\Desktop\\flag.txt — Droit : ReadData — Résultat : Autorisé (membre Backup Operators)" }
      },
      EVENTS_DISPLAY_ORDER:['C','A','D','B'],
      hints:[
        ["Avant de conclure quoi que ce soit, regarde ce qui se trouve dans ce dossier d'incident.",
         "Il y a un journal de sécurité dans ce dossier — regarde son contenu.",
         "Commence par `dir`, puis `type security.log` pour lire les événements corrélés à l'alerte."],
        ["Un des événements a un détail technique qui ne colle pas avec les autres.",
         "Compare le type de chiffrement utilisé dans chaque demande de ticket Kerberos (EventID 4769). Un des deux est nettement plus ancien/faible que l'autre.",
         "Le chiffrement RC4-HMAC sur un des événements 4769, alors que l'autre utilise AES256, est le signal classique du Kerberoasting — soumets ta conclusion avec `report --technique kerberoasting`."],
        ["Regarde quel compte est directement visé par l'événement suspect, puis ce qui lui arrive juste après dans le journal.",
         "Le compte visé par la demande de ticket au chiffrement faible est aussi celui qui ouvre une session juste après, sur un poste inattendu.",
         "Le compte compromis est svc_backup — soumets-le avec `report --account svc_backup`."],
        ["Les événements ne sont pas affichés dans l'ordre chronologique du journal — base-toi sur les horodatages, pas sur l'ordre d'affichage.",
         "Classe les 4 événements du plus ancien au plus récent d'après leur heure exacte.",
         "Chronologie correcte, du plus ancien au plus récent : `report --order a,b,c,d`"],
        ["Une fois les trois éléments du rapport soumis et corrects, il ne reste plus qu'à clôturer le dossier.",
         "Il existe une commande dédiée pour clôturer une investigation terminée.",
         "Clôture le dossier avec `close-incident`."]
      ],
      completeSub:"Kerberoasting détecté et documenté avant l'escalade.",
      chainSteps:[
        {icon:'📄', label:'Logs lus'}, {icon:'🔍', label:'Technique'},
        {icon:'🧭', label:'Chronologie'}, {icon:'📝', label:'Rapport clos'}
      ],
      flag:'FLAG{blueteam_kerberoast_detected}',
      deepDive:{
        mitre:[{id:'T1558.003', name:"Steal or Forge Kerberos Tickets: Kerberoasting"}],
        why:"Le Kerberoasting laisse des traces discrètes mais réelles : une demande de ticket de service (Event ID 4769) chiffrée en RC4 alors que le reste de l'environnement utilise AES est un signal fort, surtout suivie de près par une ouverture de session et un accès fichier inhabituels pour ce compte. Aucun de ces événements pris isolément ne prouve une attaque — c'est leur corrélation, dans le bon ordre, qui la révèle.",
        defenses:[
          "Alerter spécifiquement sur les tickets Kerberos chiffrés en RC4 (type 0x17) quand l'environnement est censé n'utiliser que l'AES",
          "Corréler automatiquement les événements 4769 / 4624 / 4663 dans une fenêtre de temps courte pour un même compte",
          "Établir une base de référence du volume normal de demandes de ticket par compte de service, pour repérer les écarts",
          "Documenter systématiquement une chronologie précise (et non un simple constat) dans chaque rapport d'incident",
          "Déployer des comptes de service gérés (gMSA) : la cause racine ici reste un mot de passe de service faible"
        ],
        quiz:[
          { q:"Quel détail technique, dans l'Event ID 4769 suspect, trahit une demande de ticket anormale ?",
            options:["Le chiffrement RC4-HMAC alors que l'environnement utilise l'AES","L'heure de la demande, en pleine journée","Le nom du compte demandeur, trop court","L'adresse IP du contrôleur de domaine"],
            correct:0,
            explain:"Un ticket chiffré en RC4 (legacy) dans un environnement où l'AES256 est la norme est un signal fort — c'est exactement ce que révèle l'outil Kerberoasting, qui force ce choix de chiffrement." },
          { q:"Pourquoi la corrélation entre 4769, 4624 et 4663 est-elle plus fiable qu'un seul événement isolé ?",
            options:["Un seul événement suffit toujours à prouver une attaque","Aucun des événements pris seul ne prouve une attaque, mais leur enchaînement dans le bon ordre la révèle","Ces événements ne sont jamais liés entre eux","Les Event ID plus élevés sont automatiquement plus fiables"],
            correct:1,
            explain:"C'est le principe même de l'analyse SOC : chaque événement pourrait avoir une explication légitime, mais leur enchaînement précis (demande de ticket faible → ouverture de session → accès fichier) raconte l'histoire complète." },
          { q:"Quelle mesure défensive s'attaque à la cause racine de ce type d'incident ?",
            options:["Déployer des comptes de service gérés (gMSA)","Désactiver les journaux d'événements Kerberos","Supprimer le compte svc_backup sans le remplacer","Augmenter la durée de vie des tickets Kerberos"],
            correct:0,
            explain:"La cause racine reste un mot de passe de compte de service trop faible pour résister à un cassage hors-ligne — un gMSA a un mot de passe long, aléatoire et changé automatiquement." }
        ]
      }
    },
    {
      id:'adcs',
      ticket:'INC-2024-0512',
      alertLine:"délivrance de certificat suspecte suivie d'une authentification inhabituelle",
      readmeText:`<span class="out-dim">"Alerte SIEM déclenchée à 04:02 : délivrance de certificat suspecte suivie d'une authentification par certificat inhabituelle pour un compte à privilèges. Détermine s'il s'agit d'une attaque, laquelle, quel compte est concerné, et reconstitue la chronologie complète avant de clôturer le ticket." — Notes d'astreinte</span>`,
      techniqueLabel:'Abus de certificat AD CS (ESC1)',
      CORRECT_TECHNIQUE:['esc1','adcs esc1','abus de certificat','certificat esc1','abus adcs','adcs'],
      CORRECT_ACCOUNT:'administrator',
      CORRECT_ORDER:'a,b,c,d',
      EVENTS:{
        A:{ time:'04:02:10', text:'EventID 4886 (Certificate Services a reçu une demande de certificat) — Compte demandeur : j.rossi — Modèle : WebServer — Sujet demandé (SAN) : CORP\\administrator ⚠ fourni par le demandeur' },
        B:{ time:'04:02:11', text:'EventID 4887 (Certificate Services a approuvé la demande et délivré le certificat) — Modèle : WebServer — Sujet du certificat émis : CORP\\administrator' },
        C:{ time:'04:03:40', text:'EventID 4768 (TGT Kerberos demandé) — Compte : administrator — Pré-authentification : certificat (PKINIT) — Poste source : WKS-204 ⚠ inhabituel pour ce compte' },
        D:{ time:'04:03:52', text:"EventID 4663 (Tentative d'accès à un objet) — Compte : administrator — Objet : C:\\Users\\Administrator\\Desktop\\flag.txt — Droit : ReadData — Résultat : Autorisé" }
      },
      EVENTS_DISPLAY_ORDER:['C','A','D','B'],
      hints:[
        ["Avant de conclure quoi que ce soit, regarde ce qui se trouve dans ce dossier d'incident.",
         "Il y a un journal de sécurité dans ce dossier — regarde son contenu.",
         "Commence par `dir`, puis `type security.log` pour lire les événements corrélés à l'alerte."],
        ["Un des événements de délivrance de certificat porte une information d'identité qui ne devrait pas pouvoir être choisie librement par le demandeur.",
         "Compare qui demande le certificat (4886) à l'identité pour laquelle il est finalement délivré (4887) — ce n'est pas la même personne.",
         "j.rossi a demandé un certificat, mais celui-ci a été délivré pour CORP\\administrator : c'est un abus de certificat AD CS (faille ESC1) — soumets ta conclusion avec `report --technique esc1`."],
        ["Regarde quel compte utilise ensuite ce certificat pour s'authentifier, et ce qu'il fait juste après.",
         "Le compte qui s'authentifie par certificat (PKINIT) juste après l'émission, depuis un poste qui n'est pas le sien, est celui qui a été usurpé.",
         "Le compte compromis est administrator — soumets-le avec `report --account administrator`."],
        ["Les événements ne sont pas affichés dans l'ordre chronologique du journal — base-toi sur les horodatages, pas sur l'ordre d'affichage.",
         "Classe les 4 événements du plus ancien au plus récent d'après leur heure exacte.",
         "Chronologie correcte, du plus ancien au plus récent : `report --order a,b,c,d`"],
        ["Une fois les trois éléments du rapport soumis et corrects, il ne reste plus qu'à clôturer le dossier.",
         "Il existe une commande dédiée pour clôturer une investigation terminée.",
         "Clôture le dossier avec `close-incident`."]
      ],
      completeSub:"Abus de certificat AD CS (ESC1) détecté et documenté avant l'escalade.",
      chainSteps:[
        {icon:'📄', label:'Logs lus'}, {icon:'🔍', label:'Technique'},
        {icon:'🧭', label:'Chronologie'}, {icon:'📝', label:'Rapport clos'}
      ],
      flag:'FLAG{blueteam_adcs_esc1_detected}',
      deepDive:{
        mitre:[{id:'T1649', name:"Steal or Forge Authentication Certificates"}],
        why:"Un abus de certificat AD CS laisse des traces précises mais rarement surveillées par défaut : une délivrance de certificat (Event ID 4887) dont le sujet ne correspond pas au demandeur d'origine (4886) est un signal quasi certain d'ESC1 — surtout suivie de près par une authentification par certificat (PKINIT) pour un compte à privilèges, depuis un poste qui n'est pas le sien.",
        defenses:[
          "Corréler les Event ID 4886/4887 : alerter quand l'identité demandée diffère du compte demandeur",
          "Surveiller les authentifications Kerberos par certificat (Event ID 4768, pré-authentification par certificat) pour les comptes à privilèges",
          "Auditer les modèles de certificats publiés et désactiver ENROLLEE_SUPPLIES_SUBJECT quand il n'est pas strictement nécessaire",
          "Restreindre les droits d'enrôlement aux seuls comptes qui en ont réellement besoin"
        ],
        quiz:[
          { q:"Qu'est-ce qui, dans la paire d'événements 4886/4887, trahit l'abus de certificat ?",
            options:["Le sujet du certificat émis ne correspond pas au compte demandeur d'origine","Le certificat a été émis un dimanche","Le modèle de certificat s'appelle WebServer","Le délai entre les deux événements est trop court"],
            correct:0,
            explain:"Un certificat émis au nom de CORP\\administrator alors que la demande provient de j.rossi est la signature même d'un ESC1 : le champ sujet fourni par le demandeur n'a pas été validé." },
          { q:"Pourquoi l'événement 4768 avec pré-authentification par certificat (PKINIT) est-il un indice clé ici ?",
            options:["Il prouve que le compte administrator s'authentifie avec le certificat frauduleusement obtenu, depuis un poste inhabituel","Il indique un simple changement de mot de passe","Il signifie que MFA a été désactivé","Il correspond à une sauvegarde automatique du contrôleur de domaine"],
            correct:0,
            explain:"PKINIT permet de s'authentifier avec un certificat plutôt qu'un mot de passe. Le voir utilisé par administrator depuis WKS-204 — un poste inhabituel pour ce compte — confirme l'usurpation." },
          { q:"Quelle mesure défensive cible spécifiquement la cause racine d'un ESC1 ?",
            options:["Désactiver ENROLLEE_SUPPLIES_SUBJECT sur les modèles qui n'en ont pas besoin","Changer le mot de passe de l'administrateur plus souvent","Interdire l'usage de Kerberos au profit de NTLM","Chiffrer le disque du serveur AD CS"],
            correct:0,
            explain:"C'est ce drapeau qui permet au demandeur de choisir librement le sujet du certificat. Le désactiver là où il n'est pas nécessaire ferme la porte à ce type d'abus." }
        ]
      }
    },
    {
      id:'pth',
      ticket:'INC-2024-0603',
      alertLine:"authentification NTLM inhabituelle vers un serveur de fichiers, sans ticket Kerberos correspondant",
      readmeText:`<span class="out-dim">"Alerte SIEM déclenchée à 06:01 : authentification NTLM détectée vers SRV-FILES01 pour un compte à privilèges, sans demande de ticket Kerberos correspondante. Détermine s'il s'agit d'une attaque, laquelle, quel compte est concerné, et reconstitue la chronologie complète avant de clôturer le ticket." — Notes d'astreinte</span>`,
      techniqueLabel:'Pass-the-Hash',
      CORRECT_TECHNIQUE:['pass-the-hash','pth','passe-le-hash','pass the hash'],
      CORRECT_ACCOUNT:'administrator',
      CORRECT_ORDER:'a,b,c,d',
      EVENTS:{
        A:{ time:'06:00:15', text:"EventID 4688 (Nouveau processus créé) — Compte : j.dupont — Détail : accès mémoire du processus LSASS (outil d'extraction d'identifiants) — Poste : WKS-042" },
        B:{ time:'06:01:02', text:'EventID 4624 (Ouverture de session réussie) — Compte : Administrator — Poste source : WKS-042 — Poste destination : SRV-FILES01 — Package : NTLM ⚠ — Type d\'ouverture : 3 (réseau)' },
        C:{ time:'06:01:02', text:"Analyse corrélée — Aucun EventID 4768 (TGT Kerberos) pour ce compte dans la fenêtre de l'ouverture de session : authentification NTLM directe, cohérente avec un hash réutilisé sans mot de passe en clair" },
        D:{ time:'06:01:20', text:"EventID 4663 (Tentative d'accès à un objet) — Compte : Administrator — Objet : C:\\Users\\Administrator\\Desktop\\flag.txt (SRV-FILES01) — Droit : ReadData — Résultat : Autorisé" }
      },
      EVENTS_DISPLAY_ORDER:['C','A','D','B'],
      hints:[
        ["Avant de conclure quoi que ce soit, regarde ce qui se trouve dans ce dossier d'incident.",
         "Il y a un journal de sécurité dans ce dossier — regarde son contenu.",
         "Commence par `dir`, puis `type security.log` pour lire les événements corrélés à l'alerte."],
        ["Une authentification réussie ne prouve rien en soi — regarde COMMENT elle a eu lieu, et ce qui aurait dû l'accompagner mais n'apparaît nulle part dans le journal.",
         "Un compte à privilèges qui s'authentifie en NTLM plutôt qu'en Kerberos, sans qu'aucune demande de ticket (4768) ne le précède, trahit un hash réutilisé directement — pas un mot de passe tapé au clavier.",
         "C'est un Pass-the-Hash : le hash NTLM a été réutilisé tel quel, sans jamais passer par Kerberos — soumets ta conclusion avec `report --technique pass-the-hash`."],
        ["Regarde quel compte a servi à l'authentification NTLM suspecte, pas celui qui a manipulé la mémoire au départ.",
         "Le hash extrait sur WKS-042 appartenait à un compte administrateur — c'est ce compte qui est réutilisé sur SRV-FILES01.",
         "Le compte compromis est Administrator — soumets-le avec `report --account administrator`."],
        ["Les événements ne sont pas affichés dans l'ordre chronologique du journal — base-toi sur les horodatages, pas sur l'ordre d'affichage.",
         "Classe les 4 événements du plus ancien au plus récent d'après leur heure exacte.",
         "Chronologie correcte, du plus ancien au plus récent : `report --order a,b,c,d`"],
        ["Une fois les trois éléments du rapport soumis et corrects, il ne reste plus qu'à clôturer le dossier.",
         "Il existe une commande dédiée pour clôturer une investigation terminée.",
         "Clôture le dossier avec `close-incident`."]
      ],
      completeSub:"Pass-the-Hash détecté malgré l'absence de tout mot de passe cassé.",
      chainSteps:[
        {icon:'🧠', label:'Logs lus'}, {icon:'🔍', label:'Technique'},
        {icon:'🧭', label:'Chronologie'}, {icon:'📝', label:'Rapport clos'}
      ],
      flag:'FLAG{blueteam_pth_detected}',
      deepDive:{
        mitre:[{id:'T1550.002', name:"Use Alternate Authentication Material: Pass the Hash"}],
        why:"Le Pass-the-Hash laisse une absence caractéristique plutôt qu'un signal direct : une authentification NTLM réussie pour un compte à privilèges, sans le ticket Kerberos (4768) qui l'accompagnerait normalement, trahit un hash réutilisé tel quel plutôt qu'un mot de passe tapé au clavier.",
        defenses:[
          "Alerter sur les authentifications NTLM de comptes à privilèges quand Kerberos est censé être utilisé par défaut",
          "Corréler l'absence de 4768 avant un 4624 NTLM pour détecter un hash réutilisé directement",
          "Déployer LAPS pour que chaque machine ait un mot de passe administrateur local unique",
          "Activer Credential Guard pour empêcher l'extraction de hash en mémoire"
        ],
        quiz:[
          { q:"Quelle absence, dans le journal, est le signal clé de ce Pass-the-Hash ?",
            options:["Aucun EventID 4768 (TGT Kerberos) ne précède l'ouverture de session NTLM du compte à privilèges","Aucun EventID 4624 n'apparaît dans le journal","Le journal ne contient aucun horodatage","Aucune trace de connexion réseau n'existe"],
            correct:0,
            explain:"Un compte à privilèges qui s'authentifie normalement passerait par Kerberos (4768). Son absence avant une ouverture de session NTLM (4624) trahit un hash réutilisé directement, sans mot de passe tapé." },
          { q:"À quoi sert l'événement 4688 relevé sur WKS-042 dans ce dossier ?",
            options:["Il montre l'accès mémoire du processus LSASS, cohérent avec une extraction de hash","Il prouve que le pare-feu a bloqué la connexion","Il indique une mise à jour Windows automatique","Il montre un changement de mot de passe réussi"],
            correct:0,
            explain:"L'accès au processus LSASS est la méthode classique pour extraire les hash NTLM en mémoire — c'est l'étape qui précède logiquement la réutilisation du hash observée ensuite." },
          { q:"Quelle mesure défensive limite le nombre de machines qu'un seul hash volé peut ouvrir ?",
            options:["Déployer LAPS pour un mot de passe admin local unique par machine","Augmenter la taille de la mémoire LSASS","Désactiver les journaux d'événements NTLM","Autoriser NTLM sur toutes les machines par défaut"],
            correct:0,
            explain:"Sans LAPS, un même mot de passe admin local réutilisé sur tout le parc transforme un seul hash volé en clé passe-partout. LAPS garantit un mot de passe unique et changé automatiquement par machine." }
        ]
      }
    },
    {
      id:'unconstrained',
      ticket:'INC-2024-0711',
      alertLine:"le contrôleur de domaine a ouvert une session sortante inhabituelle vers un serveur applicatif",
      readmeText:`<span class="out-dim">"Alerte SIEM déclenchée à 05:09 : le compte machine DC01$ a ouvert une session réseau sur WEB01 — un serveur applicatif qui n'a normalement aucune raison de recevoir une authentification d'un contrôleur de domaine. Une requête de réplication d'annuaire a suivi peu après. Détermine s'il s'agit d'une attaque, laquelle, quel compte est concerné, et reconstitue la chronologie complète avant de clôturer le ticket." — Notes d'astreinte</span>`,
      techniqueLabel:'Délégation sans contrainte + coercition (PetitPotam)',
      CORRECT_TECHNIQUE:['délégation sans contrainte','delegation sans contrainte','unconstrained delegation','petitpotam','coercition','délégation sans contrainte + petitpotam','coercition petitpotam'],
      CORRECT_ACCOUNT:'dc01$',
      CORRECT_ORDER:'a,b,c,d',
      EVENTS:{
        A:{ time:'05:09:58', text:"EventID 5145 (Accès détaillé à un partage réseau) — Compte : DC01$ — Partage/pipe : \\\\WEB01\\lsarpc (MS-EFSRPC) — Résultat : Autorisé ⚠ un contrôleur de domaine qui répond à une requête EFSRPC vers un serveur applicatif est inhabituel" },
        B:{ time:'05:10:03', text:'EventID 4688 (Nouveau processus créé) — Compte : svc_web — Détail : exécution de mimikatz.exe — Poste : WEB01' },
        C:{ time:'05:10:47', text:"EventID 4624 (Ouverture de session réussie) — Compte : DC01$ — Poste source/destination : WEB01 — Package : Kerberos — Type d'ouverture : 3 (réseau) ⚠ un compte machine de DC ne devrait jamais s'authentifier SUR un serveur applicatif tiers" },
        D:{ time:'05:11:20', text:"EventID 4662 (Accès à un objet du service d'annuaire) — Compte : DC01$ — Objet : CN=krbtgt — Droits demandés : DS-Replication-Get-Changes-All — Adresse réseau source : 10.0.0.50 (WEB01) ⚠ une réplication d'annuaire ne devrait jamais provenir d'une adresse qui n'est pas un contrôleur de domaine" }
      },
      EVENTS_DISPLAY_ORDER:['C','A','D','B'],
      hints:[
        ["Avant de conclure quoi que ce soit, regarde ce qui se trouve dans ce dossier d'incident.",
         "Il y a un journal de sécurité dans ce dossier — regarde son contenu.",
         "Commence par `dir`, puis `type security.log` pour lire les événements corrélés à l'alerte."],
        ["Un compte machine de contrôleur de domaine ne devrait jamais se retrouver à s'authentifier SUR un autre serveur du domaine — c'est l'inverse du sens normal des choses.",
         "Regarde d'où provient la requête de réplication d'annuaire (EventID 4662) : son adresse réseau source ne correspond à aucun contrôleur de domaine connu.",
         "Un serveur applicatif a reçu l'authentification d'un compte machine de DC, puis une réplication a été demandée depuis son adresse : c'est une délégation sans contrainte combinée à une coercition (PetitPotam) — soumets ta conclusion avec `report --technique petitpotam`."],
        ["Regarde quel compte est directement concerné par l'ouverture de session anormale et la réplication qui suit.",
         "Ce n'est pas svc_web (qui n'a fait qu'exécuter un outil localement) : c'est le compte machine dont le ticket a été capturé et réutilisé.",
         "Le compte compromis est DC01$ — soumets-le avec `report --account dc01$`."],
        ["Les événements ne sont pas affichés dans l'ordre chronologique du journal — base-toi sur les horodatages, pas sur l'ordre d'affichage.",
         "Classe les 4 événements du plus ancien au plus récent d'après leur heure exacte.",
         "Chronologie correcte, du plus ancien au plus récent : `report --order a,b,c,d`"],
        ["Une fois les trois éléments du rapport soumis et corrects, il ne reste plus qu'à clôturer le dossier.",
         "Il existe une commande dédiée pour clôturer une investigation terminée.",
         "Clôture le dossier avec `close-incident`."]
      ],
      completeSub:"Coercition et abus de délégation sans contrainte détectés avant l'escalade.",
      chainSteps:[
        {icon:'📄', label:'Logs lus'}, {icon:'🔍', label:'Technique'},
        {icon:'🧭', label:'Chronologie'}, {icon:'📝', label:'Rapport clos'}
      ],
      flag:'FLAG{blueteam_unconstrained_petitpotam_detected}',
      deepDive:{
        mitre:[{id:'T1187', name:"Forced Authentication"}, {id:'T1550.003', name:"Use Alternate Authentication Material: Pass the Ticket"}],
        why:"Cette attaque ne laisse pas un seul signal évident, mais une série d'anomalies directionnelles : un compte machine de contrôleur de domaine qui s'authentifie SUR un serveur applicatif (le sens inverse du trafic normal), un accès EFSRPC vers ce même serveur juste avant (signature typique d'une coercition comme PetitPotam), et surtout une requête de réplication d'annuaire (Event ID 4662) dont l'adresse réseau source ne correspond à aucun contrôleur de domaine légitime. Prise isolément, chaque ligne pourrait presque passer inaperçue — c'est leur direction et leur origine réseau, croisées, qui trahissent l'attaque.",
        defenses:[
          "Surveiller toute session (Event ID 4624) où le compte est un compte machine de contrôleur de domaine (suffixe $) et où la machine destination n'est pas elle-même un DC",
          "Alerter sur les requêtes EFSRPC/lsarpc (Event ID 5145) entrantes vers des serveurs qui ne sont pas des contrôleurs de domaine — signature des outils de coercition comme PetitPotam",
          "Corréler l'adresse réseau source des événements de réplication (4662 avec le GUID de réplication) : elle doit toujours correspondre à un contrôleur de domaine connu",
          "Auditer et supprimer la délégation sans contrainte sur tout objet ordinateur qui n'est pas un contrôleur de domaine"
        ],
        quiz:[
          { q:"Quelle direction de connexion est l'anomalie centrale de cet incident ?",
            options:["Un compte machine de contrôleur de domaine qui s'authentifie SUR un serveur applicatif tiers","Un utilisateur standard qui se connecte à son propre poste","Un contrôleur de domaine qui redémarre en pleine nuit","Une sauvegarde planifiée qui s'exécute normalement"],
            correct:0,
            explain:"Un compte machine de DC (ex. DC01$) reçoit habituellement des connexions, il ne s'authentifie pas SUR un serveur applicatif tiers — ce sens inversé est le signal directionnel clé de la coercition." },
          { q:"Pourquoi l'adresse réseau source de l'événement 4662 (réplication) est-elle si importante ici ?",
            options:["Elle ne l'est pas, seul le nom du compte compte","Une réplication légitime provient toujours d'un contrôleur de domaine ; ici elle provient de l'adresse du serveur applicatif WEB01","Elle indique simplement l'heure de la requête","Elle permet de connaître le fuseau horaire du serveur"],
            correct:1,
            explain:"Le compte DC01$ est légitime pour répliquer, mais une réplication qui provient de l'adresse de WEB01 (et non d'un contrôleur de domaine) prouve que son ticket a été volé et rejoué ailleurs." },
          { q:"Quelle mesure défensive s'attaque directement à la cause racine de cet incident ?",
            options:["Auditer et supprimer la délégation sans contrainte sur les objets ordinateur qui ne sont pas des contrôleurs de domaine","Forcer un changement de mot de passe mensuel sur tous les comptes","Désactiver Kerberos au profit de NTLM","Augmenter la rétention des journaux d'événements"],
            correct:0,
            explain:"Sans délégation sans contrainte sur un serveur qui n'en a pas besoin, aucune coercition ne permettrait de capturer le ticket d'un contrôleur de domaine — c'est la faille de configuration à corriger en priorité."}
        ]
      }
    },
    {
      id:'breakglass',
      ticket:'INC-2024-0902',
      alertLine:"un compte à privilèges permanents s'est connecté depuis une adresse inhabituelle, sans MFA",
      readmeText:`<span class="out-dim">"Alerte déclenchée à 03:14 : une rafale d'échecs de connexion suivie d'un succès sur le compte breakglass.admin — un compte de secours qui ne devrait quasiment jamais servir. Aucun MFA n'a été demandé. Détermine s'il s'agit d'une attaque, laquelle, quel compte est concerné, et reconstitue la chronologie complète avant de clôturer le ticket." — Notes d'astreinte</span>`,
      techniqueLabel:'Contournement de Conditional Access via un compte de secours',
      CORRECT_TECHNIQUE:['conditional access','contournement conditional access','compte de secours','break-glass','breakglass','bypass mfa','contournement mfa via compte de secours','password spray'],
      CORRECT_ACCOUNT:'breakglass.admin',
      CORRECT_ORDER:'a,b,c,d',
      EVENTS:{
        A:{ time:'03:14:02', text:"Journal de connexion Entra ID — Compte : breakglass.admin — Résultat : Échec (identifiants incorrects) — 46 tentatives en 90 secondes ⚠ signature typique d'une pulvérisation de mots de passe (password spray)" },
        B:{ time:'03:15:41', text:"Journal de connexion Entra ID — Compte : breakglass.admin — Résultat : Succès — Conditional Access : Non appliqué (compte exclu) — MFA : Non requis — Adresse IP : 187.62.14.9 (hors plage habituelle de l'entreprise) ⚠" },
        C:{ time:'03:15:44', text:"Journal d'audit Entra ID — Rôle actif sur le compte : Global Administrator — Attribution permanente depuis 2019, non éligible PIM, jamais réévaluée ⚠ aucun contrôle d'accès juste-à-temps sur ce rôle critique" },
        D:{ time:'03:17:09', text:"Journal d'audit Entra ID — Action : Ajout d'un identifiant (clé secrète) à une application principale de service à privilèges élevés — effectuée par breakglass.admin, deux minutes après la connexion ⚠ signe une tentative de persistance" }
      },
      EVENTS_DISPLAY_ORDER:['D','B','A','C'],
      hints:[
        ["Avant de conclure quoi que ce soit, regarde ce qui se trouve dans ce dossier d'incident.",
         "Il y a un journal de sécurité dans ce dossier — regarde son contenu.",
         "Commence par `dir`, puis `type security.log` pour lire les événements corrélés à l'alerte."],
        ["Une rafale d'échecs de connexion suivie d'un succès, sans le moindre MFA demandé, sur un compte censé ne presque jamais servir : pourquoi le MFA n'a-t-il jamais été exigé ?",
         "Regarde le champ Conditional Access de l'événement de connexion réussie : il indique explicitement pourquoi aucune politique ne s'est appliquée.",
         "Rafale d'échecs suivie d'un succès sans MFA, sur un compte exclu des politiques Conditional Access : c'est un contournement via un compte de secours — soumets ta conclusion avec `report --technique breakglass`."],
        ["Regarde quel compte concentre tous ces événements, de la rafale d'échecs jusqu'à l'action de persistance finale.",
         "Un seul et même compte apparaît dans les quatre événements.",
         "Le compte compromis est breakglass.admin — soumets-le avec `report --account breakglass.admin`."],
        ["Les événements ne sont pas affichés dans l'ordre chronologique du journal — base-toi sur les horodatages, pas sur l'ordre d'affichage.",
         "Classe les 4 événements du plus ancien au plus récent d'après leur heure exacte.",
         "Chronologie correcte, du plus ancien au plus récent : `report --order a,b,c,d`"],
        ["Une fois les trois éléments du rapport soumis et corrects, il ne reste plus qu'à clôturer le dossier.",
         "Il existe une commande dédiée pour clôturer une investigation terminée.",
         "Clôture le dossier avec `close-incident`."]
      ],
      completeSub:"Contournement de Conditional Access via un compte de secours détecté avant l'exfiltration.",
      chainSteps:[
        {icon:'📄', label:'Logs lus'}, {icon:'🔍', label:'Technique'},
        {icon:'🧭', label:'Chronologie'}, {icon:'📝', label:'Rapport clos'}
      ],
      flag:'FLAG{blueteam_breakglass_conditional_access_detected}',
      deepDive:{
        mitre:[{id:'T1078.004', name:"Valid Accounts: Cloud Accounts"}, {id:'T1110.003', name:"Brute Force: Password Spraying"}],
        why:"Rien ici ne relève d'une faille technique complexe : chaque événement, pris isolément, pourrait presque sembler anodin dans un grand tenant. C'est leur combinaison qui trahit l'attaque — une rafale d'échecs de connexion (signature de password spray), suivie d'un succès sans le moindre challenge MFA (parce que le compte est exclu des politiques Conditional Access), sur un compte qui détient en permanence le rôle Global Administrator sans jamais être réévalué, suivie presque immédiatement d'une action de persistance (ajout d'un identifiant à une application à privilèges). Le signal le plus fort n'est pas un événement unique mais l'absence anormale de toute friction (MFA, Conditional Access) là où elle devrait exister sur un compte aussi puissant.",
        defenses:[
          "Alerter immédiatement sur toute connexion réussie à un compte de secours (break-glass), quel que soit le moment — ce compte ne devrait presque jamais servir",
          "Corréler systématiquement une rafale d'échecs de connexion suivie d'un succès (signature de password spray), en particulier sur les comptes exclus de Conditional Access",
          "Réévaluer périodiquement la liste des comptes exclus de chaque politique Conditional Access et l'attribution permanente de rôles critiques (Global Administrator) hors PIM",
          "Surveiller les modifications d'identifiants sur les principaux de service à privilèges élevés, en particulier juste après une connexion inhabituelle"
        ],
        quiz:[
          { q:"Quel est le signal combiné le plus révélateur dans cet incident ?",
            options:["Une connexion réussie sur un compte de secours, sans MFA, juste après une rafale d'échecs typique d'un password spray","Un simple changement de mot de passe planifié","Une mise à jour Windows appliquée automatiquement","Une déconnexion normale en fin de journée"],
            correct:0,
            explain:"Pris séparément, chaque signal pourrait sembler mineur ; c'est la combinaison — rafale d'échecs, succès sans MFA, compte à rôle permanent — qui révèle le contournement de Conditional Access." },
          { q:"Pourquoi le Conditional Access ne s'est-il pas appliqué lors de la connexion réussie ?",
            options:["Parce que le compte breakglass.admin est explicitement exclu des politiques concernées","Parce que Conditional Access ne s'applique jamais la nuit","Parce que l'adresse IP était française","Parce que le compte n'existe plus dans l'annuaire"],
            correct:0,
            explain:"Un compte de secours est volontairement exclu de ces politiques pour ne jamais bloquer un accès d'urgence — un choix légitime, mais qui devient dangereux s'il n'est jamais réévalué." },
          { q:"Quelle mesure défensive s'attaque le plus directement à la cause racine de cet incident ?",
            options:["Réévaluer périodiquement les exclusions Conditional Access et les rôles permanents hors PIM","Changer le thème visuel du portail Entra ID","Augmenter la taille des journaux stockés","Désactiver totalement les comptes de secours sans alternative"],
            correct:0,
            explain:"Un compte de secours oublié après sa création, avec un rôle permanent jamais réévalué, est la cause racine — une revue périodique de ces exclusions et attributions permet de la corriger sans perdre le filet de sécurité qu'il représente."}
        ]
      }
    }
  ],

  objectives:[
    { id:'investigate', text:"Consulter les journaux de l'incident" },
    { id:'technique',   text:"Identifier la technique d'attaque utilisée" },
    { id:'account',     text:'Identifier le compte compromis' },
    { id:'timeline',    text:'Reconstituer la chronologie des événements' },
    { id:'flag',        text:"Clôturer l'incident (rapport complet)" },
  ],

  manPages:{
    'dir': { name:'dir', role:"Liste le contenu du dossier d'incident",
      explain:"Affiche les pièces jointes au ticket d'investigation en cours (journaux, notes).",
      usage:'dir' },
    'type': { name:'type', role:"Affiche le contenu d'une pièce du dossier",
      explain:"Sous Windows, l'équivalent de 'cat'. Utilise-la sur chaque fichier du dossier d'incident.",
      usage:'type <fichier>' },
    'report': { name:'report', role:"Soumets une conclusion d'investigation",
      explain:"Chaque sous-commande correspond à une partie du rapport : la technique utilisée, le compte compromis, ou la chronologie des événements (par leurs identifiants EVT-X, du plus ancien au plus récent, séparés par des virgules).",
      usage:'report --technique <valeur>   |   report --account <valeur>   |   report --order <a,b,c,...>' },
    'close-incident': { name:'close-incident', role:"Clôture le dossier d'investigation",
      explain:"Ne fonctionne que si les trois éléments du rapport (technique, compte, chronologie) ont déjà été soumis et sont corrects.",
      usage:'close-incident' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv','dir','type ',
    'report --technique ','report --account ','report --order ','close-incident'
  ],

  helpLine:'whoami /priv, dir, type &lt;fichier&gt;, report --technique &lt;valeur&gt;, report --account &lt;valeur&gt;, report --order &lt;a,b,c,...&gt;, close-incident, clear',

  cmdRefHtml:`whoami /priv<br>dir<br>type &lt;fichier&gt;<br>report --technique &lt;valeur&gt;<br>report --account &lt;valeur&gt;<br>report --order &lt;a,b,c,...&gt;<br>close-incident<br>help`,

  lessonSlides:[
    { icon:'🛰️', title:'Changer de côté : la perspective SOC', html:
      `<p>Jusqu'ici, tu as joué l'attaquant. Ce mode inverse les rôles : tu es désormais <b>analyste au centre des opérations de sécurité (SOC)</b>, et une compromission a peut-être déjà eu lieu.</p>
       <p>Pas de terminal à compromettre ici — juste des journaux à lire, et des conclusions à soumettre.</p>` },
    { icon:'📄', title:"Un journal, des milliers d'événements légitimes", html:
      `<p>Un contrôleur de domaine génère des <b>centaines</b> d'événements de sécurité chaque jour — la quasi-totalité sont parfaitement légitimes.</p>
       <p>Le travail d'un analyste n'est pas de tout regarder avec suspicion, mais de repérer le <b>détail qui cloche</b> : une information qui ne devrait pas être là, un compte qui n'a rien à faire à cet endroit, un horaire incongru.</p>` },
    { icon:'🧭', title:"La chronologie, l'outil de l'analyste", html:
      `<p>Un événement isolé ne prouve presque jamais rien. C'est la <b>corrélation</b> entre plusieurs événements — dans le bon ordre — qui raconte l'histoire complète d'une attaque.</p>
       <p>Reconstituer une chronologie précise est au cœur de tout vrai rapport d'incident : elle seule permet de dire ce qui s'est passé, dans quel ordre, et jusqu'où l'attaquant est allé.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>SOC\\t.leroux</b>. Une alerte s'est déclenchée cette nuit — sa nature exacte reste à déterminer. Consulte le journal de l'incident, identifie la technique utilisée, le compte compromis, et remets les événements dans le bon ordre — puis clôture le dossier.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise. Le dossier d'incident est tiré au sort parmi plusieurs cas possibles à chaque nouvelle investigation.</p>` }
  ],

  completeTitle:'Incident résolu',

  initState(){
    const sc = SCENARIOS.blueteam;
    const c = sc.forcedCase
      ? sc.CASES.find(x => x.id === sc.forcedCase)
      : sc.CASES[Math.floor(Math.random() * sc.CASES.length)];
    sc.forcedCase = null;
    sc.currentCaseId = c.id;
    sc.ticket = c.ticket;
    sc.techniqueLabel = c.techniqueLabel;
    sc.CORRECT_TECHNIQUE = c.CORRECT_TECHNIQUE;
    sc.CORRECT_ACCOUNT = c.CORRECT_ACCOUNT;
    sc.CORRECT_ORDER = c.CORRECT_ORDER;
    sc.EVENTS = c.EVENTS;
    sc.EVENTS_DISPLAY_ORDER = c.EVENTS_DISPLAY_ORDER;
    sc.hints = c.hints;
    sc.readmeText = c.readmeText;
    sc.completeSub = c.completeSub;
    sc.chainSteps = c.chainSteps;
    sc.flag = c.flag;
    sc.deepDive = c.deepDive;
    sc.introLines = [
      `<span class="out-dim">SOC Console [Simulation Lab]</span>`,
      `<span class="out-warn">🛰️ Ticket ouvert : ${c.ticket} — ${c.alertLine}.</span>`,
      `<span class="out-dim">Connecté en tant que SOC\\t.leroux</span>`,
      `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
    ];
    return { technique:false, account:false, timeline:false };
  },

  handle(lower, cmd, m){
    const sc = SCENARIOS.blueteam;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'dir'){
      print(`<span class="out-info"> Dossier d'incident : ${sc.ticket}</span>`);
      print(`<span class="out-dim">  security.log</span>`);
      print(`<span class="out-dim">  readme.txt</span>`);
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim().toLowerCase();
      if(file === 'readme.txt'){
        print(sc.readmeText);
        return true;
      }
      if(file === 'security.log'){
        print(`<span class="out-info">Journal de sécurité — événements corrélés à l'alerte (ordre d'affichage non chronologique) :</span>`);
        sc.EVENTS_DISPLAY_ORDER.forEach(key=>{
          const e = sc.EVENTS[key];
          print(`<span class="out-warn">[EVT-${key}]</span> <span class="out-dim">${e.time} — ${e.text}</span>`);
        });
        complete('investigate');
        return true;
      }
      print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(cmd.slice(5).trim())}</span>`);
      return true;
    }

    m = lower.match(/^report --technique (.+)$/);
    if(m){
      const val = m[1].trim();
      if(sc.CORRECT_TECHNIQUE.includes(val)){
        print(`<span class="out-good">✓ Technique confirmée : ${sc.techniqueLabel}.</span>`);
        state.extra.technique = true;
        complete('technique');
      } else {
        print(`<span class="out-bad">Ça ne correspond pas à ce que montrent les journaux. Relis security.log et compare les chiffrements des événements 4769.</span>`);
      }
      return true;
    }

    m = lower.match(/^report --account (.+)$/);
    if(m){
      const val = m[1].trim();
      if(val === sc.CORRECT_ACCOUNT){
        print(`<span class="out-good">✓ Compte compromis confirmé : ${sc.CORRECT_ACCOUNT}.</span>`);
        state.extra.account = true;
        complete('account');
      } else {
        print(`<span class="out-bad">Ce n'est pas le compte visé par l'événement suspect. Regarde à nouveau qui est concerné par le ticket au chiffrement faible, et ce qui lui arrive juste après.</span>`);
      }
      return true;
    }

    m = lower.match(/^report --order (.+)$/);
    if(m){
      const val = m[1].trim().replace(/\s+/g,'').toLowerCase();
      if(val === sc.CORRECT_ORDER){
        print(`<span class="out-good">✓ Chronologie confirmée : EVT-A → EVT-B → EVT-C → EVT-D.</span>`);
        state.extra.timeline = true;
        complete('timeline');
      } else {
        print(`<span class="out-bad">Cet ordre ne correspond pas aux horodatages du journal. Reprends chaque événement et classe-les uniquement par leur heure exacte.</span>`);
      }
      return true;
    }

    if(lower === 'close-incident'){
      if(state.extra.technique && state.extra.account && state.extra.timeline){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — incident correctement qualifié : ${sc.techniqueLabel} sur ${sc.CORRECT_ACCOUNT}, chronologie complète, dossier clôturé.</span>`);
        print(`<span class="out-dim">🛡️ Pour aller plus loin : voir "En savoir plus" pour les recommandations de détection.</span>`);
        complete('flag');
        finishMission();
      } else {
        const missing = [];
        if(!state.extra.technique) missing.push('la technique');
        if(!state.extra.account) missing.push('le compte compromis');
        if(!state.extra.timeline) missing.push('la chronologie');
        print(`<span class="out-bad">Dossier incomplet — il te manque encore : ${missing.join(', ')}.</span>`);
      }
      return true;
    }

    return false;
  }
};
