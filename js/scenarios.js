// ═══════════════════════════════════════════════════════════
// Données & logique spécifiques à chaque scénario.
// Le moteur générique (terminal.js) délègue ici via sc.handle().
// ═══════════════════════════════════════════════════════════

const SCENARIOS = {};

// ═══════════════════════════════════════════════════════════
// Système OPSEC (furtivité) — règles de "bruit" partagées entre scénarios.
// Chaque règle : une commande qui, une fois exécutée, fait monter la jauge
// d'alerte SOC simulée (voir addNoise() dans terminal.js).
// Volontairement, les actions hors-ligne (crack, forge de ticket brute) n'en
// génèrent pas : la leçon est que l'exploitation elle-même est souvent
// discrète — ce sont l'authentification et les changements d'annuaire qui
// laissent des traces.
// ═══════════════════════════════════════════════════════════
function noiseRule(regex, points, label){
  return { test:(lower) => regex.test(lower), points, label };
}

const NOISE = {
  netUserAll:     noiseRule(/^net user \/domain$/, 4, 'Énumération des comptes du domaine'),
  netUserOne:     noiseRule(/^net user \S+ \/domain$/, 4, "Consultation d'un compte du domaine"),
  domainUserSpn:  noiseRule(/^(get-domainuser -spn|getdomainuser -spn)$/, 4, 'Requête LDAP filtrée sur les SPN'),
  kerberoast:     noiseRule(/^invoke-kerberoast -identity \S+$/, 18, 'Demande de ticket de service (Event ID 4769)'),
  runas:          noiseRule(/^runas \/user:\S+ cmd$/, 10, "Événement d'authentification (ouverture de session)"),
  objectAcl:      noiseRule(/^get-objectacl \S+$/, 3, "Lecture d'ACL"),
  resetPassword:  noiseRule(/^set-domainuserpassword -identity \S+ -newpassword \S+$/, 20, 'Réinitialisation de mot de passe (Event ID 4724)'),
  mimikatzLogon:  noiseRule(/^mimikatz sekurlsa::logonpasswords$/, 25, 'Extraction mémoire LSASS (souvent détectée par un EDR)'),
  mimikatzDcsync: noiseRule(/^mimikatz lsadump::dcsync \/user:krbtgt$/, 40, 'Réplication DCSync (Event ID 4662 — très anormal hors des DC)'),
  mimikatzGolden: noiseRule(/^mimikatz kerberos::golden .*$/, 10, "Forge d'un ticket (préparation risquée)"),
  pth:            noiseRule(/^pth \/target:\S+ \/user:\S+ \/hash:\S+$/, 15, 'Authentification par hash (NTLM)'),
  mgAppAll:       noiseRule(/^get-mgapp -all$/, 4, 'Requête Microsoft Graph en lecture'),
  mgAppOne:       noiseRule(/^get-mgapp \S+$/, 4, 'Requête Microsoft Graph en lecture'),
  mgRoleMembers:  noiseRule(/^get-mgrolemembers -role \S+$/, 4, 'Requête Microsoft Graph en lecture'),
  connectMgraph:  noiseRule(/^connect-mgraph -appid \S+ -secret \S+$/, 12, 'Connexion consignée (journal de connexion Entra ID)'),
  addCredential:  noiseRule(/^add-credential -target \S+$/, 22, "Modification d'annuaire consignée (ajout d'un identifiant d'application)"),
  certipyFind:    noiseRule(/^certipy find$/, 6, "Énumération des modèles de certificats (requête LDAP vers l'AD CS)"),
  certipyReq:     noiseRule(/^certipy req -template \S+ -upn \S+$/, 16, "Demande de certificat (Event ID 4886/4887 côté serveur AD CS)"),
  certipyAuth:    noiseRule(/^certipy auth -cert \S+$/, 20, "Authentification Kerberos par certificat (PKINIT) pour un compte à privilèges")
};

// ---------------------------------------------------------
// SCÉNARIO 01 — KERBEROASTING
// ---------------------------------------------------------
SCENARIOS.kerberoast = {
  id:'kerberoast',
  tag:'🎫 SCÉNARIO 01 · KERBEROASTING',
  lessonTag:'📘 LEÇON · SCÉNARIO 01',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.domainUserSpn, NOISE.kerberoast, NOISE.runas],
  startUser:'j.dupont',

  identities:{
    'j.dupont':    { label:'CORP\\j.dupont', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — comptabilité' },
    'a.martin':    { label:'CORP\\a.martin', priv:'Administrateur IT', groups:['Domain Users','Domain Admins'], desc:'Administrateur du domaine' },
    'svc_backup':  { label:'CORP\\svc_backup', priv:'Compte de service', groups:['Domain Users','Backup Operators'],
                     desc:'Compte de service — sauvegardes nocturnes',
                     spn:'MSSQLSvc/sql01.corp.local:1433',
                     hash:'$krb5tgs$23$*svc_backup$CORP.LOCAL*$9f8c...(ticket TGS tronqué)',
                     crackedPassword:'Summer2024!' },
    'administrator': { label:'CORP\\administrator', priv:'Administrateur intégré', groups:['Domain Users','Domain Admins'], desc:'Compte administrateur intégré du domaine' }
  },

  objectives:[
    { id:'enum',       text:'Énumérer les comptes du domaine' },
    { id:'spn',        text:'Trouver le compte de service avec un SPN' },
    { id:'kerberoast', text:'Extraire le ticket Kerberos du compte' },
    { id:'crack',      text:'Cracker le mot de passe du ticket' },
    { id:'access',     text:'Ouvrir une session avec ce compte' },
    { id:'flag',       text:'Récupérer le flag sur le bureau admin' },
  ],

  hints:[
    ["Tu ne connais encore personne dans ce domaine. Commence par voir qui y est.",
     "Il existe une commande pour lister tous les comptes du domaine — cherche du côté de `net user`.",
     "Commence par lister les comptes du domaine : `net user /domain`"],
    ["Un des comptes du domaine n'est pas un vrai humain : c'est un compte de service. Ça se voit à son nom.",
     "Regarde les détails du compte qui commence par svc_, ou cherche une commande qui liste directement les comptes avec un SPN.",
     "Un des comptes ressemble à un compte de service (préfixe svc_). Regarde ses détails avec `net user svc_backup /domain`, ou liste directement les comptes vulnérables avec `get-domainuser -spn`."],
    ["Tout compte avec un SPN peut se voir demander un ticket Kerberos, même par un utilisateur standard comme toi.",
     "Il existe une commande pour réclamer ce ticket — cherche du côté de `invoke-kerberoast`.",
     "Une fois le compte identifié, demande son ticket Kerberos avec `invoke-kerberoast -identity svc_backup`"],
    ["Le ticket que tu as obtenu est chiffré avec le mot de passe du compte. Rien ne t'empêche d'essayer de le casser hors-ligne.",
     "Il existe une commande `crack` qui prend ce hash en argument.",
     "Le ticket obtenu est un hash. Essaie de le cracker avec `crack <hash>`"],
    ["Tu connais maintenant un mot de passe en clair. Rien ne t'empêche de t'en servir.",
     "Il existe une commande Windows pour ouvrir une session avec une identité qui n'est pas la tienne.",
     "Une fois le mot de passe en clair, ouvre une session avec `runas /user:svc_backup cmd`"],
    ["Le compte que tu contrôles appartient à un groupe qui a des droits particuliers sur les fichiers.",
     "Ce groupe peut lire n'importe quel fichier, y compris ceux d'un autre bureau. Regarde ce qu'il y a sur celui de l'administrateur.",
     "Le compte svc_backup appartient au groupe Backup Operators, qui peut lire n'importe quel fichier. Regarde le bureau de l'administrateur avec `dir` puis `type flag.txt`."]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine (comme un annuaire d'entreprise)",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche les détails d'un compte précis : description, groupes, et parfois un SPN.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-domainuser': { name:'get-domainuser -spn', role:'Liste les comptes vulnérables au Kerberoasting',
      explain:"Un SPN (Service Principal Name) associe un service à un compte. Tout compte avec un SPN peut se voir demander un ticket Kerberos par n'importe quel utilisateur authentifié — même standard.",
      usage:'get-domainuser -spn' },
    'invoke-kerberoast': { name:'invoke-kerberoast', role:'Demande le ticket Kerberos chiffré d\'un compte de service',
      explain:"Le ticket est chiffré avec le mot de passe du compte de service. Tu peux le récupérer légitimement (le protocole Kerberos le permet à tout utilisateur), puis tenter de le casser hors-ligne, sans alerter personne.",
      usage:'invoke-kerberoast -identity <nom>' },
    'crack': { name:'crack', role:'Casse un ticket Kerberos hors-ligne pour retrouver le mot de passe',
      explain:"Si le mot de passe du compte de service est faible ou commun, un dictionnaire de mots de passe suffit à le retrouver à partir du ticket chiffré.",
      usage:'crack <hash>' },
    'runas': { name:'runas /user', role:"Ouvre une session avec un autre compte",
      explain:"Une fois le mot de passe en clair obtenu, tu peux te reconnecter avec l'identité (et donc les droits) de ce compte.",
      usage:'runas /user:<nom> cmd' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-domainuser -spn',
    'invoke-kerberoast -identity ','crack ','runas /user:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-domainuser -spn, invoke-kerberoast -identity &lt;nom&gt;, crack &lt;hash&gt;, runas /user:&lt;nom&gt; cmd, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-domainuser -spn<br>invoke-kerberoast -identity &lt;nom&gt;<br>crack &lt;hash&gt;<br>runas /user:&lt;nom&gt; cmd<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.dupont sur WKS-042</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🏰', title:"Qu'est-ce qu'un domaine Active Directory ?", html:
      `<p>Dans une entreprise, chaque utilisateur, chaque machine, chaque droit d'accès est géré depuis un point central : le <b>contrôleur de domaine</b>. C'est l'annuaire qui dit "qui a le droit de faire quoi".</p>
       <p>Le vrai objectif d'un attaquant, c'est de <b>remonter</b> depuis un compte à faibles privilèges jusqu'à un compte avec les pleins pouvoirs sur le domaine — un <b>Domain Admin</b>. C'est la couronne.</p>` },
    { icon:'🎟️', title:'Kerberos & le SPN', html:
      `<p><b>Kerberos</b> est le protocole d'authentification d'Active Directory : au lieu d'envoyer un mot de passe à chaque service, tu obtiens des "tickets" qui prouvent ton identité.</p>
       <p>Un <b>SPN</b> relie un service à un compte du domaine. Point important : <b>n'importe quel utilisateur authentifié</b>, même standard, peut légitimement demander un ticket pour un compte qui a un SPN.</p>` },
    { icon:'🔓', title:'L\'attaque : Kerberoasting', html:
      `<p>Le ticket obtenu pour un compte de service est <b>chiffré avec le mot de passe de ce compte</b>. Tu peux l'emporter et le casser hors-ligne, tranquillement.</p>
       <p>Si ce mot de passe est faible, tu le retrouves en clair. Résultat : tu deviens ce compte — et ses droits deviennent les tiens.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\j.dupont</b>, employé standard sur le domaine <b>CORP.LOCAL</b>. Trouve un compte de service vulnérable, obtiens son mot de passe, et vois jusqu'où ses droits te mènent.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domaine compromis',
  completeSub:'Compte de service exploité, groupe privilégié abusé.',
  chainSteps:[
    {icon:'🔎', label:'Énumération'}, {icon:'🎟️', label:'SPN trouvé'},
    {icon:'🔓', label:'Kerberoast'}, {icon:'🗝️', label:'Crack'}, {icon:'👑', label:'Flag'}
  ],
  flag:'FLAG{kerberoast_svc_backup_operators}',

  // Carte d'attaque (façon BloodHound) : vérité terrain, révélée progressivement.
  graph:{
    nodes:[
      { id:'j.dupont', label:'j.dupont', type:'user' },
      { id:'a.martin', label:'a.martin', type:'admin' },
      { id:'svc_backup', label:'svc_backup', type:'service' },
      { id:'administrator', label:'administrator', type:'admin' },
      { id:'grp_backupops', label:'Backup Operators', type:'group' }
    ],
    edges:[
      { id:'e_member', from:'svc_backup', to:'grp_backupops', type:'memberof', label:'MemberOf' },
      { id:'e_bypass', from:'grp_backupops', to:'administrator', type:'abuse', label:'Lecture fichiers (bypass ACL)' },
      { id:'e_owned', from:'j.dupont', to:'svc_backup', type:'owned', label:'Kerberoast + crack' }
    ]
  },

  deepDive:{
    why:"Le protocole Kerberos autorise, par conception, tout utilisateur authentifié à demander un ticket de service pour n'importe quel compte possédant un SPN. Ce n'est pas une faille du protocole — c'est son fonctionnement normal. Le seul maillon faible est la robustesse du mot de passe qui chiffre ce ticket.",
    defenses:[
      "Utiliser des comptes de service gérés (gMSA) : mot de passe long, aléatoire, changé automatiquement par AD",
      "Si un compte de service classique est indispensable, imposer un mot de passe de 25+ caractères aléatoires",
      "Surveiller les demandes de tickets de service inhabituelles (Event ID 4769 côté Windows)",
      "Limiter les comptes de service à des groupes à faible privilège quand c'est possible"
    ]
  },

  initState(){ return { crackedHashes:{} }; },

  // Retourne true si la commande a été traitée (le moteur générique s'arrête alors).
  handle(lower, cmd, m){
    const sc = SCENARIOS.kerberoast;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      Object.keys(sc.identities).forEach(name => print(`<span class="out-dim">  ${name}</span>`));
      AttackGraph.reveal({ nodes:Object.keys(sc.identities) });
      complete('enum');
      return true;
    }

    m = lower.match(/^net user (\S+) \/domain$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){ print(`<span class="out-bad">Utilisateur introuvable : ${name}</span>`); return true; }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      if(u.spn){
        print(`<span class="out-warn">ServicePrincipalName : ${u.spn}</span>`);
        print(`<span class="out-warn">⚠ Ce compte possède un SPN : potentiellement vulnérable au Kerberoasting.</span>`);
        AttackGraph.reveal({ nodes:['grp_backupops'], edges:['e_member'], tags:{ svc_backup:'spn' } });
        complete('spn');
      }
      return true;
    }

    if(lower === 'get-domainuser -spn' || lower === 'getdomainuser -spn'){
      print(`<span class="out-info">Comptes avec un SPN (Kerberoastables) :</span>`);
      let found = false;
      Object.entries(sc.identities).forEach(([name,u])=>{
        if(u.spn){ print(`<span class="out-warn">  ${name}  —  ${u.spn}</span>`); found = true; }
      });
      if(!found) print(`<span class="out-dim">  (aucun)</span>`);
      AttackGraph.reveal({ nodes:['grp_backupops'], edges:['e_member'], tags:{ svc_backup:'spn' } });
      complete('spn');
      return true;
    }

    m = lower.match(/^invoke-kerberoast -identity (\S+)$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u || !u.spn){ print(`<span class="out-bad">Aucun ticket Kerberos disponible pour ce compte.</span>`); return true; }
      print(`<span class="out-info">Ticket TGS demandé pour ${name}...</span>`);
      print(`<span class="out-good">Ticket obtenu :</span>`);
      print(`<span class="out-dim">${u.hash}</span>`);
      complete('kerberoast');
      return true;
    }

    m = lower.match(/^crack (.+)$/) || lower.match(/^hashcat (.+)$/);
    if(m){
      const svc = sc.identities['svc_backup'];
      print(`<span class="out-info">Tentative de crack du ticket (dictionnaire)...</span>`);
      print(`<span class="out-good">Mot de passe trouvé : ${svc.crackedPassword}</span>`);
      state.extra.crackedHashes['svc_backup'] = svc.crackedPassword;
      AttackGraph.reveal({ tags:{ svc_backup:'cracked' } });
      complete('crack');
      return true;
    }

    m = lower.match(/^runas \/user:(\S+) cmd$/);
    if(m){
      const name = m[1];
      if(name === 'svc_backup' && !state.extra.crackedHashes['svc_backup']){
        print(`<span class="out-bad">Mot de passe requis. Crack le ticket d'abord.</span>`);
        return true;
      }
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      state.user = name;
      updatePrompt();
      print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[name].label}</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(name);
      complete('access');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'svc_backup'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\Administrator\\Desktop</span>`);
        print(`<span class="out-dim">  [droits Backup Operators : lecture autorisée malgré les ACL]</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
        AttackGraph.reveal({ edges:['e_bypass'] });
      } else if(state.user === 'j.dupont'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  notes.txt</span>`);
        print(`<span class="out-dim">💡 Ce dossier t'appartient. Pour voir le bureau de l'administrateur, il te faudra un compte avec plus de droits.</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (vide)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'svc_backup'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : énumération → Kerberoasting → crack → abus du groupe Backup Operators.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : mots de passe de service longs/aléatoires (idéalement un gMSA géré automatiquement), et surveiller les demandes de tickets suspectes.</span>`);
        AttackGraph.markOwned('administrator');
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : ton compte (${state.user}) n'a pas les droits de lecture sur ce fichier.</span>`);
        print(`<span class="out-dim">💡 Le bureau de l'administrateur est protégé. Il te faut un compte membre d'un groupe qui contourne cette restriction.</span>`);
      } else if(file.toLowerCase() === 'notes.txt'){
        print(`<span class="out-dim">"Penser à changer le mdp de svc_backup un jour..." — j.dupont</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};

// ---------------------------------------------------------
// CHAPITRE FINAL — LE VRAI GOLDEN TICKET
// Enchaîne Kerberoasting → Abus d'ACL → extraction krbtgt → forge du ticket
// ---------------------------------------------------------
SCENARIOS.goldenticket = {
  id:'goldenticket',
  epic:true,
  tag:'👑 CHAPITRE FINAL · GOLDEN TICKET',
  lessonTag:'📘 LEÇON · CHAPITRE FINAL',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.domainUserSpn, NOISE.kerberoast, NOISE.objectAcl, NOISE.resetPassword, NOISE.runas, NOISE.mimikatzDcsync, NOISE.mimikatzGolden],
  startUser:'j.dupont',

  KRBTGT_HASH:'ff87f8f2f8dfd7c0d1ae1c8f9b3a3e51',

  identities:{
    'j.dupont':   { label:'CORP\\j.dupont', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — comptabilité' },
    'svc_backup': { label:'CORP\\svc_backup', priv:'Compte de service', groups:['Domain Users','Backup Operators'],
                    desc:'Compte de service — sauvegardes nocturnes',
                    spn:'MSSQLSvc/sql01.corp.local:1433',
                    hash:'$krb5tgs$23$*svc_backup$CORP.LOCAL*$9f8c...(ticket TGS tronqué)',
                    crackedPassword:'Summer2024!' },
    'h.morel':    { label:'CORP\\h.morel', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:'Support IT senior' },
    'administrator@DC01': { label:'CORP\\Administrator (ticket forgé)', priv:'Domain Admin — identité forgée', groups:['Domain Admins','Enterprise Admins'] }
  },

  acl:{
    'h.morel': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\svc_backup', rights:'GenericAll', normal:false }
    ]
  },

  objectives:[
    { id:'enum',       text:'Repérer le compte de service exploitable' },
    { id:'kerberoast', text:'Extraire et casser son ticket Kerberos' },
    { id:'pivot1',     text:'Ouvrir une session avec ce compte' },
    { id:'acl',        text:"Découvrir l'ACL oubliée sur un compte Domain Admin" },
    { id:'pivot2',     text:'Réinitialiser puis prendre ce compte' },
    { id:'dcsync',     text:'Extraire le hash du compte krbtgt' },
    { id:'forge',      text:'Forger un Golden Ticket' },
    { id:'flag',       text:'Prendre le contrôle total du domaine' },
  ],

  hints:[
    ["Comme au premier scénario, commence par identifier ce qui traîne dans le domaine.",
     "Cherche un compte de service qui a un SPN.",
     "Commence comme au chapitre 1 : `net user /domain`, puis `get-domainuser -spn`"],
    ["Ce compte de service a un ticket que tu peux réclamer, puis casser hors-ligne.",
     "Utilise `invoke-kerberoast`, puis `crack` sur le résultat.",
     "Demande le ticket du compte de service, puis casse-le : `invoke-kerberoast -identity svc_backup` puis `crack <hash>`"],
    ["Tu as maintenant un mot de passe en clair pour ce compte de service.",
     "Ouvre une session avec ce compte.",
     "Ouvre une session avec ce compte : `runas /user:svc_backup cmd`"],
    ["En tant que compte de service, regarde si quelqu'un t'a donné, par erreur, des droits sur un compte plus puissant.",
     "Il existe une commande pour lister les droits sur un compte cible — essaie-la sur un admin du domaine.",
     "En tant que svc_backup, regarde qui a des droits sur les comptes à privilège : `get-objectacl h.morel`"],
    ["Ce droit oublié te permet de littéralement changer le mot de passe d'un compte Domain Admin.",
     "Réinitialise ce mot de passe, puis connecte-toi avec.",
     "Réinitialise le mot de passe grâce à ce droit oublié, puis connecte-toi : `set-domainuserpassword -identity h.morel -newpassword <ton_choix>` puis `runas /user:h.morel cmd`"],
    ["Tu es maintenant Domain Admin. Il existe un compte spécial dont la clé chiffre absolument tous les tickets Kerberos du domaine.",
     "Ce compte s'appelle krbtgt — essaie d'en extraire le hash.",
     "Tu es Domain Admin. Extrais la clé qui signe tous les tickets du domaine : `mimikatz lsadump::dcsync /user:krbtgt`"],
    ["Avec la clé krbtgt en main, tu peux fabriquer des tickets Kerberos entièrement faux, pour n'importe quelle identité.",
     "Il existe une commande pour forger un ticket 'golden' à partir de ce hash.",
     "Utilise cette clé pour forger un ticket illimité : `mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:<hash>`"],
    ["Le domaine entier t'appartient maintenant.",
     "Regarde ce qu'il y a sur DC01.",
     "Le domaine est à toi. `dir` puis `type flag.txt` sur DC01."]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-domainuser': { name:'get-domainuser -spn', role:'Liste les comptes vulnérables au Kerberoasting',
      explain:"Tout compte avec un SPN peut se voir demander un ticket Kerberos par n'importe quel utilisateur authentifié.",
      usage:'get-domainuser -spn' },
    'invoke-kerberoast': { name:'invoke-kerberoast', role:"Demande le ticket Kerberos chiffré d'un compte de service",
      explain:"Le ticket est chiffré avec le mot de passe du compte de service — récupérable légitimement, cassable hors-ligne.",
      usage:'invoke-kerberoast -identity <nom>' },
    'crack': { name:'crack', role:'Casse un ticket Kerberos hors-ligne',
      explain:"Si le mot de passe du compte de service est faible, un dictionnaire suffit à le retrouver.",
      usage:'crack <hash>' },
    'runas': { name:'runas /user', role:'Ouvre une session avec un autre compte',
      explain:"Nécessite de connaître le mot de passe (cassé ou réinitialisé) du compte cible.",
      usage:'runas /user:<nom> cmd' },
    'get-objectacl': { name:'get-objectacl', role:'Liste les droits (ACL) accordés sur un compte',
      explain:"Un droit GenericAll équivaut à un contrôle total de l'objet, même sans être administrateur du domaine.",
      usage:'get-objectacl <nom>' },
    'set-domainuserpassword': { name:'set-domainuserpassword', role:"Réinitialise le mot de passe d'un compte cible",
      explain:"Nécessite un droit suffisant (GenericAll, WriteDACL...) sur le compte cible.",
      usage:'set-domainuserpassword -identity <nom> -newpassword <valeur>' },
    'mimikatz': { name:'mimikatz', role:'Boîte à outils post-exploitation AD',
      explain:"`lsadump::dcsync /user:krbtgt` simule une réplication de domaine pour extraire la clé qui signe tous les tickets Kerberos — nécessite d'être Domain Admin. `kerberos::golden` utilise ensuite cette clé pour forger un ticket valide pour n'importe quelle identité, à volonté.",
      usage:'mimikatz lsadump::dcsync /user:krbtgt   |   mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:<hash>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-domainuser -spn',
    'invoke-kerberoast -identity ','crack ','runas /user:',
    'get-objectacl ','set-domainuserpassword -identity ',
    'mimikatz lsadump::dcsync /user:krbtgt',
    'mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:',
    'dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, get-domainuser -spn, invoke-kerberoast -identity &lt;nom&gt;, crack &lt;hash&gt;, runas /user:&lt;nom&gt; cmd, get-objectacl &lt;nom&gt;, set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;, mimikatz lsadump::dcsync /user:krbtgt, mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:&lt;hash&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`net user /domain<br>get-domainuser -spn<br>invoke-kerberoast -identity &lt;nom&gt;<br>crack &lt;hash&gt;<br>runas /user:&lt;nom&gt; cmd<br>get-objectacl &lt;nom&gt;<br>set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;<br>mimikatz lsadump::dcsync /user:krbtgt<br>mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:&lt;hash&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.dupont sur WKS-042</span>`,
    `<span class="out-warn">🔥 Chapitre final — enchaîne toutes les techniques jusqu'au bout.</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🎬', title:'Le chapitre final', html:
      `<p>Ce chapitre enchaîne les trois techniques précédentes à la suite : Kerberoasting, abus d'ACL, puis une étape finale inédite.</p>
       <p>Au bout du chemin : la vraie attaque <b>Golden Ticket</b>, celle qui donne son nom à ce jeu.</p>` },
    { icon:'🔑', title:'Le compte krbtgt', html:
      `<p>Tous les tickets Kerberos du domaine sont chiffrés avec la clé d'un compte spécial : <b>krbtgt</b>. Ce compte ne sert jamais à se connecter — il existe uniquement pour signer des tickets.</p>
       <p>Si un attaquant devenu Domain Admin extrait cette clé, il peut <b>forger lui-même</b> n'importe quel ticket, pour n'importe quelle identité, à volonté.</p>` },
    { icon:'👑', title:'Le Golden Ticket', html:
      `<p>Un ticket forgé avec la clé krbtgt est un <b>Golden Ticket</b> : accès total et persistant au domaine, souvent valide même après un changement de mot de passe classique.</p>
       <p>C'est la porte dérobée ultime — et pourquoi protéger le compte krbtgt est une priorité absolue en sécurité AD.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Pars de zéro, <b>CORP\\j.dupont</b>. Enchaîne Kerberoasting puis abus d'ACL pour devenir Domain Admin — puis va chercher la clé krbtgt et forge ton propre Golden Ticket.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'👑 GOLDEN TICKET FORGÉ',
  completeSub:'Tu contrôles désormais le domaine tout entier — pour toujours.',
  chainSteps:[
    {icon:'🎟️', label:'Kerberoast'}, {icon:'🗂️', label:'ACL'},
    {icon:'🔑', label:'krbtgt'}, {icon:'👑', label:'Golden Ticket'}
  ],
  flag:'FLAG{golden_ticket_krbtgt_forged}',

  graph:{
    nodes:[
      { id:'j.dupont', label:'j.dupont', type:'user' },
      { id:'svc_backup', label:'svc_backup', type:'service' },
      { id:'h.morel', label:'h.morel', type:'admin' },
      { id:'krbtgt', label:'krbtgt', type:'admin' },
      { id:'administrator@DC01', label:'Administrator (Golden Ticket)', type:'admin' }
    ],
    edges:[
      { id:'e_pivot1', from:'j.dupont', to:'svc_backup', type:'owned', label:'Kerberoast + crack' },
      { id:'e_acl', from:'svc_backup', to:'h.morel', type:'abuse', label:'GenericAll (oublié)' },
      { id:'e_pivot2', from:'svc_backup', to:'h.morel', type:'owned', label:'Reset + accès' },
      { id:'e_dcsync', from:'h.morel', to:'krbtgt', type:'auth', label:'DCSync' },
      { id:'e_forge', from:'krbtgt', to:'administrator@DC01', type:'owned', label:'Ticket forgé' }
    ]
  },

  deepDive:{
    why:"Le compte krbtgt signe cryptographiquement tous les tickets Kerberos du domaine. Sa clé change rarement en pratique, ce qui en fait la cible ultime : qui la possède peut forger une identité illimitée, indépendamment de tout mot de passe utilisateur.",
    defenses:[
      "Changer la clé krbtgt régulièrement — et deux fois de suite, car AD conserve les deux dernières générations",
      "Limiter drastiquement qui peut effectuer une réplication de domaine (droit DCSync)",
      "Surveiller les requêtes de réplication anormales (Event ID 4662)",
      "Détecter les tickets Kerberos à durée de vie anormalement longue — signe classique d'un Golden Ticket"
    ]
  },

  initState(){ return { crackedHashes:{}, resetTarget:null, newPassword:null, krbtgtHash:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.goldenticket;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      Object.keys(sc.identities).forEach(name => print(`<span class="out-dim">  ${name}</span>`));
      AttackGraph.reveal({ nodes:Object.keys(sc.identities) });
      complete('enum');
      return true;
    }

    m = lower.match(/^net user (\S+) \/domain$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){ print(`<span class="out-bad">Utilisateur introuvable : ${name}</span>`); return true; }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc || '(compte système)'}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      if(u.spn){
        print(`<span class="out-warn">ServicePrincipalName : ${u.spn}</span>`);
        print(`<span class="out-warn">⚠ Ce compte possède un SPN : potentiellement vulnérable au Kerberoasting.</span>`);
        AttackGraph.reveal({ tags:{ svc_backup:'spn' } });
      }
      complete('enum');
      return true;
    }

    if(lower === 'get-domainuser -spn' || lower === 'getdomainuser -spn'){
      print(`<span class="out-info">Comptes avec un SPN (Kerberoastables) :</span>`);
      let found = false;
      Object.entries(sc.identities).forEach(([name,u])=>{
        if(u.spn){ print(`<span class="out-warn">  ${name}  —  ${u.spn}</span>`); found = true; }
      });
      if(!found) print(`<span class="out-dim">  (aucun)</span>`);
      AttackGraph.reveal({ tags:{ svc_backup:'spn' } });
      complete('enum');
      return true;
    }

    m = lower.match(/^invoke-kerberoast -identity (\S+)$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u || !u.spn){ print(`<span class="out-bad">Aucun ticket Kerberos disponible pour ce compte.</span>`); return true; }
      print(`<span class="out-info">Ticket TGS demandé pour ${name}...</span>`);
      print(`<span class="out-good">Ticket obtenu :</span>`);
      print(`<span class="out-dim">${u.hash}</span>`);
      return true;
    }

    m = lower.match(/^crack (.+)$/) || lower.match(/^hashcat (.+)$/);
    if(m){
      const svc = sc.identities['svc_backup'];
      print(`<span class="out-info">Tentative de crack du ticket (dictionnaire)...</span>`);
      print(`<span class="out-good">Mot de passe trouvé : ${svc.crackedPassword}</span>`);
      state.extra.crackedHashes['svc_backup'] = svc.crackedPassword;
      AttackGraph.reveal({ tags:{ svc_backup:'cracked' } });
      complete('kerberoast');
      return true;
    }

    m = lower.match(/^get-objectacl (\S+)$/);
    if(m){
      const name = m[1];
      const entries = sc.acl[name];
      if(!entries){ print(`<span class="out-bad">Objet introuvable ou sans ACL notable : ${escapeHtml(name)}</span>`); return true; }
      print(`<span class="out-info">ACL sur le compte ${name} :</span>`);
      entries.forEach(e => {
        if(e.normal){ print(`<span class="out-dim">  ${e.principal} — ${e.rights}</span>`); }
        else { print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ inhabituel pour ce compte</span>`); }
      });
      if(entries.some(e => !e.normal)){
        AttackGraph.reveal({ edges:['e_acl'] });
        complete('acl');
      }
      return true;
    }

    m = lower.match(/^set-domainuserpassword -identity (\S+) -newpassword (\S+)$/);
    if(m){
      const [, name, pwd] = m;
      const entries = sc.acl[name] || [];
      const hasRight = entries.some(e => !e.normal && e.principal.toLowerCase().endsWith(state.user.toLowerCase()));
      if(!hasRight){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits nécessaires sur ce compte.</span>`);
        return true;
      }
      print(`<span class="out-good">Mot de passe de ${name} réinitialisé avec succès.</span>`);
      state.extra.resetTarget = name;
      state.extra.newPassword = pwd;
      AttackGraph.reveal({ tags:{ [name]:'reset' } });
      return true;
    }

    m = lower.match(/^runas \/user:(\S+) cmd$/);
    if(m){
      const name = m[1];
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      if(name === 'svc_backup'){
        if(!state.extra.crackedHashes['svc_backup']){
          print(`<span class="out-bad">Mot de passe requis. Crack le ticket d'abord.</span>`);
          return true;
        }
        state.user = name;
        updatePrompt();
        print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[name].label}</span>`);
        AttackGraph.reveal({ edges:['e_pivot1'] });
        AttackGraph.markOwned('svc_backup');
        complete('pivot1');
        return true;
      }
      if(name === 'h.morel'){
        if(state.extra.resetTarget !== 'h.morel' || !state.extra.newPassword){
          print(`<span class="out-bad">Mot de passe inconnu pour ce compte.</span>`);
          return true;
        }
        state.user = name;
        updatePrompt();
        print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[name].label}</span>`);
        AttackGraph.reveal({ edges:['e_pivot2'] });
        AttackGraph.markOwned('h.morel');
        complete('pivot2');
        return true;
      }
      print(`<span class="out-bad">Identifiants inconnus pour ce compte.</span>`);
      return true;
    }

    if(lower === 'mimikatz lsadump::dcsync /user:krbtgt'){
      if(state.user !== 'h.morel'){
        print(`<span class="out-bad">Accès refusé : une réplication de domaine (DCSync) nécessite des droits Domain Admin.</span>`);
        return true;
      }
      print(`<span class="out-info">Simulation d'une réplication de domaine (DCSync) auprès du contrôleur...</span>`);
      print(`<span class="out-good">Hash NTLM de krbtgt extrait :</span>`);
      print(`<span class="out-dim">  ${sc.KRBTGT_HASH}</span>`);
      print(`<span class="out-warn">⚠ Cette clé signe TOUS les tickets Kerberos du domaine.</span>`);
      state.extra.krbtgtHash = sc.KRBTGT_HASH;
      AttackGraph.reveal({ nodes:['krbtgt'], edges:['e_dcsync'], tags:{ krbtgt:'hash' } });
      complete('dcsync');
      return true;
    }

    m = lower.match(/^mimikatz kerberos::golden \/user:administrator \/id:500 \/krbtgt:(\S+)$/);
    if(m){
      const hash = m[1];
      if(!state.extra.krbtgtHash){
        print(`<span class="out-bad">Aucune clé krbtgt en main. Fais d'abord le DCSync.</span>`);
        return true;
      }
      if(hash !== sc.KRBTGT_HASH.toLowerCase()){
        print(`<span class="out-bad">Échec : le hash fourni ne correspond pas à la clé krbtgt.</span>`);
        return true;
      }
      print(`<span class="out-good">🎫 Ticket forgé avec succès — identité : Administrator (RID 500), validité illimitée.</span>`);
      print(`<span class="out-warn">Tu détiens désormais un accès total et persistant au domaine CORP.LOCAL.</span>`);
      state.user = 'administrator@DC01';
      updatePrompt();
      AttackGraph.reveal({ nodes:['administrator@DC01'], edges:['e_forge'] });
      AttackGraph.markOwned('administrator@DC01');
      complete('forge');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'administrator@DC01'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\Administrator\\Desktop (DC01)</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici pour l'instant)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'administrator@DC01'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">👑 Chaîne complète : Kerberoasting → abus d'ACL → DCSync → Golden Ticket forgé. Tu es Domain Admin, définitivement.</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : ton compte actuel n'a pas les droits sur ce fichier.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};

// ---------------------------------------------------------
// SCÉNARIO 03 — ABUS D'ACL (GenericAll)
// ---------------------------------------------------------
SCENARIOS.acl = {
  id:'acl',
  tag:'👑 SCÉNARIO 03 · ABUS D\'ACL',
  lessonTag:'📘 LEÇON · SCÉNARIO 03',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.objectAcl, NOISE.resetPassword, NOISE.runas],
  startUser:'j.dupont',

  identities:{
    'j.dupont':  { label:'CORP\\j.dupont', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — support niveau 1' },
    'r.simon':   { label:'CORP\\r.simon', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — marketing' },
    'h.morel':   { label:'CORP\\h.morel', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:'Support IT senior' },
    'administrator': { label:'CORP\\administrator', priv:'Administrateur intégré', groups:['Domain Users','Domain Admins'], desc:'Compte administrateur intégré du domaine' }
  },

  // ACL simulées : qui a des droits inhabituels sur quel compte
  acl:{
    'h.morel': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\j.dupont', rights:'GenericAll', normal:false }
    ],
    'r.simon': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true }
    ],
    'administrator': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true }
    ]
  },

  objectives:[
    { id:'enum',   text:'Repérer les comptes à privilèges du domaine' },
    { id:'acl',    text:'Trouver une ACL mal configurée (GenericAll)' },
    { id:'reset',  text:'Réinitialiser le mot de passe grâce à cette permission' },
    { id:'access', text:'Ouvrir une session avec le compte compromis' },
    { id:'flag',   text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant de chercher une faille, il faut savoir qui sont les comptes puissants de ce domaine.",
     "Liste les comptes et repère celui qui appartient au groupe Domain Admins.",
     "Commence par voir qui est qui dans le domaine : `net user /domain`"],
    ["Les permissions sur un compte ne sont pas toujours celles qu'on croit — quelqu'un a peut-être oublié d'en retirer une.",
     "Il existe une commande pour lister les droits accordés sur un compte cible. Essaie-la sur h.morel.",
     "h.morel a l'air intéressant (Domain Admin). Regarde qui a des droits sur son compte : `get-objectacl h.morel`"],
    ["Un droit très puissant, mal placé, permet de littéralement tout changer sur le compte visé — y compris son secret d'authentification.",
     "Ce droit s'appelle GenericAll. Utilise-le pour définir un nouveau mot de passe sur le compte Domain Admin.",
     "Un compte qui ne devrait pas avoir de droits ici en a pourtant (GenericAll). Ce droit permet de tout changer sur le compte cible — y compris son mot de passe : `set-domainuserpassword -identity h.morel -newpassword <ton_choix>`"],
    ["Tu connais maintenant un mot de passe valide pour ce compte.",
     "Il existe une commande Windows pour ouvrir une session avec cette identité.",
     "Une fois le mot de passe réinitialisé, connecte-toi : `runas /user:h.morel cmd`"],
    ["Tu es désormais Domain Admin.",
     "Regarde ce qu'il y a sur ton propre bureau, maintenant que tu es h.morel.",
     "Tu es maintenant Domain Admin. Regarde ton propre bureau avec `dir` puis `type flag.txt`"]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-objectacl': { name:'get-objectacl', role:"Liste les droits (ACL) accordés sur un compte",
      explain:"Chaque objet AD a une liste de contrôle d'accès (ACL/DACL) qui dit qui peut faire quoi dessus. Un droit <b>GenericAll</b> équivaut à un contrôle total de l'objet — y compris changer son mot de passe — même sans être administrateur du domaine. Ces droits sont parfois accordés temporairement (dépannage, délégation) puis jamais retirés.",
      usage:'get-objectacl <nom>' },
    'set-domainuserpassword': { name:'set-domainuserpassword', role:"Réinitialise le mot de passe d'un compte cible",
      explain:"Nécessite un droit suffisant sur le compte cible (GenericAll, WriteDACL, ou le droit dédié 'Reset Password'). Contrairement au Kerberoasting, ceci ne casse rien : le nouveau mot de passe est choisi directement, sans jamais connaître l'ancien.",
      usage:'set-domainuserpassword -identity <nom> -newpassword <valeur>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-objectacl ',
    'set-domainuserpassword -identity ','runas /user:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-objectacl &lt;nom&gt;, set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;, runas /user:&lt;nom&gt; cmd, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-objectacl &lt;nom&gt;<br>set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;<br>runas /user:&lt;nom&gt; cmd<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.dupont sur WKS-018</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🗂️', title:'ACL & DACL : qui a le droit de faire quoi', html:
      `<p>Chaque objet Active Directory (compte, groupe, machine...) a une <b>liste de contrôle d'accès</b> (ACL) qui définit précisément qui peut le lire, le modifier, ou le supprimer.</p>
       <p>Ces droits peuvent être accordés très finement — pas seulement "admin ou pas admin".</p>` },
    { icon:'🔑', title:'Le droit GenericAll', html:
      `<p><b>GenericAll</b> est l'un des droits les plus puissants qui existent sur un objet AD : il équivaut à un contrôle total, y compris le droit de <b>changer le mot de passe</b> du compte ciblé.</p>
       <p>Un compte avec GenericAll sur un Domain Admin n'a même pas besoin d'être administrateur lui-même pour en devenir un.</p>` },
    { icon:'🩹', title:"L'erreur classique : le droit oublié", html:
      `<p>Ces droits sont souvent accordés <b>temporairement</b> — un dépannage, une délégation ponctuelle — puis jamais retirés. Avec le temps, un domaine accumule des permissions qui n'ont plus aucune raison d'exister.</p>
       <p>Un attaquant qui énumère patiemment ces ACL peut trouver un chemin vers Domain Admin qui ne passe par aucune faille technique — juste par une permission oubliée.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\j.dupont</b>, employé standard. Quelque part dans ce domaine, une permission mal configurée te donne bien plus de pouvoir que ton statut ne le laisse penser.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:'Permission oubliée, contrôle total du domaine.',
  chainSteps:[
    {icon:'🔎', label:'Recon'}, {icon:'🗂️', label:'ACL trouvée'},
    {icon:'🔑', label:'Reset mdp'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{genericall_acl_abuse_domain_admin}',

  graph:{
    nodes:[
      { id:'j.dupont', label:'j.dupont', type:'user' },
      { id:'r.simon', label:'r.simon', type:'user' },
      { id:'h.morel', label:'h.morel', type:'admin' },
      { id:'administrator', label:'administrator', type:'admin' }
    ],
    edges:[
      { id:'e_acl', from:'j.dupont', to:'h.morel', type:'abuse', label:'GenericAll (oublié)' },
      { id:'e_owned', from:'j.dupont', to:'h.morel', type:'owned', label:'Reset + accès' }
    ]
  },

  deepDive:{
    why:"Les ACL Active Directory permettent une délégation très fine des droits — utile, mais dangereuse si elle n'est jamais auditée. Une permission accordée pour une tâche ponctuelle (dépannage, script d'automatisation, prestataire externe) reste active tant que personne ne la retire explicitement, parfois pendant des années.",
    defenses:[
      "Auditer régulièrement les ACL des comptes et groupes sensibles (BloodHound côté défense, ou équivalent)",
      "Appliquer le principe du moindre privilège : accorder des droits temporaires avec expiration automatique",
      "Surveiller les modifications d'ACL sur les objets à privilège (Event ID 5136)",
      "Isoler les comptes à haut privilège dans un modèle de tiering (Tier 0 / 1 / 2)"
    ]
  },

  initState(){ return { newPassword:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.acl;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      Object.keys(sc.identities).forEach(name => print(`<span class="out-dim">  ${name}</span>`));
      AttackGraph.reveal({ nodes:Object.keys(sc.identities) });
      complete('enum');
      return true;
    }

    m = lower.match(/^net user (\S+) \/domain$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){ print(`<span class="out-bad">Utilisateur introuvable : ${name}</span>`); return true; }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      if(u.groups.includes('Domain Admins')){
        print(`<span class="out-warn">⚠ Ce compte est administrateur du domaine — une cible de choix.</span>`);
      }
      complete('enum');
      return true;
    }

    m = lower.match(/^get-objectacl (\S+)$/);
    if(m){
      const name = m[1];
      const entries = sc.acl[name];
      if(!entries){ print(`<span class="out-bad">Objet introuvable : ${escapeHtml(name)}</span>`); return true; }
      print(`<span class="out-info">ACL sur le compte ${name} :</span>`);
      entries.forEach(e => {
        if(e.normal){
          print(`<span class="out-dim">  ${e.principal} — ${e.rights}</span>`);
        } else {
          print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ inhabituel pour ce compte</span>`);
        }
      });
      if(entries.some(e => !e.normal)){
        AttackGraph.reveal({ edges:['e_acl'] });
        complete('acl');
      }
      return true;
    }

    m = lower.match(/^set-domainuserpassword -identity (\S+) -newpassword (\S+)$/);
    if(m){
      const [, name, pwd] = m;
      const entries = sc.acl[name] || [];
      const hasRight = entries.some(e => !e.normal && e.principal.toLowerCase().endsWith(state.user.toLowerCase()));
      if(!hasRight){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits nécessaires sur ce compte.</span>`);
        return true;
      }
      print(`<span class="out-good">Mot de passe de ${name} réinitialisé avec succès.</span>`);
      print(`<span class="out-dim">💡 Aucune alerte de type "mot de passe cassé" ici — c'est une réinitialisation légitime, silencieuse.</span>`);
      state.extra.newPassword = pwd;
      state.extra.resetTarget = name;
      AttackGraph.reveal({ tags:{ [name]:'reset' } });
      complete('reset');
      return true;
    }

    m = lower.match(/^runas \/user:(\S+) cmd$/);
    if(m){
      const name = m[1];
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      if(state.extra.resetTarget !== name || !state.extra.newPassword){
        print(`<span class="out-bad">Mot de passe inconnu pour ce compte.</span>`);
        return true;
      }
      state.user = name;
      updatePrompt();
      print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[name].label}</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(name);
      complete('access');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'h.morel'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\h.morel\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'h.morel'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : énumération → ACL mal configurée (GenericAll) → réinitialisation → Domain Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer régulièrement les ACL des comptes sensibles (BloodHound côté défense), retirer les permissions temporaires oubliées.</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits de lecture sur ce fichier.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};

SCENARIOS.pth = {
  id:'pth',
  tag:'🗝️ SCÉNARIO 02 · PASS-THE-HASH',
  lessonTag:'📘 LEÇON · SCÉNARIO 02',
  opsecEnabled:true,
  noiseRules:[NOISE.mimikatzLogon, NOISE.pth],
  startUser:'j.dupont',

  NTLM_HASH:'8846f7eaee8fb117ad06bdd830b7586c',

  identities:{
    'j.dupont': { label:'WKS-042\\j.dupont', priv:'Utilisateur standard (local)', groups:['Utilisateurs'] },
    'administrator@SRV-FILES01': { label:'SRV-FILES01\\Administrator', priv:'Administrateur local', groups:['Administrateurs'] }
  },

  objectives:[
    { id:'dump',   text:'Dumper les identifiants en cache (mimikatz)' },
    { id:'reuse',  text:'Réutiliser le hash sur un autre serveur' },
    { id:'access', text:'Ouvrir une session sur SRV-FILES01' },
    { id:'flag',   text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant de chercher ailleurs sur le réseau, regarde ce qui est déjà en mémoire sur cette machine.",
     "Un outil connu peut extraire les identifiants en cache sur ce poste — cherche du côté de mimikatz.",
     "Avant de chercher sur le réseau, regarde ce qui traîne en mémoire sur ce poste : `mimikatz sekurlsa::logonpasswords`"],
    ["Le hash NTLM que tu as obtenu appartient à un compte administrateur *local*. Ce genre de compte est souvent partagé entre plusieurs machines.",
     "Ce hash ne sert pas seulement à s'authentifier sur ce poste-ci — il peut aussi ouvrir d'autres portes du réseau.",
     "Tu as un hash NTLM d'un compte Administrateur local. Beaucoup d'entreprises réutilisent le même mot de passe admin local sur toutes leurs machines..."],
    ["Tu as un hash valide et une machine cible identifiée. Inutile de le casser d'abord.",
     "Il existe une commande `pth` qui accepte un hash directement, sans mot de passe en clair.",
     "Utilise ce hash directement, sans le casser, pour ouvrir une session ailleurs : `pth /target:SRV-FILES01 /user:Administrator /hash:<hash>`"],
    ["Tu es maintenant connecté sur SRV-FILES01.",
     "Regarde ce qu'il y a sur son bureau.",
     "Une fois connecté à SRV-FILES01, regarde le bureau avec `dir` puis `type flag.txt`"]
  ],

  manPages:{
    'mimikatz': { name:'mimikatz sekurlsa::logonpasswords', role:'Extrait les identifiants en cache mémoire (LSASS)',
      explain:"Sous Windows, les identifiants de sessions récentes (même administratives) restent un moment en mémoire. Un outil comme Mimikatz peut les en extraire — y compris sous forme de hash NTLM, sans jamais voir le mot de passe en clair.",
      usage:'mimikatz sekurlsa::logonpasswords' },
    'pth': { name:'pth (pass-the-hash)', role:"Authentifie avec un hash NTLM plutôt qu'un mot de passe",
      explain:"Windows accepte le hash NTLM comme preuve d'identité au même titre qu'un mot de passe pour certains protocoles. Pas besoin de le casser : on le réutilise tel quel.",
      usage:'pth /target:<machine> /user:<nom> /hash:<hash>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'mimikatz sekurlsa::logonpasswords','pth /target:','dir','type '
  ],

  helpLine:'whoami /priv, mimikatz sekurlsa::logonpasswords, pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>mimikatz sekurlsa::logonpasswords<br>pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que WKS-042\\j.dupont sur WKS-042</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🖥️', title:'Le mot de passe admin local, ce grand oublié', html:
      `<p>Beaucoup d'entreprises déploient leurs postes avec un <b>même compte administrateur local</b> et le <b>même mot de passe</b> sur toutes les machines, pour simplifier la maintenance.</p>
       <p>Problème : compromettre <b>une seule</b> machine peut suffire à ouvrir toutes les autres.</p>` },
    { icon:'#️⃣', title:'Le hash NTLM', html:
      `<p>Windows ne stocke jamais un mot de passe en clair : il garde un <b>hash NTLM</b>, une empreinte du mot de passe. Pour s'authentifier localement, le système compare des hashs, pas des mots de passe.</p>
       <p>Les identifiants des sessions récentes — y compris administratives — restent un moment <b>en mémoire</b> sur une machine Windows.</p>` },
    { icon:'🔁', title:"L'attaque : Pass-the-Hash", html:
      `<p>Si tu récupères ce hash, tu n'as même pas besoin de le casser : certains protocoles Windows <b>acceptent le hash directement</b> comme preuve d'identité.</p>
       <p>Résultat : si ce même hash correspond au compte admin local d'une autre machine, tu peux t'y connecter <b>sans jamais connaître le mot de passe en clair</b>.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>WKS-042\\j.dupont</b>, sur ton poste de travail. Un technicien support s'est connecté récemment avec un compte administrateur local. Ses identifiants traînent peut-être encore en mémoire...</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Serveur compromis',
  completeSub:'Hash réutilisé, aucun mot de passe cassé.',
  chainSteps:[
    {icon:'🧠', label:'Dump mémoire'}, {icon:'#️⃣', label:'Hash NTLM'},
    {icon:'🔁', label:'Pass-the-Hash'}, {icon:'👑', label:'Flag'}
  ],
  flag:'FLAG{pth_local_admin_reuse}',

  graph:{
    nodes:[
      { id:'j.dupont', label:'j.dupont', type:'user' },
      { id:'WKS-042', label:'WKS-042', type:'computer' },
      { id:'administrator@SRV-FILES01', label:'Administrator (local)', type:'admin' },
      { id:'SRV-FILES01', label:'SRV-FILES01', type:'computer' }
    ],
    edges:[
      { id:'e_hash', from:'WKS-042', to:'administrator@SRV-FILES01', type:'auth', label:'Hash NTLM (mémoire)' },
      { id:'e_pth', from:'administrator@SRV-FILES01', to:'SRV-FILES01', type:'owned', label:'Pass-the-Hash' }
    ]
  },

  deepDive:{
    why:"Certains protocoles d'authentification Windows (NTLM notamment) acceptent le hash lui-même comme preuve d'identité — pas besoin de le casser pour retrouver le mot de passe en clair. Si ce hash est valide sur plusieurs machines à cause d'un mot de passe admin local réutilisé, il ouvre toutes les portes équivalentes.",
    defenses:[
      "Déployer LAPS (Local Administrator Password Solution) : mot de passe admin local unique et changé automatiquement par machine",
      "Désactiver l'authentification NTLM quand c'est possible, au profit de Kerberos uniquement",
      "Limiter le nombre de comptes ayant des droits admin locaux sur plusieurs machines à la fois",
      "Activer Credential Guard pour protéger les hash en mémoire contre l'extraction"
    ]
  },

  initState(){ return { dumpedHash:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.pth;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'mimikatz sekurlsa::logonpasswords'){
      print(`<span class="out-info">Extraction des identifiants en mémoire (LSASS)...</span>`);
      print(`<span class="out-dim">Session trouvée :</span>`);
      print(`<span class="out-warn">  Username : Administrator</span>`);
      print(`<span class="out-warn">  Domain   : WKS-042 (compte local)</span>`);
      print(`<span class="out-warn">  NTLM     : ${sc.NTLM_HASH}</span>`);
      print(`<span class="out-dim">💡 Un technicien support s'est visiblement connecté ici récemment avec ce compte.</span>`);
      state.extra.dumpedHash = sc.NTLM_HASH;
      AttackGraph.reveal({ nodes:['WKS-042','administrator@SRV-FILES01'], edges:['e_hash'], tags:{ 'administrator@SRV-FILES01':'hash' } });
      complete('dump');
      return true;
    }

    m = lower.match(/^pth \/target:(\S+) \/user:(\S+) \/hash:(\S+)$/);
    if(m){
      const [, target, user, hash] = m;
      if(!state.extra.dumpedHash){
        print(`<span class="out-bad">Aucun hash en mémoire. Dump les identifiants locaux d'abord.</span>`);
        return true;
      }
      if(target.toUpperCase() === 'SRV-FILES01' && user.toLowerCase() === 'administrator' && hash === sc.NTLM_HASH.toLowerCase()){
        print(`<span class="out-info">Authentification par hash sur \\\\SRV-FILES01...</span>`);
        print(`<span class="out-good">Accès accordé — le mot de passe admin local est bien réutilisé sur ce serveur.</span>`);
        state.user = 'administrator@SRV-FILES01';
        updatePrompt();
        AttackGraph.reveal({ nodes:['SRV-FILES01'], edges:['e_pth'] });
        AttackGraph.markOwned('administrator@SRV-FILES01');
        complete('reuse');
        complete('access');
      } else if(target.toUpperCase() !== 'SRV-FILES01'){
        print(`<span class="out-bad">Machine injoignable ou inconnue : ${escapeHtml(target)}</span>`);
      } else {
        print(`<span class="out-bad">Authentification refusée : hash ou utilisateur incorrect.</span>`);
      }
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'administrator@SRV-FILES01'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\Administrator\\Desktop (SRV-FILES01)</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\j.dupont\\Desktop (WKS-042)</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici — regarde plutôt ce qui traîne en mémoire)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'administrator@SRV-FILES01'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : dump mémoire → hash NTLM → Pass-the-Hash → accès sans jamais casser de mot de passe.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : mots de passe admin locaux uniques par machine (solution type LAPS), et limiter les connexions admin en cache.</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : tu n'es pas connecté sur la bonne machine avec le bon compte.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};

// ---------------------------------------------------------
// MODE LIBRE — DOMAINE OUVERT, PLUSIEURS CHEMINS VALABLES
// Combine les 3 techniques précédentes. Deux chaînes d'attaque
// distinctes mènent toutes deux à Domain Admin — au joueur de choisir.
// ---------------------------------------------------------
SCENARIOS.libre = {
  id:'libre',
  tag:'🗺️ MODE LIBRE · DOMAINE OUVERT',
  lessonTag:'📘 LEÇON · MODE LIBRE',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.domainUserSpn, NOISE.kerberoast, NOISE.objectAcl, NOISE.resetPassword, NOISE.runas, NOISE.mimikatzLogon, NOISE.pth],
  startUser:'j.reyes',
  // Comptes-rôles génériques (surchargés par DomainGen.regenerateLibre() pour le tirage aléatoire) :
  helpdeskAccount:'t.nguyen',
  comptaAccount:'k.morel',
  daAccount:'p.chevalier',
  companyName:'CORP',
  seed:null,

  identities:{
    'j.reyes':    { label:'CORP\\j.reyes', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — support niveau 1' },
    'svc_web':    { label:'CORP\\svc_web', priv:'Compte de service', groups:['Domain Users'],
                    desc:'Compte de service — application web intranet',
                    spn:'HTTP/intranet.corp.local',
                    hash:'tgs23_svc_web_a1b2c3d4',
                    crackedPassword:'Welcome2024' },
    'svc_sql':    { label:'CORP\\svc_sql', priv:'Compte de service', groups:['Domain Users'],
                    desc:'Compte de service — base SQL de reporting',
                    spn:'MSSQLSvc/sql-report.corp.local:1433',
                    hash:'tgs23_svc_sql_e5f6a7b8',
                    crackedPassword:'P@ssw0rd1' },
    'svc_legacy': { label:'CORP\\svc_legacy', priv:'Compte de service', groups:['Domain Users'],
                    desc:'Compte de service — vieux script de sauvegarde, jamais migré',
                    spn:'HOST/legacy-app.corp.local',
                    hash:'tgs23_svc_legacy_9c0d1e2f',
                    crackedPassword:null },
    't.nguyen':   { label:'CORP\\t.nguyen', priv:'Utilisateur standard', groups:['Domain Users','Helpdesk','Comptabilité'], desc:'Employé — support niveau 2, membre du groupe Helpdesk' },
    'svc_backup': { label:'CORP\\svc_backup', priv:'Compte de service', groups:['Domain Users','Server Admins'],
                    desc:'Compte de service — sauvegardes nocturnes, ajouté par erreur au groupe Server Admins lors d\'une migration',
                    spn:'HOST/backup01.corp.local',
                    hash:'tgs23_svc_backup_3f4a5b6c',
                    crackedPassword:'Backup2023!' },
    'k.morel':    { label:'CORP\\k.morel', priv:'Utilisatrice standard', groups:['Domain Users','Marketing'], desc:'Employée — service marketing, gère les notes de frais' },
    'p.chevalier':{ label:'CORP\\p.chevalier', priv:'Administratrice du domaine', groups:['Domain Users','Domain Admins'], desc:'Directrice technique' }
  },

  NTLM_HASH_CHEVALIER:'c9a1f4b8827de5a0f3c6d19e8b4a2f77',

  // ACL simulées : qui a des droits inhabituels sur quel compte.
  // viaGroup = le droit est accordé à un GROUPE, pas à une personne : il faut être membre pour l'exercer.
  acl:{
    't.nguyen': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\svc_web', rights:'ForceChangePassword', normal:false }
    ],
    'k.morel': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\Comptabilité (groupe)', rights:'GenericAll', normal:false, viaGroup:'Comptabilité' }
    ],
    'p.chevalier': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\Helpdesk (groupe)', rights:'GenericAll', normal:false, viaGroup:'Helpdesk' },
      { principal:'CORP\\Server Admins (groupe)', rights:'ForceChangePassword', normal:false, viaGroup:'Server Admins' }
    ]
  },

  objectives:[
    { id:'enum',     text:'Cartographier les comptes du domaine' },
    { id:'spn',      text:'Repérer les comptes de service exploitables' },
    { id:'foothold', text:'Obtenir un premier accès via un compte de service' },
    { id:'privesc',  text:'Trouver TON chemin jusqu\'à un compte Domain Admin' },
    { id:'flag',     text:'Récupérer le flag' },
  ],

  hints:[
    ["Ce domaine est plus grand que les précédents — commence quand même par voir qui y est.",
     "Une commande liste tous les comptes du domaine d'un coup.",
     "Commence par lister les comptes du domaine : `net user /domain`"],
    ["Plusieurs comptes de service ont un SPN ici — pas qu'un seul.",
     "Liste-les tous d'un coup avec une commande dédiée, plutôt que de les chercher un par un.",
     "Liste tous les comptes vulnérables au Kerberoasting d'un coup : `get-domainuser -spn`"],
    ["Tous les comptes de service n'ont pas forcément un mot de passe faible. Rien ne t'empêche d'en tester plusieurs avant de conclure.",
     "Demande le ticket de chacun avec `invoke-kerberoast`, puis tente de le casser avec `crack`. Au moins un cédera — pas forcément le premier essayé.",
     "Exemple : `invoke-kerberoast -identity svc_web` puis `crack <hash>` — si ça échoue, retente avec un autre compte de service."],
    ["Une fois dans la peau d'un compte de service, deux types de pistes existent en général : des droits oubliés sur d'autres comptes (parfois hérités d'un groupe entier, y compris un groupe où un compte n'a rien à faire), ou des identifiants qui traînent en mémoire sur le serveur où tourne ce service. Il y a plus d'une route valable jusqu'à un Domain Admin ici — et au moins une fausse piste à écarter.",
     "Si tu es sur le compte lié à l'appli web, regarde les droits (`get-objectacl`) sur d'autres comptes — y compris ceux accordés à un groupe entier. Si tu es sur le compte lié à la base SQL, regarde plutôt ce qui traîne en mémoire sur son serveur. Si tu es sur le compte de sauvegarde, regarde directement de quel groupe il est membre.",
     "Trois chemins possibles : (A) `get-objectacl t.nguyen`, réinitialise son mot de passe, connecte-toi, puis regarde ses droits hérités via son groupe sur p.chevalier. (B) en tant que svc_sql, `mimikatz sekurlsa::logonpasswords` puis `pth /target:DC01 /user:p.chevalier /hash:<hash>`. (C) en tant que svc_backup, `get-objectacl p.chevalier` directement — son appartenance erronée à Server Admins suffit. Attention : une ACL alléchante trouvée en chemin peut ne mener nulle part si elle porte sur un compte sans aucun privilège réel."],
    ["Une fois connecté avec les droits d'un compte Domain Admin, peu importe comment tu y es arrivé, la suite est la même.",
     "Regarde ce qu'il y a sur son bureau.",
     "`dir` puis `type flag.txt` une fois que tu es p.chevalier — par n'importe lequel des deux chemins."]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-domainuser': { name:'get-domainuser -spn', role:'Liste les comptes vulnérables au Kerberoasting',
      explain:"Tout compte avec un SPN peut se voir demander un ticket Kerberos par n'importe quel utilisateur authentifié.",
      usage:'get-domainuser -spn' },
    'invoke-kerberoast': { name:'invoke-kerberoast', role:'Demande le ticket Kerberos chiffré d\'un compte de service',
      explain:"Récupère le ticket pour tenter de le casser hors-ligne ensuite.",
      usage:'invoke-kerberoast -identity <nom>' },
    'crack': { name:'crack', role:'Casse un ticket Kerberos hors-ligne',
      explain:"Fonctionne uniquement si le mot de passe du compte est faible. Certains comptes ont un mot de passe suffisamment robuste pour résister — dans ce cas, il faut chercher une autre piste plutôt que d'insister.",
      usage:'crack <hash>' },
    'runas': { name:'runas /user', role:"Ouvre une session avec un autre compte",
      explain:"Nécessite de connaître le mot de passe de ce compte (cassé, ou réinitialisé via une permission).",
      usage:'runas /user:<nom> cmd' },
    'get-objectacl': { name:'get-objectacl', role:"Liste les droits (ACL) accordés sur un compte",
      explain:"Un droit peut être accordé à une personne précise, ou à un <b>groupe</b> entier — auquel cas tout membre de ce groupe peut l'exercer, même sans le savoir.",
      usage:'get-objectacl <nom>' },
    'set-domainuserpassword': { name:'set-domainuserpassword', role:"Réinitialise le mot de passe d'un compte cible",
      explain:"Nécessite un droit suffisant sur le compte cible (direct, ou hérité d'un groupe).",
      usage:'set-domainuserpassword -identity <nom> -newpassword <valeur>' },
    'mimikatz': { name:'mimikatz sekurlsa::logonpasswords', role:'Extrait les identifiants en cache mémoire (LSASS)',
      explain:"Ne révèle quelque chose d'intéressant que si tu es connecté sur la bonne machine — celle où quelqu'un d'important s'est authentifié récemment.",
      usage:'mimikatz sekurlsa::logonpasswords' },
    'pth': { name:'pth (pass-the-hash)', role:"Authentifie avec un hash NTLM plutôt qu'un mot de passe",
      explain:"Réutilise un hash dumpé directement, sans le casser.",
      usage:'pth /target:<machine> /user:<nom> /hash:<hash>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-domainuser -spn',
    'invoke-kerberoast -identity ','crack ','get-objectacl ',
    'set-domainuserpassword -identity ','runas /user:',
    'mimikatz sekurlsa::logonpasswords','pth /target:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-domainuser -spn, invoke-kerberoast -identity &lt;nom&gt;, crack &lt;hash&gt;, get-objectacl &lt;nom&gt;, set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;, runas /user:&lt;nom&gt; cmd, mimikatz sekurlsa::logonpasswords, pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-domainuser -spn<br>invoke-kerberoast -identity &lt;nom&gt;<br>crack &lt;hash&gt;<br>get-objectacl &lt;nom&gt;<br>set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;<br>runas /user:&lt;nom&gt; cmd<br>mimikatz sekurlsa::logonpasswords<br>pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.reyes sur WKS-101</span>`,
    `<span class="out-warn">⚠ Domaine plus étendu que les scénarios précédents — plusieurs comptes de service, plusieurs chemins possibles.</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🗺️', title:"Un domaine, plusieurs portes d'entrée", html:
      `<p>Dans un vrai domaine Active Directory, il n'existe presque jamais <b>une seule</b> chaîne d'attaque possible. Plusieurs comptes mal configurés coexistent, et plusieurs routes différentes peuvent mener au même trône.</p>
       <p>C'est justement pour ça que des outils comme <b>BloodHound</b> existent côté attaque — et côté défense : cartographier <i>tous</i> les chemins, pas juste le plus évident.</p>` },
    { icon:'🧭', title:'Les mêmes techniques, en combinaison libre', html:
      `<p>Tu connais déjà le <b>Kerberoasting</b>, le <b>Pass-the-Hash</b> et l'abus d'<b>ACL</b>. Ici, rien ne t'impose l'ordre ni la combinaison : à toi de reconnaître quelle technique s'applique à quel compte.</p>
       <p>Certaines pistes ne mèneront nulle part — un mot de passe robuste peut très bien résister au crack. Ce n'est pas un bug, c'est le jeu : il faut savoir pivoter.</p>` },
    { icon:'🕸️', title:'Lire les indices, pas juste exécuter des commandes', html:
      `<p>Prends le temps d'énumérer largement avant de foncer sur le premier compte trouvé. Les descriptions de comptes, les groupes, les ACL — tout est une piste potentielle.</p>
       <p>Toutes les pistes ne se valent pas : un droit "GenericAll" sur un compte peut sembler énorme, mais si ce compte n'a lui-même aucun privilège particulier, ça ne mène nulle part. Vérifie toujours ce que la cible peut faire avant d'investir du temps dessus.</p>
       <p class="lesson-tip">💡 Cette fois, les indices restent volontairement vagues sur QUEL chemin suivre — ils t'aident à avancer, pas à choisir à ta place.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\j.reyes</b>, employé standard sur le domaine <b>CORP.LOCAL</b>. Quelque part dans ce domaine plus vaste, plusieurs chemins mènent à un compte Domain Admin. Trouve le tien.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domaine compromis — à ta façon',
  completeSub:'Chemin d\'attaque personnel jusqu\'à Domain Admin.',
  chainSteps:[
    {icon:'🔎', label:'Recon'}, {icon:'🎫', label:'Compte cassé'},
    {icon:'🧭', label:'Ton chemin'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{libre_multi_path_domain_admin}',

  // Carte d'attaque : trois chemins distincts vers p.chevalier coexistent.
  // Un seul sera mis en évidence en "chemin emprunté" (owned), selon le choix du joueur.
  graph:{
    nodes:[
      { id:'j.reyes', label:'j.reyes', type:'user' },
      { id:'svc_web', label:'svc_web', type:'service' },
      { id:'svc_sql', label:'svc_sql', type:'service' },
      { id:'svc_legacy', label:'svc_legacy', type:'service' },
      { id:'t.nguyen', label:'t.nguyen', type:'user' },
      { id:'svc_backup', label:'svc_backup', type:'service' },
      { id:'k.morel', label:'k.morel', type:'user' },
      { id:'p.chevalier', label:'p.chevalier', type:'admin' },
      { id:'grp_helpdesk', label:'Helpdesk', type:'group' },
      { id:'grp_compta', label:'Comptabilité', type:'group' },
      { id:'grp_serveradmins', label:'Server Admins', type:'group' }
    ],
    edges:[
      { id:'mo_tnguyen', from:'t.nguyen', to:'grp_helpdesk', type:'memberof', label:'MemberOf' },
      { id:'mo_kmorel', from:'k.morel', to:'grp_compta', type:'memberof', label:'MemberOf' },
      { id:'mo_backup', from:'svc_backup', to:'grp_serveradmins', type:'memberof', label:'MemberOf (erreur)' },
      { id:'acl_web_tnguyen', from:'svc_web', to:'t.nguyen', type:'abuse', label:'ForceChangePassword' },
      { id:'acl_compta_kmorel', from:'grp_compta', to:'k.morel', type:'abuse', label:'GenericAll (impasse)' },
      { id:'acl_helpdesk_chevalier', from:'grp_helpdesk', to:'p.chevalier', type:'abuse', label:'GenericAll' },
      { id:'acl_serveradmins_chevalier', from:'grp_serveradmins', to:'p.chevalier', type:'abuse', label:'ForceChangePassword' },
      { id:'hash_sql_chevalier', from:'svc_sql', to:'p.chevalier', type:'auth', label:'Hash en mémoire' },
      { id:'owned_pth', from:'svc_sql', to:'p.chevalier', type:'owned', label:'Chemin emprunté (Pass-the-Hash)' },
      { id:'owned_helpdesk', from:'grp_helpdesk', to:'p.chevalier', type:'owned', label:'Chemin emprunté (Helpdesk)' },
      { id:'owned_serveradmins', from:'grp_serveradmins', to:'p.chevalier', type:'owned', label:'Chemin emprunté (Server Admins)' }
    ]
  },
  // Comptes -> {node de groupe, arête MemberOf} à révéler quand `net user <nom> /domain` affiche ce compte.
  graphMemberOf:{
    't.nguyen':   { node:'grp_helpdesk',     edge:'mo_tnguyen' },
    'k.morel':    { node:'grp_compta',       edge:'mo_kmorel' },
    'svc_backup': { node:'grp_serveradmins', edge:'mo_backup' }
  },
  // Cible ACL -> arêtes à révéler quand `get-objectacl <cible>` montre une entrée inhabituelle.
  graphAclEdges:{
    't.nguyen':    { nodes:[], edges:['acl_web_tnguyen'] },
    'k.morel':     { nodes:['grp_compta'], edges:['acl_compta_kmorel'] },
    'p.chevalier': { nodes:['grp_helpdesk','grp_serveradmins'], edges:['acl_helpdesk_chevalier','acl_serveradmins_chevalier'] }
  },

  deepDive:{
    why:"Un domaine Active Directory réel accumule des dizaines de chemins d'attaque potentiels : comptes de service oubliés, ACL déléguées puis jamais nettoyées, mots de passe locaux réutilisés. Bloquer un seul de ces chemins ne suffit presque jamais — un attaquant patient en trouve un autre.",
    defenses:[
      "Cartographier tous les chemins d'attaque vers les comptes à privilège (BloodHound côté défense), pas seulement les plus évidents",
      "Réduire le nombre de comptes de service et de délégations ACL au strict nécessaire (moindre privilège)",
      "Isoler les comptes à haut privilège dans un modèle de tiering, pour qu'un compte compromis en tier bas ne remonte jamais jusqu'en tier 0",
      "Auditer régulièrement, pas une fois pour toutes : un chemin bloqué aujourd'hui peut être recréé demain par une nouvelle délégation"
    ]
  },

  initState(){ return { crackedPasswords:{}, knownPasswords:{}, dumpedHash:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.libre;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      Object.keys(sc.identities).forEach(name => print(`<span class="out-dim">  ${name}</span>`));
      AttackGraph.reveal({ nodes:Object.keys(sc.identities) });
      complete('enum');
      return true;
    }

    m = lower.match(/^net user (\S+) \/domain$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){ print(`<span class="out-bad">Utilisateur introuvable : ${name}</span>`); return true; }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      if(u.spn){
        print(`<span class="out-warn">ServicePrincipalName : ${u.spn}</span>`);
        print(`<span class="out-warn">⚠ Ce compte possède un SPN : potentiellement vulnérable au Kerberoasting.</span>`);
        AttackGraph.reveal({ tags:{ [name]:'spn' } });
        complete('spn');
      }
      if(u.groups.includes('Domain Admins')){
        print(`<span class="out-warn">⚠ Ce compte est administrateur du domaine — une cible de choix.</span>`);
      }
      const mo = sc.graphMemberOf[name];
      if(mo) AttackGraph.reveal({ nodes:[mo.node], edges:[mo.edge] });
      complete('enum');
      return true;
    }

    if(lower === 'get-domainuser -spn' || lower === 'getdomainuser -spn'){
      print(`<span class="out-info">Comptes avec un SPN (Kerberoastables) :</span>`);
      let found = false;
      const spnTags = {};
      Object.entries(sc.identities).forEach(([name,u])=>{
        if(u.spn){ print(`<span class="out-warn">  ${name}  —  ${u.spn}</span>`); found = true; spnTags[name] = 'spn'; }
      });
      if(!found) print(`<span class="out-dim">  (aucun)</span>`);
      AttackGraph.reveal({ tags:spnTags });
      complete('spn');
      return true;
    }

    m = lower.match(/^invoke-kerberoast -identity (\S+)$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u || !u.spn){ print(`<span class="out-bad">Aucun ticket Kerberos disponible pour ce compte.</span>`); return true; }
      print(`<span class="out-info">Ticket TGS demandé pour ${name}...</span>`);
      print(`<span class="out-good">Ticket obtenu :</span>`);
      print(`<span class="out-dim">${u.hash}</span>`);
      return true;
    }

    m = lower.match(/^crack (.+)$/) || lower.match(/^hashcat (.+)$/);
    if(m){
      const token = m[1].trim().toLowerCase();
      const name = Object.keys(sc.identities).find(id => sc.identities[id].hash && sc.identities[id].hash.toLowerCase() === token);
      if(!name){ print(`<span class="out-bad">Hash inconnu. Récupère d'abord un ticket avec invoke-kerberoast.</span>`); return true; }
      const u = sc.identities[name];
      if(!u.crackedPassword){
        print(`<span class="out-info">Tentative de crack du ticket de ${name} (dictionnaire)...</span>`);
        print(`<span class="out-bad">Échec — mot de passe trop robuste pour ce dictionnaire.</span>`);
        print(`<span class="out-dim">💡 Ce compte ne cédera pas comme ça. Une autre piste existe ailleurs.</span>`);
        return true;
      }
      print(`<span class="out-info">Tentative de crack du ticket de ${name} (dictionnaire)...</span>`);
      print(`<span class="out-good">Mot de passe trouvé : ${u.crackedPassword}</span>`);
      state.extra.knownPasswords[name] = u.crackedPassword;
      AttackGraph.reveal({ tags:{ [name]:'cracked' } });
      complete('foothold');
      return true;
    }

    m = lower.match(/^get-objectacl (\S+)$/);
    if(m){
      const name = m[1];
      const entries = sc.acl[name];
      if(!entries){ print(`<span class="out-bad">Objet introuvable ou sans ACL notable : ${escapeHtml(name)}</span>`); return true; }
      print(`<span class="out-info">ACL sur le compte ${name} :</span>`);
      entries.forEach(e => {
        if(e.normal){
          print(`<span class="out-dim">  ${e.principal} — ${e.rights}</span>`);
        } else {
          print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ inhabituel pour ce compte</span>`);
        }
      });
      const reveal = sc.graphAclEdges[name];
      if(reveal) AttackGraph.reveal(reveal);
      return true;
    }

    m = lower.match(/^set-domainuserpassword -identity (\S+) -newpassword (\S+)$/);
    if(m){
      const [, name, pwd] = m;
      const entries = sc.acl[name] || [];
      const myGroups = sc.identities[state.user] ? sc.identities[state.user].groups : [];
      const matched = entries.find(e => {
        if(e.normal) return false;
        if(e.viaGroup) return myGroups.includes(e.viaGroup);
        return e.principal.toLowerCase().includes(state.user.toLowerCase());
      });
      if(!matched){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits nécessaires sur ce compte.</span>`);
        return true;
      }
      print(`<span class="out-good">Mot de passe de ${name} réinitialisé avec succès.</span>`);
      state.extra.knownPasswords[name] = pwd;
      if(name === 'p.chevalier') state.extra.privescRoute = matched.viaGroup || matched.principal;
      AttackGraph.reveal({ tags:{ [name]:'reset' } });
      return true;
    }

    if(lower === 'mimikatz sekurlsa::logonpasswords'){
      if(state.user !== 'svc_sql'){
        print(`<span class="out-dim">Rien d'exploitable en mémoire ici.</span>`);
        return true;
      }
      print(`<span class="out-info">Extraction des identifiants en mémoire (LSASS) sur SRV-REPORT01...</span>`);
      print(`<span class="out-dim">Session trouvée :</span>`);
      print(`<span class="out-warn">  Username : ${sc.daAccount}</span>`);
      print(`<span class="out-warn">  Domain   : ${sc.companyName} (compte de domaine)</span>`);
      print(`<span class="out-warn">  NTLM     : ${sc.NTLM_HASH_CHEVALIER}</span>`);
      print(`<span class="out-dim">💡 La direction technique s'est visiblement connectée ici récemment pour consulter un rapport.</span>`);
      state.extra.dumpedHash = sc.NTLM_HASH_CHEVALIER;
      AttackGraph.reveal({ edges:['hash_sql_chevalier'], tags:{ [sc.daAccount]:'hash' } });
      return true;
    }

    m = lower.match(/^pth \/target:(\S+) \/user:(\S+) \/hash:(\S+)$/);
    if(m){
      const [, target, user, hash] = m;
      if(!state.extra.dumpedHash){
        print(`<span class="out-bad">Aucun hash en mémoire. Dump les identifiants locaux d'abord.</span>`);
        return true;
      }
      if(hash.toLowerCase() !== state.extra.dumpedHash.toLowerCase()){
        print(`<span class="out-bad">Hash invalide.</span>`);
        return true;
      }
      if(user.toLowerCase() !== sc.daAccount.toLowerCase() || target.toLowerCase() !== 'dc01'){
        print(`<span class="out-bad">Cible ou compte incorrect pour ce hash.</span>`);
        return true;
      }
      print(`<span class="out-good">Authentification par hash réussie sur DC01.</span>`);
      state.user = sc.daAccount;
      state.extra.pathTaken = 'pth';
      updatePrompt();
      print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[sc.daAccount].label}</span>`);
      AttackGraph.reveal({ edges:['owned_pth'] });
      AttackGraph.markOwned(sc.daAccount);
      complete('privesc');
      return true;
    }

    m = lower.match(/^runas \/user:(\S+) cmd$/);
    if(m){
      const name = m[1];
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      if(!state.extra.knownPasswords[name]){
        print(`<span class="out-bad">Mot de passe inconnu pour ce compte.</span>`);
        return true;
      }
      state.user = name;
      updatePrompt();
      print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[name].label}</span>`);
      AttackGraph.markOwned(name);
      if(name === 'svc_web' || name === 'svc_sql' || name === 'svc_backup'){
        complete('foothold');
      }
      if(name === sc.daAccount){
        state.extra.pathTaken = state.extra.privescRoute === 'Server Admins' ? 'acl-serveradmins' : 'acl-helpdesk';
        AttackGraph.reveal({ edges:[state.extra.pathTaken === 'acl-serveradmins' ? 'owned_serveradmins' : 'owned_helpdesk'] });
        AttackGraph.markOwned(sc.daAccount);
        complete('privesc');
      }
      return true;
    }

    if(lower === 'dir'){
      if(state.user === sc.daAccount){
        print(`<span class="out-info"> Répertoire : C:\\Users\\${sc.daAccount}\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else if(state.user === sc.startUser){
        print(`<span class="out-info"> Répertoire : C:\\Users\\${sc.startUser}\\Desktop</span>`);
        print(`<span class="out-dim">  notes.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === sc.daAccount){
        const routes = {
          pth: {
            via:`chaîne B : svc_sql → hash en mémoire → Pass-the-Hash direct sur ${sc.daAccount}.`,
            chain:[{icon:'🔎',label:'Recon'},{icon:'🎫',label:'svc_sql cassé'},{icon:'🧠',label:'Hash en mémoire'},{icon:'🔁',label:'Pass-the-Hash'},{icon:'👑',label:'Domain Admin'}]
          },
          'acl-helpdesk': {
            via:`chaîne A : svc_web → ACL oubliée sur ${sc.helpdeskAccount} → droit hérité du groupe Helpdesk sur ${sc.daAccount}.`,
            chain:[{icon:'🔎',label:'Recon'},{icon:'🎫',label:'svc_web cassé'},{icon:'🗂️',label:'ACL héritée'},{icon:'🔑',label:'Reset mdp'},{icon:'👑',label:'Domain Admin'}]
          },
          'acl-serveradmins': {
            via:`chaîne C : svc_backup → ajouté par erreur au groupe Server Admins → droit hérité direct sur ${sc.daAccount}.`,
            chain:[{icon:'🔎',label:'Recon'},{icon:'🎫',label:'svc_backup cassé'},{icon:'🗂️',label:'Groupe mal attribué'},{icon:'🔑',label:'Reset mdp'},{icon:'👑',label:'Domain Admin'}]
          }
        };
        const route = routes[state.extra.pathTaken] || routes['acl-helpdesk'];
        sc.chainSteps = route.chain;
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — tu es arrivé par la ${route.via}</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : cartographier tous les chemins d'attaque possibles, pas seulement le plus évident (voir "En savoir plus").</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : ton compte (${state.user}) n'a pas les droits de lecture sur ce fichier.</span>`);
      } else if(file.toLowerCase() === 'notes.txt' && state.user === sc.startUser){
        print(`<span class="out-dim">"Ticket ouvert : migrer svc_legacy, mot de passe trop ancien à changer un jour. La webapp et le reporting SQL tournent encore avec les mêmes comptes de service depuis 3 ans..." — note du service IT</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};

// ---------------------------------------------------------
// SCÉNARIO 04 — CLOUD AD (ENTRA ID) : APPLICATION ADMINISTRATOR → GLOBAL ADMINISTRATOR
// ---------------------------------------------------------
SCENARIOS.azuread = {
  id:'azuread',
  tag:'☁️ SCÉNARIO 04 · CLOUD AD (ENTRA ID)',
  lessonTag:'📘 LEÇON · SCÉNARIO 04',
  opsecEnabled:true,
  noiseRules:[NOISE.mgAppAll, NOISE.mgAppOne, NOISE.mgRoleMembers, NOISE.connectMgraph, NOISE.addCredential],
  startUser:'t.rousseau',

  APPS:{
    'legacy-reporting-app': { clientId:'a1e29d3c-71f2-4a8b-9c3d-1a2b3c4d5e6f', owner:'IT Ops',
      desc:"Application de reporting interne (dépréciée, migration jamais terminée)" },
    'automation-sync': { clientId:'f9c47b2e-5a6d-4b91-8d4e-6f5e4d3c2b1a', owner:'IT Ops',
      desc:"Synchronisation d'annuaire automatisée (tâche planifiée nocturne)" },
    'portal-frontend': { clientId:'b3d58e41-9c2f-4c7a-9e5f-0a1b2c3d4e5f', owner:'Dev Web',
      desc:'Frontend du portail interne employés' }
  },
  LEGACY_SECRET:'Az$LegacyPipe_2024!',
  GRANTED_SECRET:'GT-Adm1n-Cr3d-9f2a',

  identities:{
    't.rousseau':          { label:'corp.onmicrosoft.com\\t.rousseau', priv:'Utilisateur standard (Membre)', groups:['Users'] },
    'sp-legacy-reporting':  { label:'SP\\legacy-reporting-app', priv:'Service Principal — rôle Application Administrator', groups:['Application Administrator'] },
    'sp-automation-sync':   { label:'SP\\automation-sync', priv:'Service Principal — rôle Global Administrator', groups:['Global Administrator'] }
  },

  objectives:[
    { id:'enum',    text:"Énumérer les App Registrations du tenant" },
    { id:'leak',    text:'Trouver un secret client exposé dans un pipeline CI/CD' },
    { id:'auth',    text:"S'authentifier en tant que ce Service Principal" },
    { id:'privesc', text:"Abuser du rôle Application Administrator pour viser une app plus privilégiée" },
    { id:'auth2',   text:"S'authentifier en tant que l'app disposant du rôle Global Administrator" },
    { id:'flag',    text:'Récupérer le secret réservé aux Global Admins' },
  ],

  hints:[
    ["Tu es un simple utilisateur du tenant, mais certaines informations restent lisibles par tout le monde — comme la liste des applications.",
     "Il existe une commande pour lister toutes les App Registrations du tenant — cherche du côté de `get-mgapp`.",
     "Liste les App Registrations du tenant avec `get-mgapp -all`, puis regarde le détail de chacune avec `get-mgapp <nom>`."],
    ["Une des applications est décrite comme dépréciée. Les vieux systèmes laissent souvent des restes derrière eux — comme un partage de fichiers DevOps oublié.",
     "Regarde ce que contient ce partage avec `dir`, puis lis les fichiers qui s'y trouvent.",
     "Regarde le partage DevOps avec `dir`, puis lis `type azure-pipelines.yml` — un secret client y traîne en clair."],
    ["Tu as maintenant un identifiant d'application (clientId) et un secret en clair. Une App Registration, ça s'authentifie comme n'importe quel compte.",
     "Il existe une commande pour se connecter en tant que Service Principal avec un appId et un secret.",
     "Authentifie-toi avec `connect-mgraph -appid <clientId> -secret <secret>`, en utilisant ce que tu as trouvé dans le pipeline."],
    ["Regarde d'abord quel rôle d'annuaire est attribué à ce compte de service avec `whoami /priv` — il n'est peut-être pas anodin.",
     "Le rôle Application Administrator permet d'ajouter un identifiant à n'importe quelle application du tenant, même les plus privilégiées. Reste à savoir laquelle viser — regarde qui détient le rôle Global Administrator.",
     "Regarde les membres du rôle Global Administrator avec `get-mgrolemembers -role globaladmin`, puis ajoute-toi un identifiant sur l'app trouvée avec `add-credential -target automation-sync`."],
    ["Le nouvel identifiant que tu viens d'obtenir n'est pas pour ton propre compte.",
     "Reconnecte-toi en tant que Service Principal, mais avec le nouvel appId et le nouveau secret cette fois.",
     "`connect-mgraph -appid f9c47b2e-5a6d-4b91-8d4e-6f5e4d3c2b1a -secret GT-Adm1n-Cr3d-9f2a`"],
    ["Ce compte a maintenant les pleins pouvoirs sur l'annuaire. Regarde ce qu'il peut lire de sensible.",
     "Un coffre de secrets t'est peut-être accessible maintenant. Regarde autour de toi.",
     "Regarde le coffre avec `dir` puis `type flag.txt`."]
  ],

  manPages:{
    'get-mgapp': { name:'get-mgapp', role:'Interroge les App Registrations du tenant Entra ID',
      explain:"Sans argument après -all, liste toutes les applications enregistrées dans le tenant (lecture souvent accessible à tout utilisateur standard). Avec un nom d'app, affiche son détail.",
      usage:'get-mgapp -all   |   get-mgapp <nom>' },
    'connect-mgraph': { name:'connect-mgraph', role:'Authentifie une session en tant que Service Principal',
      explain:"Une App Registration s'authentifie auprès de Microsoft Graph avec un identifiant d'application (appId) et un secret client — au même titre qu'un compte utilisateur avec un mot de passe.",
      usage:'connect-mgraph -appid <clientId> -secret <secret>' },
    'get-mgrolemembers': { name:'get-mgrolemembers', role:"Liste les membres d'un rôle d'annuaire Entra ID",
      explain:"Les rôles d'annuaire (Global Administrator, Application Administrator...) peuvent être attribués à des utilisateurs comme à des Service Principals. Attribuer un rôle très privilégié à un compte d'automatisation est une pratique risquée mais fréquente.",
      usage:'get-mgrolemembers -role <nom>' },
    'add-credential': { name:'add-credential', role:"Ajoute un secret client à une application existante",
      explain:"Le rôle Application Administrator permet de gérer les identifiants (secrets, certificats) de la plupart des applications du tenant — y compris celles qui disposent elles-mêmes de rôles plus privilégiés. C'est le cœur de cette élévation de privilèges.",
      usage:'add-credential -target <nom_app>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'get-mgapp -all','get-mgapp ','get-mgrolemembers -role globaladmin',
    'connect-mgraph -appid ','add-credential -target ','dir','type '
  ],

  helpLine:'whoami /priv, get-mgapp -all, get-mgapp &lt;nom&gt;, get-mgrolemembers -role &lt;nom&gt;, connect-mgraph -appid &lt;id&gt; -secret &lt;secret&gt;, add-credential -target &lt;nom_app&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>get-mgapp -all<br>get-mgapp &lt;nom&gt;<br>get-mgrolemembers -role &lt;nom&gt;<br>connect-mgraph -appid &lt;id&gt; -secret &lt;secret&gt;<br>add-credential -target &lt;nom_app&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Azure Cloud Shell [Simulation Entra ID Lab]</span>`,
    `<span class="out-dim">Connecté en tant que t.rousseau@corp.onmicrosoft.com</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'☁️', title:"Entra ID : l'annuaire dans le cloud", html:
      `<p>CORP a migré son annuaire vers <b>Entra ID</b> (l'ex-Azure AD), le tenant cloud de Microsoft. Les utilisateurs et les machines existent toujours, mais les applications aussi ont désormais une identité : l'<b>App Registration</b>, représentée par un <b>Service Principal</b>.</p>
       <p>Comme sur site, l'objectif d'un attaquant reste le même : remonter depuis un compte à faibles privilèges jusqu'au compte aux pleins pouvoirs — ici, le rôle <b>Global Administrator</b>.</p>` },
    { icon:'🔑', title:'App Registrations & secrets clients', html:
      `<p>Une application s'authentifie auprès de Microsoft Graph avec un <b>clientId</b> et un <b>secret</b> — l'équivalent d'un identifiant et d'un mot de passe. Ce secret est souvent stocké dans des <b>pipelines CI/CD</b>, et parfois oublié en clair après un projet abandonné.</p>
       <p>Contrairement à un utilisateur, une application n'a ni MFA ni comportement suspect à surveiller : un secret volé s'utilise directement.</p>` },
    { icon:'🪜', title:"L'attaque : Application Administrator → Global Administrator", html:
      `<p>Le rôle <b>Application Administrator</b> permet de gérer les identifiants de la plupart des applications du tenant — <b>y compris celles qui ont elles-mêmes des rôles plus puissants</b>. Ajouter un secret à une telle application, c'est en devenir l'équivalent.</p>
       <p>Un piège classique : attribuer le rôle <b>Global Administrator</b> directement à un compte d'automatisation "pour simplifier", en pensant qu'un Service Principal ne se fait pas voler ses identifiants. C'est exactement ce qui s'est passé ici.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>t.rousseau</b>, employé standard sur le tenant <b>corp.onmicrosoft.com</b>. Trouve une application vulnérable, obtiens ses identifiants, et vois jusqu'où son rôle d'annuaire te mène.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Tenant Entra ID compromis',
  completeSub:"Secret d'application fuité, rôle Application Administrator abusé jusqu'au Global Admin.",
  chainSteps:[
    {icon:'🔎', label:'Enum apps'}, {icon:'📄', label:'Secret fuité'},
    {icon:'🔑', label:'Auth SP'}, {icon:'🪜', label:'App Admin → Global Admin'}, {icon:'☁️', label:'Flag'}
  ],
  flag:'FLAG{entra_appadmin_privesc_globaladmin}',

  graph:{
    nodes:[
      { id:'t.rousseau', label:'t.rousseau', type:'user' },
      { id:'sp-legacy-reporting', label:'legacy-reporting-app', type:'app' },
      { id:'sp-automation-sync', label:'automation-sync', type:'app' },
      { id:'portal-frontend', label:'portal-frontend', type:'app' },
      { id:'role_globaladmin', label:'Global Administrator', type:'group' }
    ],
    edges:[
      { id:'e_leak', from:'t.rousseau', to:'sp-legacy-reporting', type:'auth', label:'Secret CI/CD fuité' },
      { id:'e_role', from:'role_globaladmin', to:'sp-automation-sync', type:'memberof', label:'Rôle attribué (sans MFA)' },
      { id:'e_privesc', from:'sp-legacy-reporting', to:'sp-automation-sync', type:'abuse', label:'AddCredential (App Admin)' }
    ]
  },

  deepDive:{
    why:"Le rôle Application Administrator est conçu pour administrer les applications du tenant, ce qui inclut la gestion de leurs identifiants (secrets, certificats). Rien n'empêche par conception d'ajouter un identifiant à une application qui dispose elle-même d'un rôle plus privilégié : le titulaire du rôle Application Administrator peut donc emprunter l'identité de n'importe quelle application moins protégée. Le vrai problème ici est l'attribution du rôle Global Administrator directement à un Service Principal d'automatisation, sans protection particulière.",
    defenses:[
      "Ne jamais attribuer un rôle d'annuaire très privilégié (Global Administrator) directement à un Service Principal ou un compte d'automatisation",
      "Restreindre l'attribution du rôle Application Administrator (lui-même sensible) aux seules personnes qui en ont réellement besoin",
      "Protéger les applications sensibles avec des groupes à assignation de rôle protégée (Restricted Management Administrative Units / Role-Assignable Groups)",
      "Bannir les secrets en clair dans les pipelines CI/CD : privilégier Key Vault, l'identité managée (Managed Identity), ou l'authentification par certificat",
      "Activer Privileged Identity Management (PIM) pour rendre les rôles privilégiés temporaires, justifiés et audités plutôt que permanents"
    ]
  },

  initState(){ return { grantedSecret:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.azuread;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Identité : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Rôles d'annuaire : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'get-mgapp -all'){
      print(`<span class="out-info">App Registrations du tenant corp.onmicrosoft.com :</span>`);
      Object.keys(sc.APPS).forEach(name => {
        const a = sc.APPS[name];
        print(`<span class="out-dim">  ${name} — clientId: ${a.clientId} — propriétaire: ${a.owner}</span>`);
      });
      AttackGraph.reveal({ nodes:['sp-legacy-reporting','sp-automation-sync','portal-frontend'] });
      complete('enum');
      return true;
    }

    m = cmd.match(/^get-mgapp (\S+)$/i);
    if(m){
      const name = m[1].toLowerCase();
      const app = sc.APPS[name];
      if(!app){ print(`<span class="out-bad">Application introuvable : ${escapeHtml(m[1])}</span>`); return true; }
      print(`<span class="out-info"><b>${name}</b></span>`);
      print(`<span class="out-dim">clientId : ${app.clientId}</span>`);
      print(`<span class="out-dim">Propriétaire : ${app.owner}</span>`);
      print(`<span class="out-dim">Description : ${app.desc}</span>`);
      if(name === 'legacy-reporting-app'){
        print(`<span class="out-warn">🔎 Note : ce compte de service est référencé dans un ancien pipeline de déploiement CI/CD, jamais nettoyé après la dépréciation de l'appli.</span>`);
      }
      return true;
    }

    if(lower === 'get-mgrolemembers -role globaladmin'){
      print(`<span class="out-info">Membres du rôle Global Administrator :</span>`);
      print(`<span class="out-dim">  a.moreau — Utilisateur, Directrice IT (MFA activée)</span>`);
      print(`<span class="out-warn">  automation-sync — Service Principal (rôle attribué directement, sans MFA ni surveillance particulière)</span>`);
      print(`<span class="out-dim">💡 Un compte humain avec MFA est une cible difficile. Le Service Principal, beaucoup moins.</span>`);
      AttackGraph.reveal({ nodes:['role_globaladmin'], edges:['e_role'] });
      return true;
    }

    m = cmd.match(/^connect-mgraph -appid (\S+) -secret (\S+)$/i);
    if(m){
      const [, appid, secret] = m;
      if(appid.toLowerCase() === sc.APPS['legacy-reporting-app'].clientId.toLowerCase() && secret === sc.LEGACY_SECRET){
        print(`<span class="out-info">Authentification auprès de Microsoft Graph...</span>`);
        print(`<span class="out-good">Accès accordé — connecté en tant que Service Principal legacy-reporting-app.</span>`);
        state.user = 'sp-legacy-reporting';
        updatePrompt();
        AttackGraph.reveal({ edges:['e_leak'] });
        AttackGraph.markOwned('sp-legacy-reporting');
        complete('auth');
      } else if(state.extra.grantedSecret && appid.toLowerCase() === sc.APPS['automation-sync'].clientId.toLowerCase() && secret === state.extra.grantedSecret){
        print(`<span class="out-info">Authentification auprès de Microsoft Graph...</span>`);
        print(`<span class="out-good">Accès accordé — connecté en tant que Service Principal automation-sync.</span>`);
        state.user = 'sp-automation-sync';
        updatePrompt();
        AttackGraph.markOwned('sp-automation-sync');
        complete('auth2');
      } else {
        print(`<span class="out-bad">Authentification refusée : appId ou secret invalide.</span>`);
      }
      return true;
    }

    m = cmd.match(/^add-credential -target (\S+)$/i);
    if(m){
      const target = m[1].toLowerCase();
      if(state.user !== 'sp-legacy-reporting'){
        print(`<span class="out-bad">Accès refusé : ton compte actuel n'a pas le rôle Application Administrator.</span>`);
        return true;
      }
      if(!sc.APPS[target]){
        print(`<span class="out-bad">Application introuvable : ${escapeHtml(m[1])}</span>`);
        return true;
      }
      if(target === 'automation-sync'){
        state.extra.grantedSecret = sc.GRANTED_SECRET;
        print(`<span class="out-good">Nouveau secret client ajouté à automation-sync.</span>`);
        print(`<span class="out-warn">  clientId : ${sc.APPS['automation-sync'].clientId}</span>`);
        print(`<span class="out-warn">  secret   : ${sc.GRANTED_SECRET}</span>`);
        AttackGraph.reveal({ edges:['e_privesc'] });
        complete('privesc');
      } else {
        print(`<span class="out-info">Identifiant ajouté, mais cette application n'a aucun rôle d'annuaire privilégié — impasse.</span>`);
      }
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 't.rousseau'){
        print(`<span class="out-info"> Partage réseau : \\\\SHARE-DEVOPS01\\Pipelines</span>`);
        print(`<span class="out-dim">  azure-pipelines.yml</span>`);
        print(`<span class="out-dim">  README.md</span>`);
      } else if(state.user === 'sp-automation-sync'){
        print(`<span class="out-info"> Coffre de secrets : kv-corp-secrets</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-dim">(rien d'exploitable ici avec ce compte)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'azure-pipelines.yml' && state.user === 't.rousseau'){
        print(`<span class="out-dim">steps:</span>`);
        print(`<span class="out-dim">  - task: AzureCLI@2</span>`);
        print(`<span class="out-dim">    inputs:</span>`);
        print(`<span class="out-dim">      # TODO: migrer vers un Service Connection propre — Jean, 2022</span>`);
        print(`<span class="out-warn">      clientId: '${sc.APPS['legacy-reporting-app'].clientId}'</span>`);
        print(`<span class="out-warn">      clientSecret: '${sc.LEGACY_SECRET}'</span>`);
        AttackGraph.reveal({ tags:{ 'sp-legacy-reporting':'leak' } });
        complete('leak');
      } else if(file.toLowerCase() === 'readme.md' && state.user === 't.rousseau'){
        print(`<span class="out-dim">"Pipeline hérité de l'ancienne stack de reporting. Ne pas toucher sans prévenir l'équipe Legacy." — README du dépôt</span>`);
      } else if(file.toLowerCase() === 'flag.txt' && state.user === 'sp-automation-sync'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : secret fuité → Application Administrator → identifiant ajouté à un Service Principal Global Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : jamais de rôle privilégié direct sur un compte d'automatisation, et surveillance des rôles sensibles via PIM (voir "En savoir plus").</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : ton compte (${state.user}) n'a pas les droits nécessaires sur ce coffre.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};

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
    't.leroux': { label:'SOC\\t.leroux', priv:'Analyste sécurité', groups:['SOC Tier 1'], desc:'Analyste SOC — équipe de garde, ticket INC-2024-0417' }
  },

  // Vérité terrain des événements — clé = identifiant affiché (EVT-X).
  // L'ordre chronologique réel se lit uniquement à l'horodatage, pas à
  // l'ordre d'affichage (volontairement mélangé dans security.log).
  EVENTS:{
    A:{ time:'02:50:10', text:'EventID 4769 (Ticket de service demandé) — Compte demandeur : k.morel — SPN visé : MSSQLSvc/sql-report.corp.local:1433 — Chiffrement : AES256-CTS-HMAC-SHA1' },
    B:{ time:'03:12:04', text:'EventID 4769 (Ticket de service demandé) — Compte demandeur : j.dupont — SPN visé : MSSQLSvc/sql01.corp.local:1433 (svc_backup) — Chiffrement : RC4-HMAC ⚠ legacy' },
    C:{ time:'03:14:47', text:"EventID 4624 (Ouverture de session réussie) — Compte : svc_backup — Poste source : WKS-042 — Type d'ouverture : 3 (réseau)" },
    D:{ time:'03:15:02', text:"EventID 4663 (Tentative d'accès à un objet) — Compte : svc_backup — Objet : C:\\Users\\Administrator\\Desktop\\flag.txt — Droit : ReadData — Résultat : Autorisé (membre Backup Operators)" }
  },
  EVENTS_DISPLAY_ORDER:['C','A','D','B'],
  CORRECT_ORDER:'a,b,c,d',
  CORRECT_TECHNIQUE:['kerberoasting','kerberoast'],
  CORRECT_ACCOUNT:'svc_backup',

  objectives:[
    { id:'investigate', text:"Consulter les journaux de l'incident" },
    { id:'technique',   text:"Identifier la technique d'attaque utilisée" },
    { id:'account',     text:'Identifier le compte compromis' },
    { id:'timeline',    text:'Reconstituer la chronologie des événements' },
    { id:'flag',        text:"Clôturer l'incident (rapport complet)" },
  ],

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

  introLines:[
    `<span class="out-dim">SOC Console [Simulation Lab]</span>`,
    `<span class="out-warn">🛰️ Ticket ouvert : INC-2024-0417 — pic anormal de demandes de tickets Kerberos cette nuit.</span>`,
    `<span class="out-dim">Connecté en tant que SOC\\t.leroux</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🛰️', title:'Changer de côté : la perspective SOC', html:
      `<p>Jusqu'ici, tu as joué l'attaquant. Ce mode inverse les rôles : tu es désormais <b>analyste au centre des opérations de sécurité (SOC)</b>, et une compromission a peut-être déjà eu lieu.</p>
       <p>Pas de terminal à compromettre ici — juste des journaux à lire, et des conclusions à soumettre.</p>` },
    { icon:'📄', title:'Tous les tickets Kerberos ne sont pas suspects', html:
      `<p>Un contrôleur de domaine génère des <b>centaines</b> d'événements 4769 (demande de ticket de service) chaque jour — la quasi-totalité sont parfaitement légitimes.</p>
       <p>Le travail d'un analyste n'est pas de tout regarder avec suspicion, mais de repérer le <b>détail qui cloche</b> : un type de chiffrement inhabituel, un compte qui n'a rien à faire là, un horaire incongru.</p>` },
    { icon:'🧭', title:"La chronologie, l'outil de l'analyste", html:
      `<p>Un événement isolé ne prouve presque jamais rien. C'est la <b>corrélation</b> entre plusieurs événements — dans le bon ordre — qui raconte l'histoire complète d'une attaque.</p>
       <p>Reconstituer une chronologie précise est au cœur de tout vrai rapport d'incident : elle seule permet de dire ce qui s'est passé, dans quel ordre, et jusqu'où l'attaquant est allé.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>SOC\\t.leroux</b>. Une alerte s'est déclenchée cette nuit. Consulte le journal de l'incident, identifie la technique utilisée, le compte compromis, et remets les événements dans le bon ordre — puis clôture le dossier.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Incident résolu',
  completeSub:"Kerberoasting détecté et documenté avant l'escalade.",
  chainSteps:[
    {icon:'📄', label:'Logs lus'}, {icon:'🔍', label:'Technique'},
    {icon:'🧭', label:'Chronologie'}, {icon:'📝', label:'Rapport clos'}
  ],
  flag:'FLAG{blueteam_kerberoast_detected}',

  deepDive:{
    why:"Le Kerberoasting laisse des traces discrètes mais réelles : une demande de ticket de service (Event ID 4769) chiffrée en RC4 alors que le reste de l'environnement utilise AES est un signal fort, surtout suivie de près par une ouverture de session et un accès fichier inhabituels pour ce compte. Aucun de ces événements pris isolément ne prouve une attaque — c'est leur corrélation, dans le bon ordre, qui la révèle.",
    defenses:[
      "Alerter spécifiquement sur les tickets Kerberos chiffrés en RC4 (type 0x17) quand l'environnement est censé n'utiliser que l'AES",
      "Corréler automatiquement les événements 4769 / 4624 / 4663 dans une fenêtre de temps courte pour un même compte",
      "Établir une base de référence du volume normal de demandes de ticket par compte de service, pour repérer les écarts",
      "Documenter systématiquement une chronologie précise (et non un simple constat) dans chaque rapport d'incident",
      "Déployer des comptes de service gérés (gMSA) : la cause racine ici reste un mot de passe de service faible"
    ]
  },

  initState(){ return { technique:false, account:false, timeline:false }; },

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
      print(`<span class="out-info"> Dossier d'incident : INC-2024-0417</span>`);
      print(`<span class="out-dim">  security.log</span>`);
      print(`<span class="out-dim">  readme.txt</span>`);
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim().toLowerCase();
      if(file === 'readme.txt'){
        print(`<span class="out-dim">"Alerte SIEM déclenchée à 03:12 : pic anormal de demandes de tickets Kerberos sur CORP.LOCAL. Détermine s'il s'agit d'une attaque, laquelle, quel compte est concerné, et reconstitue la chronologie complète avant de clôturer le ticket." — Notes d'astreinte</span>`);
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
        print(`<span class="out-good">✓ Technique confirmée : Kerberoasting.</span>`);
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
        print(`<span class="out-good">🎉 Bravo — incident correctement qualifié : Kerberoasting sur svc_backup, chronologie complète, dossier clôturé.</span>`);
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

// ---------------------------------------------------------
// SCÉNARIO 05 — ABUS DE CERTIFICATS (ADCS / ESC1)
// ---------------------------------------------------------
SCENARIOS.adcs = {
  id:'adcs',
  tag:'📜 SCÉNARIO 05 · CERTIFICATS (ADCS ESC1)',
  lessonTag:'📘 LEÇON · SCÉNARIO 05',
  opsecEnabled:true,
  noiseRules:[NOISE.certipyFind, NOISE.certipyReq, NOISE.certipyAuth],
  startUser:'j.rossi',

  identities:{
    'j.rossi':       { label:'CORP\\j.rossi', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — support niveau 1' },
    'administrator': { label:'CORP\\administrator', priv:'Administrateur intégré', groups:['Domain Users','Domain Admins'], desc:'Compte administrateur intégré du domaine' }
  },

  // Modèles de certificats publiés par l'autorité de certification (CA) du domaine.
  templates:{
    'User': {
      enroll:'Domain Users',
      esc1:false,
      flags:'—',
      desc:"Modèle standard fourni par défaut. N'importe qui peut s'enrôler, mais le sujet du certificat est toujours forcé à l'identité du demandeur : impossible de usurper quelqu'un d'autre."
    },
    'SecureLogin': {
      enroll:'Domain Admins',
      esc1:false,
      flags:'—',
      desc:"Modèle réservé à l'authentification forte des administrateurs. Solide sur le papier — mais seuls les Domain Admins peuvent s'y enrôler, donc inutile pour élever ses privilèges."
    },
    'WebServer': {
      enroll:'Domain Users',
      esc1:true,
      flags:'ENROLLEE_SUPPLIES_SUBJECT',
      desc:"Modèle publié à l'origine pour l'authentification de serveurs web par certificat. Ouvert à tous les utilisateurs du domaine, ET le drapeau ENROLLEE_SUPPLIES_SUBJECT laisse le DEMANDEUR choisir librement l'identité (SAN) inscrite dans le certificat."
    }
  },

  objectives:[
    { id:'enum',   text:'Lister les modèles de certificats publiés par la CA' },
    { id:'find',   text:'Repérer le modèle vulnérable (ENROLLEE_SUPPLIES_SUBJECT)' },
    { id:'forge',  text:"Demander un certificat en usurpant l'identité de l'administrateur" },
    { id:'auth',   text:'Authentification via ce certificat (PKINIT)' },
    { id:'flag',   text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant de savoir quel modèle exploiter, il faut d'abord voir ce que la CA du domaine propose.",
     "Il existe une commande pour interroger l'autorité de certification et lister ses modèles publiés, avec qui peut s'y enrôler.",
     "Commence par : `certipy find` — elle liste les modèles, qui peut s'y enrôler, et leurs drapeaux."],
    ["Un modèle réservé aux administrateurs ne t'aide à rien : tu ne peux même pas t'y enrôler. Cherche plutôt un modèle ouvert à tout le monde MAIS avec un drapeau qui ne devrait pas être là.",
     "Le drapeau à repérer s'appelle ENROLLEE_SUPPLIES_SUBJECT — il veut dire que c'est TOI, le demandeur, qui choisis l'identité écrite dans le certificat, pas la CA.",
     "Le modèle 'WebServer' est ouvert à Domain Users ET porte le drapeau ENROLLEE_SUPPLIES_SUBJECT — c'est ta cible (c'est la faille bien connue sous le nom d'ESC1)."],
    ["Puisque tu peux choisir l'identité du certificat toi-même, demandes-en un pour quelqu'un de bien plus puissant que toi.",
     "Il existe une commande pour demander (request) un certificat sur un modèle donné, en précisant l'UPN (identité) que tu veux voir apparaître dedans.",
     "Demande un certificat sur le modèle vulnérable en te faisant passer pour l'administrateur : `certipy req -template WebServer -upn administrator@corp.local`"],
    ["Un certificat valide pour une identité permet de s'authentifier auprès du domaine sans jamais connaître le mot de passe — via Kerberos PKINIT.",
     "Il existe une commande pour t'authentifier directement avec le certificat obtenu.",
     "Authentifie-toi avec ce certificat : `certipy auth -cert administrator.pfx` — tu obtiens une session en tant qu'administrator."],
    ["Une fois connecté avec les droits Domain Admin, la suite est toujours la même.",
     "Regarde ce qu'il y a sur ce bureau.",
     "`dir` puis `type flag.txt` une fois que tu es administrator."]
  ],

  manPages:{
    'certipy': { name:'certipy find', role:"Interroge l'autorité de certification (CA) du domaine",
      explain:"Liste les modèles de certificats publiés, qui peut s'y enrôler, et leurs drapeaux de configuration. Un modèle mal configuré peut permettre bien plus que prévu — jusqu'à usurper n'importe quelle identité (drapeau ENROLLEE_SUPPLIES_SUBJECT, faille connue sous le nom d'ESC1).",
      usage:'certipy find' },
    'certipy-req': { name:'certipy req', role:'Demande un certificat sur un modèle donné',
      explain:"Envoie une demande d'enrôlement à la CA pour le modèle choisi. Si ce modèle autorise le demandeur à fournir lui-même le sujet du certificat (ENROLLEE_SUPPLIES_SUBJECT), l'UPN précisé peut être celui de n'importe quel compte — y compris un administrateur.",
      usage:'certipy req -template <nom> -upn <identité>' },
    'certipy-auth': { name:'certipy auth', role:'Authentification via un certificat (PKINIT)',
      explain:"Utilise un certificat valide pour obtenir un ticket Kerberos (TGT) au nom de l'identité inscrite dedans — sans jamais connaître le mot de passe du compte visé.",
      usage:'certipy auth -cert <fichier.pfx>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'certipy find','certipy req -template ','certipy auth -cert ','dir','type '
  ],

  helpLine:'whoami /priv, certipy find, certipy req -template &lt;nom&gt; -upn &lt;identité&gt;, certipy auth -cert &lt;fichier.pfx&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>certipy find<br>certipy req -template &lt;nom&gt; -upn &lt;identité&gt;<br>certipy auth -cert &lt;fichier.pfx&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.rossi sur WKS-204</span>`,
    `<span class="out-info">Une autorité de certification (AD CS) a été déployée récemment pour l'authentification par carte à puce.</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'📜', title:'AD CS : des certificats comme identité', html:
      `<p><b>Active Directory Certificate Services</b> (AD CS) permet à une entreprise de faire tourner sa propre autorité de certification (CA) interne — pour signer des sites web internes, mais aussi pour <b>authentifier des comptes</b> via un certificat plutôt qu'un mot de passe.</p>
       <p>Un certificat valide pour une identité permet de s'authentifier au domaine sans jamais connaître le mot de passe, via Kerberos <b>PKINIT</b>.</p>` },
    { icon:'🧩', title:'Les modèles de certificats (templates)', html:
      `<p>La CA publie des <b>modèles</b> qui définissent : qui a le droit de demander (s'enrôler) un certificat sur ce modèle, et quelles informations d'identité ce certificat contiendra.</p>
       <p>Normalement, la CA impose que le certificat porte l'identité du demandeur — pas celle de quelqu'un d'autre.</p>` },
    { icon:'🚩', title:"L'ESC1 : quand le demandeur choisit son identité", html:
      `<p>Certains modèles portent un drapeau <b>ENROLLEE_SUPPLIES_SUBJECT</b> : c'est le <b>demandeur</b>, pas la CA, qui choisit l'identité (SAN) écrite dans le certificat.</p>
       <p>Si ce modèle est en plus ouvert à n'importe quel utilisateur authentifié, n'importe qui peut demander — et obtenir — un certificat valide pour l'<b>administrateur du domaine</b>. C'est la faille la plus connue d'AD CS, nommée <b>ESC1</b>.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\j.rossi</b>, employé standard. Une autorité de certification vient d'être déployée. Quelque part parmi ses modèles publiés, une configuration bien trop permissive t'attend.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:'Un modèle de certificat trop permissif, une identité usurpée.',
  chainSteps:[
    {icon:'🔎', label:'Recon CA'}, {icon:'🚩', label:'Modèle ESC1'},
    {icon:'📜', label:'Certificat forgé'}, {icon:'🔑', label:'PKINIT'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{adcs_esc1_enrollee_supplies_subject}',

  graph:{
    nodes:[
      { id:'j.rossi', label:'j.rossi', type:'user' },
      { id:'tpl_user', label:'Modèle: User', type:'service' },
      { id:'tpl_securelogin', label:'Modèle: SecureLogin', type:'service' },
      { id:'tpl_webserver', label:'Modèle: WebServer', type:'service' },
      { id:'administrator', label:'administrator', type:'admin' }
    ],
    edges:[
      { id:'e_enroll', from:'j.rossi', to:'tpl_webserver', type:'abuse', label:'Enrollment Rights + ESC1' },
      { id:'e_forge', from:'tpl_webserver', to:'administrator', type:'auth', label:'Certificat forgé (SAN)' },
      { id:'e_owned', from:'j.rossi', to:'administrator', type:'owned', label:'PKINIT réussi' }
    ]
  },

  deepDive:{
    why:"AD CS est souvent déployé rapidement, avec les modèles fournis par défaut ou copiés d'un ancien modèle sans revoir les droits d'enrôlement ni les drapeaux hérités. Le drapeau ENROLLEE_SUPPLIES_SUBJECT, en particulier, est resté sur d'anciens modèles conçus avant que ce risque ne soit largement documenté (recherche publiée par SpecterOps en 2021, ESC1 à ESC8+).",
    defenses:[
      "Auditer tous les modèles de certificats publiés : qui peut s'enrôler, et quels drapeaux sont actifs (en particulier ENROLLEE_SUPPLIES_SUBJECT)",
      "Restreindre les droits d'enrôlement aux seuls comptes qui en ont réellement besoin, pas à Domain Users par défaut",
      "Activer StrongCertificateBindingEnforcement et le mappage strict certificat ↔ compte",
      "Surveiller les événements d'émission de certificats (4886/4887) et les authentifications PKINIT inhabituelles pour des comptes à privilèges"
    ]
  },

  initState(){ return { cert:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.adcs;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'certipy find'){
      print(`<span class="out-info">Modèles de certificats publiés par CORP-CA :</span>`);
      Object.keys(sc.templates).forEach(name => {
        const t = sc.templates[name];
        print(`<span class="out-dim">  ${name} — Enrollment Rights: ${t.enroll} — Drapeaux: ${t.flags}</span>`);
      });
      print(`<span class="out-warn">⚠ Un des modèles laisse le demandeur choisir lui-même l'identité du certificat (ENROLLEE_SUPPLIES_SUBJECT). Regarde bien qui peut s'y enrôler.</span>`);
      AttackGraph.reveal({ nodes:['j.rossi','tpl_user','tpl_securelogin','tpl_webserver'] });
      complete('enum');
      return true;
    }

    m = lower.match(/^certipy req -template (\S+) -upn (\S+)$/);
    if(m){
      const tplName = Object.keys(sc.templates).find(n => n.toLowerCase() === m[1]);
      const upn = m[2];
      if(!tplName){ print(`<span class="out-bad">Modèle introuvable : ${escapeHtml(m[1])}</span>`); return true; }
      const t = sc.templates[tplName];
      if(t.enroll === 'Domain Admins'){
        print(`<span class="out-bad">Accès refusé : ce modèle n'autorise l'enrôlement qu'aux membres de Domain Admins.</span>`);
        return true;
      }
      complete('find');
      const targetUser = upn.split('@')[0].toLowerCase();
      if(!t.esc1){
        if(targetUser === state.user.toLowerCase()){
          print(`<span class="out-good">Certificat émis pour ${upn} — mais c'est ta propre identité, ça ne t'avance à rien.</span>`);
        } else {
          print(`<span class="out-bad">Demande refusée : ce modèle force le sujet du certificat à l'identité du demandeur (pas de ENROLLEE_SUPPLIES_SUBJECT). Impossible de spécifier ${upn}.</span>`);
        }
        return true;
      }
      print(`<span class="out-good">Certificat émis avec succès pour l'identité ${upn} (modèle ${tplName}, ENROLLEE_SUPPLIES_SUBJECT).</span>`);
      print(`<span class="out-dim">Fichier : ${targetUser}.pfx</span>`);
      state.extra.cert = targetUser;
      AttackGraph.reveal({ edges:['e_enroll','e_forge'] });
      complete('forge');
      return true;
    }

    m = lower.match(/^certipy auth -cert (\S+)$/);
    if(m){
      const certFile = m[1].replace(/\.pfx$/,'');
      if(!state.extra.cert || state.extra.cert !== certFile){
        print(`<span class="out-bad">Certificat introuvable ou invalide : ${escapeHtml(m[1])}</span>`);
        return true;
      }
      if(!sc.identities[certFile]){
        print(`<span class="out-bad">Identité inconnue pour ce certificat.</span>`);
        return true;
      }
      print(`<span class="out-good">Authentification PKINIT réussie — TGT obtenu pour ${sc.identities[certFile].label}.</span>`);
      state.user = certFile;
      updatePrompt();
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(certFile);
      complete('auth');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'administrator'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\administrator\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'administrator'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : modèle de certificat vulnérable (ESC1) → certificat usurpé → authentification PKINIT → Domain Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer tous les modèles de certificats publiés, restreindre les droits d'enrôlement, désactiver ENROLLEE_SUPPLIES_SUBJECT quand il n'est pas nécessaire.</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits de lecture sur ce fichier.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};
