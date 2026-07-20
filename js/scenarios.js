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
  dcsyncAny:      noiseRule(/^mimikatz lsadump::dcsync \/user:\S+$/, 40, "Réplication DCSync (Event ID 4662 — très anormal hors d'un contrôleur de domaine)"),
  mimikatzGolden: noiseRule(/^mimikatz kerberos::golden .*$/, 10, "Forge d'un ticket (préparation risquée)"),
  pth:            noiseRule(/^pth \/target:\S+ \/user:\S+ \/hash:\S+$/, 15, 'Authentification par hash (NTLM)'),
  mgAppAll:       noiseRule(/^get-mgapp -all$/, 4, 'Requête Microsoft Graph en lecture'),
  mgAppOne:       noiseRule(/^get-mgapp \S+$/, 4, 'Requête Microsoft Graph en lecture'),
  mgRoleMembers:  noiseRule(/^get-mgrolemembers -role \S+$/, 4, 'Requête Microsoft Graph en lecture'),
  connectMgraph:  noiseRule(/^connect-mgraph -appid \S+ -secret \S+$/, 12, 'Connexion consignée (journal de connexion Entra ID)'),
  addCredential:  noiseRule(/^add-credential -target \S+$/, 22, "Modification d'annuaire consignée (ajout d'un identifiant d'application)"),
  certipyFind:    noiseRule(/^certipy find$/, 6, "Énumération des modèles de certificats (requête LDAP vers l'AD CS)"),
  certipyReq:     noiseRule(/^certipy req -template \S+ -upn \S+$/, 16, "Demande de certificat (Event ID 4886/4887 côté serveur AD CS)"),
  certipyAuth:    noiseRule(/^certipy auth -cert \S+$/, 20, "Authentification Kerberos par certificat (PKINIT) pour un compte à privilèges"),
  whiskerAdd:     noiseRule(/^whisker add \/target:\S+$/, 17, "Modification de l'attribut msDS-KeyCredentialLink (Event ID 5136)"),
  whiskerAuth:    noiseRule(/^whisker auth \/target:\S+$/, 20, "Authentification Kerberos par clé (PKINIT) pour un compte à privilèges"),
  domainComputerUnconstrained: noiseRule(/^get-domaincomputer -unconstrained$/, 5, "Requête LDAP sur les comptes machine trustés pour la délégation"),
  petitpotam:     noiseRule(/^petitpotam \/listener:\S+ \/target:\S+$/, 30, "Coercition d'authentification forcée par MS-EFSRPC (très visible sur le réseau)"),
  sekurlsaTickets: noiseRule(/^mimikatz sekurlsa::tickets \/export$/, 15, 'Extraction mémoire LSASS des tickets Kerberos en cache'),
  kerberosPtt:    noiseRule(/^mimikatz kerberos::ptt \S+$/, 12, "Injection d'un ticket Kerberos en mémoire (Pass-the-Ticket)")
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
    ],
    quiz:[
      { q:"Pourquoi un utilisateur standard peut-il demander le ticket Kerberos d'un compte de service ?",
        options:["C'est une faille du protocole Kerberos","C'est le fonctionnement normal de Kerberos pour tout compte avec un SPN","Il faut d'abord être administrateur du domaine","Le compte de service a mal configuré ses ACL"],
        correct:1,
        explain:"Kerberos est conçu ainsi : tout utilisateur authentifié peut demander un ticket de service pour n'importe quel SPN. La seule protection réelle est la robustesse du mot de passe qui chiffre ce ticket." },
      { q:"Quelle mesure réduit le plus efficacement le risque de Kerberoasting ?",
        options:["Changer le mot de passe de l'utilisateur standard","Utiliser des comptes de service gérés (gMSA)","Désactiver le compte administrateur intégré","Chiffrer le disque du contrôleur de domaine"],
        correct:1,
        explain:"Un gMSA a un mot de passe long, aléatoire, et changé automatiquement par AD — il devient donc pratiquement impossible à casser hors-ligne." },
      { q:"Quel Event ID Windows permet de repérer une demande de ticket de service suspecte ?",
        options:["4624","4769","4886","4662"],
        correct:1,
        explain:"L'Event ID 4769 correspond à une demande de ticket de service Kerberos (TGS) — une activité normale en soi, mais anormale en volume ou sur un compte à SPN sensible." }
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
    ],
    quiz:[
      { q:"Pourquoi le compte krbtgt est-il la cible ultime dans un domaine Active Directory ?",
        options:["Il contient tous les mots de passe des utilisateurs","Sa clé signe cryptographiquement tous les tickets Kerberos du domaine","C'est le seul compte avec accès à Internet","Il gère les mises à jour Windows du domaine"],
        correct:1,
        explain:"Quiconque possède la clé krbtgt peut forger des tickets Kerberos valides pour n'importe quelle identité — sans dépendre du mot de passe d'un compte réel." },
      { q:"Pourquoi faut-il changer la clé krbtgt deux fois de suite, et pas une seule ?",
        options:["Pour respecter une norme ISO obligatoire","Parce qu'AD conserve les deux dernières générations de la clé","Pour forcer tous les utilisateurs à se reconnecter","Un seul changement suffit toujours"],
        correct:1,
        explain:"AD garde en mémoire l'ancienne et la nouvelle clé krbtgt pour éviter de casser les tickets en cours ; un seul changement laisse donc encore un Golden Ticket valide avec l'ancienne clé." },
      { q:"Quel signe technique trahit souvent un Golden Ticket en usage ?",
        options:["Une connexion depuis un nouveau pays","Un ticket Kerberos à durée de vie anormalement longue","Un mot de passe changé récemment","Un compte verrouillé après plusieurs échecs"],
        correct:1,
        explain:"Un Golden Ticket forgé a souvent une durée de vie fixée arbitrairement (parfois des années), très différente de la durée de vie normale d'un ticket légitime — un signal fort pour la détection." }
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
    ],
    quiz:[
      { q:"Pourquoi une ACL dangereuse reste-t-elle souvent en place pendant des années ?",
        options:["Windows la supprime automatiquement après 90 jours","Elle reste active tant que personne ne la retire explicitement","Elle n'est visible que par l'administrateur qui l'a créée","Les ACL AD expirent seulement en cas de changement de mot de passe"],
        correct:1,
        explain:"Une permission accordée pour un besoin ponctuel n'a pas de date d'expiration native : sans audit régulier, elle survit largement au-delà de son utilité." },
      { q:"Quel outil est couramment utilisé côté défense pour auditer les chemins d'abus d'ACL avant qu'un attaquant ne les trouve ?",
        options:["BloodHound","Wireshark","Nmap","Metasploit"],
        correct:0,
        explain:"BloodHound cartographie les relations AD (groupes, ACL, sessions) et révèle les chemins d'escalade de privilèges — le même outil sert aussi à l'attaque, d'où son usage défensif préventif." },
      { q:"Quel principe limite le risque qu'une ACL trop permissive mène jusqu'à Domain Admin ?",
        options:["Le moindre privilège avec droits temporaires","Le partage de mots de passe entre administrateurs","La désactivation complète des ACL","L'authentification unique (SSO) généralisée"],
        correct:0,
        explain:"Accorder des droits temporaires, avec expiration automatique et strictement nécessaires à la tâche, réduit la fenêtre et la portée d'une ACL mal configurée." }
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
    ],
    quiz:[
      { q:"Pourquoi le Pass-the-Hash fonctionne-t-il sans jamais connaître le mot de passe en clair ?",
        options:["Le hash est automatiquement déchiffré par Windows","NTLM accepte le hash lui-même comme preuve d'identité","Le hash est stocké en clair sur le disque","Il faut d'abord casser le hash pour l'utiliser"],
        correct:1,
        explain:"NTLM authentifie avec le hash directement — inutile de le casser pour retrouver le mot de passe en clair, il suffit de le rejouer tel quel." },
      { q:"Pourquoi un même hash NTLM ouvre-t-il parfois plusieurs machines différentes ?",
        options:["Toutes les machines partagent le même contrôleur de domaine","Le mot de passe administrateur local a été réutilisé sur plusieurs postes","Le hash change automatiquement selon la machine","C'est impossible sans droits Domain Admin"],
        correct:1,
        explain:"Quand le même mot de passe admin local est déployé partout, un seul hash volé devient une clé passe-partout — c'est exactement ce que LAPS empêche." },
      { q:"Quelle solution est spécifiquement conçue pour empêcher la réutilisation d'un compte admin local sur tout le parc ?",
        options:["LAPS","gMSA","Credential Guard","AD CS"],
        correct:0,
        explain:"LAPS (Local Administrator Password Solution) attribue un mot de passe admin local unique par machine, changé automatiquement — un hash volé ne vaut alors plus que pour une seule machine." }
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
    ],
    quiz:[
      { q:"Pourquoi un secret d'App Registration qui fuite dans un pipeline CI/CD est-il si dangereux ?",
        options:["Il permet de s'authentifier directement en tant que ce Service Principal","Il ne fonctionne que depuis le réseau de l'entreprise","Il expire automatiquement au bout d'une heure","Il ne donne accès qu'à des ressources en lecture seule"],
        correct:0,
        explain:"Un secret client suffit à s'authentifier comme le Service Principal correspondant — s'il a des rôles privilégiés, c'est comme voler l'identité de ce compte d'automatisation." },
      { q:"Pourquoi le rôle Application Administrator permet-il indirectement de devenir Global Administrator ici ?",
        options:["Il donne directement les droits Global Administrator","Il permet d'ajouter un identifiant à une application qui a elle-même ce rôle plus privilégié","Il permet de lire le mot de passe du Global Administrator","Il désactive automatiquement le MFA du tenant"],
        correct:1,
        explain:"Gérer les identifiants d'une application signifie pouvoir s'authentifier à sa place. Si cette application dispose du rôle Global Administrator, ses identifiants ouvrent ce rôle." },
      { q:"Quelle bonne pratique évite qu'un rôle ultra-privilégié reste attribué en permanence ?",
        options:["Privileged Identity Management (PIM)","Le partage du mot de passe entre administrateurs","La désactivation du MFA pour simplifier les audits","L'attribution du rôle à tous les Service Principals"],
        correct:0,
        explain:"PIM permet de rendre les rôles privilégiés temporaires, activés à la demande et justifiés, plutôt que attribués en permanence à un compte — y compris un Service Principal." }
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
    ],
    quiz:[
      { q:"Que permet concrètement le drapeau ENROLLEE_SUPPLIES_SUBJECT sur un modèle de certificat ?",
        options:["Le demandeur choisit lui-même l'identité (le sujet) inscrite dans le certificat","Le certificat expire automatiquement après usage","Seul un administrateur peut demander ce certificat","Le certificat ne fonctionne que sur la machine qui l'a demandé"],
        correct:0,
        explain:"Ce drapeau laisse le demandeur préciser le sujet du certificat — s'il est ouvert à tous, n'importe qui peut demander un certificat au nom de l'administrateur." },
      { q:"Comment ce certificat forgé permet-il ensuite de s'authentifier comme l'administrateur ?",
        options:["Par PKINIT, l'authentification Kerberos par certificat","En le collant dans un fichier de mots de passe","En le renommant avec le nom de l'administrateur","Il ne permet pas de s'authentifier, seulement de le visualiser"],
        correct:0,
        explain:"PKINIT est l'extension Kerberos qui permet de s'authentifier avec un certificat plutôt qu'un mot de passe — un certificat au nom de l'admin y suffit." },
      { q:"Quelle pratique aurait empêché ce scénario dès le départ ?",
        options:["Auditer les modèles publiés et restreindre les droits d'enrôlement","Changer le mot de passe de l'administrateur plus souvent","Désactiver Kerberos au profit de NTLM","Chiffrer le contrôleur de domaine avec BitLocker"],
        correct:0,
        explain:"Un audit régulier des modèles de certificats publiés (droits d'enrôlement, drapeaux hérités) aurait révélé le modèle vulnérable avant qu'un attaquant ne l'exploite." }
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

// ---------------------------------------------------------
// SCÉNARIO 06 — SHADOW CREDENTIALS (abus de msDS-KeyCredentialLink)
// Contrairement au scénario 03 (ACL/GenericAll), ici le droit détourné
// est étroit et discret — écrire sur UN SEUL attribut, pas tout
// contrôler — et l'exploitation ne touche jamais au mot de passe :
// aucune réinitialisation, donc aucun Event ID 4724, et l'utilisateur
// légitime continue de se connecter normalement sans rien remarquer.
// ---------------------------------------------------------
SCENARIOS.shadowcred = {
  id:'shadowcred',
  tag:'👻 SCÉNARIO 06 · SHADOW CREDENTIALS',
  lessonTag:'📘 LEÇON · SCÉNARIO 06',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.objectAcl, NOISE.whiskerAdd, NOISE.whiskerAuth],
  startUser:'m.dubois',

  identities:{
    'm.dubois':  { label:'CORP\\m.dubois', priv:'Utilisateur standard', groups:['Domain Users','IT Passwordless Rollout'], desc:'Technicien support — projet Windows Hello for Business' },
    'c.blanc':   { label:'CORP\\c.blanc', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employée — ressources humaines' },
    's.lefevre': { label:'CORP\\s.lefevre', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:'Direction des systèmes d\'information' }
  },

  // ACL simulées : qui a des droits inhabituels sur quel compte.
  // Ici le droit vulnérable est volontairement étroit (Write sur un
  // seul attribut), pas un contrôle total — c'est tout l'intérêt
  // pédagogique par rapport au scénario 03.
  acl:{
    's.lefevre': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\IT Passwordless Rollout', rights:'Write msDS-KeyCredentialLink', normal:false }
    ]
  },

  objectives:[
    { id:'enum',   text:'Repérer les comptes à privilèges du domaine' },
    { id:'keyacl', text:"Trouver un droit d'écriture sur l'attribut msDS-KeyCredentialLink" },
    { id:'addkey', text:"Injecter une clé d'identification (shadow credential) sur le compte cible" },
    { id:'auth',   text:"S'authentifier par cette clé (PKINIT), sans jamais toucher au mot de passe" },
    { id:'flag',   text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant de chercher une faille, il faut savoir qui sont les comptes puissants de ce domaine.",
     "Liste les comptes et repère celui qui appartient au groupe Domain Admins.",
     "Commence par voir qui est qui dans le domaine : `net user /domain`"],
    ["Les droits ne sont pas toujours \"tout ou rien\" — certains ne portent que sur un seul attribut, et passent d'autant plus inaperçus.",
     "Regarde les droits accordés sur s.lefevre : un groupe dont tu es membre y figure peut-être, avec un droit très ciblé.",
     "Ton groupe CORP\\IT Passwordless Rollout a un droit d'écriture étroit sur s.lefevre. Regarde-le avec : `get-objectacl s.lefevre`"],
    ["Ce droit d'écriture porte sur un attribut précis, utilisé pour l'authentification sans mot de passe (Windows Hello for Business). Rien n'empêche d'y écrire sa propre clé.",
     "Il existe un outil pour ajouter une clé d'identification (shadow credential) sur un compte, à condition d'avoir ce droit d'écriture.",
     "Ajoute ta propre clé d'identification sur le compte cible avec : `whisker add /target:s.lefevre`"],
    ["Cette clé n'est pas un mot de passe — elle sert à s'authentifier autrement, via le même mécanisme que les certificats (PKINIT).",
     "Utilise cette clé pour t'authentifier directement en tant que s.lefevre, sans jamais connaître ni changer son mot de passe.",
     "Authentifie-toi avec la clé injectée : `whisker auth /target:s.lefevre`"],
    ["Tu es désormais Domain Admin, et le mot de passe original de s.lefevre n'a jamais changé.",
     "Regarde ce qu'il y a sur ton propre bureau, maintenant que tu es s.lefevre.",
     "Tu es maintenant Domain Admin. Regarde ton propre bureau avec `dir` puis `type flag.txt`"]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-objectacl': { name:'get-objectacl', role:"Liste les droits (ACL) accordés sur un compte",
      explain:"Un droit peut porter sur l'objet entier (GenericAll) ou sur un seul attribut précis — comme <b>msDS-KeyCredentialLink</b>, l'attribut qui stocke les clés d'authentification sans mot de passe (Windows Hello for Business, FIDO). Un droit d'écriture sur ce seul attribut suffit à s'authentifier comme le compte cible, sans jamais toucher à son mot de passe.",
      usage:'get-objectacl <nom>' },
    'whisker': { name:'whisker', role:"Manipule l'attribut msDS-KeyCredentialLink d'un compte",
      explain:"<code>add</code> injecte une nouvelle clé d'identification (shadow credential) sur le compte cible, à condition d'avoir un droit d'écriture suffisant sur cet attribut. <code>auth</code> utilise ensuite cette clé pour obtenir un ticket Kerberos (TGT) par authentification PKINIT — le même mécanisme que pour un certificat, mais sans jamais passer par une autorité de certification ni changer le mot de passe du compte.",
      usage:'whisker add /target:<nom>   |   whisker auth /target:<nom>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-objectacl ',
    'whisker add /target:','whisker auth /target:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-objectacl &lt;nom&gt;, whisker add /target:&lt;nom&gt;, whisker auth /target:&lt;nom&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-objectacl &lt;nom&gt;<br>whisker add /target:&lt;nom&gt;<br>whisker auth /target:&lt;nom&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\m.dubois sur WKS-077</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🪪', title:'Authentification sans mot de passe : une nouvelle attaque de surface', html:
      `<p>Windows Hello for Business et les clés de sécurité (FIDO2) permettent de s'authentifier sans mot de passe, grâce à une paire de clés stockée dans l'attribut <b>msDS-KeyCredentialLink</b> du compte.</p>
       <p>Pour déployer ce système, les équipes IT ont souvent besoin d'un droit d'écriture sur cet attribut — un droit étroit, en apparence anodin.</p>` },
    { icon:'👻', title:'Shadow Credentials : injecter sa propre clé', html:
      `<p>Si ce droit d'écriture est mal restreint, rien n'empêche un attaquant d'y ajouter <b>sa propre clé</b> — une "shadow credential" — sur le compte d'un tiers.</p>
       <p>Cette clé permet ensuite de s'authentifier comme ce compte via PKINIT (le même mécanisme que pour un certificat), sans jamais connaître son mot de passe.</p>` },
    { icon:'🥷', title:'Pourquoi c\'est particulièrement discret', html:
      `<p>Contrairement à une réinitialisation de mot de passe, injecter une clé <b>ne modifie rien de visible</b> pour l'utilisateur légitime : il continue de se connecter normalement, et aucun Event ID 4724 (changement de mot de passe) n'est généré.</p>
       <p>Pire encore pour la défense : changer le mot de passe du compte compromis <b>ne suffit pas</b> à couper l'accès de l'attaquant — la clé injectée reste valide tant qu'elle n'est pas explicitement retirée.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\m.dubois</b>, technicien support sur un projet d'authentification sans mot de passe. Ton groupe de projet a gardé un droit qu'il n'aurait plus dû avoir.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:"Une clé injectée, jamais un mot de passe touché.",
  chainSteps:[
    {icon:'🔎', label:'Recon'}, {icon:'🪪', label:'Droit trouvé'},
    {icon:'👻', label:'Clé injectée'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{shadow_credentials_msdskeycredentiallink_pkinit}',

  graph:{
    nodes:[
      { id:'m.dubois', label:'m.dubois', type:'user' },
      { id:'c.blanc', label:'c.blanc', type:'user' },
      { id:'s.lefevre', label:'s.lefevre', type:'admin' },
      { id:'grp_passwordless', label:'IT Passwordless Rollout', type:'group' }
    ],
    edges:[
      { id:'e_member', from:'m.dubois', to:'grp_passwordless', type:'memberof', label:'MemberOf' },
      { id:'e_acl', from:'grp_passwordless', to:'s.lefevre', type:'abuse', label:'Write msDS-KeyCredentialLink (oublié)' },
      { id:'e_owned', from:'m.dubois', to:'s.lefevre', type:'owned', label:'Shadow credential + PKINIT' }
    ]
  },

  deepDive:{
    why:"L'attribut msDS-KeyCredentialLink stocke les clés utilisées pour l'authentification sans mot de passe (Windows Hello for Business, FIDO2). Un droit d'écriture sur ce seul attribut — souvent accordé largement pendant un déploiement, puis jamais retiré — permet à quiconque le possède d'y ajouter sa propre clé, et de s'authentifier comme le compte cible via PKINIT. C'est un droit étroit, donc facile à accorder sans réfléchir, et facile à oublier dans un audit qui ne cherche que les GenericAll évidents.",
    defenses:[
      "Auditer spécifiquement les droits d'écriture sur msDS-KeyCredentialLink, pas seulement les droits larges comme GenericAll",
      "Limiter au strict nécessaire, et dans le temps, les groupes impliqués dans un déploiement d'authentification sans mot de passe",
      "Surveiller les modifications de l'attribut msDS-KeyCredentialLink (Event ID 5136) en dehors des postes et comptes attendus",
      "Retenir qu'une réinitialisation de mot de passe seule ne suffit pas à révoquer l'accès : il faut aussi supprimer toute clé injectée sur le compte"
    ],
    quiz:[
      { q:"Pourquoi un droit d'écriture sur msDS-KeyCredentialLink est-il souvent oublié lors d'un audit d'ACL ?",
        options:["Il n'existe dans aucun journal Windows","C'est un droit étroit sur un seul attribut, moins visible qu'un droit large comme GenericAll","Il ne peut être accordé qu'aux comptes de service","Microsoft ne documente pas cet attribut"],
        correct:1,
        explain:"Un audit qui cherche surtout les droits larges et évidents (GenericAll, Full Control) peut facilement laisser passer un droit d'écriture étroit sur un seul attribut, techniquement tout aussi dangereux ici." },
      { q:"Pourquoi cette technique ne génère-t-elle pas d'Event ID 4724 (changement de mot de passe) ?",
        options:["Parce que l'Event ID 4724 est désactivé par défaut","Parce qu'aucun mot de passe n'est jamais modifié — seule une clé est ajoutée en plus","Parce que l'attaquant supprime le journal après coup","Parce que 4724 ne concerne que les comptes de service"],
        correct:1,
        explain:"La technique n'a jamais besoin de toucher au mot de passe du compte : elle ajoute simplement une clé d'authentification alternative, ce qui ne déclenche pas les mêmes événements qu'une réinitialisation." },
      { q:"Pourquoi changer le mot de passe du compte compromis ne suffit-il pas à couper l'accès de l'attaquant ?",
        options:["Le mot de passe et la clé injectée sont deux méthodes d'authentification indépendantes — la clé reste valide tant qu'elle n'est pas retirée explicitement","Changer un mot de passe ne fonctionne jamais sur les comptes Domain Admin","La clé injectée devient automatiquement le nouveau mot de passe","Il faut redémarrer le contrôleur de domaine pour que le changement prenne effet"],
        correct:0,
        explain:"PKINIT via la clé injectée est un chemin d'authentification totalement séparé du mot de passe. Sans supprimer explicitement la clé de msDS-KeyCredentialLink, l'attaquant garde son accès même après un changement de mot de passe." }
    ]
  },

  initState(){ return { shadowKeyTarget:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.shadowcred;

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
          print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ droit étroit mais suffisant pour s'authentifier</span>`);
        }
      });
      if(entries.some(e => !e.normal)){
        AttackGraph.reveal({ edges:['e_member','e_acl'] });
        complete('keyacl');
      }
      return true;
    }

    m = lower.match(/^whisker add \/target:(\S+)$/);
    if(m){
      const name = m[1];
      const entries = sc.acl[name] || [];
      const me = sc.identities[state.user];
      const hasRight = entries.some(e => !e.normal && me.groups.some(g => e.principal.toLowerCase().endsWith(g.toLowerCase())));
      if(!hasRight){
        print(`<span class="out-bad">Accès refusé : tu n'as pas de droit d'écriture sur msDS-KeyCredentialLink pour ce compte.</span>`);
        return true;
      }
      print(`<span class="out-good">Clé d'identification injectée avec succès sur ${name} (msDS-KeyCredentialLink).</span>`);
      print(`<span class="out-dim">💡 Empreinte de la clé : 1a3f9c...(tronquée). Aucun mot de passe modifié — l'utilisateur légitime peut continuer à se connecter normalement, sans rien remarquer.</span>`);
      state.extra.shadowKeyTarget = name;
      AttackGraph.reveal({ edges:['e_acl'] });
      complete('addkey');
      return true;
    }

    m = lower.match(/^whisker auth \/target:(\S+)$/);
    if(m){
      const name = m[1];
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      if(state.extra.shadowKeyTarget !== name){
        print(`<span class="out-bad">Aucune clé d'identification injectée pour ce compte.</span>`);
        return true;
      }
      state.user = name;
      updatePrompt();
      print(`<span class="out-good">TGT Kerberos obtenu par PKINIT avec la clé injectée — session ouverte en tant que ${sc.identities[name].label}.</span>`);
      print(`<span class="out-dim">💡 Le mot de passe original de ce compte n'a jamais été consulté ni modifié.</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(name);
      complete('auth');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 's.lefevre'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\s.lefevre\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 's.lefevre'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : droit d'écriture étroit oublié (msDS-KeyCredentialLink) → clé injectée → authentification PKINIT → Domain Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer spécifiquement les droits sur msDS-KeyCredentialLink, pas seulement les GenericAll évidents — et retenir qu'un changement de mot de passe seul ne révoque pas une clé injectée.</span>`);
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

// ---------------------------------------------------------
// SCÉNARIO 07 — DCSYNC (abus de droits de réplication délégués)
// Le twist pédagogique : pas besoin d'être Domain Admin. Un simple
// compte de service (typiquement le compte de synchronisation Azure AD
// Connect) qui a gardé les droits DS-Replication-Get-Changes /
// -Get-Changes-All sur le domaine peut répliquer le hash de n'importe
// quel compte — Domain Admin, ou même krbtgt (le Golden Ticket).
// ---------------------------------------------------------
SCENARIOS.dcsync = {
  id:'dcsync',
  tag:'🧬 SCÉNARIO 07 · DCSYNC',
  lessonTag:'📘 LEÇON · SCÉNARIO 07',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.objectAcl, NOISE.dcsyncAny, NOISE.pth],
  startUser:'svc_adsync',

  identities:{
    'svc_adsync': { label:'CORP\\svc_adsync', priv:'Compte de service (non-admin)', groups:['Domain Users','ADSync Operators'], desc:'Compte de synchronisation Azure AD Connect — installé une fois, jamais restreint depuis' },
    'p.girard':   { label:'CORP\\p.girard', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — service commercial' },
    'a.faure':    { label:'CORP\\a.faure', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:"Administrateur — équipe infrastructure" }
  },

  // Hashes NTLM (simulés) qu'une réplication DCSync fait tomber.
  // Le point clé : ils sont accessibles sans jamais toucher aux comptes
  // eux-mêmes, ni connaître un seul mot de passe.
  hashes:{
    'a.faure':    'b4f3d2a1c0e9f8b7a6d5c4e3f2a1b0c9',
    'p.girard':   '31d6cfe0d16ae931b73c59d7e0c089c0',
    'svc_adsync': '7a2e4c1f9b8d6a3e5c7f1b9d2a4e6c8f',
    'krbtgt':     'ff87f8f2f8dfd7c0d1ae1c8f9b3a3e51'
  },

  // L'ACL vulnérable ne porte pas sur un compte, mais sur l'objet
  // domaine lui-même (le contexte de nommage) — c'est là que se
  // délèguent les droits de réplication. On l'interroge via
  // `get-objectacl domain`.
  acl:{
    'domain': [
      { principal:'CORP\\Domain Admins',       rights:'Full Control', normal:true },
      { principal:'CORP\\Domain Controllers',  rights:'DS-Replication-Get-Changes-All', normal:true },
      { principal:'CORP\\ADSync Operators',    rights:'DS-Replication-Get-Changes, DS-Replication-Get-Changes-All', normal:false }
    ]
  },

  objectives:[
    { id:'enum',    text:'Repérer les comptes à privilèges du domaine' },
    { id:'replacl', text:'Découvrir des droits de réplication (DCSync) délégués à un compte non-admin' },
    { id:'dcsync',  text:"Répliquer le hash NTLM d'un administrateur du domaine" },
    { id:'pth',     text:'Rejouer ce hash pour ouvrir une session (Pass-the-Hash)' },
    { id:'flag',    text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant tout, il faut savoir qui sont les comptes puissants de ce domaine.",
     "Liste les comptes et repère celui qui appartient au groupe Domain Admins.",
     "Commence par voir qui est qui : `net user /domain`"],
    ["Les droits de réplication (DCSync) ne se posent pas sur un compte, mais sur le domaine lui-même — regarde ce niveau-là.",
     "Ton compte est membre d'un groupe de synchronisation. Ce groupe a peut-être gardé des droits qu'il ne devrait plus avoir sur le domaine.",
     "Inspecte les droits posés sur l'objet domaine : `get-objectacl domain`"],
    ["Avec les droits DS-Replication-Get-Changes-All, tu peux demander au contrôleur de te répliquer les secrets d'un compte — sans être Domain Admin.",
     "Cible l'administrateur du domaine et réplique son hash NTLM.",
     "Réplique le hash de l'administrateur : `mimikatz lsadump::dcsync /user:a.faure`"],
    ["Un hash NTLM se rejoue tel quel : pas besoin de le casser pour s'en servir (Pass-the-Hash).",
     "Réutilise le hash d'a.faure pour ouvrir une session en son nom.",
     "Rejoue le hash récupéré : `pth /target:DC01 /user:a.faure /hash:<hash>`"],
    ["Tu es désormais Domain Admin, et personne n'a changé de mot de passe.",
     "Regarde ce qu'il y a sur le bureau d'a.faure, maintenant que tu es lui.",
     "Tu es Domain Admin. Fais `dir` puis `type flag.txt`"]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-objectacl': { name:'get-objectacl', role:"Liste les droits (ACL) posés sur un objet",
      explain:"Fonctionne sur un compte, mais aussi sur l'objet <b>domaine</b> lui-même (<code>get-objectacl domain</code>). C'est à ce niveau que se délèguent les droits de <b>réplication</b> : <b>DS-Replication-Get-Changes</b> + <b>DS-Replication-Get-Changes-All</b>. Un compte qui les possède peut extraire les secrets de n'importe quel compte, sans être Domain Admin.",
      usage:'get-objectacl domain   |   get-objectacl <nom>' },
    'mimikatz': { name:'mimikatz', role:'Boîte à outils post-exploitation AD',
      explain:"<code>lsadump::dcsync /user:&lt;nom&gt;</code> simule une réplication d'annuaire auprès du contrôleur pour extraire le hash NTLM (et les clés Kerberos) du compte visé. Contrairement à une extraction mémoire (LSASS), <b>ça ne nécessite pas d'être Domain Admin</b> : les seuls droits de réplication suffisent. Cibler <b>krbtgt</b> donne de quoi forger un Golden Ticket (voir le Chapitre Final).",
      usage:'mimikatz lsadump::dcsync /user:<nom>' },
    'pth': { name:'pth (pass-the-hash)', role:'Rejoue un hash NTLM comme preuve d\'identité',
      explain:"Ouvre une session au nom d'un compte en présentant son hash NTLM au lieu de son mot de passe en clair — le protocole NTLM ne fait pas la différence. Le hash suffit : nul besoin de le casser.",
      usage:'pth /target:<machine> /user:<nom> /hash:<hash>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-objectacl ',
    'mimikatz lsadump::dcsync /user:','pth /target:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-objectacl domain, get-objectacl &lt;nom&gt;, mimikatz lsadump::dcsync /user:&lt;nom&gt;, pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-objectacl domain<br>get-objectacl &lt;nom&gt;<br>mimikatz lsadump::dcsync /user:&lt;nom&gt;<br>pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\svc_adsync sur SRV-SYNC01</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🔁', title:'La réplication : le cœur d\'Active Directory', html:
      `<p>Les contrôleurs de domaine se synchronisent en permanence en <b>répliquant</b> leur base entre eux — y compris les secrets (hashes de mots de passe). Deux droits gouvernent cette réplication : <b>DS-Replication-Get-Changes</b> et <b>DS-Replication-Get-Changes-All</b>.</p>
       <p>Normalement, seuls les contrôleurs de domaine (et les Domain Admins) les possèdent.</p>` },
    { icon:'🧬', title:'DCSync : se faire passer pour un contrôleur', html:
      `<p>Un compte qui détient ces droits peut <b>demander au vrai contrôleur de lui répliquer</b> les secrets de n'importe quel compte — comme s'il était lui-même un DC. C'est l'attaque <b>DCSync</b>.</p>
       <p>Le piège : ces droits sont parfois <b>délégués à un compte non-admin</b>. Le cas d'école : le compte de synchronisation d'Azure AD Connect, installé avec ces droits et rarement restreint ensuite.</p>` },
    { icon:'🥷', title:'Pourquoi c\'est redoutable', html:
      `<p>Pas besoin d'être Domain Admin, ni de toucher au compte cible, ni de casser quoi que ce soit : le hash tombe directement. On peut répliquer un Domain Admin — ou même <b>krbtgt</b>, la clé qui signe tous les tickets, et forger un <b>Golden Ticket</b>.</p>
       <p>Côté défense, seule la surveillance des réplications anormales (Event ID 4662 hors des DC) trahit l'attaque.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu contrôles <b>CORP\\svc_adsync</b>, le compte de synchronisation Azure AD Connect. Il n'est pas administrateur — mais on ne lui a jamais retiré ses droits de réplication. Sers-t'en pour répliquer le hash d'un Domain Admin et t'emparer du domaine.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:"Un simple compte de sync, et tout le domaine réplique.",
  chainSteps:[
    {icon:'🔎', label:'Recon'}, {icon:'🧬', label:'Droits de réplication'},
    {icon:'🔑', label:'Hash répliqué'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{dcsync_replication_getchangesall_no_admin}',

  graph:{
    nodes:[
      { id:'svc_adsync', label:'svc_adsync', type:'user' },
      { id:'grp_adsync', label:'ADSync Operators', type:'group' },
      { id:'dom', label:'CORP.LOCAL', type:'group' },
      { id:'p.girard', label:'p.girard', type:'user' },
      { id:'a.faure', label:'a.faure', type:'admin' }
    ],
    edges:[
      { id:'e_member', from:'svc_adsync', to:'grp_adsync', type:'memberof', label:'MemberOf' },
      { id:'e_repl', from:'grp_adsync', to:'dom', type:'abuse', label:'DS-Replication-Get-Changes-All (oublié)' },
      { id:'e_dcsync', from:'dom', to:'a.faure', type:'auth', label:'DCSync → hash NTLM' },
      { id:'e_owned', from:'svc_adsync', to:'a.faure', type:'owned', label:'Pass-the-Hash' }
    ]
  },

  deepDive:{
    why:"La réplication d'annuaire est un mécanisme légitime et essentiel d'Active Directory : les contrôleurs se synchronisent en s'échangeant tout le contenu de la base, secrets compris. Les droits DS-Replication-Get-Changes et -Get-Changes-All autorisent cet échange. Le problème n'est pas le mécanisme, mais sa délégation : accordés à un compte qui n'est pas un contrôleur de domaine — typiquement le compte de synchronisation Azure AD Connect, ou un compte à qui on a donné ces droits « juste pour un outil » — ils permettent de répliquer le hash de n'importe quel compte sans jamais être administrateur, sans toucher aux comptes visés, et sans rien casser hors-ligne. C'est le chemin par lequel on obtient en pratique le hash de krbtgt qui rend un Golden Ticket possible.",
    defenses:[
      "Auditer précisément qui détient DS-Replication-Get-Changes et -Get-Changes-All sur le domaine — la liste doit se limiter aux contrôleurs de domaine et aux comptes strictement nécessaires",
      "Traiter le compte de synchronisation Azure AD Connect comme un compte à privilèges (Tier 0) : mot de passe long et protégé, connexions restreintes, et retrait de tout droit superflu après installation",
      "Surveiller les requêtes de réplication (Event ID 4662 sur l'objet domaine avec le GUID de réplication) provenant d'une source qui n'est pas un contrôleur de domaine",
      "Segmenter les rôles : un outil qui a besoin de lire l'annuaire n'a presque jamais besoin des droits de réplication complets"
    ],
    quiz:[
      { q:"Qu'est-ce qui rend l'attaque DCSync possible sans être Domain Admin ?",
        options:["Une faille dans le protocole Kerberos","La possession des droits de réplication (DS-Replication-Get-Changes-All), même délégués à un compte non-admin","Un mot de passe krbtgt trop faible","L'accès physique au contrôleur de domaine"],
        correct:1,
        explain:"DCSync exploite un mécanisme légitime : la réplication. Seuls les droits de réplication comptent, pas l'appartenance aux Domain Admins — c'est pourquoi une délégation trop large est si dangereuse." },
      { q:"Pourquoi le compte de synchronisation Azure AD Connect est-il une cible classique de cette attaque ?",
        options:["Il est toujours membre des Domain Admins","Il est souvent installé avec des droits de réplication larges qui ne sont jamais restreints ensuite","Son mot de passe est stocké en clair par défaut","Il ne peut pas se voir appliquer de politique de mot de passe"],
        correct:1,
        explain:"L'installation d'Azure AD Connect accorde des droits de réplication au compte de synchronisation ; faute de durcissement, ce compte non-admin devient un chemin direct vers tous les secrets du domaine." },
      { q:"Quel événement permet le mieux de détecter un DCSync malveillant ?",
        options:["Event ID 4724 (changement de mot de passe)","Event ID 4662 (accès à l'objet domaine avec le GUID de réplication) depuis une source qui n'est pas un contrôleur de domaine","Event ID 4769 (demande de ticket de service)","Aucun, l'attaque est totalement invisible"],
        correct:1,
        explain:"Une réplication est normale entre contrôleurs de domaine. La même requête (Event ID 4662) venant d'un poste ou d'un compte de service ordinaire est le signal d'alarme d'un DCSync abusif." }
    ]
  },

  initState(){ return { dcsyncHash:{} }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.dcsync;

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
      print(`<span class="out-dim">  krbtgt</span>`);
      AttackGraph.reveal({ nodes:['svc_adsync','p.girard','a.faure'] });
      complete('enum');
      return true;
    }

    m = lower.match(/^net user (\S+) \/domain$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){
        if(name === 'krbtgt'){
          print(`<span class="out-info">Nom du compte : krbtgt</span>`);
          print(`<span class="out-info">Description : Compte de service Kerberos (signe tous les tickets du domaine)</span>`);
          print(`<span class="out-warn">⚠ Ce compte ne sert jamais à se connecter — mais répliquer sa clé permet de forger un Golden Ticket.</span>`);
          return true;
        }
        print(`<span class="out-bad">Utilisateur introuvable : ${escapeHtml(name)}</span>`);
        return true;
      }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      if(u.groups.includes('Domain Admins')){
        print(`<span class="out-warn">⚠ Ce compte est administrateur du domaine — la cible à répliquer.</span>`);
      }
      complete('enum');
      return true;
    }

    m = lower.match(/^get-objectacl (\S+)$/);
    if(m){
      const name = m[1];
      if(name === 'domain' || name === 'corp.local' || name === 'dc=corp,dc=local'){
        print(`<span class="out-info">ACL sur l'objet domaine CORP.LOCAL (contexte de nommage) :</span>`);
        sc.acl['domain'].forEach(e => {
          if(e.normal){
            print(`<span class="out-dim">  ${e.principal} — ${e.rights}</span>`);
          } else {
            print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ droits de réplication délégués à un compte non-admin</span>`);
          }
        });
        print(`<span class="out-dim">💡 Tu es membre de CORP\\ADSync Operators : ces droits de réplication sont les tiens.</span>`);
        AttackGraph.reveal({ edges:['e_member','e_repl'] });
        complete('replacl');
        return true;
      }
      if(sc.identities[name]){
        print(`<span class="out-info">ACL sur le compte ${name} :</span>`);
        print(`<span class="out-dim">  CORP\\Domain Admins — Full Control</span>`);
        print(`<span class="out-dim">  (rien d'anormal ici — les droits de réplication se posent sur le domaine, pas sur un compte : essaie get-objectacl domain)</span>`);
        return true;
      }
      print(`<span class="out-bad">Objet introuvable : ${escapeHtml(name)}</span>`);
      return true;
    }

    m = lower.match(/^mimikatz lsadump::dcsync \/user:(\S+)$/);
    if(m){
      const target = m[1];
      const me = sc.identities[state.user];
      const hasRepl = sc.acl['domain'].some(e => !e.normal && me.groups.some(g => e.principal.toLowerCase().endsWith(g.toLowerCase())));
      if(!hasRepl){
        print(`<span class="out-bad">Accès refusé : la réplication (DCSync) nécessite les droits DS-Replication-Get-Changes-All sur le domaine.</span>`);
        return true;
      }
      const h = sc.hashes[target];
      if(!h){ print(`<span class="out-bad">Compte introuvable dans l'annuaire : ${escapeHtml(target)}</span>`); return true; }
      print(`<span class="out-info">Réplication d'annuaire demandée au contrôleur pour ${target}...</span>`);
      print(`<span class="out-good">Hash NTLM répliqué (sans droits Domain Admin) :</span>`);
      print(`<span class="out-dim">  ${target}:${h}</span>`);
      state.extra.dcsyncHash[target] = h;
      if(target === 'a.faure'){
        AttackGraph.reveal({ edges:['e_dcsync'], tags:{ 'a.faure':'hash' } });
        complete('dcsync');
      } else if(target === 'krbtgt'){
        print(`<span class="out-warn">🔑 C'est la clé qui signe tous les tickets du domaine — de quoi forger un Golden Ticket (voir le Chapitre Final). Pour cette mission, ce n'est pas nécessaire : réplique plutôt un administrateur du domaine.</span>`);
      }
      return true;
    }

    m = lower.match(/^pth \/target:(\S+) \/user:(\S+) \/hash:(\S+)$/);
    if(m){
      const user = m[2], hash = m[3];
      if(!sc.identities[user]){ print(`<span class="out-bad">Compte inconnu : ${escapeHtml(user)}</span>`); return true; }
      if(state.extra.dcsyncHash[user] !== hash){
        print(`<span class="out-bad">Authentification refusée : ce hash ne correspond pas à ${escapeHtml(user)}. Réplique d'abord son hash avec DCSync, puis rejoue-le exactement.</span>`);
        return true;
      }
      state.user = user;
      updatePrompt();
      print(`<span class="out-good">Session ouverte en tant que ${sc.identities[user].label} (Pass-the-Hash) — aucun mot de passe saisi.</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(user);
      complete('pth');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'a.faure'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\a.faure\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'a.faure'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : droits de réplication oubliés sur un compte non-admin → DCSync du hash d'un Domain Admin → Pass-the-Hash → Domain Admin. Jamais un mot de passe touché.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer qui détient DS-Replication-Get-Changes-All, traiter le compte Azure AD Connect en Tier 0, et alerter sur tout Event ID 4662 de réplication qui ne vient pas d'un contrôleur de domaine.</span>`);
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

// ---------------------------------------------------------
// SCÉNARIO 08 — DÉLÉGATION SANS CONTRAINTE + COERCITION (PETITPOTAM)
// ---------------------------------------------------------
SCENARIOS.unconstrained = {
  id:'unconstrained',
  tag:'🪤 SCÉNARIO 08 · DÉLÉGATION SANS CONTRAINTE',
  lessonTag:'📘 LEÇON · SCÉNARIO 08',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.domainComputerUnconstrained, NOISE.petitpotam, NOISE.sekurlsaTickets, NOISE.kerberosPtt, NOISE.dcsyncAny],
  startUser:'svc_web',

  identities:{
    'svc_web':  { label:'CORP\\svc_web', priv:'Administrateur local sur WEB01', groups:['Domain Users'], desc:"Compte de service applicatif — administrateur local de WEB01 uniquement, aucun droit sur le domaine" },
    'DC01$':    { label:'CORP\\DC01$', priv:'Compte machine — contrôleur de domaine', groups:['Domain Users','Domain Controllers'], desc:'Compte machine du contrôleur de domaine DC01' },
    'a.rousseau': { label:'CORP\\a.rousseau', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:'Administrateur — équipe infrastructure' }
  },

  computers:{
    'WEB01': { desc:'Serveur applicatif — hébergement intranet', unconstrained:true,
      note:"Déployé rapidement pour une intégration SSO, jamais revu depuis : coché « Approuver cet ordinateur pour la délégation à n'importe quel service » (délégation sans contrainte)." },
    'DC01':  { desc:'Contrôleur de domaine', unconstrained:true,
      note:'Un contrôleur de domaine a toujours la délégation sans contrainte activée par défaut — normal pour un DC, pas pour un serveur applicatif.' },
    'SQL01': { desc:'Serveur de base de données', unconstrained:false, note:'Délégation contrainte uniquement — rien d\'anormal ici.' }
  },

  hashes:{ 'krbtgt': 'e19ccf75ee54e06b06a5907af13cef42' },

  ticketName:'[0;3e7]-2-0-60a10000-DC01$@krbtgt-CORP.LOCAL.kirbi',

  objectives:[
    { id:'enum',    text:'Repérer les ordinateurs trustés pour la délégation sans contrainte' },
    { id:'coerce',  text:"Forcer le contrôleur de domaine à s'authentifier sur WEB01 (coercition)" },
    { id:'capture', text:'Extraire le ticket du contrôleur de domaine capturé en mémoire' },
    { id:'ptt',     text:"Rejouer ce ticket pour devenir DC01$ (Pass-the-Ticket)" },
    { id:'dcsync',  text:"Répliquer le hash de krbtgt en te faisant passer pour un contrôleur de domaine" },
  ],

  hints:[
    ["Tu es administrateur local d'un serveur, mais lequel a une configuration de délégation dangereuse ? Il faut chercher du côté des comptes machine.",
     "Il existe une commande qui liste les ordinateurs du domaine trustés pour la délégation sans contrainte.",
     "Liste les ordinateurs à délégation sans contrainte : `get-domaincomputer -unconstrained`"],
    ["WEB01 accepte n'importe quelle authentification entrante et la met en cache, y compris celle d'un contrôleur de domaine. Encore faut-il le faire venir à toi.",
     "Il existe un outil qui force une machine distante à s'authentifier sur un serveur de ton choix, en abusant d'un protocole Windows légitime (MS-EFSRPC) — sans connaître le moindre mot de passe.",
     "Force DC01 à s'authentifier sur WEB01 : `petitpotam /listener:WEB01 /target:DC01`"],
    ["Quand DC01 s'est authentifié sur WEB01, son ticket a été mis en cache en mémoire — parce que WEB01 est en délégation sans contrainte.",
     "Utilise mimikatz pour exporter les tickets Kerberos présents en mémoire sur WEB01.",
     "Exporte les tickets en cache : `mimikatz sekurlsa::tickets /export`"],
    ["Le ticket exporté est un vrai TGT du compte machine DC01$. Un TGT se rejoue directement, comme un hash.",
     "Utilise mimikatz pour injecter ce ticket dans ta session actuelle.",
     "Injecte le ticket capturé : `mimikatz kerberos::ptt <nom_du_ticket>`"],
    ["Tu es maintenant DC01$ — littéralement un contrôleur de domaine aux yeux de l'annuaire. Un DC a toujours le droit de répliquer n'importe quel secret.",
     "Réplique le hash du compte krbtgt, la clé qui signe tous les tickets du domaine.",
     "Réplique krbtgt en te faisant passer pour DC01 : `mimikatz lsadump::dcsync /user:krbtgt`"]
  ],

  manPages:{
    'get-domaincomputer': { name:'get-domaincomputer -unconstrained', role:"Liste les comptes machine trustés pour la délégation sans contrainte",
      explain:"Un ordinateur en délégation sans contrainte met en cache, en mémoire, le TGT complet de tout compte qui s'y authentifie — y compris un contrôleur de domaine. C'est censé ne concerner que les DC ; un serveur applicatif qui l'a aussi est une faille de configuration classique.",
      usage:'get-domaincomputer -unconstrained' },
    'petitpotam': { name:'petitpotam', role:"Force une machine distante à s'authentifier sur un serveur choisi (coercition)",
      explain:"Abuse du protocole MS-EFSRPC (chiffrement de fichiers à distance) pour convaincre une machine — même un contrôleur de domaine — d'ouvrir une connexion d'authentification vers un serveur que tu contrôles. Aucun mot de passe n'est nécessaire : c'est le protocole lui-même qui est détourné.",
      usage:'petitpotam /listener:<serveur_piège> /target:<machine_a_coercer>' },
    'mimikatz': { name:'mimikatz', role:'Boîte à outils post-exploitation AD',
      explain:"<code>sekurlsa::tickets /export</code> exporte tous les tickets Kerberos actuellement en mémoire sur la machine — y compris ceux capturés grâce à la délégation sans contrainte. <code>kerberos::ptt &lt;ticket&gt;</code> injecte un ticket exporté dans ta session (Pass-the-Ticket). <code>lsadump::dcsync /user:&lt;nom&gt;</code> réplique le hash d'un compte en se faisant passer pour un contrôleur de domaine — ce qui fonctionne dès lors que ton identité actuelle EST un compte machine de contrôleur de domaine.",
      usage:'mimikatz sekurlsa::tickets /export | mimikatz kerberos::ptt <ticket> | mimikatz lsadump::dcsync /user:<nom>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','get-domaincomputer -unconstrained',
    'petitpotam /listener:WEB01 /target:DC01',
    'mimikatz sekurlsa::tickets /export',
    'mimikatz kerberos::ptt ',
    'mimikatz lsadump::dcsync /user:'
  ],

  helpLine:'whoami /priv, net user /domain, get-domaincomputer -unconstrained, petitpotam /listener:&lt;serveur&gt; /target:&lt;machine&gt;, mimikatz sekurlsa::tickets /export, mimikatz kerberos::ptt &lt;ticket&gt;, mimikatz lsadump::dcsync /user:&lt;nom&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>get-domaincomputer -unconstrained<br>petitpotam /listener:&lt;serveur&gt; /target:&lt;machine&gt;<br>mimikatz sekurlsa::tickets /export<br>mimikatz kerberos::ptt &lt;ticket&gt;<br>mimikatz lsadump::dcsync /user:&lt;nom&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\svc_web sur WEB01 (administrateur local)</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🪤', title:'La délégation sans contrainte', html:
      `<p>Un ordinateur du domaine peut être configuré pour la <b>délégation sans contrainte</b> : quand un utilisateur s'y authentifie, la machine reçoit une <b>copie complète et réutilisable de son TGT</b> (son ticket d'accès complet), mise en cache en mémoire.</p>
       <p>C'est prévu pour certains cas légitimes (un DC en a toujours besoin). Le problème : ça se retrouve parfois aussi sur un simple serveur applicatif, activé par erreur ou par facilité lors d'un déploiement.</p>` },
    { icon:'📨', title:'La coercition : forcer la venue', html:
      `<p>Avoir un serveur piégé ne sert à rien si personne d'intéressant ne s'y connecte. Des outils comme <b>PetitPotam</b> abusent de protocoles Windows légitimes (MS-EFSRPC) pour <b>forcer une machine distante</b> — même un contrôleur de domaine — à initier une authentification vers un serveur choisi par l'attaquant.</p>
       <p>Aucun mot de passe, aucun clic utilisateur nécessaire : la machine cible obéit au protocole.</p>` },
    { icon:'👑', title:"Capturer un contrôleur de domaine", html:
      `<p>Si le serveur piégé est en délégation sans contrainte, le TGT du contrôleur de domaine coercé (son <b>compte machine</b>, ex. <code>DC01$</code>) est capturé en mémoire. Ce compte machine a, de fait, <b>tous les droits d'un contrôleur de domaine</b> — y compris répliquer n'importe quel secret (DCSync).</p>
       <p>Résultat : un simple accès admin local sur un serveur mal configuré mène directement au hash de <b>krbtgt</b>, la clé de voûte du domaine.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es administrateur local de <b>WEB01</b>, un serveur applicatif — rien de plus, aucun droit sur le domaine. Découvre pourquoi sa configuration de délégation est dangereuse, force le contrôleur de domaine à s'y authentifier, et capture de quoi devenir lui.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Contrôleur de domaine impersonné',
  completeSub:"Un admin local sur un serveur oublié, et voilà le domaine entier répliqué.",
  chainSteps:[
    {icon:'🪤', label:'Délégation repérée'}, {icon:'📨', label:'DC coercé'},
    {icon:'🎟️', label:'TGT capturé'}, {icon:'🧬', label:'DCSync krbtgt'}
  ],
  flag:'FLAG{unconstrained_delegation_petitpotam_dcsync_krbtgt}',

  graph:{
    nodes:[
      { id:'svc_web', label:'svc_web', type:'user' },
      { id:'web01', label:'WEB01 (délégation ⚠)', type:'group' },
      { id:'dc01', label:'DC01', type:'group' },
      { id:'dc01_machine', label:'DC01$', type:'admin' },
      { id:'krbtgt', label:'krbtgt', type:'admin' }
    ],
    edges:[
      { id:'e_local', from:'svc_web', to:'web01', type:'memberof', label:'Admin local' },
      { id:'e_coerce', from:'web01', to:'dc01', type:'auth', label:'Coercition PetitPotam' },
      { id:'e_capture', from:'dc01', to:'dc01_machine', type:'abuse', label:'TGT capturé (délégation sans contrainte)' },
      { id:'e_owned', from:'svc_web', to:'dc01_machine', type:'owned', label:'Pass-the-Ticket' },
      { id:'e_dcsync', from:'dc01_machine', to:'krbtgt', type:'auth', label:'DCSync' }
    ]
  },

  deepDive:{
    why:"La délégation sans contrainte est un réglage légitime pour les contrôleurs de domaine, mais dangereux dès qu'il se retrouve sur un serveur applicatif ordinaire : n'importe quel compte qui s'y authentifie y laisse une copie complète et réutilisable de son ticket. Combinée à la coercition (forcer une authentification, par exemple via PetitPotam et le protocole MS-EFSRPC), cette configuration permet de capturer le ticket d'un contrôleur de domaine sans jamais avoir de droit sur le domaine au départ — un simple accès administrateur local sur le mauvais serveur suffit. Une fois ce ticket rejoué, l'attaquant EST littéralement un contrôleur de domaine aux yeux de l'annuaire, avec tous les droits de réplication qui vont avec.",
    defenses:[
      "Ne jamais activer la délégation sans contrainte sur autre chose qu'un contrôleur de domaine — utiliser la délégation contrainte (ou contrainte avec authentification protégée par ressource) partout ailleurs",
      "Ajouter les comptes à privilèges (et si possible les comptes machine sensibles) au groupe « Protected Users » ou cocher « Ce compte est sensible et ne peut pas être délégué »",
      "Corriger MS-EFSRPC et les protocoles de coercition similaires (mises à jour de sécurité), et restreindre RPC/SMB entrant vers les contrôleurs de domaine depuis les serveurs applicatifs",
      "Auditer régulièrement les objets ordinateur avec l'attribut TRUSTED_FOR_DELEGATION activé — la liste doit être connue et minimale"
    ],
    quiz:[
      { q:"Que capture-t-on précisément grâce à la délégation sans contrainte ?",
        options:["Le mot de passe en clair de la machine qui s'authentifie","Une copie complète et réutilisable du TGT (ticket Kerberos) de la machine qui s'authentifie","Un hash NTLM aléatoire","Rien, la délégation sans contrainte est un mécanisme purement défensif"],
        correct:1,
        explain:"La machine en délégation sans contrainte reçoit et met en cache une copie complète du TGT de tout compte qui s'y authentifie — c'est ce ticket qui devient réutilisable par l'attaquant." },
      { q:"À quoi sert un outil de coercition comme PetitPotam dans cette chaîne d'attaque ?",
        options:["À casser un mot de passe hors-ligne","À forcer une machine distante (ex. un contrôleur de domaine) à initier une authentification vers un serveur choisi par l'attaquant","À chiffrer les fichiers de la victime","À élever discrètement ses propres droits locaux"],
        correct:1,
        explain:"Sans coercition, un serveur en délégation sans contrainte ne capture que les comptes qui s'y connectent naturellement. PetitPotam force artificiellement la venue d'une cible choisie, comme un contrôleur de domaine." },
      { q:"Pourquoi capturer le TGT du compte machine d'un contrôleur de domaine (DC01$) est-il si grave ?",
        options:["Ça ne l'est pas, un compte machine n'a aucun droit particulier","Un compte machine de contrôleur de domaine a, de fait, les droits de réplication complets sur le domaine (DCSync)","Ça permet uniquement de redémarrer le serveur","Ça ne fonctionne que si l'attaquant est déjà Domain Admin"],
        correct:1,
        explain:"Un contrôleur de domaine réplique en permanence l'annuaire avec les autres DC : son compte machine possède donc nativement les droits de réplication complets, exploitables via DCSync une fois son ticket rejoué." }
    ]
  },

  initState(){ return { ticketExported:false, ptt:false }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.unconstrained;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      Object.keys(sc.identities).forEach(name => { if(!name.endsWith('$')) print(`<span class="out-dim">  ${name}</span>`); });
      print(`<span class="out-dim">💡 Les comptes machine (ex: DC01$) n'apparaissent pas ici — cherche du côté de get-domaincomputer.</span>`);
      complete('enum');
      return true;
    }

    if(lower === 'get-domaincomputer -unconstrained'){
      print(`<span class="out-info">Ordinateurs trustés pour la délégation sans contrainte :</span>`);
      Object.entries(sc.computers).forEach(([name, c]) => {
        if(c.unconstrained){
          const warn = name === 'WEB01' ? ' ⚠ serveur applicatif — anormal' : ' (normal pour un contrôleur de domaine)';
          print(`<span class="out-warn">  ${name} — ${c.desc}${warn}</span>`);
        }
      });
      print(`<span class="out-dim">💡 Tu es administrateur local de WEB01 : n'importe quelle machine qui s'y authentifie y laisse son TGT en mémoire.</span>`);
      AttackGraph.reveal({ nodes:['svc_web','web01','dc01'], edges:['e_local'] });
      complete('enum');
      return true;
    }

    m = lower.match(/^petitpotam \/listener:(\S+) \/target:(\S+)$/);
    if(m){
      const listener = m[1].toUpperCase(), target = m[2].toUpperCase();
      if(listener !== 'WEB01' || !sc.computers[target]){
        print(`<span class="out-bad">Coercition échouée : vérifie le nom du serveur piège et de la cible (ex: WEB01 et DC01).</span>`);
        return true;
      }
      if(target !== 'DC01'){
        print(`<span class="out-warn">${target} s'authentifie bien sur WEB01, mais ce n'est pas un contrôleur de domaine — son TGT n'a pas grand intérêt. Cible plutôt DC01.</span>`);
        return true;
      }
      print(`<span class="out-info">Requête MS-EFSRPC envoyée à DC01 (prétexte : accès à un fichier chiffré sur WEB01)...</span>`);
      print(`<span class="out-good">DC01 s'authentifie sur WEB01 — son TGT (compte machine DC01$) vient d'être mis en cache en mémoire sur WEB01, où tu es administrateur local.</span>`);
      state.extra.coerced = true;
      AttackGraph.reveal({ nodes:['dc01_machine'], edges:['e_coerce','e_capture'] });
      complete('coerce');
      return true;
    }

    if(lower === 'mimikatz sekurlsa::tickets /export'){
      if(!state.extra.coerced){
        print(`<span class="out-bad">Aucun ticket intéressant en mémoire pour l'instant — force d'abord une authentification vers WEB01 avec petitpotam.</span>`);
        return true;
      }
      print(`<span class="out-info">Export des tickets Kerberos en mémoire sur WEB01...</span>`);
      print(`<span class="out-good">Ticket exporté :</span>`);
      print(`<span class="out-dim">  ${sc.ticketName}</span>`);
      state.extra.ticketExported = true;
      complete('capture');
      return true;
    }

    m = lower.match(/^mimikatz kerberos::ptt (\S+)$/);
    if(m){
      if(!state.extra.ticketExported){
        print(`<span class="out-bad">Aucun ticket exporté à injecter — exporte d'abord les tickets en mémoire avec sekurlsa::tickets /export.</span>`);
        return true;
      }
      if(m[1] !== sc.ticketName.toLowerCase()){
        print(`<span class="out-bad">Ticket introuvable ou nom incorrect. Réutilise exactement le nom de fichier renvoyé par l'export.</span>`);
        return true;
      }
      state.user = 'DC01$';
      state.extra.ptt = true;
      updatePrompt();
      print(`<span class="out-good">Ticket injecté avec succès — tu es désormais CORP\\DC01$ aux yeux de l'annuaire (Pass-the-Ticket).</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned('dc01_machine');
      complete('ptt');
      return true;
    }

    m = lower.match(/^mimikatz lsadump::dcsync \/user:(\S+)$/);
    if(m){
      const target = m[1];
      if(!state.extra.ptt){
        print(`<span class="out-bad">Accès refusé : la réplication (DCSync) nécessite d'être authentifié comme un contrôleur de domaine. Injecte d'abord le ticket capturé.</span>`);
        return true;
      }
      if(target !== 'krbtgt'){
        print(`<span class="out-warn">Réplication possible, mais c'est le hash de krbtgt qui referme cette chaîne d'attaque (clé de tous les tickets du domaine).</span>`);
        return true;
      }
      const h = sc.hashes['krbtgt'];
      print(`<span class="out-info">Réplication d'annuaire demandée au contrôleur pour krbtgt, en tant que CORP\\DC01$...</span>`);
      print(`<span class="out-good">Hash NTLM de krbtgt répliqué :</span>`);
      print(`<span class="out-dim">  krbtgt:${h}</span>`);
      AttackGraph.reveal({ edges:['e_dcsync'] });
      print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
      print(`<span class="out-good">🎉 Bravo — chaîne complète : admin local sur un serveur en délégation sans contrainte → coercition du DC (PetitPotam) → capture du TGT DC01$ → Pass-the-Ticket → DCSync de krbtgt. Aucun mot de passe touché, aucun droit de domaine possédé au départ.</span>`);
      print(`<span class="out-dim">🛡️ Pour se défendre : bannir la délégation sans contrainte hors des contrôleurs de domaine, corriger les vecteurs de coercition (MS-EFSRPC), et protéger les comptes sensibles contre la délégation.</span>`);
      complete('dcsync');
      finishMission();
      return true;
    }

    return false;
  }
};
