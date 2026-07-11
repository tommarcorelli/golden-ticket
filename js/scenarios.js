// ═══════════════════════════════════════════════════════════
// Données & logique spécifiques à chaque scénario.
// Le moteur générique (terminal.js) délègue ici via sc.handle().
// ═══════════════════════════════════════════════════════════

const SCENARIOS = {};

// ---------------------------------------------------------
// SCÉNARIO 01 — KERBEROASTING
// ---------------------------------------------------------
SCENARIOS.kerberoast = {
  id:'kerberoast',
  tag:'🎫 SCÉNARIO 01 · KERBEROASTING',
  lessonTag:'📘 LEÇON · SCÉNARIO 01',
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
    ["Tu ne connais encore aucun compte du domaine. Il existe une commande pour tous les lister.",
     "Commence par lister les comptes du domaine : `net user /domain`"],
    ["Un type de compte est particulièrement exposé au Kerberoasting : celui qui a un SPN (Service Principal Name) associé à un service.",
     "Un des comptes ressemble à un compte de service (préfixe svc_). Regarde ses détails avec `net user svc_backup /domain`, ou liste directement les comptes vulnérables avec `get-domainuser -spn`."],
    ["Tout utilisateur authentifié peut demander le ticket Kerberos chiffré d'un compte ayant un SPN — sans alerter personne.",
     "Une fois le compte identifié, demande son ticket Kerberos avec `invoke-kerberoast -identity svc_backup`"],
    ["Ce ticket est chiffré avec le mot de passe du compte de service. S'il est faible, il peut être retrouvé hors-ligne.",
     "Le ticket obtenu est un hash. Essaie de le cracker avec `crack <hash>`"],
    ["Tu as maintenant un mot de passe valide pour un autre compte. Windows a une commande dédiée pour ouvrir une session sous une autre identité.",
     "Une fois le mot de passe en clair, ouvre une session avec `runas /user:svc_backup cmd`"],
    ["Le compte que tu contrôles appartient à un groupe avec des droits particuliers sur les fichiers. Regarde ce qu'il peut lire.",
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
      complete('access');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'svc_backup'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\Administrator\\Desktop</span>`);
        print(`<span class="out-dim">  [droits Backup Operators : lecture autorisée malgré les ACL]</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
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
    ["Ce chapitre reprend le tout premier scénario : identifie les comptes du domaine, puis repère celui qui a un SPN exploitable.",
     "Commence comme au chapitre 1 : `net user /domain`, puis `get-domainuser -spn`"],
    ["Une fois le compte de service repéré, tu peux demander son ticket Kerberos et tenter de le casser hors-ligne.",
     "Demande le ticket du compte de service, puis casse-le : `invoke-kerberoast -identity svc_backup` puis `crack <hash>`"],
    ["Un mot de passe valide en poche, il existe une commande Windows pour ouvrir une session sous cette identité.",
     "Ouvre une session avec ce compte : `runas /user:svc_backup cmd`"],
    ["En tant que ce compte de service, cherche si quelqu'un a des droits inhabituels sur un compte à privilèges.",
     "En tant que svc_backup, regarde qui a des droits sur les comptes à privilège : `get-objectacl h.morel`"],
    ["Un droit oublié permet de changer le mot de passe d'un compte sans le connaître. Utilise-le, puis connecte-toi avec.",
     "Réinitialise le mot de passe grâce à ce droit oublié, puis connecte-toi : `set-domainuserpassword -identity h.morel -newpassword <ton_choix>` puis `runas /user:h.morel cmd`"],
    ["Te voilà Domain Admin. Un compte spécial signe cryptographiquement tous les tickets Kerberos du domaine — ce niveau de privilège permet d'en extraire la clé.",
     "Tu es Domain Admin. Extrais la clé qui signe tous les tickets du domaine : `mimikatz lsadump::dcsync /user:krbtgt`"],
    ["Cette clé permet de forger n'importe quel ticket, pour n'importe quelle identité, à volonté. C'est exactement ça, un Golden Ticket.",
     "Utilise cette clé pour forger un ticket illimité : `mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:<hash>`"],
    ["Le domaine est entièrement à toi désormais. Va voir ce qu'il y a sur le bureau du contrôleur de domaine.",
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
      if(entries.some(e => !e.normal)) complete('acl');
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
    ["Tu ne sais pas encore qui, dans ce domaine, a des privilèges élevés. Une commande liste tous les comptes.",
     "Commence par voir qui est qui dans le domaine : `net user /domain`"],
    ["Un compte Domain Admin a peut-être hérité d'une permission qu'il ne devrait pas avoir. Il existe une commande pour lister les droits (ACL) sur un compte précis.",
     "h.morel a l'air intéressant (Domain Admin). Regarde qui a des droits sur son compte : `get-objectacl h.morel`"],
    ["Un droit qui donne un contrôle quasi-total sur un objet permet aussi de changer son mot de passe, sans le connaître.",
     "Un compte qui ne devrait pas avoir de droits ici en a pourtant (GenericAll). Ce droit permet de tout changer sur le compte cible — y compris son mot de passe : `set-domainuserpassword -identity h.morel -newpassword <ton_choix>`"],
    ["Une fois le mot de passe changé, il existe une commande Windows pour ouvrir une session sous cette identité.",
     "Une fois le mot de passe réinitialisé, connecte-toi : `runas /user:h.morel cmd`"],
    ["Tu es désormais Domain Admin. Regarde ce que ton nouveau compte peut lire.",
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
      if(entries.some(e => !e.normal)) complete('acl');
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
    ["Avant de chercher ailleurs, il peut valoir le coup de regarder ce qui traîne déjà en mémoire sur ce poste.",
     "Avant de chercher sur le réseau, regarde ce qui traîne en mémoire sur ce poste : `mimikatz sekurlsa::logonpasswords`"],
    ["Ce hash appartient à un compte administrateur *local*. Une mauvaise pratique très répandue le rend réutilisable ailleurs.",
     "Tu as un hash NTLM d'un compte Administrateur *local*. Beaucoup d'entreprises réutilisent le même mot de passe admin local sur toutes leurs machines..."],
    ["Un hash NTLM peut s'utiliser directement pour s'authentifier, sans jamais avoir besoin de le casser.",
     "Utilise ce hash directement, sans le casser, pour ouvrir une session ailleurs : `pth /target:SRV-FILES01 /user:Administrator /hash:<hash>`"],
    ["Te voilà connecté à un autre poste avec les droits admin. Regarde ce qu'il y a sur son bureau.",
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
