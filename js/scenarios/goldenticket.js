
// ---------------------------------------------------------
// CHAPITRE FINAL — LE VRAI GOLDEN TICKET
// Enchaîne Kerberoasting → Abus d'ACL → extraction krbtgt → forge du ticket
// ---------------------------------------------------------
SCENARIOS.goldenticket = {
  id:'goldenticket',
  cmdBudget:12,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
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
  certLabel:'Golden Ticket',
  certDomainLine:'pour avoir compromis intégralement le domaine CORP.LOCAL',
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
    mitre:[{id:'T1558.001', name:"Steal or Forge Kerberos Tickets: Golden Ticket"}, {id:'T1003.006', name:"OS Credential Dumping: DCSync"}, {id:'T1558.003', name:"Steal or Forge Kerberos Tickets: Kerberoasting"}, {id:'T1098', name:"Account Manipulation"}],
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
