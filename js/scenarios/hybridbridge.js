
// ---------------------------------------------------------
// CHAPITRE FINAL II — LE PONT HYBRIDE
// Compromettre le serveur Azure AD Connect, c'est compromettre
// à la fois l'AD on-prem (DCSync → Golden Ticket) ET le tenant
// cloud Entra ID (Global Administrator) — un seul pivot, deux royaumes.
// ---------------------------------------------------------
SCENARIOS.hybridbridge = {
  id:'hybridbridge',
  epic:true,
  tag:'🌉 CHAPITRE FINAL II · LE PONT HYBRIDE',
  lessonTag:'📘 LEÇON · CHAPITRE FINAL II',
  opsecEnabled:true,
  noiseRules:[NOISE.dumpAdsyncDb, NOISE.decryptAdsyncCreds, NOISE.dcsyncAny, NOISE.mimikatzGolden, NOISE.connectMguser],
  startUser:'svc_web',

  identities:{
    'svc_web':    { label:'CORP\\svc_web', priv:'Administrateur local sur SRV-ADCONNECT01', groups:['Domain Users'], desc:"Compte de service applicatif, réutilisé ici comme point d'entrée — administrateur local du serveur qui héberge Azure AD Connect" },
    'svc_adsync': { label:'CORP\\svc_adsync', priv:'Compte de service (non-admin) — droits de réplication AD délégués', groups:['Domain Users','ADSync Operators'], desc:"Compte de synchronisation on-prem d'Azure AD Connect" }
  },

  ONPREM_PASSWORD:'AdSync_C0nn3ct0r!2021',
  CLOUD_ACCOUNT:'sync_srv-adconnect01@corp.onmicrosoft.com',
  CLOUD_SECRET:'Hybrid-Sync-9f3a2e1c',
  KRBTGT_HASH:'ff87f8f2f8dfd7c0d1ae1c8f9b3a3e51',

  objectives:[
    { id:'enum',       text:"Localiser la base de configuration ADSync sur le serveur" },
    { id:'decrypt',    text:"Déchiffrer les deux identifiants de connecteur qu'elle contient" },
    { id:'pivot',      text:"Prendre l'identité du connecteur on-prem (svc_adsync)" },
    { id:'dcsync',     text:"Répliquer le hash du compte krbtgt" },
    { id:'forge',      text:'Forger un Golden Ticket (royaume on-prem conquis)' },
    { id:'cloudauth',  text:"S'authentifier avec le connecteur cloud — Global Administrator du tenant" },
    { id:'flag',       text:'Récupérer le flag du pont hybride (les deux royaumes, un seul pivot)' },
  ],

  hints:[
    ["Azure AD Connect doit bien stocker ses identifiants quelque part sur le serveur qui l'héberge — regarde ce qu'il y a sur ce poste.",
     "Il existe une commande pour lire la base de configuration locale d'ADSync (une base SQL Server Express embarquée).",
     "Localise la base ADSync : `dump-adsyncdb`"],
    ["Les identifiants stockés dans cette base sont chiffrés — mais avec une clé propre à CETTE machine, sur laquelle tu es déjà administrateur.",
     "Il existe une commande pour déchiffrer ces identifiants localement, en utilisant les clés DPAPI de la machine.",
     "Déchiffre les deux jeux d'identifiants : `decrypt-adsynccreds`"],
    ["Tu as maintenant le mot de passe en clair du connecteur on-prem.",
     "Ouvre une session avec ce compte, comme tu l'as déjà fait ailleurs.",
     "Prends l'identité du connecteur on-prem : `runas /user:svc_adsync cmd`"],
    ["Ce compte a gardé des droits de réplication délégués sur le domaine — comme tu l'as vu ailleurs, ça suffit pour DCSync.",
     "Réplique le hash du compte krbtgt, la clé qui signe tous les tickets du domaine.",
     "Réplique krbtgt : `mimikatz lsadump::dcsync /user:krbtgt`"],
    ["Avec la clé krbtgt en main, tu peux forger un ticket Kerberos illimité pour n'importe quelle identité.",
     "Utilise cette clé pour forger un Golden Ticket.",
     "Forge le ticket : `mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:<hash>`"],
    ["La base ADSync ne contenait pas qu'un seul identifiant — il y en avait un second, pour le connecteur cloud.",
     "Authentifie-toi auprès d'Entra ID avec ce second identifiant.",
     "Connecte-toi au tenant cloud : `connect-mguser -user sync_srv-adconnect01@corp.onmicrosoft.com -password <secret_déchiffré>`"],
    ["Un seul serveur compromis, et les deux royaumes (on-prem et cloud) te répondent maintenant.",
     "Regarde ce que ce double accès te permet de récupérer.",
     "Le pont hybride est franchi. `dir` puis `type flag.txt`."]
  ],

  manPages:{
    'dump-adsyncdb': { name:'dump-adsyncdb', role:'Extrait les identifiants chiffrés stockés par Azure AD Connect',
      explain:"Azure AD Connect stocke, dans une base SQL Server Express locale, les identifiants de <b>deux connecteurs</b> : celui utilisé pour synchroniser l'annuaire on-prem, et celui utilisé pour écrire dans le tenant Entra ID. Les deux sont chiffrés, mais présents sur le disque du serveur.",
      usage:'dump-adsyncdb' },
    'decrypt-adsynccreds': { name:'decrypt-adsynccreds', role:"Déchiffre localement les identifiants extraits",
      explain:"Le chiffrement de ces identifiants repose sur les clés DPAPI de la machine elle-même — n'importe quel administrateur local du serveur Azure AD Connect peut donc les déchiffrer, exactement comme le fait légitimement le service au démarrage. C'est le cœur de cette attaque : un seul serveur compromis livre les deux royaumes.",
      usage:'decrypt-adsynccreds' },
    'runas': { name:'runas /user', role:"Ouvre une session avec un autre compte",
      explain:"Une fois le mot de passe en clair obtenu, tu peux te reconnecter avec l'identité (et donc les droits) de ce compte.",
      usage:'runas /user:<nom> cmd' },
    'mimikatz': { name:'mimikatz', role:'Boîte à outils post-exploitation AD',
      explain:"<code>lsadump::dcsync /user:krbtgt</code> réplique la clé qui signe tous les tickets Kerberos du domaine, via les droits de réplication du connecteur on-prem. <code>kerberos::golden</code> utilise ensuite cette clé pour forger un ticket valide pour n'importe quelle identité, à volonté.",
      usage:'mimikatz lsadump::dcsync /user:krbtgt   |   mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:<hash>' },
    'connect-mguser': { name:'connect-mguser', role:'Authentifie une session auprès du tenant Entra ID',
      explain:"Le connecteur cloud d'Azure AD Connect est lui-même un compte du tenant Entra ID, avec des privilèges élevés pour pouvoir écrire dans l'annuaire cloud. Ses identifiants s'utilisent comme ceux de n'importe quel compte.",
      usage:'connect-mguser -user <compte> -password <secret>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'dump-adsyncdb','decrypt-adsynccreds','runas /user:svc_adsync cmd',
    'mimikatz lsadump::dcsync /user:krbtgt',
    'mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:',
    'connect-mguser -user sync_srv-adconnect01@corp.onmicrosoft.com -password ',
    'dir','type '
  ],

  helpLine:'whoami /priv, dump-adsyncdb, decrypt-adsynccreds, runas /user:&lt;nom&gt; cmd, mimikatz lsadump::dcsync /user:krbtgt, mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:&lt;hash&gt;, connect-mguser -user &lt;compte&gt; -password &lt;secret&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>dump-adsyncdb<br>decrypt-adsynccreds<br>runas /user:&lt;nom&gt; cmd<br>mimikatz lsadump::dcsync /user:krbtgt<br>mimikatz kerberos::golden /user:Administrator /id:500 /krbtgt:&lt;hash&gt;<br>connect-mguser -user &lt;compte&gt; -password &lt;secret&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\svc_web sur SRV-ADCONNECT01 (administrateur local)</span>`,
    `<span class="out-warn">🌉 Chapitre final II — un seul serveur, deux royaumes à conquérir.</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🌉', title:"L'identité hybride : un pont entre deux mondes", html:
      `<p>CORP.LOCAL n'existe plus seulement sur site : <b>Azure AD Connect</b> synchronise en permanence l'annuaire on-prem vers le tenant cloud <b>Entra ID</b>. Ce pont est indispensable au quotidien — et c'est justement ce qui en fait une cible de choix.</p>
       <p>Ce chapitre combine deux techniques déjà vues (DCSync et l'authentification Entra ID) autour d'un seul point de pivot : le serveur qui héberge ce pont.</p>` },
    { icon:'🗄️', title:'Deux connecteurs, une seule base', html:
      `<p>Pour fonctionner, Azure AD Connect a besoin des identifiants de <b>deux connecteurs</b> : un pour lire/écrire dans l'AD on-prem, un pour écrire dans Entra ID. Les deux sont stockés, chiffrés, dans une base SQL Server Express <b>locale au serveur</b>.</p>
       <p>Le chiffrement repose sur les clés DPAPI de la machine elle-même — ce qui veut dire qu'un administrateur local de ce serveur peut les déchiffrer, exactement comme le service le fait pour fonctionner.</p>` },
    { icon:'👑', title:'Un seul pivot, deux royaumes', html:
      `<p>Le connecteur on-prem a gardé des droits de réplication (DCSync) — de quoi extraire <b>krbtgt</b> et forger un Golden Ticket, comme tu l'as déjà fait. Le connecteur cloud, lui, dispose souvent de privilèges élevés dans Entra ID pour pouvoir y écrire — jusqu'au <b>Global Administrator</b> dans les configurations les moins durcies.</p>
       <p>Compromettre ce seul serveur, c'est donc potentiellement compromettre <b>les deux mondes à la fois</b> — c'est pourquoi Azure AD Connect doit être traité comme un actif Tier 0, au même titre qu'un contrôleur de domaine.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es déjà <b>administrateur local de SRV-ADCONNECT01</b>, le serveur qui héberge Azure AD Connect. Extrais et déchiffre les deux identifiants qu'il protège, conquiers l'AD on-prem par DCSync et Golden Ticket, puis le tenant cloud par le connecteur Entra ID — jusqu'au pont hybride complet.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'🌉 PONT HYBRIDE FRANCHI',
  completeSub:'Un seul serveur compromis — le domaine on-prem ET le tenant cloud tombent ensemble.',
  certLabel:'Pont Hybride',
  certDomainLine:"pour avoir compromis à la fois le domaine on-prem CORP.LOCAL et le tenant cloud corp.onmicrosoft.com",
  chainSteps:[
    {icon:'🗄️', label:'Base ADSync'}, {icon:'🔓', label:'Identifiants déchiffrés'},
    {icon:'🧬', label:'DCSync + Golden Ticket'}, {icon:'☁️', label:'Global Admin cloud'}
  ],
  flag:'FLAG{hybrid_bridge_adconnect_dual_realm_compromise}',

  graph:{
    nodes:[
      { id:'svc_web', label:'svc_web', type:'user' },
      { id:'adsyncdb', label:'Base ADSync (chiffrée)', type:'group' },
      { id:'svc_adsync', label:'svc_adsync (on-prem)', type:'service' },
      { id:'krbtgt', label:'krbtgt', type:'admin' },
      { id:'golden', label:'Golden Ticket', type:'admin' },
      { id:'cloudsync', label:'sync_srv-adconnect01 (cloud)', type:'app' },
      { id:'globaladmin', label:'Global Administrator', type:'admin' }
    ],
    edges:[
      { id:'e_dump', from:'svc_web', to:'adsyncdb', type:'auth', label:'Admin local — lecture base' },
      { id:'e_onprem', from:'adsyncdb', to:'svc_adsync', type:'abuse', label:'Identifiant on-prem déchiffré' },
      { id:'e_dcsync', from:'svc_adsync', to:'krbtgt', type:'auth', label:'DCSync' },
      { id:'e_forge', from:'krbtgt', to:'golden', type:'owned', label:'Ticket forgé' },
      { id:'e_cloud', from:'adsyncdb', to:'cloudsync', type:'abuse', label:'Identifiant cloud déchiffré' },
      { id:'e_globaladmin', from:'cloudsync', to:'globaladmin', type:'owned', label:'Authentification Entra ID' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1552.001', name:"Unsecured Credentials: Credentials In Files"}, {id:'T1003.006', name:"OS Credential Dumping: DCSync"}, {id:'T1078.004', name:"Valid Accounts: Cloud Accounts"}],
    why:"Azure AD Connect existe pour faire le pont entre un annuaire on-prem et un tenant cloud — ce qui signifie qu'il détient, sur un seul serveur, des identifiants capables d'agir des deux côtés. Ces identifiants sont chiffrés, mais avec les clés DPAPI de la machine elle-même : n'importe quel administrateur local de ce serveur peut donc les déchiffrer, exactement comme le service le fait pour fonctionner. Résultat, un unique serveur compromis peut livrer à la fois les droits de réplication on-prem (menant à krbtgt et à un Golden Ticket) et un compte cloud à privilèges élevés dans Entra ID — parfois jusqu'au Global Administrator, quand ce connecteur n'a pas été correctement restreint au rôle minimal nécessaire (Directory Synchronization Accounts).",
    defenses:[
      "Traiter tout serveur Azure AD Connect comme un actif Tier 0, au même titre qu'un contrôleur de domaine : accès restreint, durci, surveillé en continu",
      "Vérifier que le connecteur cloud dispose uniquement du rôle Directory Synchronization Accounts, jamais de Global Administrator",
      "Déployer Azure AD Connect en topologie « staging server » ou avec Seamless SSO durci, et isoler le serveur du reste du réseau utilisateur",
      "Auditer régulièrement les droits de réplication (DS-Replication-Get-Changes-All) du compte de synchronisation on-prem, et les limiter au strict nécessaire",
      "Surveiller toute activité de lecture anormale sur la base de configuration ADSync locale (accès fichier, exécution d'outils d'extraction connus)"
    ],
    quiz:[
      { q:"Pourquoi la compromission du serveur Azure AD Connect est-elle si grave ?",
        options:["Elle ne permet d'accéder qu'à des rapports de synchronisation, sans droits réels","Elle peut livrer à la fois les droits de réplication on-prem ET un compte à privilèges dans le tenant cloud, depuis un seul serveur","Elle ne fonctionne que si le serveur est un contrôleur de domaine","Elle n'affecte que les utilisateurs créés après son installation"],
        correct:1,
        explain:"Ce serveur détient les identifiants des deux connecteurs (on-prem et cloud) : un seul point de compromission peut donc ouvrir les deux royaumes à la fois." },
      { q:"Pourquoi un administrateur local du serveur Azure AD Connect peut-il déchiffrer les identifiants stockés dans sa base ADSync ?",
        options:["Parce qu'ils sont stockés en clair par défaut","Parce que leur chiffrement repose sur les clés DPAPI de la machine elle-même, disponibles à tout administrateur local","Parce que Microsoft fournit une clé maître universelle","Ce n'est pas possible, la base est protégée par un mot de passe unique"],
        correct:1,
        explain:"DPAPI lie le chiffrement à la machine : un administrateur local peut donc déchiffrer ces secrets exactement comme le service ADSync le fait lui-même au démarrage." },
      { q:"Quelle mesure limite le mieux l'impact d'une compromission de ce serveur côté cloud ?",
        options:["S'assurer que le connecteur cloud n'a que le rôle Directory Synchronization Accounts, jamais Global Administrator","Désactiver complètement la synchronisation hybride","Changer le mot de passe de tous les utilisateurs chaque semaine","Autoriser l'accès au serveur depuis n'importe quel poste du réseau"],
        correct:0,
        explain:"Un connecteur cloud correctement restreint au rôle Directory Synchronization Accounts limite fortement ce qu'un attaquant peut faire dans le tenant, même s'il obtient ses identifiants."}
    ]
  },

  initState(){ return { dumped:false, decrypted:false, onpremPassword:null, cloudSecret:null, krbtgtHash:null, forged:false }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.hybridbridge;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'dump-adsyncdb'){
      print(`<span class="out-info">Lecture de la base de configuration ADSync (SQL Server Express local, instance ADSYNC)...</span>`);
      print(`<span class="out-good">Deux identifiants de connecteur trouvés (chiffrés, DPAPI) :</span>`);
      print(`<span class="out-dim">  [1] Connecteur AD DS (on-prem, CORP.LOCAL) — blob chiffré</span>`);
      print(`<span class="out-dim">  [2] Connecteur Azure Active Directory (cloud, corp.onmicrosoft.com) — blob chiffré</span>`);
      print(`<span class="out-dim">💡 Le chiffrement repose sur les clés DPAPI de cette machine — un admin local peut les déchiffrer.</span>`);
      state.extra.dumped = true;
      AttackGraph.reveal({ nodes:['svc_web','adsyncdb'], edges:['e_dump'] });
      complete('enum');
      return true;
    }

    if(lower === 'decrypt-adsynccreds'){
      if(!state.extra.dumped){
        print(`<span class="out-bad">Rien à déchiffrer pour l'instant — localise d'abord la base avec dump-adsyncdb.</span>`);
        return true;
      }
      print(`<span class="out-info">Déchiffrement local via les clés DPAPI de la machine...</span>`);
      print(`<span class="out-good">Connecteur on-prem : CORP\\svc_adsync — mot de passe : ${sc.ONPREM_PASSWORD}</span>`);
      print(`<span class="out-good">Connecteur cloud   : ${sc.CLOUD_ACCOUNT} — secret : ${sc.CLOUD_SECRET}</span>`);
      state.extra.decrypted = true;
      state.extra.onpremPassword = sc.ONPREM_PASSWORD;
      state.extra.cloudSecret = sc.CLOUD_SECRET;
      AttackGraph.reveal({ nodes:['svc_adsync','cloudsync'], edges:['e_onprem','e_cloud'] });
      complete('decrypt');
      return true;
    }

    m = lower.match(/^runas \/user:(\S+) cmd$/);
    if(m){
      const target = m[1];
      if(target !== 'svc_adsync'){
        print(`<span class="out-bad">Identité inconnue ou identifiants non déchiffrés pour ce compte : ${escapeHtml(target)}</span>`);
        return true;
      }
      if(!state.extra.decrypted){
        print(`<span class="out-bad">Tu n'as pas encore déchiffré le mot de passe de svc_adsync — utilise decrypt-adsynccreds d'abord.</span>`);
        return true;
      }
      state.user = 'svc_adsync';
      updatePrompt();
      print(`<span class="out-good">Session ouverte en tant que CORP\\svc_adsync (connecteur on-prem).</span>`);
      complete('pivot');
      return true;
    }

    if(lower === 'mimikatz lsadump::dcsync /user:krbtgt'){
      if(state.user !== 'svc_adsync'){
        print(`<span class="out-bad">Accès refusé : la réplication (DCSync) nécessite les droits du connecteur on-prem svc_adsync.</span>`);
        return true;
      }
      print(`<span class="out-info">Réplication d'annuaire demandée au contrôleur pour krbtgt...</span>`);
      print(`<span class="out-good">Hash NTLM de krbtgt répliqué :</span>`);
      print(`<span class="out-dim">  krbtgt:${sc.KRBTGT_HASH}</span>`);
      state.extra.krbtgtHash = sc.KRBTGT_HASH;
      AttackGraph.reveal({ edges:['e_dcsync'] });
      complete('dcsync');
      return true;
    }

    m = lower.match(/^mimikatz kerberos::golden \/user:administrator \/id:500 \/krbtgt:(\S+)$/);
    if(m){
      if(m[1] !== sc.KRBTGT_HASH){
        print(`<span class="out-bad">Hash krbtgt incorrect ou pas encore répliqué.</span>`);
        return true;
      }
      print(`<span class="out-good">👑 Golden Ticket forgé pour CORP\\Administrator — royaume on-prem conquis.</span>`);
      state.extra.forged = true;
      AttackGraph.reveal({ nodes:['golden'], edges:['e_forge'] });
      complete('forge');
      return true;
    }

    m = cmd.match(/^connect-mguser -user (\S+) -password (\S+)$/i);
    if(m){
      const [, user, secret] = m;
      if(user.toLowerCase() !== sc.CLOUD_ACCOUNT){
        print(`<span class="out-bad">Compte inconnu ou non pertinent : ${escapeHtml(user)}</span>`);
        return true;
      }
      if(!state.extra.decrypted || secret !== sc.CLOUD_SECRET){
        print(`<span class="out-bad">Authentification refusée : secret incorrect.</span>`);
        return true;
      }
      print(`<span class="out-good">Accès accordé — connecté en tant que ${sc.CLOUD_ACCOUNT} (Global Administrator du tenant).</span>`);
      state.extra.cloudAuth = true;
      AttackGraph.reveal({ nodes:['globaladmin'], edges:['e_globaladmin'] });
      complete('cloudauth');
      return true;
    }

    if(lower === 'dir'){
      if(state.extra.forged && state.extra.cloudAuth){
        print(`<span class="out-info"> Coffre du pont hybride : kv-hybrid-bridge</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-dim">(rien d'exploitable ici pour l'instant — il te manque un des deux royaumes)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.extra.forged && state.extra.cloudAuth){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — un seul serveur (Azure AD Connect) compromis, et les deux royaumes tombent : Golden Ticket on-prem ET Global Administrator cloud, à partir des mêmes identifiants déchiffrés localement.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : traiter Azure AD Connect comme un actif Tier 0, restreindre le connecteur cloud au rôle Directory Synchronization Accounts, et surveiller étroitement ce serveur (voir "En savoir plus").</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : il te manque encore un des deux royaumes (Golden Ticket forgé et/ou Global Admin cloud).</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};
