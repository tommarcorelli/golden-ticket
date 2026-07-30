
// ---------------------------------------------------------
// MODE LIBRE — DOMAINE OUVERT, PLUSIEURS CHEMINS VALABLES
// Combine les 3 techniques précédentes. Deux chaînes d'attaque
// distinctes mènent toutes deux à Domain Admin — au joueur de choisir.
// ---------------------------------------------------------
SCENARIOS.libre = {
  id:'libre',
  cmdBudget:10,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
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

  counterMeasure:{
    label:'Audit ACL généralisé + LAPS',
    briefing:"🛡️ Contre-mesure appliquée : deux défenses vues séparément dans des scénarios précédents ont été déployées ensemble ici. L'audit des ACL a retiré tous les droits délégués par erreur sur les comptes à privilège (directs ou hérités d'un groupe), et LAPS assure désormais un mot de passe administrateur local unique par machine. Les trois chemins connus vers p.chevalier sont fermés — pas seulement un."
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
    mitre:[{id:'T1558.003', name:"Steal or Forge Kerberos Tickets: Kerberoasting"}, {id:'T1550.002', name:"Use Alternate Authentication Material: Pass the Hash"}, {id:'T1098', name:"Account Manipulation"}],
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
      if(state.mitigationApplied && matched){
        print(`<span class="out-bad">Accès refusé (0x80070005) : droits insuffisants sur ce compte.</span>`);
        print(`<span class="out-dim">💡 Ce droit délégué par erreur (direct ou hérité d'un groupe) a été retiré lors de l'audit des ACL.</span>`);
        return true;
      }
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
      if(state.mitigationApplied){
        print(`<span class="out-bad">Authentification refusée : hash ou utilisateur incorrect.</span>`);
        print(`<span class="out-dim">💡 LAPS est désormais déployé : le mot de passe admin local est unique et tourné automatiquement par machine — ce hash ne vaut plus rien ailleurs.</span>`);
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
