
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
  cmdBudget:8,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
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

  counterMeasure:{
    label:'Restriction des droits de réplication',
    briefing:"🛡️ Contre-mesure appliquée : les droits de réplication délégués par erreur à CORP\\ADSync Operators ont été retirés lors de l'audit. Seuls les contrôleurs de domaine et les comptes d'administration du domaine les possèdent désormais."
  },
  deepDive:{
    mitre:[{id:'T1003.006', name:"OS Credential Dumping: DCSync"}],
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
      const hasRepl = !state.mitigationApplied && sc.acl['domain'].some(e => !e.normal && me.groups.some(g => e.principal.toLowerCase().endsWith(g.toLowerCase())));
      if(!hasRepl){
        print(`<span class="out-bad">Accès refusé : la réplication (DCSync) nécessite les droits DS-Replication-Get-Changes-All sur le domaine.</span>`);
        if(state.mitigationApplied){
          print(`<span class="out-dim">💡 Les droits délégués par erreur à CORP\\ADSync Operators ont été retirés lors de l'audit. Seuls les contrôleurs de domaine et les comptes d'administration du domaine les possèdent désormais.</span>`);
        }
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
