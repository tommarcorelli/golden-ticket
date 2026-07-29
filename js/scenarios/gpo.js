
// ---------------------------------------------------------
// SCÉNARIO 10 — ABUS DE GPO (délégation copiée sur le mauvais objet)
// Le twist pédagogique : la délégation GPO du joueur est parfaitement
// légitime sur son périmètre d'origine (une GPO d'impression) — mais
// elle a été recopiée « pour aller plus vite » sur une deuxième GPO,
// liée cette fois à une OU de serveurs applicatifs. Le joueur peut
// abuser des DEUX GPO de la même façon (Restricted Groups), mais une
// seule mène à un compte Domain Admin qui vient s'y connecter — les
// indices comptent plus que la simple répétition de la commande.
// ---------------------------------------------------------
SCENARIOS.gpo = {
  id:'gpo',
  cmdBudget:12,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
  tag:'🧩 SCÉNARIO 10 · ABUS DE GPO',
  lessonTag:'📘 LEÇON · SCÉNARIO 10',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.domainGpoEnum, NOISE.objectAcl, NOISE.gpoAbuse, NOISE.gpupdateForce, NOISE.mimikatzLogon, NOISE.pth],
  startUser:'t.giraud',

  NTLM_HASH:'a4f1c9d8b6e23f0d7a5c1e9b3f6d0a82',

  identities:{
    't.giraud': { label:'CORP\\t.giraud', priv:'Utilisateur standard', groups:['Domain Users','Helpdesk - GPO Imprimantes'],
      desc:"Technicien support — délégué depuis deux ans pour gérer la GPO de déploiement des imprimantes réseau" },
    'm.faure': { label:'CORP\\m.faure', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'],
      desc:"Responsable infrastructure — se connecte régulièrement sur SRV-APP03 pour la maintenance applicative" }
  },

  // GPO du domaine : nom → OU de liaison, description, postes concernés.
  gpos:{
    'GPO-Imprimantes-Agences': { linkedOU:'OU=Postes de travail,DC=corp,DC=local', desc:"Déploiement des files d'attente d'imprimantes réseau", computers:['WKS-021','WKS-034'] },
    'GPO-AppServers-Baseline': { linkedOU:'OU=Serveurs Applicatifs,DC=corp,DC=local', desc:'Paramètres de sécurité de base des serveurs applicatifs', computers:['SRV-APP03','SRV-APP07'] }
  },

  // ACL simulées sur les objets GPO eux-mêmes (pas sur des comptes).
  // Le même groupe a un droit d'édition sur les deux GPO : c'est
  // légitime sur la première (son périmètre d'origine), mais copié
  // par erreur sur la seconde — bien plus dangereuse à abuser.
  acl:{
    'GPO-Imprimantes-Agences': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\Helpdesk - GPO Imprimantes', rights:'Edit settings, delete, modify security', normal:true }
    ],
    'GPO-AppServers-Baseline': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\Helpdesk - GPO Imprimantes', rights:'Edit settings, delete, modify security', normal:false }
    ]
  },

  objectives:[
    { id:'enum',    text:'Repérer les comptes à privilèges du domaine' },
    { id:'gpoenum', text:'Lister les GPO du domaine et leurs liaisons (OU, postes concernés)' },
    { id:'gpoacl',  text:'Découvrir une délégation GPO copiée par erreur sur le mauvais objet' },
    { id:'abuse',   text:'Pousser un compte administrateur local via la GPO (Restricted Groups)' },
    { id:'refresh', text:"Forcer l'application de la stratégie sur le bon poste cible" },
    { id:'dump',    text:"Récupérer les identifiants en cache d'un Domain Admin de passage" },
    { id:'access',  text:'Rejouer ces identifiants pour obtenir une session Domain Admin' },
    { id:'flag',    text:'Récupérer le flag' }
  ],

  hints:[
    ["Avant de chercher une faille, il faut savoir qui sont les comptes puissants de ce domaine.",
     "Liste les comptes et repère celui qui appartient au groupe Domain Admins.",
     "Commence par voir qui est qui dans le domaine : `net user /domain`"],
    ["Une GPO peut modifier bien plus qu'un fond d'écran — elle peut s'appliquer à tout un groupe de machines d'un coup. Regarde combien il en existe et où elles sont liées.",
     "Il existe une commande pour lister les objets GPO du domaine, avec leur OU de liaison et les postes concernés.",
     "Liste les GPO du domaine avec : `get-domaingpo`"],
    ["Tu es délégué sur une GPO pour une raison précise (les imprimantes). Vérifie si ce droit s'arrête vraiment là où il devrait.",
     "Regarde les droits accordés sur chacune des GPO listées — le même groupe pourrait apparaître deux fois, pas toujours avec la même légitimité.",
     "Vérifie les droits sur chaque GPO avec : `get-objectacl GPO-Imprimantes-Agences` puis `get-objectacl GPO-AppServers-Baseline`"],
    ["Un droit d'édition sur une GPO permet d'y ajouter un réglage \"Restricted Groups\" : un moyen normal de gérer des groupes locaux à grande échelle, y compris pour un attaquant.",
     "Un outil peut pousser un compte dans le groupe Administrateurs locaux via une GPO, à condition d'avoir un droit d'édition dessus.",
     "Pousse ton propre compte en administrateur local via la GPO vulnérable : `gpoabuse -gpo GPO-AppServers-Baseline -type localadmin -target t.giraud`"],
    ["Un changement de GPO ne s'applique pas tout seul instantanément — il faut une actualisation de la stratégie sur le poste concerné. Et encore faut-il cibler un poste où ça compte vraiment.",
     "Regarde bien quels postes sont réellement liés à la GPO que tu as modifiée avant de choisir ta cible.",
     "Force l'actualisation de la stratégie sur le serveur applicatif : `gpupdate /force /target:SRV-APP03`"],
    ["Te voilà administrateur local sur ce serveur. Quelqu'un de plus intéressant que toi s'y connecte peut-être régulièrement...",
     "Un outil peut extraire les identifiants encore en mémoire sur cette machine, y compris ceux d'un compte à privilèges qui vient d'y passer.",
     "Dump les identifiants en cache mémoire avec : `mimikatz sekurlsa::logonpasswords`"],
    ["Ce hash appartient à un compte Domain Admin. Pas besoin de le casser pour l'utiliser ailleurs.",
     "Rejoue ce hash directement sur le contrôleur de domaine.",
     "Utilise ce hash sans le casser : `pth /target:DC01 /user:m.faure /hash:<hash>`"],
    ["Tu es désormais Domain Admin, et aucun mot de passe n'a été cassé.",
     "Regarde ce qu'il y a sur le bureau de m.faure, maintenant que tu es lui.",
     "Regarde le bureau avec `dir` puis `type flag.txt`"]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-domaingpo': { name:'get-domaingpo', role:'Liste les objets GPO du domaine',
      explain:"Une GPO (Group Policy Object) regroupe des réglages — sécurité, tâches planifiées, appartenance à des groupes locaux — appliqués automatiquement à toutes les machines d'une OU (unité d'organisation) à laquelle elle est liée. Modifier une seule GPO peut donc affecter des dizaines de postes d'un coup.",
      usage:'get-domaingpo' },
    'get-objectacl': { name:'get-objectacl', role:'Liste les droits (ACL) accordés sur un objet — y compris une GPO',
      explain:"Un droit d'édition (WriteProperty/GenericWrite) sur une GPO permet d'en modifier le contenu au même titre qu'un administrateur délégué. Ce droit est souvent accordé à une équipe support pour une GPO précise (ex : imprimantes) — le risque apparaît quand il est recopié \"par commodité\" sur une autre GPO, plus sensible.",
      usage:'get-objectacl <nom-de-la-gpo>' },
    'gpoabuse': { name:'gpoabuse', role:"Ajoute un compte en administrateur local via une GPO (Restricted Groups)",
      explain:"Le réglage \"Restricted Groups\" d'une GPO sert normalement à gérer qui appartient au groupe Administrateurs local sur tout un parc de machines. Quiconque a un droit d'édition sur la GPO peut y ajouter n'importe quel compte — le sien, par exemple — sans avoir besoin d'un accès direct aux machines concernées.",
      usage:'gpoabuse -gpo <nom-de-la-gpo> -type localadmin -target <compte>' },
    'gpupdate': { name:'gpupdate /force', role:"Force l'application immédiate d'une stratégie de groupe sur un poste",
      explain:"En temps normal, une GPO modifiée s'applique au prochain cycle d'actualisation (jusqu'à 90-120 minutes). Cette commande simule une actualisation immédiate sur la machine ciblée — mais seuls les postes réellement liés à la GPO modifiée sont concernés.",
      usage:'gpupdate /force /target:<machine>' },
    'mimikatz': { name:'mimikatz sekurlsa::logonpasswords', role:'Extrait les identifiants en cache mémoire (LSASS)',
      explain:"Sous Windows, les identifiants de sessions récentes (même administratives) restent un moment en mémoire. Un outil comme Mimikatz peut les en extraire — y compris sous forme de hash NTLM, sans jamais voir le mot de passe en clair.",
      usage:'mimikatz sekurlsa::logonpasswords' },
    'pth': { name:'pth (pass-the-hash)', role:"Authentifie avec un hash NTLM plutôt qu'un mot de passe",
      explain:"Windows accepte le hash NTLM comme preuve d'identité au même titre qu'un mot de passe pour certains protocoles. Pas besoin de le casser : on le réutilise tel quel.",
      usage:'pth /target:<machine> /user:<nom> /hash:<hash>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-domaingpo','get-objectacl ',
    'gpoabuse -gpo ','gpupdate /force /target:',
    'mimikatz sekurlsa::logonpasswords','pth /target:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-domaingpo, get-objectacl &lt;gpo&gt;, gpoabuse -gpo &lt;gpo&gt; -type localadmin -target &lt;compte&gt;, gpupdate /force /target:&lt;machine&gt;, mimikatz sekurlsa::logonpasswords, pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-domaingpo<br>get-objectacl &lt;gpo&gt;<br>gpoabuse -gpo &lt;gpo&gt; -type localadmin -target &lt;compte&gt;<br>gpupdate /force /target:&lt;machine&gt;<br>mimikatz sekurlsa::logonpasswords<br>pth /target:&lt;machine&gt; /user:&lt;nom&gt; /hash:&lt;hash&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\t.giraud sur WKS-HELPDESK-03</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🧩', title:'Les GPO : bien plus que de simples réglages', html:
      `<p>Une <b>GPO</b> (Group Policy Object) regroupe des paramètres — sécurité, tâches planifiées, appartenance à des groupes locaux — appliqués automatiquement à toutes les machines d'une <b>OU</b> (unité d'organisation) à laquelle elle est liée.</p>
       <p>C'est extrêmement pratique pour administrer un parc entier... et tout aussi puissant entre de mauvaises mains : une seule GPO modifiée peut affecter des dizaines de machines d'un coup.</p>` },
    { icon:'🔓', title:'La délégation GPO, un droit qui grandit vite', html:
      `<p>Il est courant de <b>déléguer</b> le droit d'éditer une GPO précise à une équipe support — par exemple pour déployer des imprimantes réseau, sans donner les pleins pouvoirs sur tout le domaine.</p>
       <p>Le risque classique : cette délégation est parfois <b>recopiée "pour aller plus vite"</b> sur une autre GPO, liée à une OU bien plus sensible — un raccourci qui étend silencieusement la portée du droit initial.</p>` },
    { icon:'🧨', title:"L'attaque : abus de GPO (Restricted Groups)", html:
      `<p>Un droit d'édition sur une GPO permet d'y ajouter un réglage <b>Restricted Groups</b>, qui gère normalement l'appartenance au groupe Administrateurs local sur un ensemble de machines.</p>
       <p>Rien n'empêche d'y ajouter <b>son propre compte</b>. Au prochain cycle d'actualisation de la stratégie, toutes les machines liées à cette GPO appliquent le changement — sans qu'aucun mot de passe n'ait été touché.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\t.giraud</b>, technicien support, délégué de longue date sur la GPO de déploiement des imprimantes. Ce droit d'édition s'est peut-être retrouvé ailleurs qu'il ne le devrait...</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise. Lis bien quels postes sont réellement liés à chaque GPO avant d'agir : toutes les cibles ne se valent pas.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:'Une GPO détournée, sans jamais casser de mot de passe.',
  chainSteps:[
    {icon:'🔎', label:'Recon'}, {icon:'🧩', label:'GPO abusée'},
    {icon:'🛡️', label:'Admin local'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{gpo_restricted_groups_delegation_creep}',

  graph:{
    nodes:[
      { id:'t.giraud', label:'t.giraud', type:'user' },
      { id:'grp_helpdesk_gpo', label:'Helpdesk - GPO Imprimantes', type:'group' },
      { id:'gpo_appservers', label:'GPO: AppServers-Baseline', type:'group' },
      { id:'SRV-APP03', label:'SRV-APP03', type:'computer' },
      { id:'m.faure', label:'m.faure', type:'admin' }
    ],
    edges:[
      { id:'e_member', from:'t.giraud', to:'grp_helpdesk_gpo', type:'memberof', label:'MemberOf' },
      { id:'e_acl', from:'grp_helpdesk_gpo', to:'gpo_appservers', type:'abuse', label:'Edit GPO (délégation copiée par erreur)' },
      { id:'e_push', from:'gpo_appservers', to:'SRV-APP03', type:'abuse', label:'Restricted Groups poussé' },
      { id:'e_localadmin', from:'t.giraud', to:'SRV-APP03', type:'owned', label:'Admin local (GPO)' },
      { id:'e_dump', from:'SRV-APP03', to:'m.faure', type:'auth', label:'Identifiants en cache (maintenance)' },
      { id:'e_owned', from:'t.giraud', to:'m.faure', type:'owned', label:'Pass-the-Hash' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1484.001', name:"Domain Policy Modification: Group Policy Modification"}, {id:'T1550.002', name:"Use Alternate Authentication Material: Pass the Hash"}],
    why:"Un droit d'édition sur une GPO (GenericWrite/WriteProperty) équivaut à un contrôle total sur toutes les machines liées à l'OU de cette GPO — via un réglage Restricted Groups, une tâche planifiée immédiate, ou un script de démarrage. Ce droit est souvent délégué légitimement à une équipe support pour un périmètre précis, puis recopié par commodité sur une autre GPO plus sensible lors d'une évolution — une délégation qui grandit sans que personne ne l'ait décidé explicitement. Le résultat : un compte anodin peut se retrouver administrateur local de serveurs critiques, simplement parce qu'une case a été cochée au mauvais endroit un jour.",
    defenses:[
      "Auditer régulièrement les délégations GPO (qui peut éditer quelle GPO, et sur quelle OU elle est liée) — pas seulement les groupes à privilèges évidents",
      "Appliquer le principe de moindre privilège : une délégation GPO ne devrait jamais être plus large que son objectif initial",
      "Surveiller les modifications de GPO (Event ID 5136) en dehors des équipes et horaires attendus, en particulier sur les OU contenant des serveurs sensibles",
      "Séparer strictement les OU des postes utilisateurs et des serveurs applicatifs des OU d'infrastructure critique, pour limiter la portée d'une délégation mal placée"
    ],
    quiz:[
      { q:"Pourquoi un simple droit d'édition sur une GPO peut-il donner le contrôle de plusieurs machines d'un coup ?",
        options:["Parce qu'une GPO ne s'applique qu'à un seul poste à la fois","Parce qu'une GPO s'applique automatiquement à toutes les machines de l'OU à laquelle elle est liée","Parce que les GPO ne concernent que les comptes utilisateurs, jamais les machines","Parce qu'il faut être Domain Admin pour éditer une GPO"],
        correct:1,
        explain:"Une GPO liée à une OU s'applique à toutes les machines qu'elle contient — modifier la GPO revient donc à modifier toutes ces machines en une seule action." },
      { q:"Comment une délégation GPO légitime devient-elle souvent dangereuse ?",
        options:["Elle expire automatiquement après un an et personne ne le remarque","Elle est recopiée par commodité sur une autre GPO plus sensible, élargissant silencieusement sa portée","Microsoft revoit périodiquement les délégations à la baisse","Elle ne peut jamais être exploitée si le compte délégué est un compte standard"],
        correct:1,
        explain:"Le scénario classique est la dérive de délégation (« delegation creep ») : un droit accordé pour un périmètre précis se retrouve, souvent par commodité, appliqué ailleurs — sans revue explicite du risque que cela représente." },
      { q:"Quelle mesure limite le mieux ce type d'abus ?",
        options:["Désactiver complètement les GPO dans le domaine","Auditer régulièrement les délégations GPO et appliquer le principe de moindre privilège","Changer le mot de passe de tous les comptes du domaine chaque semaine","Chiffrer le contenu des GPO sur le contrôleur de domaine"],
        correct:1,
        explain:"Sans audit régulier des délégations GPO (qui peut éditer quoi, sur quelle OU), une dérive de privilège comme celle-ci reste invisible jusqu'à ce qu'elle soit exploitée." }
    ]
  },

  initState(){ return { gpoAbused:{}, localAdminOn:null, dumpedHash:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.gpo;

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
      AttackGraph.reveal({ nodes:['t.giraud'] });
      complete('enum');
      return true;
    }

    m = lower.match(/^net user (\S+) \/domain$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){ print(`<span class="out-bad">Utilisateur introuvable : ${escapeHtml(name)}</span>`); return true; }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      if(u.groups.includes('Domain Admins')){
        print(`<span class="out-warn">⚠ Ce compte est administrateur du domaine — une cible de choix.</span>`);
        AttackGraph.reveal({ nodes:['m.faure'] });
      }
      complete('enum');
      return true;
    }

    if(lower === 'get-domaingpo'){
      print(`<span class="out-info">GPO du domaine CORP.LOCAL :</span>`);
      Object.entries(sc.gpos).forEach(([name, g]) => {
        print(`<span class="out-dim">  ${name}</span>`);
        print(`<span class="out-dim">    Liée à : ${g.linkedOU}</span>`);
        print(`<span class="out-dim">    Description : ${g.desc}</span>`);
        print(`<span class="out-dim">    Postes concernés : ${g.computers.join(', ')}</span>`);
      });
      AttackGraph.reveal({ nodes:['grp_helpdesk_gpo','gpo_appservers'] });
      complete('gpoenum');
      return true;
    }

    m = lower.match(/^get-objectacl (\S+)$/);
    if(m){
      const gpoKey = Object.keys(sc.gpos).find(k => k.toLowerCase() === m[1].toLowerCase());
      if(!gpoKey){ print(`<span class="out-bad">Objet introuvable : ${escapeHtml(m[1])}</span>`); return true; }
      const entries = sc.acl[gpoKey];
      print(`<span class="out-info">ACL sur la GPO ${gpoKey} :</span>`);
      entries.forEach(e => {
        if(e.normal){
          print(`<span class="out-dim">  ${e.principal} — ${e.rights}</span>`);
        } else {
          print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ délégation identique à celle d'une autre GPO — copiée par erreur ?</span>`);
        }
      });
      if(entries.some(e => !e.normal)){
        AttackGraph.reveal({ edges:['e_member','e_acl'] });
        complete('gpoacl');
      }
      return true;
    }

    m = lower.match(/^gpoabuse -gpo (\S+) -type localadmin -target (\S+)$/);
    if(m){
      const [, gpoNameLower, target] = m;
      const gpoKey = Object.keys(sc.gpos).find(k => k.toLowerCase() === gpoNameLower.toLowerCase());
      if(!gpoKey){ print(`<span class="out-bad">GPO introuvable : ${escapeHtml(gpoNameLower)}</span>`); return true; }
      const entries = sc.acl[gpoKey] || [];
      const me = sc.identities[state.user];
      const hasRight = entries.some(e => me.groups.some(g => e.principal.toLowerCase().endsWith(g.toLowerCase())));
      if(!hasRight){
        print(`<span class="out-bad">Accès refusé : tu n'as aucun droit d'édition sur cette GPO.</span>`);
        return true;
      }
      print(`<span class="out-good">Réglage Restricted Groups ajouté : ${escapeHtml(target)} sera administrateur local de tous les postes liés à ${gpoKey}.</span>`);
      print(`<span class="out-dim">💡 Postes concernés : ${sc.gpos[gpoKey].computers.join(', ')}. Vérifie lequel présente vraiment un intérêt avant d'actualiser la stratégie.</span>`);
      state.extra.gpoAbused[gpoKey] = target;
      AttackGraph.reveal({ edges:['e_acl'] });
      complete('abuse');
      return true;
    }

    m = lower.match(/^gpupdate \/force \/target:(\S+)$/);
    if(m){
      const target = m[1].toUpperCase();
      const matchedGpo = Object.entries(sc.gpos).find(([name, g]) =>
        state.extra.gpoAbused[name] && g.computers.some(c => c.toUpperCase() === target)
      );
      if(!matchedGpo){
        print(`<span class="out-bad">Aucune stratégie modifiée ne s'applique à ce poste : ${escapeHtml(m[1])}</span>`);
        return true;
      }
      const [gpoKey] = matchedGpo;
      if(gpoKey === 'GPO-AppServers-Baseline' && target === 'SRV-APP03'){
        print(`<span class="out-info">Actualisation de la stratégie sur ${target}...</span>`);
        print(`<span class="out-good">Stratégie appliquée — tu es désormais administrateur local de ${target}.</span>`);
        state.extra.localAdminOn = target;
        AttackGraph.reveal({ nodes:['SRV-APP03'], edges:['e_push','e_localadmin'] });
        AttackGraph.markOwned('t.giraud');
        complete('refresh');
      } else {
        print(`<span class="out-info">Actualisation de la stratégie sur ${target}...</span>`);
        print(`<span class="out-good">Stratégie appliquée — tu es administrateur local de ${target}.</span>`);
        print(`<span class="out-dim">💡 Mais ce poste ne semble présenter aucun intérêt particulier : aucun compte à privilèges n'y traîne. Relis les indices sur les postes réellement concernés par chaque GPO.</span>`);
      }
      return true;
    }

    if(lower === 'mimikatz sekurlsa::logonpasswords'){
      if(state.extra.localAdminOn !== 'SRV-APP03'){
        print(`<span class="out-info">Extraction des identifiants en mémoire (LSASS)...</span>`);
        print(`<span class="out-dim">Rien d'exploitable ici — obtiens d'abord un accès admin local sur une machine qui en vaut la peine.</span>`);
        return true;
      }
      print(`<span class="out-info">Extraction des identifiants en mémoire (LSASS) sur ${state.extra.localAdminOn}...</span>`);
      print(`<span class="out-dim">Session trouvée :</span>`);
      print(`<span class="out-warn">  Username : m.faure</span>`);
      print(`<span class="out-warn">  Domain   : CORP (Domain Admin)</span>`);
      print(`<span class="out-warn">  NTLM     : ${sc.NTLM_HASH}</span>`);
      print(`<span class="out-dim">💡 m.faure s'est visiblement connecté ici récemment pour de la maintenance applicative.</span>`);
      state.extra.dumpedHash = sc.NTLM_HASH;
      AttackGraph.reveal({ edges:['e_dump'] });
      complete('dump');
      return true;
    }

    m = lower.match(/^pth \/target:(\S+) \/user:(\S+) \/hash:(\S+)$/);
    if(m){
      const [, target, user, hash] = m;
      if(!state.extra.dumpedHash){
        print(`<span class="out-bad">Aucun hash en mémoire. Dump les identifiants d'un compte à privilèges d'abord.</span>`);
        return true;
      }
      if(target.toUpperCase() === 'DC01' && user.toLowerCase() === 'm.faure' && hash === sc.NTLM_HASH.toLowerCase()){
        print(`<span class="out-info">Authentification par hash sur \\\\DC01...</span>`);
        print(`<span class="out-good">Accès accordé — session Domain Admin ouverte, sans jamais casser de mot de passe.</span>`);
        state.user = 'm.faure';
        updatePrompt();
        AttackGraph.reveal({ edges:['e_owned'] });
        AttackGraph.markOwned('m.faure');
        complete('access');
      } else if(target.toUpperCase() !== 'DC01'){
        print(`<span class="out-bad">Machine injoignable ou sans intérêt : ${escapeHtml(target)}</span>`);
      } else {
        print(`<span class="out-bad">Authentification refusée : hash ou utilisateur incorrect.</span>`);
      }
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'm.faure'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\m.faure\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'm.faure'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : délégation GPO copiée par erreur → admin local via Restricted Groups → identifiants en cache → Pass-the-Hash jusqu'à Domain Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer régulièrement les délégations GPO et leur portée réelle, pas seulement les groupes à privilèges évidents — une GPO mal déléguée vaut souvent un accès direct aux machines qu'elle contrôle.</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : tu n'es pas connecté avec le bon compte.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};
