
// ---------------------------------------------------------
// SCÉNARIO 04 — CLOUD AD (ENTRA ID) : APPLICATION ADMINISTRATOR → GLOBAL ADMINISTRATOR
// ---------------------------------------------------------
SCENARIOS.azuread = {
  id:'azuread',
  cmdBudget:9,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
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

  counterMeasure:{
    label:'Rotation du secret + retrait du rôle Application Administrator',
    briefing:"🛡️ Contre-mesure appliquée : le secret client de legacy-reporting-app (fuité dans un ancien pipeline CI/CD) a été révoqué, et son rôle Application Administrator retiré lors de l'audit."
  },
  deepDive:{
    mitre:[{id:'T1552.001', name:"Unsecured Credentials: Credentials In Files"}, {id:'T1098.001', name:"Account Manipulation: Additional Cloud Credentials"}],
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

  // 'portal-frontend' est un honeytoken : une application volontairement plantée sans
  // rôle privilégié, pour attirer un attaquant qui ajoute des identifiants un peu partout
  // sans vérifier d'abord les rôles réellement attribués (voir get-mgapp).
  checkHoneytoken(lower){
    if(/^add-credential -target portal-frontend$/i.test(lower)){
      return {
        label:'Ajout d\'un identifiant à une application-leurre (portal-frontend)',
        message:"💡 Cette application n'a jamais eu de rôle d'annuaire privilégié — c'est un honeytoken planté par l'équipe sécurité. Vérifier les rôles réellement attribués (get-mgrolemembers) avant d'agir évite ce genre de piège."
      };
    }
    return null;
  },

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
      if(state.mitigationApplied && appid.toLowerCase() === sc.APPS['legacy-reporting-app'].clientId.toLowerCase()){
        print(`<span class="out-bad">Authentification refusée : appId ou secret invalide.</span>`);
        print(`<span class="out-dim">💡 Le secret client legacy a été révoqué lors de l'audit — même retrouvé dans l'ancien pipeline CI/CD, il ne vaut plus rien.</span>`);
        return true;
      }
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
