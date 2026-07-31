SCENARIOS.asrep = {
  id:'asrep',
  cmdBudget:13,
  tag:'⚡ SCÉNARIO 11 · AS-REP ROASTING',
  lessonTag:'📘 LEÇON · SCÉNARIO 11',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.asrepFind, NOISE.asreproast,
              NOISE.objectAcl, NOISE.resetPassword, NOISE.runas],
  startUser:'m.gauthier',

  ASREP_HASH:'$krb5asrep$23$svc_intranet@CORP.LOCAL:7c4f2a9e3d8b1c6f0a5e3d9b2f8c4a7e1d6b...(hash tronqué)',

  identities:{
    'm.gauthier':  { label:'CORP\\m.gauthier', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Développeur web — portail intranet' },
    'svc_intranet':{ label:'CORP\\svc_intranet', priv:'Compte de service', groups:['Domain Users'],
                     desc:'Compte de service — portail intranet legacy (ASP.NET 4.x)',
                     preAuthDisabled:true,
                     asrepHash:'$krb5asrep$23$svc_intranet@CORP.LOCAL:7c4f2a9e3d8b1c6f0a5e3d9b2f8c4a7e1d6b...(hash tronqué)',
                     crackedPassword:'Intranet2019!' },
    'c.martin':    { label:'CORP\\c.martin', priv:'Administrateur Systèmes & Infrastructure', groups:['Domain Users','Domain Admins'], desc:'Responsable infrastructure — domaine et Active Directory' }
  },

  acl:{
    'c.martin':[ { principal:'CORP\\svc_intranet', right:'ForceChangePassword',
                   note:'Droit accordé en 2019 lors de la migration du portail — jamais retiré' } ]
  },

  objectives:[
    { id:'enum',       text:'Énumérer les comptes du domaine' },
    { id:'preauth',    text:'Identifier un compte sans pré-authentification Kerberos' },
    { id:'asrep',      text:'Extraire le hash AS-REP sans credential' },
    { id:'crack',      text:'Retrouver le mot de passe en clair' },
    { id:'lateral',    text:'Ouvrir une session avec ce compte' },
    { id:'acl_find',   text:'Découvrir un droit exploitable sur un compte à privilèges' },
    { id:'escalate',   text:'Réinitialiser le mot de passe du compte cible' },
    { id:'flag',       text:'Récupérer le flag sur le bureau de l\'administrateur' },
  ],

  counterMeasure:{
    label:'Réactivation de la pré-authentification Kerberos',
    briefing:"🛡️ Contre-mesure appliquée : le flag DONT_REQ_PREAUTH a été retiré du compte svc_intranet. Kerberos exige désormais que le client prouve qu'il connaît le mot de passe avant que le contrôleur de domaine délivre un TGT — impossible donc d'extraire un hash à cracker sans credential préalable."
  },

  hints:[
    ["Commence par voir qui est dans ce domaine. Personne ne t'a donné de liste.",
     "Il existe une commande Windows classique pour interroger l'annuaire du domaine.",
     "Liste les comptes du domaine avec `net user /domain`"],
    ["Parmi les comptes du domaine, un compte de service n'a pas la configuration par défaut de Kerberos. Ce flag s'appelle DONT_REQ_PREAUTH.",
     "Il existe une commande PowerView pour filtrer directement les comptes qui ont ce flag.",
     "Cherche les comptes vulnérables avec `get-domainuser -preauthdisabled`"],
    ["La particularité de cette attaque : tu n'as besoin d'aucun credential pour extraire un hash crackable. Le contrôleur de domaine te répond sans vérifier que tu connais le mot de passe.",
     "La commande ressemble à invoke-kerberoast, mais pour les AS-REP.",
     "Extrais le hash sans credential : `invoke-asreproast -identity svc_intranet`"],
    ["Le hash AS-REP est chiffré avec le mot de passe du compte. Si ce mot de passe est faible, un dictionnaire suffit.",
     "La commande `crack` prend ce hash en argument, comme pour le Kerberoasting.",
     "Cracke le hash hors-ligne : `crack $krb5asrep$23$svc_intranet@CORP.LOCAL:7c4f2a9e3d8b1c6f0a5e3d9b2f8c4a7e1d6b`"],
    ["Tu connais maintenant un mot de passe en clair. Ouvre une session avec ce compte pour voir ce à quoi il a accès.",
     "C'est la même commande que dans les scénarios précédents.",
     "Ouvre une session : `runas /user:svc_intranet cmd`"],
    ["En tant que compte de service, tu as peut-être des droits sur d'autres comptes du domaine. Vérifie les ACL des comptes à privilèges.",
     "La commande `get-objectacl` affiche qui a quels droits sur un compte — ici, ce qui compte c'est ce que TU peux faire, pas ce que d'autres peuvent faire sur toi.",
     "Vérifie les droits sur le compte admin : `get-objectacl c.martin`"],
    ["Le droit ForceChangePassword te permet de changer le mot de passe d'un compte sans connaître l'actuel.",
     "La commande est la même que dans le scénario ACL.",
     "Réinitialise le mot de passe : `set-domainuserpassword -identity c.martin -newpassword Golden123!`"],
    ["Tu contrôles désormais le compte de l'administrateur. Ouvre une session, puis récupère le flag.",
     "Connecte-toi avec c.martin, puis regarde son bureau avec `dir` et `type flag.txt`.",
     "Dernière ligne droite : `runas /user:c.martin cmd` → `dir` → `type flag.txt`"]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche les détails d'un compte précis.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-domainuser': { name:'get-domainuser -preauthdisabled', role:'Liste les comptes avec DONT_REQ_PREAUTH activé',
      explain:"La pré-authentification Kerberos est active par défaut sur tous les comptes. Ce filtre repère les exceptions — souvent des comptes legacy ou mal configurés — qui permettent l'AS-REP Roasting.",
      usage:'get-domainuser -preauthdisabled' },
    'invoke-asreproast': { name:'invoke-asreproast', role:'Extrait le hash AS-REP d\'un compte sans pré-authentification',
      explain:"Contrairement au Kerberoasting, aucun credential n'est requis : le contrôleur de domaine répond à la demande de TGT sans vérifier l'identité de l'appelant. Le hash renvoyé est chiffré avec le mot de passe du compte.",
      usage:'invoke-asreproast -identity <nom>' },
    'crack': { name:'crack', role:'Casse un hash AS-REP hors-ligne pour retrouver le mot de passe',
      explain:"Si le mot de passe est faible ou dans un dictionnaire, la clé de chiffrement du TGT peut être retrouvée par force brute ou attaque par dictionnaire — sans jamais contacter le contrôleur de domaine.",
      usage:'crack <hash>' },
    'runas': { name:'runas /user', role:'Ouvre une session avec un autre compte',
      explain:"Une fois un mot de passe en clair obtenu, tu peux te reconnecter avec l'identité (et donc les droits) de ce compte.",
      usage:'runas /user:<nom> cmd' },
    'get-objectacl': { name:'get-objectacl', role:'Affiche les droits délégués sur un objet AD',
      explain:"Chaque objet AD (compte, groupe, GPO) possède une liste de droits. Certains droits dangereux — ForceChangePassword, GenericAll, WriteDACL — peuvent permettre de prendre le contrôle de l'objet.",
      usage:'get-objectacl <nom>' },
    'set-domainuserpassword': { name:'set-domainuserpassword', role:'Réinitialise le mot de passe d\'un compte sans connaître l\'actuel',
      explain:"Si tu as le droit ForceChangePassword sur un compte, tu peux en changer le mot de passe directement, sans connaître l'ancien. L'opération est journalisée (Event ID 4723/4724).",
      usage:'set-domainuserpassword -identity <nom> -newpassword <nouveau>' }
  },

  knownCommands:[
    'help','clear','man ',
    'whoami /priv',
    'net user /domain','net user ',
    'get-domainuser -preauthdisabled',
    'invoke-asreproast -identity ',
    'crack ','runas /user:',
    'get-objectacl ',
    'set-domainuserpassword -identity ',
    'dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-domainuser -preauthdisabled, invoke-asreproast -identity &lt;nom&gt;, crack &lt;hash&gt;, runas /user:&lt;nom&gt; cmd, get-objectacl &lt;nom&gt;, set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;mdp&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-domainuser -preauthdisabled<br>invoke-asreproast -identity &lt;nom&gt;<br>crack &lt;hash&gt;<br>runas /user:&lt;nom&gt; cmd<br>get-objectacl &lt;nom&gt;<br>set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;mdp&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\m.gauthier sur WKS-DEV-07</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🔑', title:'La pré-authentification Kerberos', html:
      `<p>Quand tu demandes un ticket Kerberos (TGT), le client envoie d'abord un <b>pré-authentificateur chiffré avec ton mot de passe</b>. Le contrôleur de domaine vérifie que tu connais bien le mot de passe <i>avant</i> de te délivrer quoi que ce soit.</p>
       <p>C'est le comportement par défaut depuis Windows 2000. Sans cette étape, n'importe qui pourrait demander un ticket chiffré pour n'importe quel compte — et tenter de le casser hors-ligne.</p>` },
    { icon:'⚡', title:'AS-REP Roasting : la variante sans credentials', html:
      `<p>Certains comptes ont le flag <b>DONT_REQ_PREAUTH</b> activé — souvent des applications legacy qui ne savent pas gérer la pré-authentification.</p>
       <p>Pour ces comptes, le KDC répond directement avec un TGT chiffré avec le mot de passe du compte, <b>sans vérifier qui demande</b>. Résultat : un attaquant peut extraire un hash crackable sans aucun credential préalable — même depuis internet, si le port 88 est ouvert.</p>` },
    { icon:'🔍', title:'Kerberoasting vs AS-REP Roasting', html:
      `<table class="lesson-table">
        <tr><th></th><th>Kerberoasting</th><th>AS-REP Roasting</th></tr>
        <tr><td>Credentials requis</td><td>✅ Oui (compte domaine)</td><td>❌ Non</td></tr>
        <tr><td>Cible</td><td>Comptes avec SPN</td><td>Comptes sans pré-auth</td></tr>
        <tr><td>Hash obtenu</td><td>TGS (RC4/AES)</td><td>TGT (AS-REP, RC4)</td></tr>
        <tr><td>Détection</td><td>Event ID 4769</td><td>Event ID 4768</td></tr>
      </table>
      <p class="lesson-tip">💡 Les deux techniques ciblent des configurations différentes. AS-REP Roasting est souvent plus dangereux car il ne nécessite aucun accès préalable au domaine.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\m.gauthier</b>, développeur web sur le domaine <b>CORP.LOCAL</b>. Un compte de service legacy a été laissé sans pré-authentification lors d'une migration. Trouve-le, craque son mot de passe, et suis la chaîne jusqu'au Domain Admin.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domaine compromis',
  completeSub:'Compte legacy exploité sans credential — Domain Admin via un droit oublié.',
  chainSteps:[
    {icon:'🔎', label:'Énumération'}, {icon:'⚡', label:'DONT_REQ_PREAUTH'},
    {icon:'🎟️', label:'AS-REP extrait'}, {icon:'🗝️', label:'Crack'},
    {icon:'📋', label:'ACL exploitée'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{asrep_intranet2019_forget_nothing}',

  graph:{
    nodes:[
      { id:'m.gauthier',  label:'m.gauthier',  type:'user' },
      { id:'svc_intranet',label:'svc_intranet', type:'service' },
      { id:'c.martin',    label:'c.martin',     type:'admin' },
      { id:'grp_da',      label:'Domain Admins', type:'group' }
    ],
    edges:[
      { id:'e_asrep',  from:'m.gauthier',  to:'svc_intranet', type:'owned',    label:'AS-REP Roast (sans creds)' },
      { id:'e_fcp',    from:'svc_intranet', to:'c.martin',     type:'abuse',    label:'ForceChangePassword' },
      { id:'e_member', from:'c.martin',     to:'grp_da',       type:'memberof', label:'MemberOf' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1558.004', name:'Steal or Forge Kerberos Tickets: AS-REP Roasting'}],
    why:"Lorsque la pré-authentification Kerberos est désactivée sur un compte (flag DONT_REQ_PREAUTH), le contrôleur de domaine répond à toute demande de TGT sans vérifier l'identité de l'appelant. La réponse contient un paquet chiffré avec le mot de passe du compte visé — qu'un attaquant peut récupérer et tenter de casser hors-ligne. Contrairement au Kerberoasting, aucun credential de domaine n'est requis : l'attaque peut partir d'un poste non joint au domaine, ou même depuis internet si le port Kerberos (TCP 88) est accessible.",
    defenses:[
      "Activer la pré-authentification Kerberos sur tous les comptes (retirer le flag DONT_REQ_PREAUTH) — c'est la valeur par défaut et ça suffit à bloquer l'extraction du hash",
      "Auditer régulièrement avec `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` pour repérer les comptes non conformes",
      "Si une application legacy l'impose vraiment, imposer un mot de passe de 25+ caractères aléatoires pour résister au crackage hors-ligne",
      "Surveiller les Event ID 4768 avec le type de chiffrement RC4 (0x17) dans les logs du contrôleur de domaine — un indicateur de tentative AS-REP Roasting",
      "Coupler avec un audit des ACL : un compte de service ne devrait jamais avoir ForceChangePassword sur un Domain Admin"
    ],
    quiz:[
      { q:"Quelle est la principale différence entre Kerberoasting et AS-REP Roasting ?",
        options:["AS-REP Roasting ne nécessite aucun credential de domaine","AS-REP Roasting cible les comptes avec un SPN","Kerberoasting ne peut pas être détecté par les logs Windows","AS-REP Roasting casse un ticket TGS, pas un TGT"],
        correct:0,
        explain:"C'est la différence clé : Kerberoasting nécessite un compte domaine valide pour demander un ticket de service (TGS), alors qu'AS-REP Roasting fonctionne sans aucun credential — le KDC répond sans vérifier l'identité de l'appelant si DONT_REQ_PREAUTH est absent." },
      { q:"Quel Event ID surveiller pour détecter une tentative d'AS-REP Roasting ?",
        options:["4769 (demande de ticket de service)","4768 (demande de TGT)","4624 (ouverture de session)","4662 (accès à un objet AD)"],
        correct:1,
        explain:"L'AS-REP Roasting génère des Event ID 4768 (Kerberos Authentication Service Request) avec un type de chiffrement RC4 (0x17) au lieu d'AES — une combinaison anormale qui trahit l'attaque dans les logs du contrôleur de domaine." },
      { q:"Quelle mesure suffit à elle seule à empêcher l'extraction du hash AS-REP ?",
        options:["Imposer un mot de passe long au compte de service","Activer la pré-authentification Kerberos sur le compte","Désactiver RC4 sur le contrôleur de domaine","Retirer le SPN du compte de service"],
        correct:1,
        explain:"La pré-authentification Kerberos est le verrou : quand elle est activée (comportement par défaut), le contrôleur de domaine exige une preuve de connaissance du mot de passe avant de délivrer le TGT. Sans ce verrou, n'importe qui peut demander le hash chiffré — peu importe la longueur du mot de passe." }
    ]
  },

  initState(){
    return {
      asrepExtracted: false,
      crackedPassword: null,
      knownPasswords: {}
    };
  },

  handle(lower, cmd, m){
    const sc = SCENARIOS.asrep;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      addNoise(NOISE.netUserAll.points, NOISE.netUserAll.label);
      complete('enum');
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      print(`<span class="out-dim">Administrator    c.martin    j.giraud    m.gauthier</span>`);
      print(`<span class="out-dim">m.hernandez      svc_intranet    svc_backup    krbtgt</span>`);
      print(`<span class="out-dim">... (${Math.floor(Math.random()*30)+180} comptes au total)</span>`);
      return true;
    }

    if(lower.startsWith('net user ') && lower.endsWith('/domain')){
      const name = lower.replace('net user ','').replace(' /domain','').trim();
      addNoise(NOISE.netUserOne.points, NOISE.netUserOne.label);
      const id = sc.identities[name];
      if(id){
        print(`<span class="out-info">Compte : ${id.label}</span>`);
        print(`<span class="out-info">Rôle : ${id.priv}</span>`);
        print(`<span class="out-info">Description : ${id.desc}</span>`);
        print(`<span class="out-info">Groupes : ${id.groups.join(', ')}</span>`);
        if(id.preAuthDisabled){
          print(`<span class="out-warn">⚠ Paramètre Kerberos : DONT_REQ_PREAUTH — pré-authentification désactivée</span>`);
        }
      } else {
        print(`<span class="out-bad">Compte introuvable : ${escapeHtml(name)}</span>`);
      }
      return true;
    }

    if(lower === 'get-domainuser -preauthdisabled'){
      addNoise(NOISE.asrepFind.points, NOISE.asrepFind.label);
      complete('preauth');
      print(`<span class="out-info">Comptes avec DONT_REQ_PREAUTH (pré-authentification Kerberos désactivée) :</span>`);
      print(`<span class="out-dim">─────────────────────────────────────────────────────</span>`);
      print(`<span class="out-warn">svc_intranet</span>`);
      print(`<span class="out-dim">  Description    : Compte de service — portail intranet legacy (ASP.NET 4.x)</span>`);
      print(`<span class="out-dim">  PasswordLastSet : 12/03/2019</span>`);
      print(`<span class="out-dim">  DoesNotRequirePreAuth : True ← vulnérable à l'AS-REP Roasting</span>`);
      return true;
    }

    if(lower.startsWith('invoke-asreproast -identity ')){
      const target = lower.replace('invoke-asreproast -identity ','').trim();
      addNoise(NOISE.asreproast.points, NOISE.asreproast.label);
      if(target !== 'svc_intranet'){
        print(`<span class="out-bad">Aucun TGT AS-REP obtenu pour ${escapeHtml(target)} : pré-authentification activée sur ce compte.</span>`);
        return true;
      }
      if(state.mitigationApplied){
        print(`<span class="out-bad">KDC_ERR_PREAUTH_REQUIRED : le contrôleur de domaine exige la pré-authentification pour ce compte.</span>`);
        print(`<span class="out-dim">💡 Le flag DONT_REQ_PREAUTH a été retiré de svc_intranet — Kerberos vérifie désormais que l'appelant prouve sa connaissance du mot de passe avant de délivrer un TGT.</span>`);
        return true;
      }
      print(`<span class="out-info">[*] Envoi d'une requête AS-REQ sans pré-authentification pour svc_intranet...</span>`);
      print(`<span class="out-good">[+] Réponse AS-REP reçue sans credential — aucune authentification requise !</span>`);
      print(`<span class="out-good">[+] Hash extrait :</span>`);
      print(`<span class="out-warn">${escapeHtml(sc.ASREP_HASH)}</span>`);
      state.extra.asrepExtracted = true;
      complete('asrep');
      return true;
    }

    if(lower.startsWith('crack ')){
      const hash = lower.replace('crack ','').trim();
      if(!state.extra.asrepExtracted){
        print(`<span class="out-bad">Aucun hash AS-REP extrait. Lance d'abord invoke-asreproast.</span>`);
        return true;
      }
      if(!hash.startsWith('$krb5asrep$') && !hash.startsWith('$krb5tgs$')){
        print(`<span class="out-bad">Format non reconnu. Copie le hash tel qu'il a été affiché.</span>`);
        return true;
      }
      print(`<span class="out-info">[*] Attaque par dictionnaire (rockyou.txt) sur le hash AS-REP...</span>`);
      print(`<span class="out-dim">  Progrès : [████████████████████████] 100%</span>`);
      print(`<span class="out-good">[+] Mot de passe retrouvé : <b>Intranet2019!</b></span>`);
      state.extra.crackedPassword = 'Intranet2019!';
      state.extra.knownPasswords['svc_intranet'] = 'Intranet2019!';
      complete('crack');
      if(typeof AttackGraph !== 'undefined'){
        AttackGraph.markOwned('svc_intranet');
      }
      return true;
    }

    if(lower.startsWith('runas /user:')){
      const rest = lower.replace('runas /user:','');
      const parts = rest.split(' ');
      const user = parts[0];
      addNoise(NOISE.runas.points, NOISE.runas.label);

      if(user === 'svc_intranet'){
        if(!state.extra.knownPasswords['svc_intranet']){
          print(`<span class="out-bad">Authentification échouée : mot de passe inconnu. Cracke d'abord le hash.</span>`);
          return true;
        }
        state.user = 'svc_intranet';
        complete('lateral');
        print(`<span class="out-good">Session ouverte en tant que CORP\\svc_intranet sur WKS-DEV-07</span>`);
        print(`<span class="out-dim">Compte de service du portail intranet — membre de Domain Users uniquement.</span>`);
        if(typeof AttackGraph !== 'undefined') AttackGraph.markOwned('svc_intranet');
        if(typeof updatePrompt === 'function') updatePrompt();
        return true;
      }

      if(user === 'c.martin'){
        if(!state.extra.knownPasswords['c.martin']){
          print(`<span class="out-bad">Authentification échouée : mot de passe inconnu pour c.martin.</span>`);
          return true;
        }
        state.user = 'c.martin';
        complete('escalate');
        print(`<span class="out-good">Session ouverte en tant que CORP\\c.martin sur WKS-DEV-07</span>`);
        print(`<span class="out-good">🔑 Groupe : Domain Admins — accès complet au domaine.</span>`);
        if(typeof AttackGraph !== 'undefined') AttackGraph.markOwned('c.martin');
        if(typeof updatePrompt === 'function') updatePrompt();
        return true;
      }

      const u = sc.identities[user];
      if(u){
        print(`<span class="out-bad">Authentification échouée pour ${escapeHtml(user)} : mot de passe non disponible.</span>`);
      } else {
        print(`<span class="out-bad">Compte inconnu : ${escapeHtml(user)}</span>`);
      }
      return true;
    }

    if(lower.startsWith('get-objectacl ')){
      const target = lower.replace('get-objectacl ','').trim();
      addNoise(NOISE.objectAcl.points, NOISE.objectAcl.label);
      const entries = sc.acl[target];
      if(!entries){
        print(`<span class="out-info">Aucun droit délégué notable sur ${escapeHtml(target)} pour ton compte actuel.</span>`);
        return true;
      }
      if(state.user !== 'svc_intranet'){
        print(`<span class="out-info">Droits sur ${escapeHtml(target)} :</span>`);
        print(`<span class="out-dim">  (Aucun droit exploitable pour CORP\\${state.user})</span>`);
        return true;
      }
      complete('acl_find');
      print(`<span class="out-info">Droits délégués sur ${escapeHtml(target)} :</span>`);
      print(`<span class="out-dim">─────────────────────────────────────────────────────</span>`);
      entries.forEach(e => {
        print(`<span class="out-warn">  ${e.principal} → <b>${e.right}</b></span>`);
        if(e.note) print(`<span class="out-dim">  Note : ${e.note}</span>`);
      });
      if(typeof AttackGraph !== 'undefined'){
        AttackGraph.reveal('e_fcp');
      }
      return true;
    }

    if(lower.startsWith('set-domainuserpassword -identity ')){
      const rest = lower.replace('set-domainuserpassword -identity ','');
      const idParts = rest.split(' -newpassword ');
      const name = idParts[0].trim();
      const pwd = idParts[1] ? idParts[1].trim() : '';
      addNoise(NOISE.resetPassword.points, NOISE.resetPassword.label);

      if(state.user !== 'svc_intranet'){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits ForceChangePassword sur ce compte.</span>`);
        return true;
      }
      if(name !== 'c.martin'){
        print(`<span class="out-bad">Aucun droit de réinitialisation sur ${escapeHtml(name)}.</span>`);
        return true;
      }
      if(!pwd){
        print(`<span class="out-bad">Syntaxe : set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;mdp&gt;</span>`);
        return true;
      }
      if(state.mitigationApplied){
        print(`<span class="out-bad">Accès refusé (0x80070005) : droits insuffisants sur ce compte.</span>`);
        print(`<span class="out-dim">💡 Ce droit ForceChangePassword hérité d'une migration 2019 a été retiré lors de l'audit des ACL — la contre-mesure s'applique sur les deux niveaux de la chaîne.</span>`);
        return true;
      }
      print(`<span class="out-good">Mot de passe de c.martin réinitialisé avec succès.</span>`);
      print(`<span class="out-dim">Event ID 4723 / 4724 généré côté DC — l'opération est journalisée.</span>`);
      state.extra.knownPasswords['c.martin'] = pwd;
      complete('escalate');
      if(typeof AttackGraph !== 'undefined') AttackGraph.reveal('e_member');
      return true;
    }

    if(lower === 'dir'){
      if(state.user !== 'c.martin'){
        print(`<span class="out-dim">Bureau de ${escapeHtml(state.user)} :</span>`);
        print(`<span class="out-dim">  (aucun fichier intéressant)</span>`);
        return true;
      }
      print(`<span class="out-info">Contenu du bureau (C:\\Users\\c.martin\\Desktop) :</span>`);
      print(`<span class="out-dim">  flag.txt</span>`);
      print(`<span class="out-dim">  notes-infra-2024.docx</span>`);
      print(`<span class="out-dim">  scripts-gpo\\</span>`);
      return true;
    }

    if(lower.startsWith('type ')){
      const file = lower.replace('type ','').trim();
      if(state.user !== 'c.martin'){
        print(`<span class="out-bad">Accès refusé. Ce fichier appartient à un autre profil.</span>`);
        return true;
      }
      if(file === 'flag.txt'){
        complete('flag');
        print(`<span class="out-good">${escapeHtml(sc.flag)}</span>`);
        finishMission();
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};
