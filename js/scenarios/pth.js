
SCENARIOS.pth = {
  id:'pth',
  cmdBudget:7,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
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

  // Défenseur vivant : l'accès à LSASS (dump mimikatz) est l'action la plus bruyante de la
  // chaîne — un EDR réel la détecte quasi systématiquement. La réaction reste narrative :
  // le hash est déjà extrait au moment où l'alerte remonte, donc rien à rejouer — mais elle
  // pose clairement la question que la contre-mesure LAPS répondra ensuite.
  opsecReaction:{
    threshold:25,
    message:"un EDR détecte l'accès mémoire à LSASS. Trop tard : le hash est déjà extrait. La vraie question n'est pas de bloquer ce dump-ci, mais d'empêcher qu'un hash volé une fois ouvre TOUTES les machines — c'est précisément ce que corrige LAPS."
  },

  counterMeasure:{
    label:'LAPS (mots de passe admin locaux uniques)',
    briefing:"🛡️ Contre-mesure appliquée : LAPS est désormais déployé sur le parc. Chaque machine a son propre mot de passe administrateur local, unique et tourné automatiquement — un hash volé sur une machine ne marche plus sur les autres."
  },
  deepDive:{
    mitre:[{id:'T1550.002', name:"Use Alternate Authentication Material: Pass the Hash"}],
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
      if(state.mitigationApplied){
        print(`<span class="out-bad">Authentification refusée : hash ou utilisateur incorrect.</span>`);
        print(`<span class="out-dim">💡 LAPS est désormais déployé : chaque machine a son propre mot de passe administrateur local, unique et tourné automatiquement. Le hash volé sur ton poste ne correspond à aucun autre serveur.</span>`);
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
