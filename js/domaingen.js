// ═══════════════════════════════════════════════════════════
// DomainGen — générateur de domaine aléatoire pour le Mode Libre.
// Chaque partie (ou seed partagée) retire : identités des employés,
// nom d'entreprise, mots de passe faibles, hachages — en gardant
// intacte la structure des 3 chemins d'attaque + le piège ACL.
// Déterministe : même seed = même domaine, rejouable et partageable.
// ═══════════════════════════════════════════════════════════
const DomainGen = (function(){

  // --- PRNG déterministe (xmur3 + mulberry32) ---
  function xmur3(str){
    let h = 1779033703 ^ str.length;
    for(let i = 0; i < str.length; i++){
      h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
      h = (h << 13) | (h >>> 19);
    }
    return function(){
      h = Math.imul(h ^ (h >>> 16), 2246822507);
      h = Math.imul(h ^ (h >>> 13), 3266489909);
      h ^= h >>> 16;
      return h >>> 0;
    };
  }
  function mulberry32(a){
    return function(){
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function makeRng(seedStr){
    const seedFn = xmur3(seedStr);
    return mulberry32(seedFn());
  }
  function pick(rng, arr){ return arr[Math.floor(rng() * arr.length)]; }
  function pickAndRemove(rng, arr){
    const i = Math.floor(rng() * arr.length);
    return arr.splice(i, 1)[0];
  }
  function randHex(rng, len){
    let s = '';
    for(let i=0;i<len;i++) s += Math.floor(rng()*16).toString(16);
    return s;
  }
  function randInt(rng, min, max){ return min + Math.floor(rng() * (max - min + 1)); }
  function stripAccents(str){
    return str.normalize('NFD').replace(/[\u0300-\u036f]/g,'');
  }

  // --- Génère un code de seed lisible et partageable, façon Wordle. ---
  function randomSeedCode(){
    const rng = Math.random;
    const consonnes = 'BCDFGHJKLMNPQRSTVWXZ';
    const chiffres = '0123456789';
    let code = '';
    for(let i=0;i<4;i++) code += consonnes[Math.floor(rng()*consonnes.length)];
    code += '-';
    for(let i=0;i<4;i++) code += chiffres[Math.floor(rng()*chiffres.length)];
    return code;
  }

  const PERSONS = [
    {first:'Camille', gender:'f'}, {first:'Julien', gender:'m'}, {first:'Sophie', gender:'f'},
    {first:'Antoine', gender:'m'}, {first:'Manon', gender:'f'}, {first:'Hugo', gender:'m'},
    {first:'Léa', gender:'f'}, {first:'Maxime', gender:'m'}, {first:'Chloé', gender:'f'},
    {first:'Nicolas', gender:'m'}, {first:'Emma', gender:'f'}, {first:'Thomas', gender:'m'},
    {first:'Sarah', gender:'f'}, {first:'Alexandre', gender:'m'}, {first:'Laura', gender:'f'},
    {first:'Vincent', gender:'m'}, {first:'Julie', gender:'f'}, {first:'Mathieu', gender:'m'},
    {first:'Claire', gender:'f'}, {first:'Romain', gender:'m'}, {first:'Inès', gender:'f'},
    {first:'Baptiste', gender:'m'}, {first:'Aurélie', gender:'f'}, {first:'Kevin', gender:'m'}
  ];
  const NOMS = [
    'Dubois','Moreau','Lefevre','Girard','Bonnet','Francois','Mercier','Blanc','Guerin','Muller',
    'Henry','Roussel','Perrin','Fournier','Andre','Lemaire','Barbier','Renaud','Faure','Masson',
    'Marchand','Duval','Leroy','Gauthier','Meunier'
  ];
  const COMPANIES = [
    'Nexoria','Veltrex','Astralia','Meridia','Octaven','Plumeria','Kortexa','Ondalys','Brivant',
    'Corvexa','Silvarium','Trentio','Lumira','Zephyria','Argenta','Vantex','Solyx','Fintara','Krono','Ombralis'
  ];
  const WEAK_PASSWORDS = [
    'Soleil2024!','Bonjour123','Ete2025!','Password123!','Azerty123!','Automne24!','Welcome2025',
    'Printemps22!','Motdepasse1!','Chocolat2024','Vacances23!','Domaine2024!','Reseau123!',
    'Sauvegarde22!','Entreprise1!','Bienvenue24','Rapport2024!','Intranet123!','Champion22!','Nouveau2024!'
  ];
  const COMPTA_DEPTS = ['Comptabilité','Ressources Humaines','Support Commercial'];

  function login(rng, usedLogins){
    let attempt, tries = 0;
    do {
      const p = pick(rng, PERSONS);
      const n = pick(rng, NOMS);
      attempt = { id: (stripAccents(p.first[0]).toLowerCase() + '.' + stripAccents(n).toLowerCase()), first:p.first, last:n, gender:p.gender };
      tries++;
    } while(usedLogins.has(attempt.id) && tries < 50);
    usedLogins.add(attempt.id);
    return attempt;
  }

  // --- Construit un domaine complet et l'applique sur SCENARIOS.libre ---
  function regenerateLibre(seedInput){
    const seed = (seedInput && String(seedInput).trim()) || randomSeedCode();
    const rng = makeRng(seed.toUpperCase());
    const sc = SCENARIOS.libre;

    const usedLogins = new Set();
    const startP = login(rng, usedLogins);
    const helpdeskP = login(rng, usedLogins);
    const comptaP = login(rng, usedLogins);
    const daP = login(rng, usedLogins);

    const company = pick(rng, COMPANIES).toUpperCase();
    const passwords = WEAK_PASSWORDS.slice();
    const pwWeb = pickAndRemove(rng, passwords);
    const pwSql = pickAndRemove(rng, passwords);
    const pwBackup = pickAndRemove(rng, passwords);
    const comptaDept = pick(rng, COMPTA_DEPTS);

    const numLegacy = randInt(rng, 2, 9);
    const numSql = randInt(rng, 1, 9);
    const numBackup = randInt(rng, 1, 9);
    const numWks = randInt(rng, 100, 199);

    const startUser = startP.id, helpdeskAccount = helpdeskP.id, comptaAccount = comptaP.id, daAccount = daP.id;
    const daGenderVerb = daP.gender === 'f' ? 'Directrice technique' : 'Directeur technique';
    const daGenderAdmin = daP.gender === 'f' ? 'Administratrice du domaine' : 'Administrateur du domaine';
    const startDesc = 'Employé' + (startP.gender==='f'?'e':'') + ' — support niveau 1';
    const helpdeskDesc = 'Employé' + (helpdeskP.gender==='f'?'e':'') + ' — support niveau 2, membre du groupe Helpdesk';
    const comptaDescGender = 'Employé' + (comptaP.gender==='f'?'e':'') + (comptaP.gender==='f'?' — service '+comptaDept.toLowerCase()+', gère les notes de frais' : ' — service '+comptaDept.toLowerCase()+', gère les notes de frais');

    const NTLM_HASH = randHex(rng, 32);

    sc.startUser = startUser;
    sc.helpdeskAccount = helpdeskAccount;
    sc.comptaAccount = comptaAccount;
    sc.daAccount = daAccount;
    sc.companyName = company;
    sc.seed = seed;
    sc.NTLM_HASH_CHEVALIER = NTLM_HASH;

    sc.identities = {
      [startUser]: { label:`${company}\\${startUser}`, priv:'Utilisateur standard', groups:['Domain Users'], desc: startDesc },
      'svc_web': { label:`${company}\\svc_web`, priv:'Compte de service', groups:['Domain Users'],
        desc:'Compte de service — application web intranet',
        spn:`HTTP/intranet.${company.toLowerCase()}.local`,
        hash:`tgs${randInt(rng,10,99)}_svc_web_${randHex(rng,8)}`,
        crackedPassword: pwWeb },
      'svc_sql': { label:`${company}\\svc_sql`, priv:'Compte de service', groups:['Domain Users'],
        desc:'Compte de service — base SQL de reporting',
        spn:`MSSQLSvc/sql-report${numSql}.${company.toLowerCase()}.local:1433`,
        hash:`tgs${randInt(rng,10,99)}_svc_sql_${randHex(rng,8)}`,
        crackedPassword: pwSql },
      'svc_legacy': { label:`${company}\\svc_legacy`, priv:'Compte de service', groups:['Domain Users'],
        desc:'Compte de service — vieux script de sauvegarde, jamais migré',
        spn:`HOST/legacy-app${numLegacy}.${company.toLowerCase()}.local`,
        hash:`tgs${randInt(rng,10,99)}_svc_legacy_${randHex(rng,8)}`,
        crackedPassword: null },
      [helpdeskAccount]: { label:`${company}\\${helpdeskAccount}`, priv:'Utilisateur standard', groups:['Domain Users','Helpdesk',comptaDept], desc: helpdeskDesc },
      'svc_backup': { label:`${company}\\svc_backup`, priv:'Compte de service', groups:['Domain Users','Server Admins'],
        desc:'Compte de service — sauvegardes nocturnes, ajouté par erreur au groupe Server Admins lors d\'une migration',
        spn:`HOST/backup${numBackup}.${company.toLowerCase()}.local`,
        hash:`tgs${randInt(rng,10,99)}_svc_backup_${randHex(rng,8)}`,
        crackedPassword: pwBackup },
      [comptaAccount]: { label:`${company}\\${comptaAccount}`, priv: comptaP.gender==='f' ? 'Utilisatrice standard':'Utilisateur standard', groups:['Domain Users',comptaDept], desc: comptaDescGender },
      [daAccount]: { label:`${company}\\${daAccount}`, priv: daGenderAdmin, groups:['Domain Users','Domain Admins'], desc: daGenderVerb }
    };

    sc.acl = {
      [helpdeskAccount]: [
        { principal:`${company}\\Domain Admins`, rights:'Full Control', normal:true },
        { principal:`${company}\\svc_web`, rights:'ForceChangePassword', normal:false }
      ],
      [comptaAccount]: [
        { principal:`${company}\\Domain Admins`, rights:'Full Control', normal:true },
        { principal:`${company}\\${comptaDept} (groupe)`, rights:'GenericAll', normal:false, viaGroup:comptaDept }
      ],
      [daAccount]: [
        { principal:`${company}\\Domain Admins`, rights:'Full Control', normal:true },
        { principal:`${company}\\Helpdesk (groupe)`, rights:'GenericAll', normal:false, viaGroup:'Helpdesk' },
        { principal:`${company}\\Server Admins (groupe)`, rights:'ForceChangePassword', normal:false, viaGroup:'Server Admins' }
      ]
    };

    sc.graph = {
      nodes:[
        { id:startUser, label:startUser, type:'user' },
        { id:'svc_web', label:'svc_web', type:'service' },
        { id:'svc_sql', label:'svc_sql', type:'service' },
        { id:'svc_legacy', label:'svc_legacy', type:'service' },
        { id:helpdeskAccount, label:helpdeskAccount, type:'user' },
        { id:'svc_backup', label:'svc_backup', type:'service' },
        { id:comptaAccount, label:comptaAccount, type:'user' },
        { id:daAccount, label:daAccount, type:'admin' },
        { id:'grp_helpdesk', label:'Helpdesk', type:'group' },
        { id:'grp_compta', label:comptaDept, type:'group' },
        { id:'grp_serveradmins', label:'Server Admins', type:'group' }
      ],
      edges:[
        { id:'mo_tnguyen', from:helpdeskAccount, to:'grp_helpdesk', type:'memberof', label:'MemberOf' },
        { id:'mo_kmorel', from:comptaAccount, to:'grp_compta', type:'memberof', label:'MemberOf' },
        { id:'mo_backup', from:'svc_backup', to:'grp_serveradmins', type:'memberof', label:'MemberOf (erreur)' },
        { id:'acl_web_tnguyen', from:'svc_web', to:helpdeskAccount, type:'abuse', label:'ForceChangePassword' },
        { id:'acl_compta_kmorel', from:'grp_compta', to:comptaAccount, type:'abuse', label:'GenericAll (impasse)' },
        { id:'acl_helpdesk_chevalier', from:'grp_helpdesk', to:daAccount, type:'abuse', label:'GenericAll' },
        { id:'acl_serveradmins_chevalier', from:'grp_serveradmins', to:daAccount, type:'abuse', label:'ForceChangePassword' },
        { id:'hash_sql_chevalier', from:'svc_sql', to:daAccount, type:'auth', label:'Hash en mémoire' },
        { id:'owned_pth', from:'svc_sql', to:daAccount, type:'owned', label:'Chemin emprunté (Pass-the-Hash)' },
        { id:'owned_helpdesk', from:'grp_helpdesk', to:daAccount, type:'owned', label:'Chemin emprunté (Helpdesk)' },
        { id:'owned_serveradmins', from:'grp_serveradmins', to:daAccount, type:'owned', label:'Chemin emprunté (Server Admins)' }
      ]
    };

    sc.graphMemberOf = {
      [helpdeskAccount]: { node:'grp_helpdesk', edge:'mo_tnguyen' },
      [comptaAccount]: { node:'grp_compta', edge:'mo_kmorel' },
      'svc_backup': { node:'grp_serveradmins', edge:'mo_backup' }
    };
    sc.graphAclEdges = {
      [helpdeskAccount]: { nodes:[], edges:['acl_web_tnguyen'] },
      [comptaAccount]: { nodes:['grp_compta'], edges:['acl_compta_kmorel'] },
      [daAccount]: { nodes:['grp_helpdesk','grp_serveradmins'], edges:['acl_helpdesk_chevalier','acl_serveradmins_chevalier'] }
    };

    sc.introLines = [
      `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
      `<span class="out-dim">Session ouverte en tant que ${company}\\${startUser} sur WKS-${numWks}</span>`,
      `<span class="out-warn">⚠ Domaine plus étendu que les scénarios précédents — plusieurs comptes de service, plusieurs chemins possibles.</span>`,
      `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
    ];

    sc.lessonSlides[3] = { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>${company}\\${startUser}</b>, employé standard sur le domaine <b>${company}.LOCAL</b>. Quelque part dans ce domaine plus vaste, plusieurs chemins mènent à un compte Domain Admin. Trouve le tien.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise. Domaine tiré au sort — seed : <code>${seed}</code>.</p>` };

    sc.hints[3] = [
      "Une fois dans la peau d'un compte de service, deux types de pistes existent en général : des droits oubliés sur d'autres comptes (parfois hérités d'un groupe entier, y compris un groupe où un compte n'a rien à faire), ou des identifiants qui traînent en mémoire sur le serveur où tourne ce service. Il y a plus d'une route valable jusqu'à un Domain Admin ici — et au moins une fausse piste à écarter.",
      "Si tu es sur le compte lié à l'appli web, regarde les droits (`get-objectacl`) sur d'autres comptes — y compris ceux accordés à un groupe entier. Si tu es sur le compte lié à la base SQL, regarde plutôt ce qui traîne en mémoire sur son serveur. Si tu es sur le compte de sauvegarde, regarde directement de quel groupe il est membre.",
      `Trois chemins possibles : (A) \`get-objectacl ${helpdeskAccount}\`, réinitialise son mot de passe, connecte-toi, puis regarde ses droits hérités via son groupe sur ${daAccount}. (B) en tant que svc_sql, \`mimikatz sekurlsa::logonpasswords\` puis \`pth /target:DC01 /user:${daAccount} /hash:<hash>\`. (C) en tant que svc_backup, \`get-objectacl ${daAccount}\` directement — son appartenance erronée à Server Admins suffit. Attention : une ACL alléchante trouvée en chemin peut ne mener nulle part si elle porte sur un compte sans aucun privilège réel.`
    ];
    sc.hints[4] = [
      "Une fois connecté avec les droits d'un compte Domain Admin, peu importe comment tu y es arrivé, la suite est la même.",
      "Regarde ce qu'il y a sur son bureau.",
      `\`dir\` puis \`type flag.txt\` une fois que tu es ${daAccount} — par n'importe lequel des deux chemins.`
    ];

    return seed;
  }

  return { regenerateLibre, randomSeedCode };
})();
