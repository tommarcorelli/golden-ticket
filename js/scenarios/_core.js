// ═══════════════════════════════════════════════════════════
// Données & logique spécifiques à chaque scénario.
// Le moteur générique (terminal.js) délègue ici via sc.handle().
// ═══════════════════════════════════════════════════════════

const SCENARIOS = {};

// ═══════════════════════════════════════════════════════════
// Système OPSEC (furtivité) — règles de "bruit" partagées entre scénarios.
// Chaque règle : une commande qui, une fois exécutée, fait monter la jauge
// d'alerte SOC simulée (voir addNoise() dans terminal.js).
// Volontairement, les actions hors-ligne (crack, forge de ticket brute) n'en
// génèrent pas : la leçon est que l'exploitation elle-même est souvent
// discrète — ce sont l'authentification et les changements d'annuaire qui
// laissent des traces.
// ═══════════════════════════════════════════════════════════
function noiseRule(regex, points, label){
  return { test:(lower) => regex.test(lower), points, label };
}

const NOISE = {
  netUserAll:     noiseRule(/^net user \/domain$/, 4, 'Énumération des comptes du domaine'),
  netUserOne:     noiseRule(/^net user \S+ \/domain$/, 4, "Consultation d'un compte du domaine"),
  domainUserSpn:  noiseRule(/^(get-domainuser -spn|getdomainuser -spn)$/, 4, 'Requête LDAP filtrée sur les SPN'),
  kerberoast:     noiseRule(/^invoke-kerberoast -identity \S+$/, 18, 'Demande de ticket de service (Event ID 4769)'),
  runas:          noiseRule(/^runas \/user:\S+ cmd$/, 10, "Événement d'authentification (ouverture de session)"),
  objectAcl:      noiseRule(/^get-objectacl \S+$/, 3, "Lecture d'ACL"),
  resetPassword:  noiseRule(/^set-domainuserpassword -identity \S+ -newpassword \S+$/, 20, 'Réinitialisation de mot de passe (Event ID 4724)'),
  mimikatzLogon:  noiseRule(/^mimikatz sekurlsa::logonpasswords$/, 25, 'Extraction mémoire LSASS (souvent détectée par un EDR)'),
  mimikatzDcsync: noiseRule(/^mimikatz lsadump::dcsync \/user:krbtgt$/, 40, 'Réplication DCSync (Event ID 4662 — très anormal hors des DC)'),
  dcsyncAny:      noiseRule(/^mimikatz lsadump::dcsync \/user:\S+$/, 40, "Réplication DCSync (Event ID 4662 — très anormal hors d'un contrôleur de domaine)"),
  mimikatzGolden: noiseRule(/^mimikatz kerberos::golden .*$/, 10, "Forge d'un ticket (préparation risquée)"),
  pth:            noiseRule(/^pth \/target:\S+ \/user:\S+ \/hash:\S+$/, 15, 'Authentification par hash (NTLM)'),
  mgAppAll:       noiseRule(/^get-mgapp -all$/, 4, 'Requête Microsoft Graph en lecture'),
  mgAppOne:       noiseRule(/^get-mgapp \S+$/, 4, 'Requête Microsoft Graph en lecture'),
  mgRoleMembers:  noiseRule(/^get-mgrolemembers -role \S+$/, 4, 'Requête Microsoft Graph en lecture'),
  connectMgraph:  noiseRule(/^connect-mgraph -appid \S+ -secret \S+$/, 12, 'Connexion consignée (journal de connexion Entra ID)'),
  addCredential:  noiseRule(/^add-credential -target \S+$/, 22, "Modification d'annuaire consignée (ajout d'un identifiant d'application)"),
  certipyFind:    noiseRule(/^certipy find$/, 6, "Énumération des modèles de certificats (requête LDAP vers l'AD CS)"),
  certipyReq:     noiseRule(/^certipy req -template \S+ -upn \S+$/, 16, "Demande de certificat (Event ID 4886/4887 côté serveur AD CS)"),
  certipyAuth:    noiseRule(/^certipy auth -cert \S+$/, 20, "Authentification Kerberos par certificat (PKINIT) pour un compte à privilèges"),
  whiskerAdd:     noiseRule(/^whisker add \/target:\S+$/, 17, "Modification de l'attribut msDS-KeyCredentialLink (Event ID 5136)"),
  whiskerAuth:    noiseRule(/^whisker auth \/target:\S+$/, 20, "Authentification Kerberos par clé (PKINIT) pour un compte à privilèges"),
  domainComputerUnconstrained: noiseRule(/^get-domaincomputer -unconstrained$/, 5, "Requête LDAP sur les comptes machine trustés pour la délégation"),
  petitpotam:     noiseRule(/^petitpotam \/listener:\S+ \/target:\S+$/, 30, "Coercition d'authentification forcée par MS-EFSRPC (très visible sur le réseau)"),
  sekurlsaTickets: noiseRule(/^mimikatz sekurlsa::tickets \/export$/, 15, 'Extraction mémoire LSASS des tickets Kerberos en cache'),
  kerberosPtt:    noiseRule(/^mimikatz kerberos::ptt \S+$/, 12, "Injection d'un ticket Kerberos en mémoire (Pass-the-Ticket)"),
  caPolicyEnum:   noiseRule(/^get-capolicies$/, 4, "Lecture des politiques Conditional Access (Global Reader ou tableau de bord de conformité)"),
  mgUserLookup:   noiseRule(/^get-mguser \S+$/, 4, "Requête Microsoft Graph en lecture sur un compte utilisateur"),
  passwordSpray:  noiseRule(/^invoke-passwordspray -user \S+ -wordlist \S+$/, 25, "Rafale de tentatives d'authentification échouées (Event ID Entra ID « Sign-in » multiples, risque de verrouillage)"),
  connectMguser:  noiseRule(/^connect-mguser -user \S+ -password \S+$/, 10, "Connexion consignée (journal de connexion Entra ID) — sans challenge MFA"),
  dumpAdsyncDb:   noiseRule(/^dump-adsyncdb$/, 6, "Lecture de la base de configuration ADSync (SQL Server Express local)"),
  decryptAdsyncCreds: noiseRule(/^decrypt-adsynccreds$/, 14, "Déchiffrement local des identifiants de connecteur ADSync (accès aux clés DPAPI de la machine)"),
  domainGpoEnum:  noiseRule(/^get-domaingpo$/, 4, "Énumération des objets GPO du domaine (requête LDAP)"),
  gpoAbuse:       noiseRule(/^gpoabuse -gpo \S+ -type localadmin -target \S+$/, 24, "Modification de la sécurité d'un objet GPO (Event ID 5136) — un changement qui touche toute une OU d'un coup"),
  gpupdateForce:  noiseRule(/^gpupdate \/force \/target:\S+$/, 10, "Actualisation forcée de la stratégie de groupe sur un poste distant"),
  asrepFind:      noiseRule(/^get-domainuser -preauthdisabled$/, 4, 'Requête LDAP filtrée sur le flag DONT_REQ_PREAUTH (comptes sans pré-authentification Kerberos)'),
  asreproast:     noiseRule(/^invoke-asreproast -identity \S+$/, 14, 'Demande de TGT sans pré-authentification (Event ID 4768 avec RC4, visible dans les logs du contrôleur de domaine)')
};

// ---------------------------------------------------------
// SCÉNARIO 01 — KERBEROASTING
// ---------------------------------------------------------
