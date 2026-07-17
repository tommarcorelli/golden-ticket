// ═══════════════════════════════════════════════════════════
// Carte d'attaque façon BloodHound — graphe SVG qui se dessine
// EN DIRECT au fil de l'énumération.
//
// Générique : chaque scénario déclare son graphe complet (vérité
// terrain) via sc.graph = { nodes:[...], edges:[...] }. Ce module
// ne dessine jamais que ce que le joueur a réellement découvert
// (state révélé via AttackGraph.reveal()), jamais la solution
// entière d'un coup — exactement comme BloodHound se remplit au
// fil d'une énumération réelle.
//
// Convention : quand c'est possible, l'id d'un nœud correspond à
// la clé du compte dans sc.identities, ce qui permet à
// AttackGraph.markOwned(state.user) de fonctionner sans mapping.
// ═══════════════════════════════════════════════════════════
const AttackGraph = (function(){

  let discoveredNodes = new Set();
  let discoveredEdges = new Set();
  let tags = {};        // { nodeId: Set('spn'|'cracked'|'hash'|'reset'|'leak') }
  let owned = new Set();
  let rootId = null;
  let lightboxOpen = false;
  let lastFocus = null;

  const NODE_STYLE = {
    user:     { icon:'🧑', color:'var(--violet-accent)' },
    service:  { icon:'⚙️', color:'var(--gold-li)' },
    admin:    { icon:'👑', color:'var(--crimson-li)' },
    group:    { icon:'🗂️', color:'var(--text-md)' },
    computer: { icon:'🖥️', color:'var(--text-md)' },
    app:      { icon:'🧩', color:'var(--gold-li)' }
  };
  const EDGE_STYLE = {
    memberof: { dash:'4,4',  color:'var(--text-dim)',   width:1.3 },
    abuse:    { dash:'',     color:'var(--crimson-li)', width:2 },
    auth:     { dash:'2,3',  color:'var(--green)',      width:1.8 },
    owned:    { dash:'',     color:'var(--gold)',        width:2.8 }
  };
  const TAG_BADGE = { spn:'🎟️', cracked:'🔓', hash:'🧠', reset:'🔑', leak:'📄' };

  function esc(s){
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function sc(){ return (typeof currentScenario === 'function') ? currentScenario() : null; }

  function setCardVisibility(){
    const card = document.getElementById('graph-card');
    if(!card) return;
    const s = sc();
    card.style.display = (s && s.graph) ? '' : 'none';
  }

  // Réinitialise le graphe pour une nouvelle mission (appelé par bootTerminal()).
  function reset(){
    discoveredNodes = new Set();
    discoveredEdges = new Set();
    tags = {};
    owned = new Set();
    lightboxOpen = false;
    const overlay = document.getElementById('graph-lightbox');
    if(overlay){ overlay.classList.remove('show'); overlay.hidden = true; }
    const s = sc();
    rootId = s ? s.startUser : null;
    setCardVisibility();
    if(s && s.graph && rootId){
      discoveredNodes.add(rootId);
      owned.add(rootId);
    }
    render();
  }

  // Révèle progressivement des nœuds/arêtes/tags déjà présents dans sc.graph.
  // opts = { nodes:[ids], edges:[ids], tags:{ nodeId: 'tag' | ['tag',...] } }
  function reveal(opts){
    if(!opts) return;
    const s = sc();
    if(!s || !s.graph) return;
    (opts.nodes||[]).forEach(id=>{
      if(s.graph.nodes.some(n=>n.id===id)) discoveredNodes.add(id);
    });
    (opts.edges||[]).forEach(id=>{
      if(s.graph.edges.some(e=>e.id===id)) discoveredEdges.add(id);
    });
    if(opts.tags){
      Object.entries(opts.tags).forEach(([nid,tlist])=>{
        if(!tags[nid]) tags[nid] = new Set();
        (Array.isArray(tlist)?tlist:[tlist]).forEach(t=> tags[nid].add(t));
      });
    }
    render();
  }

  function markOwned(nodeId){
    if(!nodeId) return;
    owned.add(nodeId);
    discoveredNodes.add(nodeId);
    render();
  }

  // Layering BFS depuis le nœud racine (l'identité de départ du scénario) —
  // donne une lecture "de haut en bas", cohérente avec la progression du joueur.
  function computeLayout(nodes, edges){
    const adj = {};
    nodes.forEach(n=> adj[n.id] = []);
    edges.forEach(e=>{
      if(adj[e.from]) adj[e.from].push(e.to);
      if(adj[e.to]) adj[e.to].push(e.from);
    });
    const dist = {};
    if(rootId !== null && adj[rootId]){
      const q = [rootId]; dist[rootId] = 0;
      while(q.length){
        const cur = q.shift();
        (adj[cur]||[]).forEach(nb=>{ if(dist[nb] === undefined){ dist[nb] = dist[cur]+1; q.push(nb); } });
      }
    }
    let maxD = 0;
    Object.values(dist).forEach(d=> maxD = Math.max(maxD,d));
    nodes.forEach(n=>{ if(dist[n.id] === undefined) dist[n.id] = maxD + 1; });
    const layers = {};
    nodes.forEach(n=> (layers[dist[n.id]] = layers[dist[n.id]] || []).push(n));
    const layerKeys = Object.keys(layers).map(Number).sort((a,b)=>a-b);
    const W = 620;
    const rowH = 100;
    const H = Math.max(190, layerKeys.length * rowH + 30);
    const pos = {};
    layerKeys.forEach((lk, li)=>{
      const arr = layers[lk];
      const y = 42 + li * rowH;
      arr.forEach((n,i)=>{
        const x = (W/(arr.length+1)) * (i+1);
        pos[n.id] = {x,y};
      });
    });
    return {pos, W, H};
  }

  function buildSvg(large){
    const s = sc();
    if(!s || !s.graph) return '';
    const nodes = s.graph.nodes.filter(n=> discoveredNodes.has(n.id));
    const edges = s.graph.edges.filter(e=> discoveredEdges.has(e.id) && discoveredNodes.has(e.from) && discoveredNodes.has(e.to));
    if(!nodes.length) return '';
    const {pos, W, H} = computeLayout(nodes, edges);
    const r = large ? 25 : 19;
    const fs = large ? 12 : 9.5;

    let svg = `<svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Carte d'attaque : ${nodes.length} comptes découverts, ${edges.length} relation(s) trouvée(s)">`;
    svg += '<defs>';
    Object.keys(EDGE_STYLE).forEach(t=>{
      const st = EDGE_STYLE[t];
      svg += `<marker id="ag-arrow-${t}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${st.color}"/></marker>`;
    });
    svg += '</defs>';

    // arêtes d'abord (sous les nœuds)
    edges.forEach(e=>{
      const a = pos[e.from], b = pos[e.to];
      if(!a || !b) return;
      const st = EDGE_STYLE[e.type] || EDGE_STYLE.memberof;
      const mx = (a.x+b.x)/2, my = (a.y+b.y)/2;
      svg += `<line x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke="${st.color}" stroke-width="${st.width}" stroke-dasharray="${st.dash}" marker-end="url(#ag-arrow-${e.type||'memberof'})" opacity="0.9"/>`;
      if(e.label){
        const lw = Math.max(20, e.label.length * (fs*0.62));
        svg += `<rect x="${(mx-lw/2).toFixed(1)}" y="${(my-8).toFixed(1)}" width="${lw.toFixed(1)}" height="14" rx="4" fill="var(--bg1)" opacity="0.92"/>`;
        svg += `<text x="${mx.toFixed(1)}" y="${(my+2.5).toFixed(1)}" font-size="${fs}" font-family="var(--font-mono)" fill="${st.color}" text-anchor="middle">${esc(e.label)}</text>`;
      }
    });

    // nœuds
    nodes.forEach(n=>{
      const p = pos[n.id];
      if(!p) return;
      const style = NODE_STYLE[n.type] || NODE_STYLE.user;
      const isOwned = owned.has(n.id);
      svg += `<g class="ag-node">`;
      if(isOwned){
        svg += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r+4}" fill="none" stroke="var(--gold)" stroke-width="1" opacity="0.35"/>`;
      }
      svg += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r}" fill="var(--glass-md)" stroke="${isOwned ? 'var(--gold)' : style.color}" stroke-width="${isOwned?2.6:1.5}"/>`;
      svg += `<text x="${p.x.toFixed(1)}" y="${(p.y+5).toFixed(1)}" font-size="${large?17:13}" text-anchor="middle">${style.icon}</text>`;
      svg += `<text x="${p.x.toFixed(1)}" y="${(p.y+r+13).toFixed(1)}" font-size="${fs+1}" font-family="var(--font-mono)" fill="var(--text)" text-anchor="middle">${esc(n.label)}</text>`;
      const tset = tags[n.id];
      if(tset && tset.size){
        let bi = 0;
        tset.forEach(t=>{
          const badge = TAG_BADGE[t];
          if(!badge) return;
          const bx = p.x + r*0.68 + bi*(large?15:12);
          const by = p.y - r*0.68;
          svg += `<text x="${bx.toFixed(1)}" y="${by.toFixed(1)}" font-size="${large?13:10}" text-anchor="middle">${badge}</text>`;
          bi++;
        });
      }
      if(isOwned){
        svg += `<text x="${p.x.toFixed(1)}" y="${(p.y-r-6).toFixed(1)}" font-size="${large?12:9.5}" text-anchor="middle">👑</text>`;
      }
      svg += `</g>`;
    });
    svg += '</svg>';
    return svg;
  }

  function render(){
    const host = document.getElementById('graph-svg-host');
    const emptyMsg = document.getElementById('graph-empty-msg');
    if(host){
      const svg = buildSvg(false);
      host.innerHTML = svg;
      if(emptyMsg) emptyMsg.style.display = svg ? 'none' : '';
    }
    if(lightboxOpen){
      const hostLg = document.getElementById('graph-svg-host-lg');
      if(hostLg){
        const svgLg = buildSvg(true);
        hostLg.innerHTML = svgLg || `<p class="graph-empty-msg">La carte se remplit au fil de tes découvertes...</p>`;
      }
    }
  }

  function openLightbox(){
    const s = sc();
    if(!s || !s.graph) return;
    const overlay = document.getElementById('graph-lightbox');
    if(!overlay) return;
    lightboxOpen = true;
    render();
    overlay.hidden = false;
    overlay.classList.add('show');
    lastFocus = document.activeElement;
    document.addEventListener('keydown', onLightboxKey);
    const closeBtn = overlay.querySelector('.graph-lightbox-close');
    if(closeBtn) closeBtn.focus();
  }
  function closeLightbox(){
    const overlay = document.getElementById('graph-lightbox');
    if(!overlay) return;
    lightboxOpen = false;
    overlay.classList.remove('show');
    overlay.hidden = true;
    document.removeEventListener('keydown', onLightboxKey);
    if(lastFocus && document.body.contains(lastFocus)) lastFocus.focus();
  }
  function onLightboxKey(e){
    const overlay = document.getElementById('graph-lightbox');
    if(!overlay || !overlay.classList.contains('show')) return;
    if(e.key === 'Escape'){ closeLightbox(); return; }
    if(e.key !== 'Tab') return;
    const focusables = overlay.querySelectorAll('button, [href], [tabindex]:not([tabindex="-1"])');
    if(!focusables.length) return;
    const first = focusables[0], last = focusables[focusables.length-1];
    if(e.shiftKey && document.activeElement === first){ e.preventDefault(); last.focus(); }
    else if(!e.shiftKey && document.activeElement === last){ e.preventDefault(); first.focus(); }
  }

  return { reset, reveal, markOwned, openLightbox, closeLightbox, render };
})();
