function downloadCertificate(){
  const sc = SCENARIOS[state.scenarioId];
  const certLabel = sc.certLabel || 'Golden Ticket';
  const certDomainLine = sc.certDomainLine || 'pour avoir compromis intégralement le domaine CORP.LOCAL';
  const chainLine = (sc.chainSteps || []).map(s => s.label).join(' → ');
  const name = (prompt('Ton nom ou pseudo pour le certificat :', 'CORP\\Domain Admin') || 'CORP\\Domain Admin').slice(0, 40);
  const timeText = document.getElementById('mc-time').textContent;
  const cmdsText = document.getElementById('mc-cmds').textContent;
  const hintsText = document.getElementById('mc-hints').textContent;
  const modeParts = [];
  if(state.expertMode) modeParts.push('🎓 Mode Expert');
  if(state.budgetMode && SCENARIOS[state.scenarioId].cmdBudget) modeParts.push('🎯 Mode Budget');
  const modeText = modeParts.length ? modeParts.join(' + ') : 'Mode Normal';
  const dateStr = new Date().toLocaleDateString('fr-FR', { day:'2-digit', month:'long', year:'numeric' });

  const canvas = document.createElement('canvas');
  canvas.width = 1200; canvas.height = 800;
  const ctx = canvas.getContext('2d');

  const bg = ctx.createLinearGradient(0, 0, 1200, 800);
  bg.addColorStop(0, '#0d0b17'); bg.addColorStop(1, '#1a1030');
  ctx.fillStyle = bg; ctx.fillRect(0, 0, 1200, 800);

  ctx.strokeStyle = '#f2b705'; ctx.lineWidth = 4;
  ctx.strokeRect(30, 30, 1140, 740);
  ctx.strokeStyle = 'rgba(242,183,5,0.35)'; ctx.lineWidth = 1;
  ctx.strokeRect(48, 48, 1104, 704);

  ctx.textAlign = 'center';
  ctx.fillStyle = '#f2b705';
  ctx.font = '700 24px monospace';
  ctx.fillText('🎫 DOMAIN BREACH LAB', 600, 128);

  ctx.fillStyle = '#ffffff';
  ctx.font = '700 50px Georgia, "Times New Roman", serif';
  ctx.fillText(`Certificat de ${certLabel}`, 600, 205);

  ctx.fillStyle = '#b8b3c9';
  ctx.font = '20px monospace';
  ctx.fillText('décerné à', 600, 262);

  ctx.fillStyle = '#f2b705';
  ctx.font = '700 38px monospace';
  ctx.fillText(name, 600, 320);

  ctx.fillStyle = '#e5e1f0';
  ctx.font = '18px monospace';
  ctx.fillText(certDomainLine, 600, 375);
  ctx.fillText(chainLine, 600, 402);

  ctx.fillStyle = '#a78bfa';
  ctx.font = '700 22px monospace';
  ctx.fillText(`⏱ ${timeText}    💻 ${cmdsText} commandes    💡 ${hintsText} indices    ${modeText}`, 600, 470);

  ctx.fillStyle = '#7a7690';
  ctx.font = '16px monospace';
  ctx.fillText(dateStr, 600, 525);

  ctx.strokeStyle = 'rgba(242,183,5,0.3)'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(400, 560); ctx.lineTo(800, 560); ctx.stroke();

  ctx.fillStyle = '#4a4560';
  ctx.font = '13px monospace';
  ctx.fillText('Simulation pédagogique — Golden Ticket Lab. Aucun système réel compromis.', 600, 700);

  const url = canvas.toDataURL('image/png');
  const a = document.createElement('a');
  a.href = url;
  a.download = `${state.scenarioId}-certificat.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}
