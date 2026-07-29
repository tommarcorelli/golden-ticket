function playBuzzSound(){
  if(typeof soundFxEnabled !== 'undefined' && !soundFxEnabled) return;
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'square';
    const start = ctx.currentTime;
    osc.frequency.setValueAtTime(120, start);
    osc.frequency.exponentialRampToValueAtTime(75, start + 0.14);
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.exponentialRampToValueAtTime(0.045, start + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.16);
    osc.connect(gain).connect(ctx.destination);
    osc.start(start);
    osc.stop(start + 0.16);
  }catch(e){ /* audio non disponible, tant pis */ }
}

function playEpicFanfare(){
  if(typeof soundFxEnabled !== 'undefined' && !soundFxEnabled) return;
  try{
    const ctx2 = new (window.AudioContext || window.webkitAudioContext)();
    // un accord grave qui monte, puis l'arpège triomphal
    const bass = [130.81, 164.81, 196.00]; // C3 E3 G3
    bass.forEach((freq,i)=>{
      const osc = ctx2.createOscillator();
      const gain = ctx2.createGain();
      osc.type = 'sawtooth';
      osc.frequency.value = freq;
      const start = ctx2.currentTime;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.05, start + 0.05);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.9);
      osc.connect(gain).connect(ctx2.destination);
      osc.start(start); osc.stop(start + 0.9);
    });
    const arp = [523.25, 659.25, 783.99, 1046.5, 1318.5]; // C5 E5 G5 C6 E6
    arp.forEach((freq,i)=>{
      const osc = ctx2.createOscillator();
      const gain = ctx2.createGain();
      osc.type = 'triangle';
      osc.frequency.value = freq;
      const start = ctx2.currentTime + 0.15 + i * 0.11;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.14, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.35);
      osc.connect(gain).connect(ctx2.destination);
      osc.start(start); osc.stop(start + 0.35);
    });
  }catch(e){ /* audio non disponible, tant pis */ }
}

function playVictorySound(){
  if(typeof soundFxEnabled !== 'undefined' && !soundFxEnabled) return;
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const notes = [523.25, 659.25, 783.99, 1046.5]; // C5 E5 G5 C6
    notes.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.value = freq;
      const start = ctx.currentTime + i * 0.09;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.12, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.28);
      osc.connect(gain).connect(ctx.destination);
      osc.start(start);
      osc.stop(start + 0.3);
    });
  }catch(e){ /* audio non disponible, tant pis */ }
}

function playDingSound(){
  if(typeof soundFxEnabled !== 'undefined' && !soundFxEnabled) return;
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'triangle';
    const start = ctx.currentTime;
    osc.frequency.setValueAtTime(880, start);
    osc.frequency.exponentialRampToValueAtTime(1318.5, start + 0.09);
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.exponentialRampToValueAtTime(0.08, start + 0.015);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.22);
    osc.connect(gain).connect(ctx.destination);
    osc.start(start);
    osc.stop(start + 0.22);
  }catch(e){ /* audio non disponible, tant pis */ }
}
