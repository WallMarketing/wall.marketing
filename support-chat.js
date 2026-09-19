(() => {
  const style = document.createElement('style');
  style.textContent = `
    .wall-chat-launcher{display:grid;place-items:center;position:fixed;right:22px;bottom:22px;z-index:2000;width:52px;height:52px;border:0;border-radius:50%;background:#1B1D1F;color:#EDEFEC;box-shadow:0 8px 22px rgba(27,29,31,.24);font-size:1.35rem;cursor:pointer}
    .wall-chat-launcher:hover{background:#3826F0}
    .wall-chat-panel{position:fixed;right:22px;bottom:86px;z-index:2000;width:min(360px,calc(100vw - 32px));background:#F4F6F2;border:1px solid #CBD1CA;border-radius:4px;box-shadow:0 18px 46px rgba(27,29,31,.25);overflow:hidden}
    .wall-chat-panel[hidden]{display:none}
    .wall-chat-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:#1B1D1F;color:#EDEFEC}
    .wall-chat-head strong{font-weight:700}
    .wall-chat-close{padding:0 4px;border:0;background:transparent;color:inherit;font-size:1.2rem;cursor:pointer}
    .wall-chat-log{display:grid;gap:10px;max-height:300px;padding:16px;overflow-y:auto;font-size:.88rem}
    .wall-chat-message{max-width:88%;padding:9px 11px;border-radius:3px;line-height:1.4}
    .wall-chat-message.agent{background:#E6E9E4;color:#1F2225}
    .wall-chat-message.user{justify-self:end;background:#3826F0;color:#fff}
    .wall-chat-form{display:flex;gap:8px;padding:12px;border-top:1px solid #CBD1CA}
    .wall-chat-input{min-width:0;flex:1;padding:9px 10px;border:1px solid #CBD1CA;border-radius:3px;background:#fff;color:#1F2225}
    .wall-chat-send{padding:9px 12px;border:0;border-radius:3px;background:#1B1D1F;color:#F4F6F2;cursor:pointer}
    .wall-chat-send:hover{background:#3826F0}
    .wall-chat-typing{display:flex;gap:4px;align-items:center;width:max-content;padding:11px 12px;background:#E6E9E4;border-radius:3px}
    .wall-chat-typing i{width:5px;height:5px;border-radius:50%;background:#5C625E;animation:wall-chat-dot 1s infinite ease-in-out}
    .wall-chat-typing i:nth-child(2){animation-delay:.15s}.wall-chat-typing i:nth-child(3){animation-delay:.3s}
    @keyframes wall-chat-dot{0%,60%,100%{opacity:.35;transform:translateY(0)}30%{opacity:1;transform:translateY(-2px)}}
  `;
  document.head.appendChild(style);
  const launcher = document.createElement('button');
  launcher.className = 'wall-chat-launcher';
  launcher.type = 'button';
  launcher.setAttribute('aria-label', 'Open support chat');
  launcher.innerHTML = '<svg viewBox="0 0 24 24" width="28" height="28" aria-hidden="true"><path d="M4 5.5h16v10H9l-5 3v-13Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M8 10h8M8 13h5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
  const panel = document.createElement('section');
  panel.className = 'wall-chat-panel';
  panel.hidden = true;
  panel.innerHTML = '<div class="wall-chat-head"><strong>Wall Marketing - Support</strong><button class="wall-chat-close" type="button" aria-label="Close chat">&times;</button></div><div class="wall-chat-log" aria-live="polite"></div><form class="wall-chat-form"><input class="wall-chat-input" autocomplete="off" required><button class="wall-chat-send" type="submit">Send</button></form>';
  document.body.append(launcher, panel);
  const log = panel.querySelector('.wall-chat-log');
  const input = panel.querySelector('.wall-chat-input');
  const form = panel.querySelector('.wall-chat-form');
  let step = 0;
  let firstMessage = '';
  let email = '';
  let submitted = false;
  let busy = false;
  function addMessage(text, type){
    const message = document.createElement('div');
    message.className = `wall-chat-message ${type}`;
    message.textContent = text;
    log.appendChild(message);
    log.scrollTop = log.scrollHeight;
  }
  function agent(text){ addMessage(text, 'agent'); }
  function wait(milliseconds){ return new Promise((resolve) => setTimeout(resolve, milliseconds)); }
  async function delayedAgent(text, milliseconds = 900){
    busy = true;
    input.disabled = true;
    panel.querySelector('.wall-chat-send').disabled = true;
    const typing = document.createElement('div');
    typing.className = 'wall-chat-typing';
    typing.innerHTML = '<i></i><i></i><i></i>';
    log.appendChild(typing);
    log.scrollTop = log.scrollHeight;
    await wait(milliseconds);
    typing.remove();
    agent(text);
    busy = false;
    input.disabled = false;
    panel.querySelector('.wall-chat-send').disabled = false;
    input.focus();
  }
  function open(){
    panel.hidden = false;
    if (!step) { step = 1; delayedAgent('Hello, how can I help you today?', 6000); }
    input.focus();
  }
  launcher.addEventListener('click', open);
  panel.querySelector('.wall-chat-close').addEventListener('click', () => { panel.hidden = true; });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const value = input.value.trim();
    if (!value) return;
    addMessage(value, 'user');
    input.value = '';
    if (step === 1) {
      firstMessage = value;
      step = 2;
      delayedAgent('Can I get your email address in case we get disconnected?');
      input.type = 'email';
      input.placeholder = 'you@example.com';
      return;
    }
    if (step === 2) {
      email = value;
      step = 3;
      input.placeholder = '';
      input.type = 'text';
      await delayedAgent('Thank you, how can I help you today?');
      return;
    }
    if (step === 3) {
      step = 4;
      await delayedAgent('I will have someone contact you by email shortly');
      input.disabled = true;
      panel.querySelector('.wall-chat-send').disabled = true;
      if (!submitted) {
        submitted = true;
        try {
          await fetch('/api/support-conversations', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ message:firstMessage, email }) });
        } catch {}
      }
    }
  });
})();
