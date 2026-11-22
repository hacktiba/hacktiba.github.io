/**
 * Hacktiba - JS público: controla somente a interface e mostra JSON recebido.
 * A execução das consultas, correlação, indicadores e filtros ocorre no backend.
 * Não usa cookies, localStorage, identificação de visitantes nem formulários pessoais.
 */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
  const appConfig = window.HACKTIBA_CONFIG || {};
  const API = String(appConfig.apiBase || '').replace(/\/+$/, '');
  const siteKey = String(appConfig.turnstileSiteKey || '');
  const configured = /^https:\/\/[^/]+\.workers\.dev$/i.test(API) && !API.includes('CONFIGURAR')
    && /^[a-zA-Z0-9_-]{8,100}$/.test(siteKey) && !siteKey.includes('CONFIGURAR');
  let session = '';
  let acquiringSession = false;
  let widgetId = null;
  const mode = () => document.querySelector('input[name="mode"]:checked')?.value || 'feed';
  let selected = null, timer = null, revision = 0;
  let searchController = null, lastFeedData = null, lastFeedAt = 0;

  function message(text, kind = 'warn') {
    $('message').hidden = false;
    $('message').className = 'status ' + kind;
    $('message').textContent = text;
  }
  function clearMessage() { $('message').hidden = true; }
  function renderResult(title, html) {
    $('resultTitle').textContent = title;
    $('summary').hidden = true;
    $('findings').innerHTML = html;
    $('results').hidden = false;
    $('results').scrollIntoView({behavior: 'smooth', block: 'nearest'});
  }
  function showAccess(reason) {
    session = '';
    $('accessPanel').hidden = false;
    $('accessStatus').textContent = reason || 'Resolva a validação para pesquisar.';
    $('retryAccess').hidden = false;
    if (widgetId !== null && window.turnstile) {
      try {window.turnstile.reset(widgetId);} catch (_) {}
    }
    update();
  }
  window.hacktibaTurnstileReady = () => {
    if (!configured) {
      $('accessStatus').textContent = 'Site ainda não configurado. Verifique config.js e a Cloudflare.';
      return;
    }
    if (!window.turnstile) return;
    widgetId = window.turnstile.render('#turnstileWidget', {
      sitekey: siteKey,
      action: 'hacktiba_access',
      callback: async token => {
        if (acquiringSession) return;
        acquiringSession = true;
        $('accessStatus').textContent = 'Validando acesso...';
        try {
          const ctrl = new AbortController();
          const timer = setTimeout(() => ctrl.abort(), 12000);
          let resp;
          try {
            resp = await fetch(API + '/api/session', {
              method:'POST', headers:{'Content-Type':'application/json'},
              body: JSON.stringify({token}), credentials:'omit', referrerPolicy:'no-referrer', signal:ctrl.signal
            });
          } finally {clearTimeout(timer);}
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok || typeof data.session !== 'string') throw new Error(data.error || 'Não foi possível liberar a pesquisa.');
          session = data.session; // somente memória, nunca cookie ou localStorage
          $('accessPanel').hidden = true;
          $('retryAccess').hidden = true;
          update();
          if (mode() === 'feed') loadFeed();
        } catch (error) {
          showAccess(error.name === 'AbortError' ? 'Verificação demorou demais. Tente novamente.' : error.message);
        } finally {acquiringSession = false;}
      },
      'expired-callback': () => {if (!session) $('accessStatus').textContent = 'Validação expirada. Tente novamente.';},
      'error-callback': () => {if (!session) $('accessStatus').textContent = 'Erro ao carregar a verificação. Recarregue a página.';}
    });
  };
  async function request(path, params = {}, externalSignal = null) {
    if (!configured) throw new Error('Backend ainda não configurado. Verifique config.js.');
    if (!session) throw new Error('Valide seu acesso antes de pesquisar.');
    const url = new URL(API + '/api/' + path);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
    }
    const ctrl = new AbortController();
    const abortFromCaller = () => ctrl.abort();
    externalSignal?.addEventListener('abort', abortFromCaller, {once: true});
    if (externalSignal?.aborted) ctrl.abort();
    const timeout = setTimeout(() => ctrl.abort(), 27000);
    try {
      const res = await fetch(url, {signal: ctrl.signal, credentials: 'omit',
        referrerPolicy: 'no-referrer', headers: {'Authorization':`Bearer ${session}`}});
      const data = await res.json().catch(() => ({}));
      if (res.status === 401) {showAccess('A sessão expirou. Confirme seu acesso novamente.'); throw new Error('Sessão expirada.');}
      if (!res.ok) throw new Error(data.error || `Erro de consulta (${res.status}).`);
      return data;
    } catch (err) {
      if (err.name === 'AbortError') throw new Error('A consulta demorou demais. Tente novamente.');
      if (err instanceof TypeError) throw new Error('Não foi possível conectar ao backend. Verifique a rede.');
      throw err;
    } finally {clearTimeout(timeout); externalSignal?.removeEventListener('abort', abortFromCaller);}
  }
  function reset() {
    revision++;
    clearTimeout(timer);
    searchController?.abort();
    selected = null;
    $('plugin').value = '';
    $('clearQuery').hidden = true;
    $('ecosystem').value = '';
    $('malVersion').value = '';
    $('iocKind').value = 'auto';
    $('version').innerHTML = '<option value="all">Todas as versões</option>';
    $('version').disabled = true;
    $('suggestions').hidden = true;
    $('suggestions').replaceChildren();
    $('lookupStatus').textContent = 'Digite pelo menos 2 caracteres para pesquisar.';
    $('pluginOverview').hidden = true;
    $('selection').hidden = true;
    $('versionWrap').hidden = true;
    $('results').hidden = true;
    clearMessage();
    update();
  }
  function update() {
    const m = mode(), mal = m === 'malware', ioc = m === 'ioc';
    document.body.classList.toggle('feed-mode', m === 'feed');
    $('globalFeed').hidden = m !== 'feed';
    $('contextSamples').hidden = m !== 'context';
    $('cveSamples').hidden = m !== 'cve';
    $('malwareExtra').hidden = !mal;
    $('iocExtra').hidden = !ioc;
    $('stepTitle').textContent = m === 'context' ? 'Conhecer um plugin' : ioc ? 'Pesquisar indicador' : mal ? 'Pesquisar malware' : 'Pesquisar plugin e versão';
    $('pluginLabel').textContent = ioc ? 'Hash, IP, domínio, endereço web ou artefato' : mal ? 'Nome exato do pacote ou identificador MAL' : 'Buscar plugin no catálogo';
    $('plugin').placeholder = ioc ? 'Cole o indicador para pesquisar...' : mal ? 'Nome do pacote ou MAL-2025-...' : 'Comece a digitar: file manager, elementor...';
    $('plugin').maxLength = ioc ? 250 : mal ? 90 : 64;
    $('lookupStatus').hidden = mal || ioc;
    $('selection').hidden = !(m === 'context' || m === 'cve') || !selected;
    $('pluginOverview').hidden = m !== 'context' || !selected;
    $('versionWrap').hidden = m !== 'cve' || !selected;
    $('clearQuery').hidden = !$('plugin').value;
    $('analyze').hidden = m === 'context' || m === 'feed';
    $('analyze').textContent = ioc ? 'Pesquisar IOC' : mal ? 'Pesquisar malware' : 'Pesquisar vulnerabilidades';
    $('plugin').disabled = !session;
    $('refreshFeed').disabled = !session;
    for (const id of ['runContextSample','runCveSample','runIocSample']) $(id).disabled = !session;
    for (const sample of document.querySelectorAll('.example')) sample.disabled = !session;
    $('analyze').disabled = !configured || !session || (ioc ? !$('plugin').value.trim() : mal ? (!$('plugin').value.trim() || (!/^MAL-\d{4}-\d+$/i.test($('plugin').value.trim()) && !$('ecosystem').value)) : (!selected || $('version').disabled));
  }
  async function loadFeed(force = false) {
    const stamp = revision;
    const btn = $('refreshFeed');
    btn.disabled = true;
    $('globalFeedStatus').textContent = 'Consultando atualizações recentes...';
    $('globalFeedItems').replaceChildren();
    try {
      let data;
      if (!force && lastFeedData && Date.now() - lastFeedAt < 300000) {
        data = lastFeedData;
      } else {
        data = await request('feed');
        lastFeedData = data;
        lastFeedAt = Date.now();
      }
      if (stamp !== revision) return;
      for (const item of data.items || []) {
        const article = document.createElement('article');
        article.className = 'global-feed-item';
        const left = document.createElement('div');
        left.className = 'feed-entry';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = item.name || item.slug;
        btn.title = 'Consultar plugin';
        btn.addEventListener('click', () => {
          const tab = document.querySelector('input[name="mode"][value="context"]');
          tab.checked = true;
          reset();
          choose({name: item.name, slug: item.slug});
        });
        const note = document.createElement('p');
        note.textContent = item.note || '';
        const meta = document.createElement('small');
        meta.textContent = [item.version && `v${item.version}`, item.updated].filter(Boolean).join(' · ');
        const badge = document.createElement('span');
        badge.className = 'feed-security-badge';
        badge.textContent = 'Atualização de segurança';
        left.append(btn, note, meta);
        article.append(left, badge);
        $('globalFeedItems').append(article);
      }
      $('globalFeedStatus').textContent = data.notice || 'Atualizações recentes consultadas.';
      if (!data.items?.length) $('globalFeedStatus').textContent += ' Nenhuma menção encontrada nesta amostra; isso não significa ausência de riscos.';
    } catch (e) {
      if (stamp === revision) $('globalFeedStatus').textContent = e.message;
    } finally { btn.disabled = false; }
  }
  async function searchPlugins(term) {
    searchController?.abort();
    searchController = new AbortController();
    const stamp = ++revision;
    $('lookupStatus').textContent = 'Pesquisando...';
    $('suggestions').hidden = true;
    try {
      const data = await request('search', {q: term}, searchController.signal);
      if (stamp !== revision) return;
      $('suggestions').replaceChildren();
      for (const p of data.items || []) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'suggestion';
        const label = document.createElement('b'); label.textContent = p.name;
        const desc = document.createElement('small'); desc.textContent = p.slug;
        btn.append(label, desc);
        btn.addEventListener('click', () => choose(p));
        $('suggestions').append(btn);
      }
      $('suggestions').hidden = !(data.items || []).length;
      $('lookupStatus').textContent = `${(data.items || []).length} sugestão(ões) encontrada(s). Selecione um plugin.`;
    } catch (e) { if (stamp === revision) $('lookupStatus').textContent = e.message; }
  }
  async function choose(item) {
    searchController?.abort();
    const stamp = ++revision;
    selected = {name: item.name, slug: item.slug};
    $('plugin').value = item.name;
    $('suggestions').hidden = true;
    $('selection').innerHTML = `<span class="pill">✓ ${esc(item.slug)}</span>`;
    $('lookupStatus').textContent = 'Plugin selecionado.';
    $('version').innerHTML = '<option>Carregando versões...</option>';
    $('version').disabled = true;
    $('pluginOverview').hidden = true;
    update();
    try {
      const data = await request('plugin', {slug: item.slug});
      if (stamp !== revision) return;
      $('contextDescription').innerHTML = (data.description ? `<p class="context-lead">${esc(data.description)}</p>` : '<p class="help">Sem descrição disponível.</p>') +
        (data.version ? `<p class="context-meta"><b>Versão atual:</b> ${esc(data.version)}</p>` : '') +
        (data.updated ? `<p class="context-meta"><b>Última atualização:</b> ${esc(data.updated)}</p>` : '');
      const select = $('version');
      select.replaceChildren(new Option('Todas as versões (sem filtro)', 'all'));
      for (const v of data.versions || []) select.add(new Option(v, v));
      select.value = 'all';
      select.disabled = false;
      $('versionHelp').textContent = `${(data.versions || []).length} versões disponíveis. A pesquisa pode não abranger todo o histórico.`;
      update();
    } catch (e) {
      if (stamp !== revision) return;
      $('version').replaceChildren(new Option('Todas as versões', 'all'));
      $('version').disabled = false;
      message('Detalhes do plugin indisponíveis: ' + e.message, 'warn');
      update();
    }
  }
  function renderCve(data, version) {
    let html = `<p class="result-note">${esc(data.notice || '')}</p>`;
    if (!data.items?.length) html += '<div class="status warn">Nenhuma ocorrência correspondente nesta consulta. Isso não comprova segurança.</div>';
    for (const c of data.items || []) {
      const severity = String(c.severity || '').toLowerCase();
      html += `<article class="item"><div class="finding-head"><b>${esc(c.id)}</b>${c.severity ? `<span class="tag severity ${esc(severity)}">${esc(c.severity)}</span>` : ''}</div>` +
        `<p>${esc(c.description)}</p><p><b>Versão selecionada:</b> ${esc(version === 'all' ? 'Todas' : version)}</p>` +
        `<p><b>Correlação da versão:</b> ${esc(c.status)}</p>` +
        (c.score !== null ? `<p><b>CVSS:</b> ${esc(c.score)}</p>` : '') +
        (c.attack ? `<p><b>Vetor de ataque:</b> ${esc(c.attack)}</p>` : '') +
        (c.privileges ? `<p><b>Privilégios necessários:</b> ${esc(c.privileges)}</p>` : '') +
        (c.weaknesses?.length ? `<p><b>CWE:</b> ${esc(c.weaknesses.join(', '))}</p>` : '') +
        (c.vector ? `<p class="help">Vetor CVSS: ${esc(c.vector)}</p>` : '') + '</article>';
    }
    return html;
  }
  function renderMalware(data) {
    let html = `<p class="result-note">${esc(data.notice || '')}</p>`;
    if (!data.items?.length) html += '<div class="status warn">Nenhum registro MAL correspondente. Isso não comprova ausência de malware.</div>';
    for (const item of data.items || []) {
      html += `<article class="item"><div class="finding-head"><b>${esc(item.id)}</b><span class="tag">MAL</span></div>` +
        (item.summary ? `<p>${esc(item.summary)}</p>` : '') +
        (item.packages?.length ? `<p><b>Pacotes:</b> ${esc(item.packages.join(', '))}</p>` : '') +
        (item.details ? `<div class="osv-detail"><b>Detalhes técnicos publicados</b><p>${esc(item.details)}</p></div>` : '') +
        (item.updated ? `<p class="help">Registro atualizado: ${esc(item.updated)}</p>` : '');
      for (const a of item.affected || []) {
        html += `<div class="osv-detail"><b>Versões / intervalos informados</b><p>${esc(a.package)}</p>` +
          (a.versions?.length ? `<p>${esc(a.versions.join(', '))}</p>` : '') +
          (a.intervals?.length ? `<p>${esc(a.intervals.join(' · '))}</p>` : '') + '</div>';
      }
      html += '</article>';
    }
    return html;
  }
  function renderIoc(data) {
    let html = `<p class="result-note">${esc(data.notice || '')}</p>`;
    if (!data.items?.length) html += '<div class="status warn">Nenhuma referência correspondente na base demonstrativa. Isso não comprova ausência de ameaças.</div>';
    for (const item of data.items || []) {
      html += `<article class="item"><div class="finding-head"><b>${esc(item.value)}</b><span class="tag">${esc(item.type)}</span></div>` +
        (item.plugin ? `<p><b>Plugin citado:</b> ${esc(item.plugin)}</p>` : '') +
        (item.description ? `<p>${esc(item.description)}</p>` : '') + '</article>';
    }
    return html;
  }
  async function analyze() {
    const m = mode();
    $('results').hidden = true;
    clearMessage();
    const btn = $('analyze');
    btn.disabled = true;
    btn.textContent = 'Pesquisando...';
    try {
      let data, html, title;
      if (m === 'cve') {
        if (!selected) throw new Error('Selecione um plugin.');
        const version = $('version').value;
        data = await request('cve', {slug: selected.slug, name: selected.name, version});
        html = renderCve(data, version); title = 'Vulnerabilidades encontradas';
      } else if (m === 'malware') {
        data = await request('malware', {name: $('plugin').value.trim(), ecosystem: $('ecosystem').value, version: $('malVersion').value.trim()});
        html = renderMalware(data); title = 'Resultado de malware';
      } else if (m === 'ioc') {
        data = await request('ioc', {value: $('plugin').value.trim(), kind: $('iocKind').value});
        html = renderIoc(data); title = 'Indicadores encontrados';
      } else return;
      renderResult(title, html);
    } catch (e) { message(e.message, 'error'); }
    finally { update(); }
  }

  document.querySelectorAll('input[name="mode"]').forEach(tab => tab.addEventListener('change', () => {
    reset();
    if (mode() === 'feed') loadFeed();
  }));
  $('plugin').addEventListener('input', () => {
    const query = $('plugin').value.trim();
    clearTimeout(timer);
    searchController?.abort();
    selected = null;
    revision++;
    $('pluginOverview').hidden = true;
    $('selection').hidden = true;
    $('suggestions').hidden = true;
    $('results').hidden = true;
    clearMessage();
    update();
    if (!['context','cve'].includes(mode())) return;
    if (query.length < 2) { $('lookupStatus').textContent = 'Digite pelo menos 2 caracteres.'; return; }
    timer = setTimeout(() => searchPlugins(query), 500);
  });
  $('clearQuery').onclick = () => { $('plugin').value = ''; $('plugin').dispatchEvent(new Event('input')); $('plugin').focus(); };
  $('reset').onclick = reset;
  $('newSearch').onclick = () => {
    document.querySelector('input[name="mode"][value="feed"]').checked = true;
    reset(); loadFeed(); window.scrollTo({top: 0, behavior: 'smooth'});
  };
  $('refreshFeed').onclick = () => loadFeed(true);
  $('analyze').onclick = analyze;
  $('ecosystem').addEventListener('change', update);
  $('version').addEventListener('change', update);
  $('runContextSample').onclick = () => choose({name: 'Elementor Website Builder', slug: 'elementor'});
  $('runCveSample').onclick = async () => {
    await choose({name: 'File Manager', slug: 'wp-file-manager'});
    if (!selected || selected.slug !== 'wp-file-manager') return;
    if ([...$('version').options].some(o => o.value === '6.8')) $('version').value = '6.8';
    update();
    await analyze();
  };
  $('runIocSample').onclick = () => {
    $('plugin').value = 'wp-content/plugins/wp-compat/wp-compat.php';
    $('iocKind').value = 'auto'; update(); analyze();
  };
  document.querySelectorAll('.example').forEach(btn => btn.addEventListener('click', () => {
    $('plugin').value = btn.dataset.name || '';
    $('ecosystem').value = btn.dataset.eco || '';
    $('malVersion').value = '';
    update(); analyze();
  }));
  $('retryAccess').onclick = () => showAccess('Confirme seu acesso para continuar.');
  reset();
  if (!configured) $('accessStatus').textContent = 'Para utilizar, publique os Workers e execute o instalador.';
})();
