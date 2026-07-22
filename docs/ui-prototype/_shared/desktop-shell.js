(() => {
  const frame = document.querySelector('.desktop-app-frame.reference-layout');
  const titlebar = frame?.querySelector(':scope > .desktop-titlebar');
  const sidebar = frame?.querySelector('.desktop-sidebar');

  if (!frame || !titlebar || !sidebar) return;

  const isUbuntu = titlebar.classList.contains('ubuntu');
  const platformLabel = isUbuntu ? 'Ubuntu 26.04 LTS' : 'Windows 11';

  titlebar.classList.remove('ubuntu');
  titlebar.classList.add('desktop-product-titlebar');
  titlebar.innerHTML = `
    <a class="desktop-titlebar-brand" href="home.html" aria-label="返回全部设备">
      <span class="desktop-titlebar-logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4M8 10l2.5 2.5L16 7"/></svg>
      </span>
      <strong>RC 远控</strong>
      <small>${platformLabel}</small>
    </a>
    <span class="desktop-titlebar-spacer"></span>
    <div class="desktop-titlebar-actions">
      <a class="desktop-titlebar-tool desktop-titlebar-account" href="settings.html#account" title="账号与设备" aria-label="账号与设备">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>
      </a>
      <button class="desktop-titlebar-tool" id="desktop-app-menu-button" type="button" title="菜单" aria-label="菜单" aria-controls="desktop-app-menu" aria-expanded="false">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
      </button>
      <span class="desktop-titlebar-divider"></span>
      <span class="desktop-window-controls" aria-label="窗口控制">
        <button class="desktop-window-control" type="button" title="最小化" aria-label="最小化"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M5 12h14"/></svg></button>
        <button class="desktop-window-control close" type="button" title="关闭" aria-label="关闭"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button>
      </span>
    </div>
    <nav class="desktop-app-menu" id="desktop-app-menu" aria-label="应用菜单" hidden>
      <a href="server.html"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg><span><strong>服务器</strong><small>配置自建服务</small></span></a>
      <a href="history.html"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/></svg><span><strong>会话记录</strong><small>查看连接和审计状态</small></span></a>
      <a href="settings.html#about"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg><span><strong>关于</strong><small>版本与更新信息</small></span></a>
    </nav>
  `;

  sidebar.querySelector('.desktop-brand')?.remove();
  sidebar.querySelector('.desktop-account-chip')?.remove();
  sidebar.querySelectorAll('.desktop-sidebar-group').forEach((group) => {
    const label = group.querySelector('.desktop-sidebar-group-title span')?.textContent.trim();
    if (label === '工具') group.remove();
  });

  const menuButton = titlebar.querySelector('#desktop-app-menu-button');
  const menu = titlebar.querySelector('#desktop-app-menu');
  const setMenuOpen = (open) => {
    menu.hidden = !open;
    menuButton.setAttribute('aria-expanded', String(open));
    menuButton.classList.toggle('active', open);
  };

  menuButton.addEventListener('click', (event) => {
    event.stopPropagation();
    setMenuOpen(menu.hidden);
  });
  menu.addEventListener('click', (event) => event.stopPropagation());
  document.addEventListener('click', () => setMenuOpen(false));
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') setMenuOpen(false);
  });
  if (location.hash === '#menu') setMenuOpen(true);
})();
