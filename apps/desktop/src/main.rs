use remote_desktop::api::{
    now_epoch_millis, ApiClient, Architecture, CreateSessionRequest, DeviceCapabilities,
    DeviceRegistrationMetadata, LoginChallenge, LoginFinishOutcome, LoginRequest, MfaFactor,
    Platform, ReqwestHttpTransport,
};
use remote_desktop::app::MfaFlowError;
use remote_desktop::signal::SignalConnectContext;
use remote_desktop::{
    current_platform, AccountTokenManager, AppModel, DeviceIdentityManager, InputManager,
    JsonFileServiceConfigStore, LocalDeviceRegistration, LoginError, Page, ProcessSecretStore,
    ServiceConfig, ServiceConfigStore, SessionResources, SignalClient, SignalConnectionState,
    SignalWebSocketClient,
};
use remote_render::RenderSurface;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

slint::include_modules!();

struct DesktopController {
    model: AppModel,
    config_store: Option<JsonFileServiceConfigStore>,
    http: Option<Arc<ReqwestHttpTransport>>,
    tokens: AccountTokenManager,
    identity: DeviceIdentityManager,
    signal: SignalWebSocketClient,
    last_signal_state: SignalConnectionState,
    session: Option<SessionResources<Box<dyn remote_desktop::input::InputBackend>>>,
    pending_login: Option<LoginChallenge>,
}

impl DesktopController {
    fn new() -> Self {
        let platform = current_platform();
        let mut model = AppModel::new(platform.snapshot());
        let config_store = JsonFileServiceConfigStore::for_current_user().ok();
        let persisted = config_store
            .as_ref()
            .and_then(|store| store.load().ok().flatten());
        let configured = ServiceConfig::from_environment()
            .ok()
            .flatten()
            .or(persisted);
        if let Some(config) = configured {
            let label = config.environment_label();
            model.set_service_config(config, format!("已加载{label}配置"));
        }
        let http = ReqwestHttpTransport::new().ok().map(Arc::new);
        if http.is_none() {
            model.set_server_status("HTTP 客户端初始化失败");
        }
        let secret_store = Arc::new(ProcessSecretStore::default());
        Self {
            model,
            config_store,
            http,
            tokens: AccountTokenManager::new(secret_store.clone()),
            identity: DeviceIdentityManager::new(secret_store),
            signal: SignalWebSocketClient::default(),
            last_signal_state: SignalConnectionState::Disconnected,
            session: None,
            pending_login: None,
        }
    }

    fn api_client(&self, config: &ServiceConfig) -> Result<ApiClient, &'static str> {
        let transport = self.http.clone().ok_or("HTTP 客户端不可用")?;
        Ok(ApiClient::new(config.clone(), transport))
    }

    fn login(&mut self, account: &str, password: &str) {
        if let Err(error) = AppModel::validate_login(account, password) {
            self.model.set_login_status(match error {
                LoginError::MissingAccount => "请输入账号",
                LoginError::MissingPassword => "请输入密码",
            });
            return;
        }
        let Some(config) = self.model.service_config().cloned() else {
            self.model
                .set_login_status("未配置服务地址；请先使用已持久化配置或 RCTL_* 环境变量");
            return;
        };
        let client = match self.api_client(&config) {
            Ok(client) => client,
            Err(error) => {
                self.model.set_login_status(error);
                return;
            }
        };
        if let Err(error) = self.identity.load_or_create() {
            self.model
                .set_login_status(format!("设备身份初始化失败：{error}"));
            return;
        }
        let identity = self.identity.shared_current().expect("identity loaded");
        let request = LoginRequest::new(account.trim(), password, identity.as_ref());
        match client.login(&request) {
            Ok(challenge) if challenge.required_factors.is_empty() => self.finish_login_challenge(
                account.trim(),
                &config,
                &client,
                challenge,
                None,
                None,
            ),
            Ok(challenge) => {
                self.model.begin_mfa(
                    account.trim(),
                    challenge.mfa_challenge(),
                    now_epoch_millis(),
                );
                self.pending_login = Some(challenge);
            }
            Err(error) => self.model.set_login_status(format!("登录失败：{error}")),
        }
    }

    fn verify_mfa(&mut self, factor_index: i32, code: &str) {
        let factor = match factor_index {
            0 => MfaFactor::Totp,
            1 => MfaFactor::RecoveryCode,
            _ => {
                self.model.set_login_status("所选 MFA 验证方式不可用");
                return;
            }
        };
        let now = now_epoch_millis();
        let attempt = match self.model.prepare_mfa_attempt(factor, code, now) {
            Ok(attempt) => attempt,
            Err(error) => {
                self.model.set_login_status(match error {
                    MfaFlowError::MissingChallenge => "MFA 挑战不存在，请重新登录",
                    MfaFlowError::EmptyCode => "请输入身份验证器代码或恢复码",
                    MfaFlowError::FactorNotAllowed => "服务端未允许所选 MFA 验证方式",
                    MfaFlowError::Expired => "验证已过期，请取消并重新登录",
                    MfaFlowError::AttemptsExhausted => "验证次数已用尽，请取消并重新登录",
                });
                return;
            }
        };
        let Some(config) = self.model.service_config().cloned() else {
            self.model
                .set_login_status("服务配置缺失，请取消并重新登录");
            return;
        };
        let client = match self.api_client(&config) {
            Ok(client) => client,
            Err(_) => {
                self.model
                    .set_login_status("MFA 验证请求失败，请检查网络或服务状态后重试");
                return;
            }
        };
        let Some(challenge) = self.pending_login.clone() else {
            self.model.set_login_status("登录挑战已丢失，请重新登录");
            return;
        };
        if challenge.login_challenge_id != attempt.challenge_id {
            self.model.set_login_status("MFA 挑战不匹配，请重新登录");
            return;
        }
        match client.finish_login(&challenge, self.identity.current().expect("identity loaded"), Some(attempt.factor), Some(code.trim())) {
            Ok(outcome) => {
                self.model.complete_mfa();
                self.pending_login = None;
                self.finish_authenticated_login(&attempt.account, &config, &client, outcome);
            }
            Err(error) if error.code() == Some("login_verification_failed") => {
                self.model.record_mfa_rejection(now_epoch_millis());
            }
            Err(error) if error.code() == Some("unsupported_version") => self
                .model
                .set_login_status("客户端协议版本不受服务端支持，请更新客户端"),
            Err(_) => self
                .model
                .set_login_status("MFA 验证请求失败，请检查网络或服务状态后重试"),
        }
    }

    fn cancel_mfa(&mut self) {
        self.model.cancel_mfa();
        self.pending_login = None;
    }

    fn finish_login_challenge(
        &mut self,
        account: &str,
        config: &ServiceConfig,
        client: &ApiClient,
        challenge: LoginChallenge,
        factor: Option<MfaFactor>,
        code: Option<&str>,
    ) {
        let Some(identity) = self.identity.current() else {
            self.model.set_login_status("设备私钥未加载");
            return;
        };
        match client.finish_login(&challenge, identity, factor, code) {
            Ok(outcome) => self.finish_authenticated_login(account, config, client, outcome),
            Err(error) => self.model.set_login_status(format!("登录完成验证失败：{error}")),
        }
    }

    fn finish_authenticated_login(
        &mut self,
        account: &str,
        config: &ServiceConfig,
        client: &ApiClient,
        outcome: LoginFinishOutcome,
    ) {
        let tokens = outcome.tokens;
        let account_id = tokens.account_id.clone();
        let token_report = match self.tokens.install(tokens) {
            Ok(report) => report,
            Err(error) => {
                self.model
                    .set_login_status(format!("账号 token 管理失败：{error}"));
                return;
            }
        };
        let identity_report = match self.identity.load_or_create() {
            Ok(report) => report,
            Err(error) => {
                self.fail_authenticated_login(format!("设备身份初始化失败：{error}"));
                return;
            }
        };
        let access_token = match self
            .tokens
            .current()
            .and_then(|tokens| tokens.access_token(now_epoch_millis()))
        {
            Some(token) => token.to_owned(),
            None => {
                self.fail_authenticated_login("服务端返回的 access token 已过期");
                return;
            }
        };
        let identity = self.identity.shared_current().expect("identity loaded");
        let metadata = registration_metadata(&self.model);
        let registration_result = match (&outcome.device_enrollment_grant, outcome.device_state.as_str()) {
            (Some(grant), "pending_enrollment") => client.register_device(
                &access_token,
                &account_id,
                identity.as_ref(),
                metadata,
                grant,
            ).map(Some),
            (None, "registered") => Ok(None),
            _ => {
                self.fail_authenticated_login("登录完成响应的设备注册状态无效");
                return;
            }
        };
        if let Err(error) = &registration_result {
            self.fail_authenticated_login(format!("登录成功，但签名设备注册失败：{error}"));
            return;
        }
        let devices = match client.list_devices(&access_token) {
            Ok(devices) => devices,
            Err(error) => {
                self.fail_authenticated_login(format!("登录成功，但设备列表读取失败：{error}"));
                return;
            }
        };
        let local_view = registration_result.ok().flatten().or_else(|| {
            devices
                .iter()
                .find(|device| device.device_id == identity.device_id())
                .cloned()
        });
        let Some(local_view) = local_view else {
            self.fail_authenticated_login("账号设备列表中找不到当前设备");
            return;
        };
        if let Err(error) = self
            .identity
            .update_registration(local_view.public_key_id.clone(), local_view.public_key_version)
        {
            self.fail_authenticated_login(format!(
                "设备注册成功，但公钥版本无法安全持久化：{error}"
            ));
            return;
        }
        let identity = self.identity.shared_current().expect("identity persisted");
        let local = LocalDeviceRegistration {
            display_name: local_view.display_name.clone(),
            device_id: local_view.device_id.clone(),
            controller: local_view.role_capabilities.controller,
            controlled: local_view.role_capabilities.controlled,
            server_backed: true,
            public_key_id: Some(local_view.public_key_id.clone()),
            public_key_version: Some(local_view.public_key_version),
            identity_durably_persisted: identity_report.durably_persisted,
        };
        self.model
            .set_authenticated(account, &account_id, local, devices);

        let signal_context = SignalConnectContext::new(
            &config.signal_url,
            &access_token,
            &account_id,
            &local_view.device_id,
            &local_view.public_key_id,
            local_view.public_key_version,
            signal_capabilities(&self.model),
            identity,
        );
        let signal_result = self.signal.connect(signal_context);
        self.last_signal_state = self.signal.state();
        self.model.set_signal_status(match signal_result {
            Ok(()) => self.signal.state().label().to_owned(),
            Err(error) => format!("{}：{error}", self.signal.state().label()),
        });
        if !token_report.durably_persisted || !identity_report.durably_persisted {
            self.model.set_server_status(
                "服务配置已持久化；token 和设备私钥当前仅进程内，平台安全存储适配器未接入",
            );
        }
    }

    fn fail_authenticated_login(&mut self, message: impl Into<String>) {
        let mut message = message.into();
        if let Err(error) = self.tokens.clear() {
            message.push_str(&format!("；本地 token 清理失败：{error}"));
        }
        self.pending_login = None;
        self.model.set_login_status(message);
    }

    fn save_server_configuration(
        &mut self,
        api_url: &str,
        signal_url: &str,
        relay_url: &str,
        server_key: &str,
    ) {
        let config = match ServiceConfig::new(api_url, signal_url, relay_url, server_key) {
            Ok(config) => config,
            Err(error) => {
                self.model.set_server_status(format!("配置未保存：{error}"));
                return;
            }
        };
        let Some(store) = &self.config_store else {
            self.model
                .set_server_status("配置未保存：无法确定当前用户配置目录");
            return;
        };
        match store.save(&config) {
            Ok(()) => self.model.set_service_config(
                config,
                "配置已原子持久化；HTTP 使用系统证书校验，服务器指纹 pinning 尚未接入",
            ),
            Err(error) => self.model.set_server_status(format!("配置未保存：{error}")),
        }
    }

    fn test_server_configuration(
        &mut self,
        api_url: &str,
        signal_url: &str,
        relay_url: &str,
        server_key: &str,
    ) {
        let config = match ServiceConfig::new(api_url, signal_url, relay_url, server_key) {
            Ok(config) => config,
            Err(error) => {
                self.model.set_server_status(format!("配置无效：{error}"));
                return;
            }
        };
        match self
            .api_client(&config)
            .and_then(|client| client.health().map_err(|_| "API 健康检查失败"))
        {
            Ok(()) => self
                .model
                .set_server_status("API 健康检查成功；Signal 和 Relay 未验证，未宣称它们已连接"),
            Err(error) => self.model.set_server_status(error),
        }
    }

    fn request_account_session(&mut self, controlled_device_id: &str) {
        let Some(config) = self.model.service_config().cloned() else {
            self.model.set_session_status("未发起：服务配置缺失");
            return;
        };
        let Some(local_device) = self.model.local_device().cloned() else {
            self.model.set_session_status("未发起：本机设备未注册");
            return;
        };
        if local_device.device_id == controlled_device_id {
            self.model.navigate(Page::Controlled);
            return;
        }
        let target_allowed = self
            .model
            .devices()
            .iter()
            .any(|device| device.device_id == controlled_device_id && device.controlled);
        if !target_allowed {
            self.model
                .set_session_status("未发起：目标设备不具备 controlled 能力");
            return;
        }
        let Some(account_id) = self.model.account_id().map(ToOwned::to_owned) else {
            self.model.set_session_status("未发起：账号上下文缺失");
            return;
        };
        let Some(access_token) = self
            .tokens
            .current()
            .and_then(|tokens| tokens.access_token(now_epoch_millis()))
        else {
            self.model
                .set_session_status("未发起：access token 缺失或已过期");
            return;
        };
        let identity = match self.identity.current() {
            Some(identity) => identity,
            None => {
                self.model.set_session_status("未发起：设备私钥未加载");
                return;
            }
        };
        let client = match self.api_client(&config) {
            Ok(client) => client,
            Err(error) => {
                self.model.set_session_status(error);
                return;
            }
        };
        let request =
            CreateSessionRequest::account_prompt(&local_device.device_id, controlled_device_id);
        match client.create_session(access_token, &account_id, identity, &request) {
            Ok(response) => self.open_session_shell(format!(
                "会话 {} 已由 API 创建，状态 {}；Signal/QUIC/E2EE 业务通道尚未建立",
                response.session_id, response.status
            )),
            Err(error) => self
                .model
                .set_session_status(format!("会话创建失败：{error}")),
        }
    }

    fn open_session_shell(&mut self, api_status: String) {
        self.disconnect_resources();
        let platform = current_platform();
        let input = InputManager::new(platform.input_backend());
        let mut resources = SessionResources::new(
            remote_capture::platform_capturer(),
            remote_render::platform_renderer(),
            input,
        );
        let report = resources.start(RenderSurface {
            width: 1280,
            height: 720,
            scale_factor_milli: 1_000,
        });
        let resource_status = if report.ready {
            "会话资源已就绪，等待安全业务通道"
        } else {
            "原生采集、渲染或输入后端 unsupported"
        };
        self.model
            .set_session_status(format!("{api_status}；{resource_status}"));
        self.session = Some(resources);
        self.model.navigate(Page::Session);
    }

    fn disconnect_resources(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.disconnect();
        }
    }

    fn disconnect(&mut self) {
        self.disconnect_resources();
        self.model
            .set_session_status("本地会话资源已释放，输入状态已 release-all");
        self.model.navigate(Page::Devices);
    }

    fn refresh_signal_state(&mut self) {
        let state = self.signal.state();
        if state != self.last_signal_state {
            self.last_signal_state = state;
            self.model.set_signal_status(state.label());
        }
    }
}

impl Drop for DesktopController {
    fn drop(&mut self) {
        self.signal.disconnect();
        self.disconnect_resources();
    }
}

fn registration_metadata(model: &AppModel) -> DeviceRegistrationMetadata {
    DeviceRegistrationMetadata {
        display_name: model.platform().local_device_name.clone(),
        platform: current_platform_kind(),
        os_version: current_os_version(model),
        arch: current_architecture(),
        role_capabilities: DeviceCapabilities {
            controller: true,
            controlled: true,
            file_transfer: false,
            unattended: false,
        },
    }
}

fn signal_capabilities(model: &AppModel) -> serde_json::Value {
    serde_json::json!({
        "platform": match current_platform_kind() { Platform::Windows => "windows", Platform::Ubuntu => "ubuntu", Platform::Ios => "ios" },
        "os_version": current_os_version(model),
        "arch": match current_architecture() { Architecture::X86_64 => "x86_64", Architecture::Aarch64 => "aarch64" },
        "transport": ["quic", "relay"],
        "native_capture": false,
        "native_input": false
    })
}

#[cfg(target_os = "windows")]
fn current_platform_kind() -> Platform {
    Platform::Windows
}

#[cfg(not(target_os = "windows"))]
fn current_platform_kind() -> Platform {
    Platform::Ubuntu
}

fn current_os_version(model: &AppModel) -> String {
    model.platform().platform_label.clone()
}

fn current_architecture() -> Architecture {
    match std::env::consts::ARCH {
        "aarch64" => Architecture::Aarch64,
        _ => Architecture::X86_64,
    }
}

fn sync_ui(ui: &AppWindow, controller: &DesktopController) {
    let model = &controller.model;
    let platform = model.platform();
    let now = now_epoch_millis();
    ui.set_logged_in(model.account().is_some());
    ui.set_page(model.page() as i32);
    ui.set_platform_label(platform.platform_label.clone().into());
    ui.set_session_kind(platform.session_kind.clone().into());
    ui.set_capture_status(platform.capture_status.clone().into());
    ui.set_render_status(platform.render_status.clone().into());
    ui.set_input_status(platform.input_status.clone().into());
    ui.set_privacy_status(platform.privacy_status.clone().into());
    ui.set_account_label(model.account().unwrap_or_default().into());
    ui.set_login_status(model.login_status().into());
    ui.set_mfa_required(model.mfa_required());
    ui.set_mfa_account(model.mfa_account().into());
    ui.set_mfa_attempts(model.mfa_attempts_remaining().into());
    ui.set_mfa_allow_totp(model.mfa_allows_factor(MfaFactor::Totp));
    ui.set_mfa_allow_recovery(model.mfa_allows_factor(MfaFactor::RecoveryCode));
    ui.set_mfa_expired(model.mfa_expired(now));
    ui.set_assist_status(model.assist_status().into());
    ui.set_server_status(model.server_status().into());
    ui.set_signal_status(model.signal_status().into());
    ui.set_session_status(model.session_status().into());
    if let Some(config) = model.service_config() {
        ui.set_environment_label(config.environment_label().into());
        ui.set_api_url(config.api_base_url.clone().into());
        ui.set_signal_url(config.signal_url.clone().into());
        ui.set_relay_url(config.relay_url.clone().into());
        ui.set_server_key_fingerprint(config.server_key_fingerprint().into());
    } else {
        ui.set_environment_label("未配置服务".into());
    }

    if let Some(device) = model.local_device() {
        ui.set_local_device_name(device.display_name.clone().into());
        ui.set_local_device_id(device.device_id.clone().into());
        ui.set_registration_status(
            if device.identity_durably_persisted {
                "已通过服务端签名注册，设备私钥已进入平台安全存储"
            } else {
                "已通过服务端签名注册；设备私钥当前仅进程内"
            }
            .into(),
        );
    } else {
        ui.set_local_device_name(platform.local_device_name.clone().into());
    }

    let device_rows = model
        .devices()
        .iter()
        .filter(|device| !device.local)
        .map(|device| DeviceListItem {
            device_id: device.device_id.clone().into(),
            glyph: device.glyph.clone().into(),
            name: device.display_name.clone().into(),
            detail: device.detail.clone().into(),
            state: device.state.clone().into(),
            online: device.online,
            controlled: device.controlled,
        })
        .collect::<Vec<_>>();
    let online = device_rows.iter().filter(|device| device.online).count();
    ui.set_device_summary(format!("{} 台账号设备 · {online} 台在线", model.devices().len()).into());
    ui.set_devices(ModelRc::new(VecModel::from(device_rows)));
}

fn refresh(weak: &slint::Weak<AppWindow>, controller: &Rc<RefCell<DesktopController>>) {
    if let Some(ui) = weak.upgrade() {
        sync_ui(&ui, &controller.borrow());
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let controller = Rc::new(RefCell::new(DesktopController::new()));
    sync_ui(&ui, &controller.borrow());

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_login(move |account, password| {
        state.borrow_mut().login(&account, &password);
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_verify_mfa(move |factor, code| {
        state.borrow_mut().verify_mfa(factor, &code);
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_cancel_mfa(move || {
        state.borrow_mut().cancel_mfa();
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_navigate(move |page| {
        if let Some(page) = Page::from_index(page) {
            state.borrow_mut().model.navigate(page);
        }
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_connect_assist(move |device_id, code, confirmed| {
        state
            .borrow_mut()
            .model
            .request_assistance(&device_id, &code, confirmed);
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_test_server(move |api, signal, relay, key| {
        state
            .borrow_mut()
            .test_server_configuration(&api, &signal, &relay, &key);
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_save_server(move |api, signal, relay, key| {
        state
            .borrow_mut()
            .save_server_configuration(&api, &signal, &relay, &key);
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_open_session(move |device_id| {
        state.borrow_mut().request_account_session(&device_id);
        refresh(&weak, &state);
    });

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_disconnect(move || {
        state.borrow_mut().disconnect();
        refresh(&weak, &state);
    });

    let signal_timer = slint::Timer::default();
    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    signal_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(250),
        move || {
            state.borrow_mut().refresh_signal_state();
            refresh(&weak, &state);
        },
    );

    let result = ui.run();
    signal_timer.stop();
    result
}
