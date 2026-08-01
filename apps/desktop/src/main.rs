use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use remote_desktop::api::{
    now_epoch_millis, ApiClient, Architecture, CreateSessionRequest, DeviceCapabilities,
    DeviceRegistrationMetadata, LoginChallenge, LoginFinishOutcome, LoginRequest, MfaFactor,
    Platform, ReqwestHttpTransport,
};
use remote_desktop::app::MfaFlowError;
use remote_desktop::signal::{
    SessionPeerMessage, SessionSignalMessageKind, SessionSnapshot, SignalConnectContext,
    SignalNotification,
};
use remote_desktop::{
    current_platform, AccountTokenManager, AppModel, ControlledAccessPreferences,
    ControlledP2pTransport, ControlledSignalAction, ControlledSignalRuntime, DeviceIdentity,
    DeviceIdentityManager, EphemeralQuicIdentity, InputManager, JsonFileControlledAccessStore,
    JsonFileServiceConfigStore, LanDirectCandidate, LocalDeviceRegistration, LoginError, Page,
    ProcessSecretStore, ServiceConfig, ServiceConfigStore, SessionResources, SignalClient,
    SignalConnectionState, SignalWebSocketClient,
};
use remote_render::RenderSurface;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use uuid::Uuid;

slint::include_modules!();

enum ControlledTransportEvent {
    LanCandidatePrepared {
        session_id: String,
        candidate: Result<LanDirectCandidate, String>,
    },
    ProbeSelected {
        session_id: String,
        transport: Result<ControlledP2pTransport, String>,
    },
    RuntimeFinished {
        session_id: String,
        result: Result<(), String>,
    },
}

struct DesktopController {
    model: AppModel,
    config_store: Option<JsonFileServiceConfigStore>,
    controlled_access_store: Option<JsonFileControlledAccessStore>,
    controlled_access: ControlledAccessPreferences,
    http: Option<Arc<ReqwestHttpTransport>>,
    tokens: AccountTokenManager,
    identity: DeviceIdentityManager,
    signal: SignalWebSocketClient,
    last_signal_state: SignalConnectionState,
    controller_public_keys: HashMap<String, [u8; 32]>,
    controlled_signal: Option<ControlledSignalRuntime>,
    lan_candidate_gathering_session: Option<String>,
    accepted_controlled_session: Option<SessionSnapshot>,
    pending_lan_candidate: Option<LanDirectCandidate>,
    local_candidate_authorization: Option<remote_protocol::CandidateAuthorization>,
    pending_remote_candidate: Option<(
        remote_protocol::ConnectionCandidateDto,
        remote_protocol::CandidateAuthorization,
    )>,
    controlled_p2p: Option<ControlledP2pTransport>,
    pending_quic_identity: Option<EphemeralQuicIdentity>,
    controlled_cancellation: Option<remote_transport::TransportCancellation>,
    transport_runtime: tokio::runtime::Runtime,
    transport_events: mpsc::Receiver<ControlledTransportEvent>,
    transport_event_tx: mpsc::Sender<ControlledTransportEvent>,
    session: Option<SessionResources<Box<dyn remote_desktop::input::InputBackend>>>,
    pending_login: Option<LoginChallenge>,
}

impl DesktopController {
    fn new() -> Self {
        let platform = current_platform();
        let mut model = AppModel::new(platform.snapshot());
        let config_store = JsonFileServiceConfigStore::for_current_user().ok();
        let controlled_access_store = JsonFileControlledAccessStore::for_current_user().ok();
        let controlled_access = controlled_access_store
            .as_ref()
            .and_then(|store| store.load().ok())
            .unwrap_or_default();
        let persisted = config_store
            .as_ref()
            .and_then(|store| store.load().ok().flatten());
        let configured = ServiceConfig::from_environment()
            .ok()
            .flatten()
            .or(persisted)
            .or_else(|| ServiceConfig::official().ok());
        if let Some(config) = configured {
            let label = config.environment_label();
            model.set_service_config(config, format!("已加载{label}配置"));
        }
        let http = ReqwestHttpTransport::new().ok().map(Arc::new);
        if http.is_none() {
            model.set_server_status("HTTP 客户端初始化失败");
        }
        let secret_store = Arc::new(ProcessSecretStore::default());
        let transport_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .worker_threads(2)
            .build()
            .expect("desktop transport runtime initialization failed");
        let (transport_event_tx, transport_events) = mpsc::channel();
        Self {
            model,
            config_store,
            controlled_access_store,
            controlled_access,
            http,
            tokens: AccountTokenManager::new(secret_store.clone()),
            identity: DeviceIdentityManager::new(secret_store),
            signal: SignalWebSocketClient::default(),
            last_signal_state: SignalConnectionState::Disconnected,
            controller_public_keys: HashMap::new(),
            controlled_signal: None,
            lan_candidate_gathering_session: None,
            accepted_controlled_session: None,
            pending_lan_candidate: None,
            local_candidate_authorization: None,
            pending_remote_candidate: None,
            controlled_p2p: None,
            pending_quic_identity: None,
            controlled_cancellation: None,
            transport_runtime,
            transport_events,
            transport_event_tx,
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
            Ok(challenge) if challenge.required_factors.is_empty() => {
                self.finish_login_challenge(account.trim(), &config, &client, challenge, None, None)
            }
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
        match client.finish_login(
            &challenge,
            self.identity.current().expect("identity loaded"),
            Some(attempt.factor),
            Some(code.trim()),
        ) {
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
            Err(error) => self
                .model
                .set_login_status(format!("登录完成验证失败：{error}")),
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
        let registration_result = match (
            &outcome.device_enrollment_grant,
            outcome.device_state.as_str(),
        ) {
            (Some(grant), "pending_enrollment") => client
                .register_device(
                    &access_token,
                    &account_id,
                    identity.as_ref(),
                    metadata,
                    grant,
                )
                .map(Some),
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
        if let Err(error) = self.identity.update_registration(
            local_view.public_key_id.clone(),
            local_view.public_key_version,
        ) {
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
        self.clear_controlled_transport();
        self.disconnect_resources();
        self.model
            .set_session_status("本地会话资源已释放，输入状态已 release-all");
        self.model.navigate(Page::Devices);
    }

    fn refresh_signal_state(&mut self) {
        self.refresh_controlled_transport_events();
        let state = self.signal.state();
        if state != self.last_signal_state {
            self.last_signal_state = state;
            self.model.set_signal_status(state.label());
        }
        loop {
            match self.signal.try_recv_notification() {
                Ok(Some(notification)) => self.handle_signal_notification(notification),
                Ok(None) => break,
                Err(_) if state != SignalConnectionState::Online => break,
                Err(error) => {
                    self.model
                        .set_signal_status(format!("Signal 通知读取失败：{error}"));
                    break;
                }
            }
        }
    }

    fn handle_signal_notification(&mut self, notification: SignalNotification) {
        match notification {
            SignalNotification::SessionInvite(invite) => {
                eprintln!(
                    "[rctl-signal] session_invite session={} status={} controller={} controlled={}",
                    invite.session.session_id,
                    invite.session.status,
                    invite.session.controller_device_id,
                    invite.session.controlled_device_id
                );
                self.respond_to_account_invite(invite.session)
            }
            SignalNotification::SessionAcceptAck(state) => {
                eprintln!(
                    "[rctl-signal] session_accept_ack session={} status={} controller={} controlled={}",
                    state.session_id,
                    state.status,
                    state.session.controller_device_id,
                    state.session.controlled_device_id
                );
                let Some(local) = self.model.local_device() else {
                    return;
                };
                if state.status != "accepted"
                    || state.session.controlled_device_id != local.device_id
                {
                    return;
                }
                match ControlledSignalRuntime::from_accepted(&state.session) {
                    Ok(mut runtime) => {
                        let session_id = runtime.session_id().to_owned();
                        if let Some(public_key) = self
                            .controller_public_keys
                            .get(runtime.controller_device_id())
                            .copied()
                        {
                            let controller_device_id = runtime.controller_device_id().to_owned();
                            if let Err(error) =
                                runtime.set_controller_public_key(&controller_device_id, public_key)
                            {
                                self.model
                                    .set_session_status(format!("主控设备身份绑定无效：{error}"));
                                return;
                            }
                        }
                        self.controlled_signal = Some(runtime);
                        self.accepted_controlled_session = Some(state.session.clone());
                        if let Err(error) = self.signal.request_online_devices() {
                            self.model.set_session_status(format!(
                                "会话已接受，但主控设备公钥刷新失败：{error}"
                            ));
                            return;
                        }
                        self.begin_lan_candidate_if_peer_key_ready();
                        if self.lan_candidate_gathering_session.as_deref()
                            != Some(session_id.as_str())
                        {
                            self.model
                                .set_session_status("会话已接受；正在等待主控设备权威公钥");
                        }
                    }
                    Err(error) => self
                        .model
                        .set_session_status(format!("已接受会话的安全上下文无效：{error}")),
                }
            }
            SignalNotification::OnlineDevices(devices) => {
                eprintln!("[rctl-signal] online_devices count={}", devices.len());
                for device in devices {
                    let Ok(public_key) = URL_SAFE_NO_PAD.decode(device.public_key) else {
                        self.model
                            .set_session_status("主控设备公钥编码无效，已停止等待密钥交换");
                        return;
                    };
                    let Ok(public_key) = <[u8; 32]>::try_from(public_key.as_slice()) else {
                        self.model
                            .set_session_status("主控设备公钥长度无效，已停止等待密钥交换");
                        return;
                    };
                    self.controller_public_keys
                        .insert(device.device_id, public_key);
                }
                if let Some(runtime) = self.controlled_signal.as_mut() {
                    let controller_device_id = runtime.controller_device_id().to_owned();
                    if let Some(public_key) = self
                        .controller_public_keys
                        .get(&controller_device_id)
                        .copied()
                    {
                        if let Err(error) =
                            runtime.set_controller_public_key(&controller_device_id, public_key)
                        {
                            self.model
                                .set_session_status(format!("主控设备身份绑定无效：{error}"));
                            return;
                        }
                    }
                }
                self.begin_lan_candidate_if_peer_key_ready();
            }
            SignalNotification::CandidateTokenIssued(issued) => {
                eprintln!(
                    "[rctl-signal] candidate_token_issued session={} device={} role={:?} candidate_id={}",
                    issued.session_id,
                    issued.device_id,
                    issued.role,
                    issued.candidate_id
                );
                self.handle_candidate_token_issued(issued);
            }
            SignalNotification::SessionMessage(message) => {
                eprintln!(
                    "[rctl-signal] session_message kind={:?} session={} from={} role={:?}",
                    message.kind,
                    message.session_id,
                    message.from_device_id,
                    message.role
                );
                let peer_candidate = (message.kind
                    == SessionSignalMessageKind::ConnectionCandidate)
                    .then(|| decode_peer_candidate(&message))
                    .transpose();
                let Some(runtime) = self.controlled_signal.as_mut() else {
                    return;
                };
                let actions = match runtime.handle_peer_message(&message, now_epoch_millis()) {
                    Ok(actions) => actions,
                    Err(error) => {
                        self.model
                            .set_session_status(format!("被控 Signal 会话消息已拒绝：{error}"));
                        return;
                    }
                };
                match peer_candidate {
                    Ok(Some((candidate, authorization))) => {
                        self.begin_authorized_probe(candidate, authorization)
                    }
                    Err(()) => {
                        self.model
                            .set_session_status("主控候选载荷无效，未启动 UDP 探测");
                        return;
                    }
                    Ok(None) => {}
                }
                for action in actions {
                    match action {
                        ControlledSignalAction::Send {
                            kind,
                            session_id,
                            role,
                            payload,
                        } => {
                            if let Err(error) =
                                self.signal
                                    .send_session_message(kind, &session_id, role, payload)
                            {
                                self.model
                                    .set_session_status(format!("安全握手消息发送失败：{error}"));
                                return;
                            }
                        }
                        ControlledSignalAction::Ready => self.handle_secure_session_ready(),
                    }
                }
            }
            SignalNotification::SessionRejectAck(state)
            | SignalNotification::SessionCancelAck(state)
            | SignalNotification::SessionCloseAck(state) => {
                eprintln!(
                    "[rctl-signal] session_terminal session={} status={} reason={:?}",
                    state.session_id,
                    state.status,
                    state.reason
                );
                if self
                    .controlled_signal
                    .as_ref()
                    .is_some_and(|runtime| runtime.session_id() == state.session_id)
                {
                    if let Some(runtime) = self.controlled_signal.as_mut() {
                        runtime.close();
                    }
                    self.clear_controlled_transport();
                    self.model
                        .set_session_status("会话已关闭；未启动媒体或输入通道");
                }
            }
            SignalNotification::ConnectionState(_) => {}
        }
    }

    fn begin_lan_candidate_gathering(&mut self, session_id: String) {
        let Some(local) = self.model.local_device() else {
            return;
        };
        let Some(identity) = self.identity.shared_current() else {
            self.model
                .set_session_status("设备身份未加载，未创建 LAN 候选");
            return;
        };
        let Ok(session_id_u128) = Uuid::parse_str(&session_id).map(|value| value.as_u128()) else {
            self.model
                .set_session_status("会话 ID 无效，未创建 LAN 候选");
            return;
        };
        let device_id = local.device_id.clone();
        let sender = self.transport_event_tx.clone();
        self.transport_runtime.spawn(async move {
            let candidate = LanDirectCandidate::gather(
                session_id_u128,
                &device_id,
                identity.as_ref(),
                now_epoch_millis(),
            )
            .await
            .map_err(|error| error.to_string());
            let _ = sender.send(ControlledTransportEvent::LanCandidatePrepared {
                session_id,
                candidate,
            });
        });
    }

    fn begin_lan_candidate_if_peer_key_ready(&mut self) {
        let Some(runtime) = self.controlled_signal.as_ref() else {
            return;
        };
        if !runtime.controller_public_key_ready() {
            return;
        }
        let session_id = runtime.session_id().to_owned();
        if self.lan_candidate_gathering_session.as_deref() == Some(session_id.as_str()) {
            return;
        }
        self.lan_candidate_gathering_session = Some(session_id.clone());
        self.begin_lan_candidate_gathering(session_id);
        self.model
            .set_session_status("主控设备公钥已绑定；正在采集经签名的 LAN 候选");
    }

    fn refresh_controlled_transport_events(&mut self) {
        loop {
            let event = match self.transport_events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => break,
            };
            match event {
                ControlledTransportEvent::LanCandidatePrepared {
                    session_id,
                    candidate,
                } => {
                    if self
                        .controlled_signal
                        .as_ref()
                        .is_none_or(|runtime| runtime.session_id() != session_id)
                    {
                        continue;
                    }
                    match candidate {
                        Ok(candidate) => {
                            if let Err(error) = self
                                .signal
                                .request_candidate_token(&candidate.token_request)
                            {
                                self.model.set_session_status(format!(
                                    "LAN 候选 token 请求发送失败：{error}"
                                ));
                                continue;
                            }
                            self.pending_lan_candidate = Some(candidate);
                            eprintln!(
                                "[rctl-signal] lan_candidate_prepared session={} endpoint={}",
                                session_id,
                                self.pending_lan_candidate
                                    .as_ref()
                                    .map(|value| value.candidate.endpoint.as_str())
                                    .unwrap_or("?")
                            );
                            self.model.set_session_status(
                                "已绑定私网 UDP socket，等待 Signal 签发 LAN candidate token",
                            );
                        }
                        Err(error) => self.model.set_session_status(format!(
                            "LAN Direct 不可用：{error}；未创建候选或启动探测"
                        )),
                    }
                }
                ControlledTransportEvent::ProbeSelected {
                    session_id,
                    transport,
                } => {
                    if self
                        .controlled_signal
                        .as_ref()
                        .is_none_or(|runtime| runtime.session_id() != session_id)
                    {
                        continue;
                    }
                    match transport {
                        Ok(transport) => self.begin_controlled_key_exchange(transport),
                        Err(error) => self.model.set_session_status(format!(
                            "经授权的 LAN UDP 探测失败：{error}；未进入密钥交换"
                        )),
                    }
                }
                ControlledTransportEvent::RuntimeFinished { session_id, result } => {
                    if self
                        .controlled_signal
                        .as_ref()
                        .is_none_or(|runtime| runtime.session_id() != session_id)
                    {
                        continue;
                    }
                    self.controlled_cancellation.take();
                    self.model.set_session_status(match result {
                        Ok(()) => "远程会话已结束，采集和输入资源已释放".to_owned(),
                        Err(error) => format!("远程会话已停止：{error}"),
                    });
                }
            }
        }
    }

    fn handle_candidate_token_issued(&mut self, issued: remote_protocol::CandidateTokenIssued) {
        let Some(runtime) = self.controlled_signal.as_ref() else {
            return;
        };
        let Some(candidate) = self.pending_lan_candidate.as_ref() else {
            return;
        };
        if Uuid::parse_str(runtime.session_id())
            .ok()
            .is_none_or(|session_id| session_id.as_u128() != issued.session_id)
            || issued.device_id != candidate.candidate.device_id
            || issued.role != remote_protocol::SessionRole::Controlled
            || issued.candidate_id != candidate.candidate.candidate_id
        {
            return;
        }
        let authorization = remote_protocol::CandidateAuthorization {
            candidate_token: issued.candidate_token,
            candidate_token_binding_hash: issued.candidate_token_binding_hash,
            expires_at_epoch_millis: issued.expires_at_epoch_millis,
        };
        let payload = serde_json::json!({
            "candidate": candidate.candidate,
            "authorization": authorization,
            "transport_certificate_der": URL_SAFE_NO_PAD.encode(
                candidate.quic_identity.certificate_der()
            ),
            "server_name": candidate.quic_identity.server_name(),
        });
        if let Err(error) = self.signal.send_session_message(
            SessionSignalMessageKind::ConnectionCandidate,
            runtime.session_id(),
            remote_protocol::SessionRole::Controlled,
            payload,
        ) {
            self.model
                .set_session_status(format!("LAN 候选发送失败：{error}"));
            return;
        }
        self.local_candidate_authorization = Some(authorization);
        eprintln!(
            "[rctl-signal] controlled_candidate_sent session={} endpoint={}",
            runtime.session_id(),
            candidate.candidate.endpoint
        );
        if !self.try_begin_authorized_probe() {
            self.model
                .set_session_status("LAN 候选与单会话 QUIC 证书已发送；等待主控授权探测");
        }
    }

    fn begin_authorized_probe(
        &mut self,
        remote_candidate: remote_protocol::ConnectionCandidateDto,
        remote_authorization: remote_protocol::CandidateAuthorization,
    ) {
        self.pending_remote_candidate = Some((remote_candidate, remote_authorization));
        if !self.try_begin_authorized_probe() {
            self.model
                .set_session_status("已缓存主控授权候选；等待本地候选 token 后自动启动 UDP 探测");
        }
    }

    fn try_begin_authorized_probe(&mut self) -> bool {
        let Some((local, local_authorization, (remote_candidate, remote_authorization))) =
            take_probe_materials_if_ready(
                &mut self.pending_lan_candidate,
                &mut self.local_candidate_authorization,
                &mut self.pending_remote_candidate,
            )
        else {
            return false;
        };
        let Some(runtime) = self.controlled_signal.as_ref() else {
            self.pending_lan_candidate = Some(local);
            self.local_candidate_authorization = Some(local_authorization);
            self.pending_remote_candidate = Some((remote_candidate, remote_authorization));
            return false;
        };
        let session_id = runtime.session_id().to_owned();
        eprintln!(
            "[rctl-signal] authorized_probe_start session={} local={} remote={}",
            session_id,
            local.candidate.endpoint,
            remote_candidate.endpoint
        );
        let permissions_digest =
            match accepted_permissions_digest(self.accepted_controlled_session.as_ref()) {
                Ok(digest) => digest,
                Err(error) => {
                    self.model.set_session_status(error);
                    return true;
                }
            };
        self.pending_quic_identity = Some(local.quic_identity.clone());
        let sender = self.transport_event_tx.clone();
        self.transport_runtime.spawn(async move {
            eprintln!(
                "[rctl-transport] constructing session={} local={} remote={}",
                session_id,
                local.candidate.endpoint,
                remote_candidate.endpoint
            );
            let transport = match ControlledP2pTransport::new(
                local.socket,
                local.candidate,
                local_authorization,
                remote_candidate,
                remote_authorization,
                local.local_networks,
                permissions_digest,
                now_epoch_millis(),
            ) {
                Ok(mut transport) => {
                    eprintln!("[rctl-transport] constructed session={session_id}");
                    match transport.accept_probe(now_epoch_millis()).await {
                        Ok(_) => {
                            eprintln!("[rctl-transport] probe accepted session={session_id}");
                            Ok(transport)
                        }
                        Err(error) => {
                            eprintln!(
                                "[rctl-transport] probe failed session={} error={}",
                                session_id, error
                            );
                            Err(error.to_string())
                        }
                    }
                }
                Err(error) => {
                    eprintln!(
                        "[rctl-transport] construction failed session={} error={}",
                        session_id, error
                    );
                    Err(error.to_string())
                }
            };
            let _ = sender.send(ControlledTransportEvent::ProbeSelected {
                session_id,
                transport,
            });
        });
        self.model
            .set_session_status("已收到并校验主控候选；正在后台等待授权 UDP probe");
        true
    }

    fn begin_controlled_key_exchange(&mut self, transport: ControlledP2pTransport) {
        let (Some(runtime), Some(session), Some(account_id), Some(identity)) = (
            self.controlled_signal.as_mut(),
            self.accepted_controlled_session.as_ref(),
            self.model.account_id(),
            self.identity.shared_current(),
        ) else {
            self.model
                .set_session_status("会话上下文缺失，未进入密钥交换");
            return;
        };
        let Some(path) = transport.selected_path() else {
            self.model
                .set_session_status("未选中实际候选路径，未进入密钥交换");
            return;
        };
        let config = match session_handshake_config(session, account_id, path, identity.as_ref()) {
            Ok(config) => config,
            Err(error) => {
                self.model.set_session_status(error);
                return;
            }
        };
        match runtime.begin_key_exchange(config, path, identity.as_ref()) {
            Ok(ControlledSignalAction::Send {
                kind,
                session_id,
                role,
                payload,
            }) => {
                if let Err(error) =
                    self.signal
                        .send_session_message(kind, &session_id, role, payload)
                {
                    self.model
                        .set_session_status(format!("密钥交换消息发送失败：{error}"));
                    return;
                }
                self.controlled_p2p = Some(transport);
                self.model
                    .set_session_status("LAN 路径已验证，已发送签名密钥交换消息");
            }
            Ok(ControlledSignalAction::Ready) | Err(_) => {
                self.model
                    .set_session_status("密钥交换状态无效，未启动 QUIC");
            }
        }
    }

    fn handle_secure_session_ready(&mut self) {
        let (Some(identity), Some(mut transport), Some(runtime)) = (
            self.pending_quic_identity.take(),
            self.controlled_p2p.take(),
            self.controlled_signal.as_mut(),
        ) else {
            self.model
                .set_session_status("密钥确认后 QUIC 会话材料不完整");
            return;
        };
        let Some(secure_session) = runtime.take_secure_session() else {
            self.model
                .set_session_status("端到端会话尚未就绪，未启动 QUIC 数据通道");
            return;
        };
        let session_id = runtime.session_id().to_owned();
        let cancellation = remote_transport::TransportCancellation::default();
        self.controlled_cancellation = Some(cancellation.clone());
        let sender = self.transport_event_tx.clone();
        let capturer = remote_capture::platform_capturer();
        let input = InputManager::new(current_platform().input_backend());
        self.transport_runtime.spawn(async move {
            let result = transport
                .accept_and_run(
                    secure_session,
                    identity.tls_config(),
                    remote_transport::DataChannelLimits::default(),
                    &cancellation,
                    capturer,
                    input,
                    "primary".to_owned(),
                    30,
                )
                .await
                .map_err(|error| error.to_string());
            let _ = sender.send(ControlledTransportEvent::RuntimeFinished { session_id, result });
        });
        self.model
            .set_session_status("端到端密钥已确认；正在等待 QUIC 连接并启动 H.264/输入通道");
    }

    fn clear_controlled_transport(&mut self) {
        if let Some(cancellation) = self.controlled_cancellation.take() {
            cancellation.cancel();
        }
        if let Some(mut transport) = self.controlled_p2p.take() {
            transport.close();
        }
        self.pending_lan_candidate.take();
        self.lan_candidate_gathering_session.take();
        self.local_candidate_authorization.take();
        self.pending_remote_candidate.take();
        self.pending_quic_identity.take();
        self.accepted_controlled_session.take();
        if let Some(runtime) = self.controlled_signal.as_mut() {
            runtime.close();
        }
    }

    fn set_allow_account_remote(&mut self, enabled: bool) {
        let previous = self.controlled_access;
        let next = ControlledAccessPreferences {
            allow_account_devices: enabled,
        };
        let Some(store) = &self.controlled_access_store else {
            self.model.set_session_status("被控访问设置无法持久化");
            return;
        };
        match store.save(next) {
            Ok(()) => {
                self.controlled_access = next;
                self.model.set_session_status(if enabled {
                    "已允许我的账号设备远程访问"
                } else {
                    "已关闭我的账号设备远程访问"
                });
            }
            Err(error) => {
                self.controlled_access = previous;
                self.model
                    .set_session_status(format!("被控访问设置保存失败：{error}"));
            }
        }
    }

    fn respond_to_account_invite(&mut self, session: remote_desktop::signal::SessionSnapshot) {
        let Some(local) = self.model.local_device() else {
            return;
        };
        if session.controlled_device_id != local.device_id || session.status != "waiting_approval" {
            return;
        }
        let Some(account_id) = self.model.account_id().map(ToOwned::to_owned) else {
            return;
        };
        let Some(config) = self.model.service_config().cloned() else {
            return;
        };
        let Some(access_token) = self
            .tokens
            .current()
            .and_then(|tokens| tokens.access_token(now_epoch_millis()))
            .map(ToOwned::to_owned)
        else {
            self.model
                .set_session_status("会话邀请未处理：账号 token 已过期");
            return;
        };
        let Some(identity) = self.identity.shared_current() else {
            return;
        };
        let client = match self.api_client(&config) {
            Ok(client) => client,
            Err(error) => {
                self.model.set_session_status(error);
                return;
            }
        };
        let accept = self.controlled_access.allow_account_devices;
        match client.respond_to_session(
            &access_token,
            &account_id,
            identity.as_ref(),
            &session.session_id,
            accept,
            (!accept).then_some("account_remote_access_disabled"),
        ) {
            Ok(response) => self
                .model
                .set_session_status(if response.status == "accepted" {
                    "已接受我的账号设备连接，正在建立安全通道"
                } else {
                    "已拒绝连接：本机未允许账号设备远程访问"
                }),
            Err(error) => self
                .model
                .set_session_status(format!("会话邀请响应失败：{error}")),
        }
    }
}

impl Drop for DesktopController {
    fn drop(&mut self) {
        self.signal.disconnect();
        self.clear_controlled_transport();
        self.disconnect_resources();
    }
}

fn decode_peer_candidate(
    message: &SessionPeerMessage,
) -> Result<
    (
        remote_protocol::ConnectionCandidateDto,
        remote_protocol::CandidateAuthorization,
    ),
    (),
> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CandidatePayload {
        candidate: remote_protocol::ConnectionCandidateDto,
        authorization: remote_protocol::CandidateAuthorization,
    }
    let payload: CandidatePayload =
        serde_json::from_value(message.payload.clone()).map_err(|_| ())?;
    Ok((payload.candidate, payload.authorization))
}

fn take_probe_materials_if_ready<A, B, C>(
    local_candidate: &mut Option<A>,
    local_authorization: &mut Option<B>,
    remote_candidate: &mut Option<C>,
) -> Option<(A, B, C)> {
    if local_candidate.is_none() || local_authorization.is_none() || remote_candidate.is_none() {
        return None;
    }
    Some((
        local_candidate.take().expect("local candidate checked"),
        local_authorization
            .take()
            .expect("local authorization checked"),
        remote_candidate.take().expect("remote candidate checked"),
    ))
}

fn accepted_permissions_digest(session: Option<&SessionSnapshot>) -> Result<[u8; 32], String> {
    let session = session.ok_or_else(|| "会话权限上下文缺失".to_owned())?;
    let permissions: remote_protocol::SessionPermissions = serde_json::from_value(
        session
            .payload
            .get("permissions")
            .cloned()
            .ok_or_else(|| "会话未提供有效权限".to_owned())?,
    )
    .map_err(|_| "会话权限载荷无效".to_owned())?;
    let expected = remote_crypto::permissions_digest(permissions)
        .map_err(|_| "会话权限摘要计算失败".to_owned())?;
    let supplied = session
        .payload
        .get("permissions_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "会话未提供权限摘要".to_owned())?;
    if decode_hex_digest(supplied)? != expected {
        return Err("会话权限摘要不匹配，已拒绝候选路径".to_owned());
    }
    Ok(expected)
}

fn session_handshake_config(
    session: &SessionSnapshot,
    account_id: &str,
    path: &remote_transport::ValidatedCandidatePath,
    identity: &DeviceIdentity,
) -> Result<remote_runtime::SessionHandshakeConfig, String> {
    let permissions: remote_protocol::SessionPermissions = serde_json::from_value(
        session
            .payload
            .get("permissions")
            .cloned()
            .ok_or_else(|| "会话未提供有效权限".to_owned())?,
    )
    .map_err(|_| "会话权限载荷无效".to_owned())?;
    let permissions_digest = accepted_permissions_digest(Some(session))?;
    let session_id = Uuid::parse_str(&session.session_id)
        .map_err(|_| "会话 ID 无效".to_owned())?
        .as_u128();
    let expires = session
        .payload
        .get("session_expires_at_epoch_millis")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "会话过期时间缺失".to_owned())?;
    let mut key_exchange_nonce = [0_u8; 32];
    rand::Rng::fill(&mut rand::rng(), &mut key_exchange_nonce);
    Ok(remote_runtime::SessionHandshakeConfig {
        context: remote_protocol::SessionKdfContext {
            account_id: account_id.to_owned(),
            session_id,
            controller_device_id: session.controller_device_id.clone(),
            controlled_device_id: session.controlled_device_id.clone(),
            permissions_digest,
            protocol_version: remote_protocol::PROTOCOL_VERSION,
            session_expires_at_epoch_millis: expires,
            selected_transport_path: path.binding.transport_path,
            selected_candidate_pair_id: path.binding.candidate_pair_id,
            relay_node_id: path.binding.relay_node_id.clone(),
            key_exchange_transcript_hash: [0; 32],
        },
        permissions,
        local_role: remote_protocol::SessionRole::Controlled,
        local_device_id: session.controlled_device_id.clone(),
        local_device_public_key: identity.public_key(),
        key_exchange_nonce,
        timestamp_epoch_millis: now_epoch_millis(),
    })
}

fn decode_hex_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("权限摘要长度无效".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| "权限摘要编码无效".to_owned())?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| "权限摘要编码无效".to_owned())?;
    }
    Ok(bytes)
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
    let platform = model.platform();
    serde_json::json!({
        "platform": match current_platform_kind() { Platform::Windows => "windows", Platform::Ubuntu => "ubuntu", Platform::Ios => "ios" },
        "os_version": current_os_version(model),
        "arch": match current_architecture() { Architecture::X86_64 => "x86_64", Architecture::Aarch64 => "aarch64" },
        "transport": ["quic", "relay"],
        "native_capture": backend_is_available(&platform.capture_status),
        "native_input": backend_is_available(&platform.input_status)
    })
}

fn backend_is_available(status: &str) -> bool {
    !status.starts_with("unsupported:")
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
    ui.set_capture_available(backend_is_available(&platform.capture_status));
    ui.set_input_available(backend_is_available(&platform.input_status));
    ui.set_controlled_active(controller.controlled_cancellation.is_some());
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
    ui.set_allow_account_remote(controller.controlled_access.allow_account_devices);
}

fn refresh(weak: &slint::Weak<AppWindow>, controller: &Rc<RefCell<DesktopController>>) {
    if let Some(ui) = weak.upgrade() {
        sync_ui(&ui, &controller.borrow());
    }
}

#[cfg(test)]
mod controlled_signal_tests {
    use super::*;

    #[test]
    fn signal_capabilities_report_the_detected_native_backends() {
        let model = AppModel::new(remote_desktop::PlatformSnapshot {
            platform_label: "Ubuntu Desktop 26.04 LTS".into(),
            local_device_name: "Ubuntu Desktop".into(),
            session_kind: "Wayland".into(),
            capture_status: "PipeWire + xdg-desktop-portal ScreenCast: 已接入".into(),
            render_status: "unsupported: controller renderer is not installed".into(),
            input_status: "xdg-desktop-portal RemoteDesktop: 已接入".into(),
            privacy_status: "unsupported: privacy mode is not installed".into(),
        });
        let capabilities = signal_capabilities(&model);
        assert_eq!(capabilities["native_capture"], true);
        assert_eq!(capabilities["native_input"], true);
        assert!(!backend_is_available(&model.platform().render_status));
    }

    #[test]
    fn fake_signal_candidate_is_decoded_only_when_the_exact_pair_is_present() {
        let message = SessionPeerMessage {
            kind: SessionSignalMessageKind::ConnectionCandidate,
            session_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            role: remote_protocol::SessionRole::Controller,
            from_device_id: "ios-1".to_owned(),
            payload: serde_json::json!({
                "candidate": {
                    "candidate_id": "00000000000000000000000000000001",
                    "session_id": "00000000-0000-4000-8000-000000000001",
                    "device_id": "ios-1",
                    "role": "controller",
                    "kind": "lan_direct",
                    "endpoint": "192.168.1.12:50000",
                    "source": "local_interface",
                    "observe_result_id": null,
                    "priority": 0,
                    "rtt_ms": null,
                    "loss_ppm": null,
                    "jitter_ms": null,
                    "relay_node_id": null
                },
                "authorization": {
                    "candidate_token": [1, 2, 3],
                    "candidate_token_binding_hash": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    "expires_at_epoch_millis": 30000
                }
            }),
        };
        let (candidate, authorization) = decode_peer_candidate(&message).expect("candidate");
        assert_eq!(candidate.device_id, "ios-1");
        assert_eq!(authorization.candidate_token, [1, 2, 3]);

        let malformed = SessionPeerMessage {
            payload: serde_json::json!({ "candidate": {} }),
            ..message
        };
        assert!(decode_peer_candidate(&malformed).is_err());
    }

    #[test]
    fn early_remote_candidate_is_not_consumed_before_local_token_arrives() {
        let mut local_candidate = Some("local-socket");
        let mut local_authorization = None::<&str>;
        let mut remote_candidate = Some("ios-candidate");

        assert!(take_probe_materials_if_ready(
            &mut local_candidate,
            &mut local_authorization,
            &mut remote_candidate,
        )
        .is_none());
        assert_eq!(local_candidate, Some("local-socket"));
        assert_eq!(remote_candidate, Some("ios-candidate"));

        local_authorization = Some("local-token");
        assert_eq!(
            take_probe_materials_if_ready(
                &mut local_candidate,
                &mut local_authorization,
                &mut remote_candidate,
            ),
            Some(("local-socket", "local-token", "ios-candidate"))
        );
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let controller = Rc::new(RefCell::new(DesktopController::new()));
    let runtime_handle = controller.borrow().transport_runtime.handle().clone();
    let _runtime_guard = runtime_handle.enter();
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

    let weak = ui.as_weak();
    let state = Rc::clone(&controller);
    ui.on_set_allow_account_remote(move |enabled| {
        state.borrow_mut().set_allow_account_remote(enabled);
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
