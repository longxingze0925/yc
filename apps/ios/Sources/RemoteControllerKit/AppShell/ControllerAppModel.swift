import Combine
import Foundation

public struct SessionLaunch: Identifiable, Sendable {
    public let response: SessionCreateResponse
    public let descriptor: SessionDescriptor
    public let deviceName: String

    public var id: UUID { response.sessionID }
}

@MainActor
public final class ControllerAppModel: ObservableObject {
    public enum Phase: Equatable {
        case launching
        case needsServiceConfiguration
        case signedOut
        case authenticating
        case mfa(MFAChallenge)
        case signedIn
    }

    @Published public private(set) var phase: Phase = .launching
    @Published public private(set) var devices: [DeviceSummary] = []
    @Published public private(set) var accountID: String?
    @Published public private(set) var controllerDeviceID: String?
    @Published public private(set) var signalStatus = "未连接"
    @Published public private(set) var activeSession: SessionLaunch?
    @Published public private(set) var totpEnrollment: TOTPEnrollmentStartResponse?
    @Published public private(set) var pendingTOTPEnrollmentFactorID: String?
    @Published public private(set) var recoveryCodeDelivery: RecoveryCodeDelivery?
    @Published public var errorMessage: String?

    public var serviceConfiguration: ServiceConfiguration? { configurationStore.current }

    private let configurationStore: ServiceConfigurationStore
    private let tokenVault: TokenVault
    private let identityStore: DeviceIdentityStore
    private let recoveryCodeDeliveryVault: RecoveryCodeDeliveryVault
    private let proofClient: any CredentialProofClient
    private var api: (any RemoteAPI)?
    private var signal: SignalClient?
    private var signalEventsTask: Task<Void, Never>?
    private let signalSessionRouter = SignalSessionEventRouter()
    private var pendingLoginChallenge: LoginChallenge?
    private var authenticationFlowID = UUID()
    private var bootstrapped = false

    public init(
        configurationStore: ServiceConfigurationStore? = nil,
        secureStore: any SecureStoring = KeychainStore(),
        proofClient: any CredentialProofClient = UnavailableCredentialProofClient()
    ) {
        self.configurationStore = configurationStore ?? ServiceConfigurationStore()
        tokenVault = TokenVault(store: secureStore)
        identityStore = DeviceIdentityStore(store: secureStore)
        recoveryCodeDeliveryVault = RecoveryCodeDeliveryVault(store: secureStore)
        self.proofClient = proofClient
        pendingTOTPEnrollmentFactorID = try? recoveryCodeDeliveryVault.pendingFactorID()
    }

    deinit {
        signalEventsTask?.cancel()
    }

    public func bootstrap() async {
        guard !bootstrapped else { return }
        bootstrapped = true
        if configurationStore.current == nil, let official = try? ServiceConfiguration.official() {
            try? configurationStore.save(official)
        }
        guard configurationStore.current != nil else {
            phase = .needsServiceConfiguration
            return
        }
        rebuildAPI()
        let authenticationFlowID = beginAuthenticationFlow()
        do {
            guard let api else { throw APIClientError.serviceNotConfigured }
            guard var tokens = try tokenVault.load() else {
                phase = .signedOut
                return
            }
            if !tokens.accessTokenIsValid {
                let refreshed = try await api.refresh(using: tokens.refreshToken)
                try requireAuthenticationFlow(authenticationFlowID)
                guard refreshed.accountID == tokens.accountID else {
                    throw APIClientError.invalidResponse
                }
                tokens = refreshed.tokenSet
                try tokenVault.save(tokens)
            }
            try await enterSignedIn(
                tokens: tokens,
                challenge: nil,
                enrollmentGrant: nil,
                authenticationFlowID: authenticationFlowID
            )
        } catch {
            guard self.authenticationFlowID == authenticationFlowID else { return }
            try? tokenVault.clear()
            phase = .signedOut
            errorMessage = error.localizedDescription
        }
    }

    public func saveServiceConfiguration(_ configuration: ServiceConfiguration) async {
        if (try? recoveryCodeDeliveryVault.hasPendingEnrollment()) == true {
            errorMessage = "请先完成并确认保存 MFA 恢复码"
            return
        }
        let authenticationFlowID = invalidateAuthenticationFlow()
        await stopSignal()
        guard self.authenticationFlowID == authenticationFlowID else { return }
        try? tokenVault.clear()
        do {
            try configurationStore.save(configuration)
            rebuildAPI()
            devices = []
            accountID = nil
            controllerDeviceID = nil
            activeSession = nil
            pendingLoginChallenge = nil
            phase = .signedOut
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func login(email: String, password: String) async {
        guard let api else {
            phase = .needsServiceConfiguration
            return
        }
        let authenticationFlowID = beginAuthenticationFlow()
        phase = .authenticating
        errorMessage = nil
        do {
            let challenge = try await api.login(
                identityStore.loginRequest(email: email, password: password)
            )
            try requireAuthenticationFlow(authenticationFlowID)
            guard challenge.expiresAtEpochMillis > Date.now.epochMillis else {
                throw APIClientError.invalidResponse
            }
            pendingLoginChallenge = challenge
            if !challenge.requiredFactors.isEmpty {
                phase = .mfa(challenge.mfaChallenge)
                return
            }
            try await finishLogin(
                challenge: challenge,
                factor: nil,
                code: nil,
                authenticationFlowID: authenticationFlowID
            )
        } catch {
            guard self.authenticationFlowID == authenticationFlowID else { return }
            try? tokenVault.clear()
            pendingLoginChallenge = nil
            phase = .signedOut
            errorMessage = error.localizedDescription
        }
    }

    public func verifyMFA(challengeID: String, factor: String, code: String) async {
        guard api != nil else { return }
        let authenticationFlowID = self.authenticationFlowID
        let pendingChallenge: MFAChallenge?
        if case let .mfa(challenge) = phase {
            pendingChallenge = challenge
        } else {
            pendingChallenge = nil
        }
        phase = .authenticating
        errorMessage = nil
        do {
            guard let challenge = pendingLoginChallenge,
                  challenge.loginChallengeID == challengeID,
                  challenge.requiredFactors.contains(factor) else {
                throw APIClientError.invalidResponse
            }
            try await finishLogin(
                challenge: challenge,
                factor: factor,
                code: code,
                authenticationFlowID: authenticationFlowID
            )
        } catch {
            guard self.authenticationFlowID == authenticationFlowID else { return }
            try? tokenVault.clear()
            if let pendingChallenge, pendingChallenge.expiresAtEpochMillis > Date.now.epochMillis {
                phase = .mfa(pendingChallenge)
            } else {
                pendingLoginChallenge = nil
                phase = .signedOut
            }
            errorMessage = error.localizedDescription
        }
    }

    public func refreshDevices() async {
        guard let api else { return }
        do {
            devices = try await api.listDevices()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func startTOTPEnrollment() async {
        guard let api else {
            errorMessage = APIClientError.serviceNotConfigured.localizedDescription
            return
        }
        errorMessage = nil
        do {
            guard let tokens = try tokenVault.load() else {
                throw APIClientError.authenticationRequired
            }
            let material = try recoveryCodeDeliveryVault.prepareStart(tokens: tokens)
            if let factorID = material.existingFactorID {
                pendingTOTPEnrollmentFactorID = factorID
                errorMessage = "TOTP enrollment 已开始，请继续验证"
                return
            }
            let response = try await api.startTOTPEnrollment(
                try TOTPEnrollmentStartRequest(
                    recoveryDeliveryPublicKey: material.recoveryDeliveryPublicKey
                ),
                authorizationToken: material.authorizationToken
            )
            try recoveryCodeDeliveryVault.recordStart(response)
            totpEnrollment = response
            pendingTOTPEnrollmentFactorID = response.factorID
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func finishTOTPEnrollment(code: String) async {
        guard let api else {
            errorMessage = APIClientError.serviceNotConfigured.localizedDescription
            return
        }
        errorMessage = nil
        do {
            let material = try recoveryCodeDeliveryVault.finishMaterial()
            let envelope = try await api.finishTOTPEnrollment(
                try TOTPEnrollmentFinishRequest(factorID: material.factorID, code: code),
                idempotencyKey: material.idempotencyKey,
                authorizationToken: material.authorizationToken
            )
            let delivery = try recoveryCodeDeliveryVault.decrypt(envelope)
            await stopSignal()
            try? tokenVault.clear()
            accountID = nil
            controllerDeviceID = nil
            devices = []
            activeSession = nil
            phase = .signedOut

            recoveryCodeDelivery = delivery
            totpEnrollment = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func confirmRecoveryCodesSaved() {
        guard let delivery = recoveryCodeDelivery else {
            errorMessage = RecoveryCodeDeliveryError.missingPendingEnrollment.localizedDescription
            return
        }
        do {
            try recoveryCodeDeliveryVault.confirmSaved(deliveryID: delivery.deliveryID)
            recoveryCodeDelivery = nil
            pendingTOTPEnrollmentFactorID = nil
            totpEnrollment = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func connect(to device: DeviceSummary) async {
        guard let controllerDeviceID,
              device.canBeControlled,
              device.status == .online else { return }
        await createSession(
            request: SessionCreateRequest(
                controllerDeviceID: controllerDeviceID,
                controlledDeviceID: device.deviceID,
                authMethod: .accountPrompt,
                requestedPermissions: .requestedControllerDefaults,
                idempotencyKey: UUID()
            ),
            deviceName: device.displayName
        )
    }

    public func connectWithTemporaryCode(deviceID: String, code: String) async {
        guard let api, let accountID, let controllerDeviceID else { return }
        let secret = OneTimeSecret(code)
        defer { secret.wipe() }
        do {
            let response = try await api.createSession(SessionCreateRequest(
                controllerDeviceID: controllerDeviceID,
                controlledDeviceID: deviceID,
                authMethod: .temporaryCode,
                requestedPermissions: .requestedControllerDefaults,
                idempotencyKey: UUID()
            ))
            try await proofClient.verifyTemporaryCode(session: response, secret: secret, api: api)
            activeSession = SessionLaunch(
                response: response,
                descriptor: try response.descriptor(
                    accountID: accountID,
                    controllerDeviceID: controllerDeviceID
                ),
                deviceName: response.controlledDeviceName ?? deviceID
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func logout() async {
        if (try? recoveryCodeDeliveryVault.hasPendingEnrollment()) == true {
            errorMessage = "请先完成并确认保存 MFA 恢复码"
            return
        }
        let authenticationFlowID = invalidateAuthenticationFlow()
        if let api { try? await api.logout() }
        guard self.authenticationFlowID == authenticationFlowID else { return }
        await stopSignal()
        guard self.authenticationFlowID == authenticationFlowID else { return }
        try? tokenVault.clear()
        accountID = nil
        controllerDeviceID = nil
        devices = []
        activeSession = nil
        pendingLoginChallenge = nil
        phase = .signedOut
    }

    public func dismissSession() {
        activeSession = nil
    }

    private func createSession(request: SessionCreateRequest, deviceName: String) async {
        guard let api, let accountID, let controllerDeviceID else { return }
        do {
            let response = try await api.createSession(request)
            activeSession = SessionLaunch(
                response: response,
                descriptor: try response.descriptor(
                    accountID: accountID,
                    controllerDeviceID: controllerDeviceID
                ),
                deviceName: deviceName
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func finishLogin(
        challenge: LoginChallenge,
        factor: String?,
        code: String?,
        authenticationFlowID: UUID
    ) async throws {
        guard let api else { throw APIClientError.serviceNotConfigured }
        let response = try await api.finishLogin(
            challenge: challenge,
            factor: factor,
            code: code
        )
        try requireAuthenticationFlow(authenticationFlowID)
        guard response.accountID == challenge.accountID else {
            throw APIClientError.invalidResponse
        }
        switch challenge.deviceState {
        case .pendingEnrollment:
            guard response.deviceEnrollmentGrant?.isEmpty == false,
                  let expiresAt = response.deviceEnrollmentGrantExpiresAtEpochMillis,
                  expiresAt > Date.now.epochMillis else {
                throw APIClientError.invalidResponse
            }
        case .registered:
            guard response.deviceEnrollmentGrant == nil,
                  response.deviceEnrollmentGrantExpiresAtEpochMillis == nil else {
                throw APIClientError.invalidResponse
            }
        }
        try await enterSignedIn(
            tokens: response.tokenSet,
            challenge: challenge,
            enrollmentGrant: response.deviceEnrollmentGrant,
            authenticationFlowID: authenticationFlowID
        )
    }

    private func enterSignedIn(
        tokens: TokenSet,
        challenge: LoginChallenge?,
        enrollmentGrant: String?,
        authenticationFlowID: UUID
    ) async throws {
        try requireAuthenticationFlow(authenticationFlowID)
        guard let api else { throw APIClientError.serviceNotConfigured }
        try tokenVault.save(tokens)
        let identity = try identityStore.loadOrCreate()
        let registrationBinding: (publicKeyID: String, publicKeyVersion: UInt32)?
        switch challenge?.deviceState {
        case .some(.pendingEnrollment):
            guard let enrollmentGrant, !enrollmentGrant.isEmpty else {
                throw APIClientError.invalidResponse
            }
            let registered = try await api.registerControllerDevice(
                identityStore.registration(enrollmentGrant: enrollmentGrant)
            )
            guard registered.deviceID == identity.deviceID else {
                throw APIClientError.invalidResponse
            }
            registrationBinding = (
                publicKeyID: registered.publicKeyID,
                publicKeyVersion: registered.publicKeyVersion
            )
            try identityStore.updateRegistration(
                publicKeyID: registered.publicKeyID,
                publicKeyVersion: registered.publicKeyVersion
            )
        case .some(.registered):
            guard enrollmentGrant == nil else { throw APIClientError.invalidResponse }
            registrationBinding = nil
        case .none:
            guard enrollmentGrant == nil else { throw APIClientError.invalidResponse }
            registrationBinding = nil
        }
        let listedDevices = try await api.listDevices()
        let localDevice = listedDevices.first(where: { $0.deviceID == identity.deviceID })
        guard let binding = registrationBinding ?? localDevice.flatMap({ device in
            guard let publicKeyID = device.publicKeyID,
                  let publicKeyVersion = device.publicKeyVersion else { return nil }
            return (publicKeyID: publicKeyID, publicKeyVersion: publicKeyVersion)
        }) else {
            throw APIClientError.invalidResponse
        }
        if registrationBinding == nil {
            try identityStore.updateRegistration(
                publicKeyID: binding.publicKeyID,
                publicKeyVersion: binding.publicKeyVersion
            )
        }
        try requireAuthenticationFlow(authenticationFlowID)
        accountID = tokens.accountID
        controllerDeviceID = identity.deviceID
        pendingLoginChallenge = nil
        phase = .signedIn
        devices = listedDevices
        await startSignal(
            accountID: tokens.accountID,
            authenticationFlowID: authenticationFlowID
        )
    }

    private func rebuildAPI() {
        guard let configuration = configurationStore.current else {
            api = nil
            return
        }
        api = URLSessionRemoteAPI(
            configuration: configuration,
            tokenVault: tokenVault,
            identityStore: identityStore
        )
    }

    private func startSignal(accountID: String, authenticationFlowID: UUID) async {
        guard let configuration = configurationStore.current, let api else { return }
        await stopSignal()
        guard self.authenticationFlowID == authenticationFlowID else { return }
        let client = SignalClient(configuration: configuration)
        signal = client
#if REMOTE_CORE_FFI
        NativeRustCoreSessionBridge.shared.install(
            driverFactory: SignalNativeSecureTransportDriverFactory(
                signal: client,
                router: signalSessionRouter,
                identityStore: identityStore
            )
        )
#endif
        signalEventsTask = Task { [weak self] in
            for await event in client.events {
                guard let self else { return }
                guard self.authenticationFlowID == authenticationFlowID else {
                    await client.stop()
                    return
                }
                await signalSessionRouter.route(event)
                switch event {
                case .connecting:
                    signalStatus = "连接中"
                case .authenticated:
                    signalStatus = "已连接"
                case let .onlineDevices(value):
                    let statuses = Dictionary(
                        value.map { ($0.deviceID, $0.status) },
                        uniquingKeysWith: { _, latest in latest }
                    )
                    devices = devices.map { device in
                        device.replacingStatus(with: statuses[device.deviceID] ?? .offline)
                    }
                case let .disconnected(reason):
                    signalStatus = "已断开"
                    errorMessage = reason
                case let .authenticationFailed(reason):
                    signalStatus = "鉴权失败"
#if REMOTE_CORE_FFI
                    NativeRustCoreSessionBridge.shared.uninstallDriverFactory()
#endif
                    await signalSessionRouter.removeAll()
                    await client.stop()
                    signal = nil
                    signalEventsTask = nil
                    try? tokenVault.clear()
                    self.accountID = nil
                    controllerDeviceID = nil
                    devices = []
                    activeSession = nil
                    invalidateAuthenticationFlow()
                    phase = .signedOut
                    errorMessage = reason
                    return
                case .sessionState, .candidateTokenIssued, .sessionMessage:
                    break
                }
            }
        }
        do {
            try await client.start(
                accountID: accountID,
                identityStore: identityStore,
                capabilities: .ios(
                    appVersion: Self.appVersion,
                    osVersion: DeviceIdentityStore.currentOSVersion,
                    arch: DeviceIdentityStore.currentArchitecture
                ),
                accessTokenProvider: { [tokenVault, api] in
                    guard let tokens = try tokenVault.load() else {
                        throw APIClientError.authenticationRequired
                    }
                    if tokens.accessTokenIsValid {
                        return tokens.accessToken
                    }
                    let response: LoginResponse
                    do {
                        response = try await api.refresh(using: tokens.refreshToken)
                    } catch let error as APIClientError {
                        if case let .server(_, _, status) = error,
                           status == 401 || status == 403 {
                            throw APIClientError.authenticationRequired
                        }
                        throw error
                    }
                    guard response.accountID == tokens.accountID else {
                        throw APIClientError.invalidResponse
                    }
                    let refreshed = response.tokenSet
                    try tokenVault.save(refreshed)
                    return refreshed.accessToken
                }
            )
        } catch {
            guard self.authenticationFlowID == authenticationFlowID else { return }
#if REMOTE_CORE_FFI
            NativeRustCoreSessionBridge.shared.uninstallDriverFactory()
#endif
            await signalSessionRouter.removeAll()
            signalEventsTask?.cancel()
            signalEventsTask = nil
            signal = nil
            signalStatus = "未连接"
            errorMessage = error.localizedDescription
        }
    }

    @discardableResult
    private func beginAuthenticationFlow() -> UUID {
        let flowID = UUID()
        authenticationFlowID = flowID
        pendingLoginChallenge = nil
        return flowID
    }

    @discardableResult
    private func invalidateAuthenticationFlow() -> UUID {
        let flowID = UUID()
        authenticationFlowID = flowID
        pendingLoginChallenge = nil
        return flowID
    }

    private func requireAuthenticationFlow(_ flowID: UUID) throws {
        guard authenticationFlowID == flowID else { throw CancellationError() }
    }

    private func stopSignal() async {
#if REMOTE_CORE_FFI
        NativeRustCoreSessionBridge.shared.uninstallDriverFactory()
#endif
        await signalSessionRouter.removeAll()
        signalEventsTask?.cancel()
        signalEventsTask = nil
        if let signal { await signal.stop() }
        signal = nil
        signalStatus = "未连接"
    }

    private static var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0"
    }
}

private extension DeviceSummary {
    func replacingStatus(with status: DeviceStatus) -> DeviceSummary {
        DeviceSummary(
            deviceID: deviceID,
            displayName: displayName,
            platform: platform,
            osVersion: osVersion,
            status: status,
            roleCapabilities: roleCapabilities,
            lastSeenEpochMillis: lastSeenEpochMillis,
            publicKeyID: publicKeyID,
            publicKeyVersion: publicKeyVersion
        )
    }
}
