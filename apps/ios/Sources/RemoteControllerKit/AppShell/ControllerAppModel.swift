import Combine
import Foundation

public struct SessionLaunch: Identifiable, Sendable {
    public let response: SessionCreateResponse
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
    @Published public var errorMessage: String?

    public var serviceConfiguration: ServiceConfiguration? { configurationStore.current }

    private let configurationStore: ServiceConfigurationStore
    private let tokenVault: TokenVault
    private let identityStore: DeviceIdentityStore
    private let proofClient: any CredentialProofClient
    private var api: (any RemoteAPI)?
    private var signal: SignalClient?
    private var signalEventsTask: Task<Void, Never>?
    private var bootstrapped = false

    public init(
        configurationStore: ServiceConfigurationStore = ServiceConfigurationStore(),
        secureStore: any SecureStoring = KeychainStore(),
        proofClient: any CredentialProofClient = UnavailableCredentialProofClient()
    ) {
        self.configurationStore = configurationStore
        tokenVault = TokenVault(store: secureStore)
        identityStore = DeviceIdentityStore(store: secureStore)
        self.proofClient = proofClient
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
        do {
            guard let api else { throw APIClientError.serviceNotConfigured }
            guard var tokens = try tokenVault.load() else {
                phase = .signedOut
                return
            }
            if !tokens.accessTokenIsValid {
                guard let refreshed = try await api.refresh(using: tokens.refreshToken).tokenSet else {
                    throw APIClientError.authenticationRequired
                }
                tokens = refreshed
                try tokenVault.save(tokens)
            }
            try await enterSignedIn(tokens: tokens)
        } catch {
            try? tokenVault.clear()
            phase = .signedOut
            errorMessage = error.localizedDescription
        }
    }

    public func saveServiceConfiguration(_ configuration: ServiceConfiguration) async {
        await stopSignal()
        try? tokenVault.clear()
        do {
            try configurationStore.save(configuration)
            rebuildAPI()
            devices = []
            accountID = nil
            controllerDeviceID = nil
            activeSession = nil
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
        phase = .authenticating
        errorMessage = nil
        do {
            let response = try await api.login(LoginRequest(email: email, password: password))
            if let challenge = response.challenge {
                phase = .mfa(challenge)
                return
            }
            guard let tokens = response.tokenSet else { throw APIClientError.invalidResponse }
            try await enterSignedIn(tokens: tokens)
        } catch {
            phase = .signedOut
            errorMessage = error.localizedDescription
        }
    }

    public func verifyMFA(challengeID: String, factor: String, code: String) async {
        guard let api else { return }
        let pendingChallenge: MFAChallenge?
        if case let .mfa(challenge) = phase {
            pendingChallenge = challenge
        } else {
            pendingChallenge = nil
        }
        phase = .authenticating
        errorMessage = nil
        do {
            let response = try await api.verifyMFA(
                MFAVerifyRequest(challengeID: challengeID, factor: factor, code: code)
            )
            guard let tokens = response.tokenSet else { throw APIClientError.invalidResponse }
            try await enterSignedIn(tokens: tokens)
        } catch {
            if let pendingChallenge, pendingChallenge.expiresAtEpochMillis > Date.now.epochMillis {
                phase = .mfa(pendingChallenge)
            } else {
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
        guard let api, let controllerDeviceID else { return }
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
            activeSession = SessionLaunch(response: response, deviceName: response.controlledDeviceName ?? deviceID)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func logout() async {
        if let api { try? await api.logout() }
        await stopSignal()
        try? tokenVault.clear()
        accountID = nil
        controllerDeviceID = nil
        devices = []
        activeSession = nil
        phase = .signedOut
    }

    public func dismissSession() {
        activeSession = nil
    }

    private func createSession(request: SessionCreateRequest, deviceName: String) async {
        guard let api else { return }
        do {
            activeSession = SessionLaunch(response: try await api.createSession(request), deviceName: deviceName)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func enterSignedIn(tokens: TokenSet) async throws {
        guard let api else { throw APIClientError.serviceNotConfigured }
        try tokenVault.save(tokens)
        let identity = try identityStore.loadOrCreate()
        var listedDevices = try await api.listDevices()
        if let registered = listedDevices.first(where: { $0.deviceID == identity.deviceID }) {
            if let publicKeyID = registered.publicKeyID,
               let publicKeyVersion = registered.publicKeyVersion {
                try identityStore.updateRegistration(
                    publicKeyID: publicKeyID,
                    publicKeyVersion: publicKeyVersion
                )
            }
        } else {
            let registered = try await api.registerControllerDevice(identityStore.registration())
            guard registered.deviceID == identity.deviceID else {
                throw APIClientError.invalidResponse
            }
            try identityStore.updateRegistration(
                publicKeyID: registered.publicKeyID,
                publicKeyVersion: registered.publicKeyVersion
            )
            listedDevices = try await api.listDevices()
        }
        accountID = tokens.accountID
        controllerDeviceID = identity.deviceID
        phase = .signedIn
        devices = listedDevices
        await startSignal(accountID: tokens.accountID)
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

    private func startSignal(accountID: String) async {
        guard let configuration = configurationStore.current, let api else { return }
        await stopSignal()
        let client = SignalClient(configuration: configuration)
        signal = client
        signalEventsTask = Task { [weak self] in
            for await event in client.events {
                guard let self else { return }
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
                    await client.stop()
                    signal = nil
                    signalEventsTask = nil
                    try? tokenVault.clear()
                    self.accountID = nil
                    controllerDeviceID = nil
                    devices = []
                    activeSession = nil
                    phase = .signedOut
                    errorMessage = reason
                    return
                case .sessionState:
                    break
                }
            }
        }
        await client.start(
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
                guard let refreshed = try await api.refresh(using: tokens.refreshToken).tokenSet else {
                    throw APIClientError.authenticationRequired
                }
                try tokenVault.save(refreshed)
                return refreshed.accessToken
            }
        )
    }

    private func stopSignal() async {
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
