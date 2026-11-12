import SwiftUI
import AppKit
import CryptoKit
import LocalAuthentication
import Security
import Network
import Combine
import CommonCrypto


/// Best-effort overwrite for mutable Data owned by this module.
/// Swift Data copy-on-write and framework-internal copies mean this is not an absolute RAM-erasure guarantee.
private func imnoTextBestEffortZeroize(_ data: inout Data) {
    guard !data.isEmpty else { return }
    data.resetBytes(in: 0..<data.count)
    data.removeAll(keepingCapacity: false)
}

// MARK: - 1. MÔ HÌNH DỮ LIỆU CẤP 5 & ĐÓNG GÓI ĐƠN TỆP (.VAULT)

/// Bản ghi dữ liệu văn bản nguyên bản (Raw UTF-8) của IMNO-Text
public struct IMNOTextRecord: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public let timestampMs: Int64
    public let senderCode: String
    public let firstReceiverCode: String
    public let byteSize: Int
    public let sha256Hash: String
    public let rawText: String

    public init(
        id: UUID = UUID(),
        timestampMs: Int64 = Self.currentMillisecond(),
        senderCode: String,
        firstReceiverCode: String,
        rawText: String
    ) {
        self.id = id
        self.timestampMs = timestampMs
        self.senderCode = senderCode
        self.firstReceiverCode = firstReceiverCode
        let utf8Data = Data(rawText.utf8)
        self.byteSize = utf8Data.count
        self.sha256Hash = SHA256.hash(data: utf8Data).compactMap { String(format: "%02x", $0) }.joined()
        self.rawText = rawText
    }

    /// Kiểm tra tính toàn vẹn SHA-256 và kích thước byte của bản ghi
    public var isIntegrityValid: Bool {
        let utf8Data = Data(rawText.utf8)
        let computedHash = SHA256.hash(data: utf8Data).compactMap { String(format: "%02x", $0) }.joined()
        return utf8Data.count == byteSize && computedHash == sha256Hash
    }

    public static func currentMillisecond() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000.0).rounded())
    }
}

/// Nhật ký kiểm toán nội bộ nằm bên trong khối mã hóa .vault
public struct VaultAuditEntry: Codable, Sendable, Identifiable {
    public let id: UUID
    public let timestampMs: Int64
    public let actionCode: String // "INIT", "INPUT", "EXPORT", "MERGE", "MEMBER_CODE_ROTATE", "WITHDRAW"
    public let integrityChecksum: String
}

/// Cấu trúc lõi được đóng gói toàn khối vào duy nhất 1 tệp imno_text.vault
public struct IMNOVaultPayload: Codable, Sendable {
    public var schemaVersion: Int = 1
    public var memberCode: String
    public var systemIdentifier: String
    public var records: [IMNOTextRecord]
    public var auditTrail: [VaultAuditEntry]
    /// Đệm ngẫu nhiên chống phân tích kích thước bản ghi trên APFS/Finder (Zero-Metadata Leakage)
    public var randomPadding: Data

    public init(
        memberCode: String = "IMNO-Text-DEFAULT", ///////////
        systemIdentifier: String = "APPLE-ES-IMNO-Text",
        records: [IMNOTextRecord] = [],
        auditTrail: [VaultAuditEntry] = []
    ) {
        self.memberCode = memberCode
        self.systemIdentifier = systemIdentifier
        self.records = records
        self.auditTrail = auditTrail
        self.randomPadding = Self.generatePadding()
    }

    public static func generatePadding() -> Data {
        let randomLength = Int.random(in: 256...2048)
        var bytes = [UInt8](repeating: 0, count: randomLength)
        _ = SecRandomCopyBytes(kSecRandomDefault, randomLength, &bytes)
        return Data(bytes)
    }
}

/// Phong bì tệp di động dùng cho Export / Merge liên máy chủ với Siêu Mật Khẩu
public struct PortableVaultEnvelope: Codable, Sendable {
    public let magicHeader: String // "IMNO-Text-VAULT-V1"
    public let salt: Data
    public let systemDomainTag: String
    /// Absent only in legacy envelopes created by the pre-PBKDF2 build.
    public let kdfIdentifier: String?
    public let combinedSealedBox: Data
}

// MARK: - 2. QUẢN LÝ SINH TRẮC HỌC APPLE ES & KHÓA CHỦ KEYCHAIN

public enum IMNOSecurityError: Error, LocalizedError {
    case biometricUnavailable
    case biometricFailed
    case keychainFailure(OSStatus)
    case corruptedVaultFile
    case integrityViolation(UUID)
    case invalidSuperPassword
    case unauthorizedMemberCode
    case ioDisabled
    case forbiddenExternalQueryField
    case sessionLocked
    case keyDerivationFailure(Int32)

    public var errorDescription: String? {
        switch self {
        case .biometricUnavailable: return "BIO_UNAVAILABLE"
        case .biometricFailed: return "BIO_AUTH_FAILED"
        case .keychainFailure(let status): return "KC_ERR_\(status)"
        case .corruptedVaultFile: return "VAULT_CORRUPTED"
        case .integrityViolation(let id): return "SHA256_MISMATCH_\(id.uuidString.prefix(6))"
        case .invalidSuperPassword: return "SUPER_KEY_INVALID"
        case .unauthorizedMemberCode: return "INVALID_MEMBER_CODE"
        case .ioDisabled: return "IO_DISABLED"
        case .forbiddenExternalQueryField: return "ROUTE_QUERY_FORBIDDEN"
        case .sessionLocked: return "VAULT_SESSION_LOCKED"
        case .keyDerivationFailure(let status): return "KDF_ERR_\(status)"
        }
    }
}

public actor BiometricSecurityManager {
    public static let shared = BiometricSecurityManager()
    private let keychainService = "es.imno.level5.imno-text.vault"
    private let masterKeyAccount = "master-vault-key-256"

    private init() {}

    /// Yêu cầu xác thực Sinh trắc học Apple ES (Touch ID) trực tiếp ngay tại thời điểm thao tác
    public func authenticateLiveBiometrics(reason: String = "IMNO-Text Security Gate") async throws {
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedCancelTitle = "Cancel"
        context.localizedFallbackTitle = "" // Bắt buộc dùng Sinh trắc học theo Hiến chương

        var authError: NSError?
        let policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics
        guard context.canEvaluatePolicy(policy, error: &authError) else {
            throw IMNOSecurityError.biometricUnavailable
        }

        let success = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, Error>) in
            context.evaluatePolicy(policy, localizedReason: reason) { granted, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: granted)
                }
            }
        }

        guard success else { throw IMNOSecurityError.biometricFailed }
    }

    /// Truy xuất hoặc khởi tạo Khóa chủ 256-bit (Master Vault Key) lưu trong Keychain máy chủ hiện tại
    func loadOrCreateMasterKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: masterKeyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess, let keyData = item as? Data, keyData.count == 32 {
            return SymmetricKey(data: keyData)
        } else if status == errSecItemNotFound {
            let newKey = SymmetricKey(size: .bits256)
            let keyData = newKey.withUnsafeBytes { Data($0) }

            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: masterKeyAccount,
                kSecValueData as String: keyData,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]

            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw IMNOSecurityError.keychainFailure(addStatus)
            }
            return newKey
        } else {
            throw IMNOSecurityError.keychainFailure(status)
        }
    }
}

// MARK: - 3. LÕI MÃ HÓA PHONG BÌ LAI & LƯU TRỮ ĐƠN TỆP (imno_text.vault)

public actor IMNOTextVaultEngine {
    public static let shared = IMNOTextVaultEngine()

    public let vaultFileURL: URL
    private let systemDomainTag = "APPLE-ES-SUPER-SYSTEM-IMNO-C5"

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let directory = appSupport.appendingPathComponent("IMNO", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        self.vaultFileURL = directory.appendingPathComponent("imno_text.vault", isDirectory: false)
    }

    // MARK: - Đọc / Ghi Tệp Đơn Khối AES-256-GCM

    private func loadPayloadInternal(using providedMasterKey: SymmetricKey? = nil) throws -> IMNOVaultPayload {
        let masterKey: SymmetricKey
        if let providedMasterKey {
            masterKey = providedMasterKey
        } else {
            masterKey = try requireMasterKey()
        }
        guard FileManager.default.fileExists(atPath: vaultFileURL.path) else {
            var initial = IMNOVaultPayload()
            initial.auditTrail.append(
                VaultAuditEntry(
                    id: UUID(),
                    timestampMs: IMNOTextRecord.currentMillisecond(),
                    actionCode: "INIT",
                    integrityChecksum: "GENESIS"
                )
            )
            try savePayloadInternal(initial, using: masterKey)
            return initial
        }

        let encryptedBlob = try Data(contentsOf: vaultFileURL)
        guard let sealedBox = try? AES.GCM.SealedBox(combined: encryptedBlob) else {
            throw IMNOSecurityError.corruptedVaultFile
        }

        var decryptedData: Data
        do {
            decryptedData = try AES.GCM.open(sealedBox, using: masterKey)
        } catch {
            throw IMNOSecurityError.corruptedVaultFile
        }
        defer { imnoTextBestEffortZeroize(&decryptedData) }

        let payload: IMNOVaultPayload
        do {
            payload = try JSONDecoder().decode(IMNOVaultPayload.self, from: decryptedData)
        } catch {
            throw IMNOSecurityError.corruptedVaultFile
        }

        // Kiểm tra tính toàn vẹn SHA-256 của toàn bộ bản ghi
        for record in payload.records {
            if !record.isIntegrityValid {
                throw IMNOSecurityError.integrityViolation(record.id)
            }
        }
        return payload
    }

    private func savePayloadInternal(_ payload: IMNOVaultPayload, using masterKey: SymmetricKey) throws {
        var mutablePayload = payload
        mutablePayload.randomPadding = IMNOVaultPayload.generatePadding()
        mutablePayload.records.sort { $0.timestampMs > $1.timestampMs }

        var encoded = try JSONEncoder().encode(mutablePayload)
        defer { imnoTextBestEffortZeroize(&encoded) }
        let sealedBox = try AES.GCM.seal(encoded, using: masterKey)
        guard let combined = sealedBox.combined else {
            throw IMNOSecurityError.corruptedVaultFile
        }

        try combined.write(to: vaultFileURL, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: vaultFileURL.path)
    }

    /// Key chỉ được dùng bởi các thao tác yêu cầu phiên UI đã xác thực.
    private var cachedMasterKey: SymmetricKey?
    /// Key I/O tách biệt về quyền sử dụng; chỉ tồn tại khi cổng I/O được bật.
    private var cachedIOMasterKey: SymmetricKey?
    private var isSessionAuthorized: Bool = false
    private var sessionGeneration: UInt64 = 0
    /// Trạng thái I/O suy ra từ key I/O còn hiệu lực; không thể ON nếu thiếu key.
    private var ioEnabled: Bool { cachedIOMasterKey != nil }

    /// Chỉ cấp quyền phiên sau khi Engine tự xác thực sinh trắc học thành công.
    /// Không dựa vào cờ do ViewModel truyền vào để chứng minh người dùng đã xác thực.
    func authorizeSession(reason: String, enableIO: Bool = true) async throws {
        let generationAtStart = sessionGeneration
        try await BiometricSecurityManager.shared.authenticateLiveBiometrics(reason: reason)
        guard generationAtStart == sessionGeneration, !Task.isCancelled else {
            throw IMNOSecurityError.sessionLocked
        }

        if isSessionAuthorized, let currentMasterKey = cachedMasterKey {
            if enableIO {
                cachedIOMasterKey = currentMasterKey
            }
            return
        }

        let key = try await BiometricSecurityManager.shared.loadOrCreateMasterKey()
        guard generationAtStart == sessionGeneration, !Task.isCancelled else {
            throw IMNOSecurityError.sessionLocked
        }

        cachedMasterKey = key
        isSessionAuthorized = true
        if enableIO {
            cachedIOMasterKey = key
        }
    }

    /// Thu hồi quyền UI và xóa UI key. Chỉ xóa I/O key khi chính sách yêu cầu tắt cổng.
    public func lockVault(disableIO: Bool = false) {
        sessionGeneration &+= 1
        isSessionAuthorized = false
        cachedMasterKey = nil
        if disableIO {
            cachedIOMasterKey = nil
        }
    }

    func setIOEnabled(_ enabled: Bool) {
        guard enabled else {
            cachedIOMasterKey = nil
            return
        }

        // Không được bật I/O nếu Engine không có key UI vừa được xác thực.
        guard isSessionAuthorized, let key = cachedMasterKey else { return }
        cachedIOMasterKey = key
    }

    private func requireMasterKey() throws -> SymmetricKey {
        guard isSessionAuthorized, let key = cachedMasterKey else {
            throw IMNOSecurityError.sessionLocked
        }
        return key
    }

    private func requireIOMasterKey() throws -> SymmetricKey {
        guard ioEnabled, let key = cachedIOMasterKey else {
            throw IMNOSecurityError.ioDisabled
        }
        return key
    }

    /// Internal read-only state for unit tests; exposes no key material.
    var isLockedForTesting: Bool {
        !isSessionAuthorized && cachedMasterKey == nil
    }

    // MARK: - 5 Nhiệm Vụ Độc Quyền Của IMNO-Text

    /// Nhiệm vụ 1 & 2: Nhận dữ liệu từ Cửa sổ đè 3/4 (chỉ khi Cổng I/O đang BẬT).
    /// Khi cổng OFF, ViewModel phải xác thực sinh trắc và bật đồng bộ trước khi gọi.
    public func ingestDirectOverlayText(_ rawText: String) async throws -> IMNOTextRecord {
        guard ioEnabled else { throw IMNOSecurityError.ioDisabled }
        _ = try requireMasterKey()
        // Re-check after await in case the gate was closed while the key was warming up.
        guard ioEnabled else { throw IMNOSecurityError.ioDisabled }
        var payload = try loadPayloadInternal()

        let record = IMNOTextRecord(
            senderCode: payload.memberCode,
            firstReceiverCode: payload.memberCode,
            rawText: rawText
        )
        payload.records.insert(record, at: 0)
        payload.auditTrail.append(
            VaultAuditEntry(
                id: UUID(),
                timestampMs: record.timestampMs,
                actionCode: "INPUT_OVERLAY",
                integrityChecksum: record.sha256Hash
            )
        )

        let key = try requireMasterKey()
        try savePayloadInternal(payload, using: key)
        return record
    }

    /// Nhiệm vụ 1 & 3: Nhận dữ liệu từ thành viên khác khi Cổng I/O đang BẬT.
    /// Không có sinh trắc tại đầu gửi; vì vậy mọi yêu cầu đến khi cổng OFF đều bị từ chối.
    public func ingestFromExternalMember(
        senderCode: String,
        targetMemberCode: String,
        rawText: String
    ) async throws -> IMNOTextRecord {
        guard ioEnabled else { throw IMNOSecurityError.ioDisabled }
        let ioKey = try requireIOMasterKey()
        // Re-check the gate before touching the vault with the I/O-scoped key.
        guard ioEnabled else { throw IMNOSecurityError.ioDisabled }
        var payload = try loadPayloadInternal(using: ioKey)

        guard constantTimeCompare(payload.memberCode, targetMemberCode) else {
            throw IMNOSecurityError.unauthorizedMemberCode
        }

        let cleanSender = senderCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "UNKNOWN_MEMBER"
            : senderCode

        let record = IMNOTextRecord(
            senderCode: cleanSender,
            firstReceiverCode: payload.memberCode,
            rawText: rawText
        )
        payload.records.insert(record, at: 0)
        payload.auditTrail.append(
            VaultAuditEntry(
                id: UUID(),
                timestampMs: record.timestampMs,
                actionCode: "INPUT_EXTERNAL",
                integrityChecksum: record.sha256Hash
            )
        )

        try savePayloadInternal(payload, using: ioKey)
        return record
    }

    /// Xác thực, mở phiên Engine, bật I/O và đọc danh sách trong cùng một giao dịch.
    /// Không báo mở khóa thành công cho ViewModel trước khi payload được giải mã và kiểm tra.
    public func unlockAndReadAllRecords(
        reason: String = "Unlock IMNO-Text Vault"
    ) async throws -> [IMNOTextRecord] {
        let generationAtStart = sessionGeneration
        do {
            try await BiometricSecurityManager.shared.authenticateLiveBiometrics(reason: reason)
            guard generationAtStart == sessionGeneration, !Task.isCancelled else {
                throw IMNOSecurityError.sessionLocked
            }

            let key = try await BiometricSecurityManager.shared.loadOrCreateMasterKey()
            guard generationAtStart == sessionGeneration, !Task.isCancelled else {
                throw IMNOSecurityError.sessionLocked
            }

            cachedMasterKey = key
            cachedIOMasterKey = key
            isSessionAuthorized = true

            let payload = try loadPayloadInternal()
            guard generationAtStart == sessionGeneration, isSessionAuthorized else {
                throw IMNOSecurityError.sessionLocked
            }
            return payload.records.sorted { $0.timestampMs > $1.timestampMs }
        } catch {
            // Do not tear down a newer session if this request was superseded by a lock/re-unlock.
            if generationAtStart == sessionGeneration {
                isSessionAuthorized = false
                cachedMasterKey = nil
                cachedIOMasterKey = nil
            }
            throw error
        }
    }

    /// Xem Mã Thành Viên (Sau khi đã xác thực Sinh trắc học trực tiếp)
    public func readMemberCode() async throws -> String {
        _ = try requireMasterKey()
        let payload = try loadPayloadInternal()
        return payload.memberCode
    }

    /// Đổi Mã Thành Viên (Sau khi đã xác thực Sinh trắc học trực tiếp)
    public func updateMemberCode(_ newCode: String) async throws {
        let trimmed = newCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        _ = try requireMasterKey()
        var payload = try loadPayloadInternal()
        payload.memberCode = trimmed
        payload.auditTrail.append(
            VaultAuditEntry(
                id: UUID(),
                timestampMs: IMNOTextRecord.currentMillisecond(),
                actionCode: "MEMBER_CODE_ROTATE",
                integrityChecksum: SHA256.hash(data: Data(trimmed.utf8)).compactMap { String(format: "%02x", $0) }.joined()
            )
        )
        let key = try requireMasterKey()
        try savePayloadInternal(payload, using: key)
    }

    /// Nhiệm vụ 4: Đường Output cho thành viên khác (Kiểm tra Mã Thành Viên + Cổng I/O + Cấm lọc theo Mã gửi/nhận)
    public func queryForExternalMember(
        providedMemberCode: String,
        isIOEnabled: Bool,
        contentQuery: String?,
        startTimeMs: Int64?,
        endTimeMs: Int64?,
        exactTimeMs: Int64?
    ) async throws -> [ExternalSafeTextRecord] {
        guard isIOEnabled && ioEnabled else {
            throw IMNOSecurityError.ioDisabled
        }

        let ioKey = try requireIOMasterKey()
        // Kiểm tra lại cổng trước khi giải mã bằng khóa I/O riêng.
        guard ioEnabled else { throw IMNOSecurityError.ioDisabled }
        var payload = try loadPayloadInternal(using: ioKey)

        guard constantTimeCompare(payload.memberCode, providedMemberCode) else {
            throw IMNOSecurityError.unauthorizedMemberCode
        }

        let filtered = payload.records.filter { record in
            if let exact = exactTimeMs, record.timestampMs != exact { return false }
            if let start = startTimeMs, record.timestampMs < start { return false }
            if let end = endTimeMs, record.timestampMs > end { return false }
            if let q = contentQuery, !q.isEmpty {
                if !record.rawText.localizedCaseInsensitiveContains(q) { return false }
            }
            return true
        }

        payload.auditTrail.append(
            VaultAuditEntry(
                id: UUID(),
                timestampMs: IMNOTextRecord.currentMillisecond(),
                actionCode: "WITHDRAW_EXTERNAL",
                integrityChecksum: "COUNT_\(filtered.count)"
            )
        )
        try savePayloadInternal(payload, using: ioKey)

        // Tuyệt đối không trả về senderCode và firstReceiverCode cho bên ngoài
        return filtered.map {
            ExternalSafeTextRecord(
                id: $0.id,
                timestampMs: $0.timestampMs,
                byteSize: $0.byteSize,
                sha256Hash: $0.sha256Hash,
                rawText: $0.rawText
            )
        }
    }

    // MARK: - Nhiệm vụ 5: Export & Merge Liên Máy Chủ (Hybrid Envelope HKDF-SHA256)

    private static let portableKDFIdentifier = "PBKDF2-HMAC-SHA256-600000"
    private static let portableKDFIterations: UInt32 = 600_000
    private static let portableSaltByteCount = 32

    /// PBKDF2-HMAC-SHA256 (OWASP: 600,000 iterations), then HKDF for domain separation.
    private func derivePortableKey(superPassword: String, salt: Data) throws -> SymmetricKey {
        guard !superPassword.isEmpty, salt.count == Self.portableSaltByteCount else {
            throw IMNOSecurityError.invalidSuperPassword
        }

        var passwordBytes = Array(superPassword.utf8)
        passwordBytes.append(0x7C) // Domain separator: "|"
        passwordBytes.append(contentsOf: systemDomainTag.utf8)
        var derivedBytes = [UInt8](repeating: 0, count: 32)
        defer {
            for index in passwordBytes.indices { passwordBytes[index] = 0 }
            for index in derivedBytes.indices { derivedBytes[index] = 0 }
        }

        let status: Int32 = passwordBytes.withUnsafeBufferPointer { passwordBuffer in
            guard let passwordBase = passwordBuffer.baseAddress else { return Int32(kCCParamError) }
            return salt.withUnsafeBytes { saltBuffer in
                guard let saltBase = saltBuffer.bindMemory(to: UInt8.self).baseAddress else {
                    return Int32(kCCParamError)
                }
                return derivedBytes.withUnsafeMutableBufferPointer { outputBuffer in
                    guard let outputBase = outputBuffer.baseAddress else { return Int32(kCCParamError) }
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        UnsafeRawPointer(passwordBase).assumingMemoryBound(to: Int8.self),
                        passwordBuffer.count,
                        saltBase,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        Self.portableKDFIterations,
                        outputBase,
                        outputBuffer.count
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw IMNOSecurityError.keyDerivationFailure(status)
        }

        let pbkdf2Key = SymmetricKey(data: Data(derivedBytes))
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: pbkdf2Key,
            salt: salt,
            info: Data(systemDomainTag.utf8),
            outputByteCount: 32
        )
    }

    /// Import-only compatibility for pre-PBKDF2 portable .vault files.
    /// New exports never use this fast-hash KDF; re-export legacy imports to upgrade the wrapper.
    private func deriveLegacyPortableKey(superPassword: String, salt: Data) -> SymmetricKey {
        var stretched = Data((superPassword + "|" + systemDomainTag).utf8) + salt
        defer { imnoTextBestEffortZeroize(&stretched) }
        for _ in 0..<100_000 {
            stretched = Data(SHA256.hash(data: stretched))
        }
        let inputKey = SymmetricKey(data: stretched)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: Data(systemDomainTag.utf8),
            outputByteCount: 32
        )
    }

    /// Xuất (Export) toàn bộ tệp .vault được bọc bằng khóa dẫn xuất từ Siêu Mật Khẩu
    public func exportPortableVaultData(superPassword: String) async throws -> Data {
        guard !superPassword.isEmpty else { throw IMNOSecurityError.invalidSuperPassword }
        _ = try requireMasterKey()
        var payload = try loadPayloadInternal()

        payload.auditTrail.append(
            VaultAuditEntry(
                id: UUID(),
                timestampMs: IMNOTextRecord.currentMillisecond(),
                actionCode: "EXPORT",
                integrityChecksum: "RECORDS_\(payload.records.count)"
            )
        )
        let masterKey = try requireMasterKey()
        try savePayloadInternal(payload, using: masterKey)

        var saltBytes = [UInt8](repeating: 0, count: Self.portableSaltByteCount)
        let randomStatus = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard randomStatus == errSecSuccess else {
            throw IMNOSecurityError.keychainFailure(randomStatus)
        }
        let salt = Data(saltBytes)

        let portableKey = try derivePortableKey(superPassword: superPassword, salt: salt)
        var plainPayloadData = try JSONEncoder().encode(payload)
        defer { imnoTextBestEffortZeroize(&plainPayloadData) }
        let sealed = try AES.GCM.seal(plainPayloadData, using: portableKey)
        guard let combined = sealed.combined else { throw IMNOSecurityError.corruptedVaultFile }

        let envelope = PortableVaultEnvelope(
            magicHeader: "IMNO-Text-VAULT-V1",
            salt: salt,
            systemDomainTag: systemDomainTag,
            kdfIdentifier: Self.portableKDFIdentifier,
            combinedSealedBox: combined
        )
        return try JSONEncoder().encode(envelope)
    }

    /// Nhập & Hợp nhất (Import & Merge) tệp .vault: Giải mã, kiểm tra SHA-256, chống trùng theo ID/Hash và sắp xếp lại theo ms
    public func importAndMergeVaultData(_ externalData: Data, superPassword: String) async throws -> [IMNOTextRecord] {
        _ = try requireMasterKey()
        let masterKey = try requireMasterKey()
        var currentPayload = try loadPayloadInternal()

        let incomingPayload: IMNOVaultPayload

        // Hỗ trợ mở cả tệp Portable (.vault bọc bằng Siêu Mật Khẩu) hoặc tệp .vault cùng máy chủ
        if let envelope = try? JSONDecoder().decode(PortableVaultEnvelope.self, from: externalData),
           envelope.magicHeader == "IMNO-Text-VAULT-V1" {
            guard envelope.systemDomainTag == systemDomainTag else {
                throw IMNOSecurityError.corruptedVaultFile
            }
            guard !superPassword.isEmpty, envelope.salt.count == Self.portableSaltByteCount else {
                throw IMNOSecurityError.invalidSuperPassword
            }

            let portableKey: SymmetricKey
            switch envelope.kdfIdentifier {
            case Self.portableKDFIdentifier:
                portableKey = try derivePortableKey(superPassword: superPassword, salt: envelope.salt)
            case nil:
                portableKey = deriveLegacyPortableKey(superPassword: superPassword, salt: envelope.salt)
            default:
                throw IMNOSecurityError.invalidSuperPassword
            }

            guard let box = try? AES.GCM.SealedBox(combined: envelope.combinedSealedBox),
                  var opened = try? AES.GCM.open(box, using: portableKey) else {
                throw IMNOSecurityError.invalidSuperPassword
            }
            defer { imnoTextBestEffortZeroize(&opened) }
            guard let decoded = try? JSONDecoder().decode(IMNOVaultPayload.self, from: opened) else {
                throw IMNOSecurityError.invalidSuperPassword
            }
            incomingPayload = decoded
        } else if let box = try? AES.GCM.SealedBox(combined: externalData),
                  var opened = try? AES.GCM.open(box, using: masterKey) {
            defer { imnoTextBestEffortZeroize(&opened) }
            guard let decoded = try? JSONDecoder().decode(IMNOVaultPayload.self, from: opened) else {
                throw IMNOSecurityError.invalidSuperPassword
            }
            incomingPayload = decoded
        } else {
            throw IMNOSecurityError.invalidSuperPassword
        }

        // Từ chối payload sai schema hoặc thuộc ứng dụng IMNO khác trước khi merge.
        guard incomingPayload.schemaVersion == 1,
              incomingPayload.systemIdentifier == "APPLE-ES-IMNO-Text" else {
            throw IMNOSecurityError.corruptedVaultFile
        }

        // Kiểm tra tính toàn vẹn SHA-256 của từng bản ghi trước khi hợp nhất
        for record in incomingPayload.records {
            if !record.isIntegrityValid {
                throw IMNOSecurityError.integrityViolation(record.id)
            }
        }

        // Chống trùng lặp tuyệt đối theo UUID hoặc (SHA-256 + TimestampMs)
        var existingIDs = Set(currentPayload.records.map(\.id))
        var existingSignatures = Set(currentPayload.records.map { "\($0.sha256Hash)_\($0.timestampMs)" })
        var mergedCount = 0

        for record in incomingPayload.records {
            let signature = "\(record.sha256Hash)_\(record.timestampMs)"
            if !existingIDs.contains(record.id) && !existingSignatures.contains(signature) {
                currentPayload.records.append(record)
                existingIDs.insert(record.id)
                existingSignatures.insert(signature)
                mergedCount += 1
            }
        }

        // Sắp xếp lại chính xác theo mili-giây giảm dần (mới nhất lên đầu)
        currentPayload.records.sort { $0.timestampMs > $1.timestampMs }
        currentPayload.auditTrail.append(
            VaultAuditEntry(
                id: UUID(),
                timestampMs: IMNOTextRecord.currentMillisecond(),
                actionCode: "MERGE_ADDED_\(mergedCount)",
                integrityChecksum: "TOTAL_\(currentPayload.records.count)"
            )
        )

        try savePayloadInternal(currentPayload, using: masterKey)
        return currentPayload.records
    }

    private func constantTimeCompare(_ a: String, _ b: String) -> Bool {
        let aBytes = Array(a.utf8)
        let bBytes = Array(b.utf8)
        guard aBytes.count == bBytes.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<aBytes.count {
            diff |= aBytes[i] ^ bBytes[i]
        }
        return diff == 0
    }
}

// MARK: - 4. CLIPBOARD BẢO MẬT TỰ HỦY SAU 15 GIÂY

@MainActor
public final class SecureClipboardManager: ObservableObject {
    public static let shared = SecureClipboardManager()

    @Published public private(set) var activeCopiedTag: String? = nil
    @Published public private(set) var remainingSeconds: Int = 0

    private var wipeTask: Task<Void, Never>?
    private var countdownTask: Task<Void, Never>?
    private var activePasteboardChangeCount: Int?

    private init() {}

    /// Chép vào Clipboard hệ thống kèm cờ ConcealedType / TransientType và tự hủy sau đúng 15 giây
    public func copySecurely(_ string: String, tag: String) {
        wipeTask?.cancel()
        countdownTask?.cancel()

        let pb = NSPasteboard.general
        pb.clearContents()

        let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
        let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
        let autoGenType = NSPasteboard.PasteboardType("org.nspasteboard.AutoGeneratedType")

        pb.declareTypes([.string, concealedType, transientType, autoGenType], owner: nil)
        pb.setString(string, forType: .string)
        pb.setData(Data(), forType: concealedType)
        pb.setData(Data(), forType: transientType)
        pb.setData(Data(), forType: autoGenType)

        let recordedChangeCount = pb.changeCount
        activePasteboardChangeCount = recordedChangeCount
        activeCopiedTag = tag
        remainingSeconds = 15

        countdownTask = Task { [weak self] in
            for tick in stride(from: 14, through: 1, by: -1) {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled else { return }
                self?.remainingSeconds = tick
            }
        }

        wipeTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(15))
            guard !Task.isCancelled else { return }
            let pasteboard = NSPasteboard.general
            if pasteboard.changeCount == recordedChangeCount {
                pasteboard.clearContents()
            }
            self?.activePasteboardChangeCount = nil
            self?.activeCopiedTag = nil
            self?.remainingSeconds = 0
        }
    }

    /// Immediately cancel the clipboard timer and clear only content still owned by IMNO.
    public func forceImmediateWipe() {
        wipeTask?.cancel()
        countdownTask?.cancel()
        let pasteboard = NSPasteboard.general
        if let ownedChangeCount = activePasteboardChangeCount,
           pasteboard.changeCount == ownedChangeCount {
            pasteboard.clearContents()
        }
        activePasteboardChangeCount = nil
        activeCopiedTag = nil
        remainingSeconds = 0
    }
}

// MARK: - 5. CỔNG GIAO TIẾP BẤT ĐỐI XỨNG CHO CÁC THÀNH VIÊN CẤP THẤP (LOCAL GATEWAY)

public struct ExternalSafeTextRecord: Codable, Sendable {
    public let id: UUID
    public let timestampMs: Int64
    public let byteSize: Int
    public let sha256Hash: String
    public let rawText: String
}

public struct ExternalMemberInputPayload: Codable, Sendable {
    public let senderCode: String
    public let targetMemberCode: String
    public let rawText: String
}

public struct ExternalMemberOutputQuery: Codable, Sendable {
    public let targetMemberCode: String
    public let contentQuery: String?
    public let startTimeMs: Int64?
    public let endTimeMs: Int64?
    public let exactTimeMs: Int64?
    // Nếu thành viên bên ngoài cố tình gửi trường lọc theo Mã gửi/nhận -> Bị từ chối ngay lập tức
    public let senderCode: String?
    public let firstReceiverCode: String?
}

/// Máy chủ cục bộ (127.0.0.1:55101) tuân thủ Quy tắc Tương thích Một chiều Cấp 5
public final class IMNOMemberGateway: @unchecked Sendable {
    public static let shared = IMNOMemberGateway()
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "es.imno.text.gateway", qos: .userInitiated)
    private var ioStateProvider: (@Sendable () async -> Bool)?

    private init() {}

    public func start(port: UInt16 = 55101, isIOEnabled: @escaping @Sendable () async -> Bool) {
        self.ioStateProvider = isIOEnabled
        guard listener == nil else { return }

        do {
            let params = NWParameters.tcp
            params.acceptLocalOnly = true
            let nwPort = NWEndpoint.Port(rawValue: port)!
            let newListener = try NWListener(using: params, on: nwPort)

            newListener.newConnectionHandler = { [weak self] connection in
                self?.handleConnection(connection)
            }
            newListener.start(queue: queue)
            self.listener = newListener
        } catch {
            // Cổng nội bộ tự động bỏ qua nếu đang bị chiếm
        }
    }

    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
////////connection.receive(minimumIncompleteLength: 1, maximumLength: 1_048_576) { [weak self] data, _, _, _ in
        connection.receive(minimumIncompleteLength: 1, maximumLength: Int.max) { [weak self] data, _, _, _ in
            guard let self, let data, !data.isEmpty else {
                connection.cancel()
                return
            }
            Task {
                let responseData = await self.processHTTPOrRawRequest(data)
                connection.send(content: responseData, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
    }

    private func processHTTPOrRawRequest(_ rawData: Data) async -> Data {
        let requestString = String(decoding: rawData, as: UTF8.self)
        let components = requestString.components(separatedBy: "\r\n\r\n")
        let headerLine = components.first?.components(separatedBy: "\r\n").first ?? ""
        let bodyString = components.dropFirst().joined(separator: "\r\n\r\n")
        let bodyData = Data(bodyString.isEmpty ? requestString.utf8 : bodyString.utf8)

        // Đường Input: đồng bộ với Cổng I/O; OFF thì từ chối cả khi UI đang ở Logo.
        if headerLine.contains("POST /imno-text/input") {
            do {
                let allowed = await ioStateProvider?() ?? false
                guard allowed else { throw IMNOSecurityError.ioDisabled }
                let req = try JSONDecoder().decode(ExternalMemberInputPayload.self, from: bodyData)
                let saved = try await IMNOTextVaultEngine.shared.ingestFromExternalMember(
                    senderCode: req.senderCode,
                    targetMemberCode: req.targetMemberCode,
                    rawText: req.rawText
                )
                await MainActor.run {
                    IMNOTextViewModel.shared.notifyExternalRecordIngested(saved)
                }
                return makeHTTPResponse(status: "200 OK", json: #"{"status":"OK","id":"\#(saved.id.uuidString)"}"#)
            } catch {
                return makeHTTPResponse(status: "403 Forbidden", json: #"{"status":"DENIED"}"#)
            }
        }

        // Đường Output (Kiểm soát nghiêm ngặt: Đúng Mã Thành Viên + I/O = ON + Cấm lọc theo Mã Thành Viên)
        if headerLine.contains("POST /imno-text/output") {
            do {
                let query = try JSONDecoder().decode(ExternalMemberOutputQuery.self, from: bodyData)
                if query.senderCode != nil || query.firstReceiverCode != nil {
                    throw IMNOSecurityError.forbiddenExternalQueryField
                }
                let allowed = await ioStateProvider?() ?? false
                let results = try await IMNOTextVaultEngine.shared.queryForExternalMember(
                    providedMemberCode: query.targetMemberCode,
                    isIOEnabled: allowed,
                    contentQuery: query.contentQuery,
                    startTimeMs: query.startTimeMs,
                    endTimeMs: query.endTimeMs,
                    exactTimeMs: query.exactTimeMs
                )
                let encoded = try JSONEncoder().encode(results)
                return makeHTTPResponse(status: "200 OK", jsonData: encoded)
            } catch {
                return makeHTTPResponse(status: "403 Forbidden", json: #"{"status":"LOCKED_OR_DENIED"}"#)
            }
        }

        return makeHTTPResponse(status: "400 Bad Request", json: #"{"status":"INVALID_PROTOCOL"}"#)
    }

    private func makeHTTPResponse(status: String, json: String) -> Data {
        makeHTTPResponse(status: status, jsonData: Data(json.utf8))
    }

    private func makeHTTPResponse(status: String, jsonData: Data) -> Data {
        var header = "HTTP/1.1 \(status)\r\n"
        header += "Content-Type: application/json; charset=utf-8\r\n"
        header += "Access-Control-Allow-Origin: *\r\n"
        header += "Content-Length: \(jsonData.count)\r\n\r\n"
        return Data(header.utf8) + jsonData
    }
}

// MARK: - 6. TRÌNH ĐIỀU KHIỂN TRẠNG THÁI, KHÓA RAM & TÌM KIẾM 4 CHIỀU (VIEWMODEL)

@MainActor
public final class IMNOTextViewModel: ObservableObject {
    public static let shared = IMNOTextViewModel()

    // Trạng thái màn hình và công tắc I/O hai chiều (Nhận + Rút).
    @Published public private(set) var isUnlocked: Bool = false
    @Published public private(set) var isIOEnabled: Bool = false
    @Published public private(set) var isUnlocking: Bool = false
    @Published public private(set) var unlockFailureMessage: String? = nil

    // Dữ liệu trên RAM giao diện (Bị xóa trắng ngay khi Single/Double Click nút góc phải)
    @Published public private(set) var decryptedRecords: [IMNOTextRecord] = []

    // Cửa sổ đè 3/4 (Đường Input 1)
    @Published public var isOverlayInputPresented: Bool = false
    @Published public var overlayDraftText: String = ""

    // Thanh tìm kiếm 4 chiều ẩn mặc định
    @Published public var searchQuery: String = ""
    @Published public private(set) var isSearchTextRevealed: Bool = false

    // 3 Tùy chọn vệ tinh ở nút góc trên bên phải
    @Published public var isControlSatelliteExpanded: Bool = false
    @Published public var activeModal: ActiveSecurityModal? = nil
    @Published public var editableMemberCode: String = ""
    @Published public var superPasswordInput: String = ""
    @Published public var pendingMergeFileURL: URL? = nil

    // Chỉ báo trạng thái màu sắc (Zero-Text)
    @Published public var statusPulseColor: Color = .clear

    public enum ActiveSecurityModal: Identifiable {
        case memberCodeEditor
        case exportSuperPassword
        case mergeSuperPassword

        public var id: Int { hashValue }
    }

    private var singleClickTask: Task<Void, Never>?
    private var securityStateGeneration: UInt64 = 0
    private var engineSessionAuthorized: Bool = false
    private var idleLockTask: Task<Void, Never>?
    private var absoluteLockTask: Task<Void, Never>?
    private var activityEventMonitor: Any?
    private var lastActivityRefresh = ContinuousClock().now

    // OWASP high-value idle range: ; absolute lifetime uses the lower
    // end of the commonly suggested range for full-day office sessions.
    private static let vaultIdleTimeout: Duration = .seconds(86_400)
    private static let vaultAbsoluteTimeout: Duration = .seconds(86_400) ////////////

    private init() {
        IMNOMemberGateway.shared.start { [weak self] in
            await MainActor.run { self?.isIOEnabled ?? false }
        }
        installVaultActivityMonitor()
    }

    // MARK: - Cổng Sinh Trắc Học Mở Khóa Vào Trong

    public func unlockVaultWithBiometrics() async {
        guard !isUnlocking else { return }
        let generationAtStart = securityStateGeneration
        isUnlocking = true
        unlockFailureMessage = nil
        defer { isUnlocking = false }

        do {
            // Engine only returns records after biometric auth, key retrieval, decryption,
            // integrity checks, and session-generation validation all succeed.
            let records = try await IMNOTextVaultEngine.shared.unlockAndReadAllRecords(
                reason: "Unlock IMNO-Text Vault"
            )
            guard generationAtStart == securityStateGeneration else { return }

            engineSessionAuthorized = true
            beginVaultSessionTimeouts()
            decryptedRecords = records
            isIOEnabled = true
            isUnlocked = true
            triggerPulse(.green)
        } catch {
            if generationAtStart == securityStateGeneration {
                let diagnostic = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
                unlockFailureMessage = diagnostic
                NSLog("[IMNO-Text] Vault unlock failed: %@", diagnostic)
                await lockVault(disableIO: true)
                triggerPulse(.red)
            }
        }
    }

    public func dismissUnlockFailure() {
        unlockFailureMessage = nil
    }

    // MARK: - Đường Input Đầu Tiên: Cửa Sổ Đè 3/4

    public func commitOverlayTextToVault() async {
        let generationAtStart = securityStateGeneration
        let text = overlayDraftText
        guard !text.isEmpty else { return }

        do {
            // Cửa sổ đè là đường nhận nội bộ duy nhất được phép bật cổng OFF sau sinh trắc.
            if !isIOEnabled || !engineSessionAuthorized {
                try await IMNOTextVaultEngine.shared.authorizeSession(
                    reason: "Enable IMNO-Text Receive and Withdraw",
                    enableIO: true
                )
                guard generationAtStart == securityStateGeneration else { return }
                engineSessionAuthorized = true
                beginVaultSessionTimeouts()
                isIOEnabled = true
            }
            guard generationAtStart == securityStateGeneration else { return }
            let savedRecord = try await IMNOTextVaultEngine.shared.ingestDirectOverlayText(text)
            guard generationAtStart == securityStateGeneration else { return }
            overlayDraftText = ""
            isOverlayInputPresented = false

            // Chỉ cập nhật RAM nếu đang mở khóa; nếu đang ở màn hình Logo thì RAM vẫn rỗng tuyệt đối
            if isUnlocked {
                decryptedRecords.insert(savedRecord, at: 0)
                decryptedRecords.sort { $0.timestampMs > $1.timestampMs }
            }
            triggerPulse(.cyan)
        } catch {
            triggerPulse(.red)
        }
    }

    public func notifyExternalRecordIngested(_ record: IMNOTextRecord) {
        if isUnlocked {
            decryptedRecords.insert(record, at: 0)
            decryptedRecords.sort { $0.timestampMs > $1.timestampMs }
        }
        triggerPulse(.cyan)
    }

    // MARK: - Nút Điều Khiển Góc Trên Bên Phải: Single Click vs Double Click

    /// Single Click chỉ khóa RAM; Double Click yêu cầu sinh trắc để đóng toàn bộ Cổng I/O.
    public func handleTopRightControlTap() {
        if let existingTask = singleClickTask {
            // Phát hiện Double Click trong cửa sổ 220ms
            existingTask.cancel()
            singleClickTask = nil
            Task { [weak self] in
                guard let self else { return }
                await self.requestIOShutdownWithBiometrics()
            }
        } else {
            singleClickTask = Task { [weak self] in
                try? await Task.sleep(for: .milliseconds(220))
                guard !Task.isCancelled else { return }
                self?.singleClickTask = nil
                await self?.performSingleClickLock()
            }
        }
    }

    /// Single Click: xóa RAM giao diện và về Logo; trạng thái Cổng I/O hai chiều được giữ nguyên.
    public func performSingleClickLock() async {
        await lockVault()
        triggerPulse(.orange)
    }

    /// Điểm đóng cổng dùng chung cho Double Click và mọi phím chức năng/tổ hợp phím trong tương lai.
    public func requestIOShutdownWithBiometrics() async {
        do {
            try await BiometricSecurityManager.shared.authenticateLiveBiometrics(
                reason: "Disable IMNO-Text Receive and Withdraw"
            )
            await lockVault(disableIO: true)
            triggerPulse(.red)
        } catch {
            // Xác thực thất bại/hủy: giữ nguyên trạng thái I/O và dữ liệu đang mở.
            triggerPulse(.red)
        }
    }

    /// Observe local user input so the idle timeout is refreshed for active use.
    private func installVaultActivityMonitor() {
        guard activityEventMonitor == nil else { return }
        let mask: NSEvent.EventTypeMask = [
            .keyDown, .flagsChanged,
            .leftMouseDown, .rightMouseDown, .otherMouseDown,
            .leftMouseDragged, .mouseMoved, .scrollWheel
        ]
        activityEventMonitor = NSEvent.addLocalMonitorForEvents(matching: mask) { [weak self] event in
            Task { @MainActor [weak self] in
                self?.noteVaultActivity()
            }
            return event
        }
    }

    private func noteVaultActivity() {
        guard engineSessionAuthorized else { return }
        let now = ContinuousClock().now
        guard now - lastActivityRefresh >= .seconds(1) else { return }
        lastActivityRefresh = now
        scheduleIdleLock()
    }

    /// Start both session limits whenever the Engine grants a freshly authenticated session.
    private func beginVaultSessionTimeouts() {
        idleLockTask?.cancel()
        absoluteLockTask?.cancel()
        lastActivityRefresh = ContinuousClock().now
        scheduleIdleLock()

        absoluteLockTask = Task { [weak self] in
            do {
                try await Task.sleep(for: Self.vaultAbsoluteTimeout)
            } catch {
                return
            }
            guard let self, self.engineSessionAuthorized else { return }
            await self.lockVault(disableIO: true)
        }
    }

    private func scheduleIdleLock() {
        idleLockTask?.cancel()
        idleLockTask = Task { [weak self] in
            do {
                try await Task.sleep(for: Self.vaultIdleTimeout)
            } catch {
                return
            }
            guard let self, self.engineSessionAuthorized else { return }
            await self.lockVault(disableIO: true)
        }
    }

    private func cancelVaultSessionTimeouts() {
        idleLockTask?.cancel()
        absoluteLockTask?.cancel()
        idleLockTask = nil
        absoluteLockTask = nil
    }

    /// Locks UI RAM/session; the Engine retains its isolated I/O key only when I/O stays enabled.
    public func lockVault(disableIO: Bool = false) async {
        securityStateGeneration &+= 1
        singleClickTask?.cancel()
        singleClickTask = nil
        cancelVaultSessionTimeouts()
        engineSessionAuthorized = false
        wipeUIRAM()
        isUnlocked = false
        if disableIO { isIOEnabled = false }
        SecureClipboardManager.shared.forceImmediateWipe()
        await IMNOTextVaultEngine.shared.lockVault(disableIO: disableIO)
    }

    private func wipeUIRAM() {
        decryptedRecords.removeAll(keepingCapacity: false)
        overlayDraftText = ""
        isOverlayInputPresented = false
        searchQuery = ""
        isSearchTextRevealed = false
        isControlSatelliteExpanded = false
        activeModal = nil
        editableMemberCode = ""
        superPasswordInput = ""
        pendingMergeFileURL = nil
    }

    /// Internal state assertion for XCTest; no sensitive material is exposed.
    var isLockedForTesting: Bool {
        !isUnlocked && !engineSessionAuthorized && decryptedRecords.isEmpty &&
        overlayDraftText.isEmpty && searchQuery.isEmpty && !isSearchTextRevealed &&
        editableMemberCode.isEmpty && superPasswordInput.isEmpty && pendingMergeFileURL == nil &&
        activeModal == nil
    }

    // MARK: - 3 Tùy Chọn Vệ Tinh (Tất cả đều bắt buộc quét Sinh trắc học trực tiếp)

    /// Vệ tinh 1: Xem và đổi Mã Thành Viên
    public func openMemberCodeSatellite() async {
        let generationAtStart = securityStateGeneration
        do {
            try await IMNOTextVaultEngine.shared.authorizeSession(reason: "Access Member Code", enableIO: isIOEnabled)
            guard generationAtStart == securityStateGeneration else { return }
            engineSessionAuthorized = true
            beginVaultSessionTimeouts()
            let code = try await IMNOTextVaultEngine.shared.readMemberCode()
            guard generationAtStart == securityStateGeneration else { return }
            editableMemberCode = code
            activeModal = .memberCodeEditor
        } catch {
            triggerPulse(.red)
        }
    }

    public func saveUpdatedMemberCode() async {
        let generationAtStart = securityStateGeneration
        let newCode = editableMemberCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !newCode.isEmpty else { return }
        do {
            try await IMNOTextVaultEngine.shared.updateMemberCode(newCode)
            guard generationAtStart == securityStateGeneration else { return }
            editableMemberCode = ""
            activeModal = nil
            triggerPulse(.green)
        } catch {
            triggerPulse(.red)
        }
    }

    /// Vệ tinh 2: Xuất (Export) tệp .vault mã hóa tuyệt đối
    public func openExportSatellite() async {
        let generationAtStart = securityStateGeneration
        do {
            try await IMNOTextVaultEngine.shared.authorizeSession(reason: "Export IMNO-Text Vault", enableIO: isIOEnabled)
            guard generationAtStart == securityStateGeneration else { return }
            engineSessionAuthorized = true
            beginVaultSessionTimeouts()
            superPasswordInput = ""
            activeModal = .exportSuperPassword
        } catch {
            triggerPulse(.red)
        }
    }

    public func executeExportWithSuperPassword() async {
        let generationAtStart = securityStateGeneration
        let password = superPasswordInput
        superPasswordInput = ""
        activeModal = nil
        guard !password.isEmpty else { return }

        do {
            // Do not construct NSSavePanel here: on some macOS 26 systems the
            // AppKit Open/Save Panel bridge blocks during panel initialization.
            // This diagnostic path deliberately exports without any file picker.
            let exportURL = try await Task.detached(priority: .utility) {
                NSLog("[IMNO-Text] Export stage 1: generating portable vault envelope")
                let portableData = try await IMNOTextVaultEngine.shared.exportPortableVaultData(superPassword: password)
                NSLog("[IMNO-Text] Export stage 2: envelope ready (\(portableData.count) bytes)")

                let fileManager = FileManager.default
                guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
                    throw CocoaError(.fileNoSuchFile)
                }

                // App-container Documents is writable even when App Sandbox is enabled.
                let exportDirectory = documentsURL.appendingPathComponent("IMNO-Exports", isDirectory: true)
                try fileManager.createDirectory(
                    at: exportDirectory,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )

                let timestamp = Int64(Date().timeIntervalSince1970)
                let uniqueSuffix = String(UUID().uuidString.prefix(8))
                let fileName = "imno_text_\(timestamp)_\(uniqueSuffix).vault"
                let destinationURL = exportDirectory.appendingPathComponent(fileName, isDirectory: false)

                NSLog("[IMNO-Text] Export stage 3: writing vault file")
                try portableData.write(to: destinationURL, options: .atomic)
                try fileManager.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: destinationURL.path
                )
                NSLog("[IMNO-Text] Export stage 4: saved at \(destinationURL.path)")
                return destinationURL
            }.value

            guard generationAtStart == securityStateGeneration else { return }
            NSWorkspace.shared.activateFileViewerSelecting([exportURL])
            triggerPulse(.green)
        } catch {
            let diagnostic = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            NSLog("[IMNO-Text] Portable export failed: %@", diagnostic)
            triggerPulse(.red)
        }
    }

    /// Vệ tinh 3: Tải lên (Import & Merge) tệp .vault
    public func openMergeSatellite() async {
        let generationAtStart = securityStateGeneration
        do {
            try await IMNOTextVaultEngine.shared.authorizeSession(reason: "Merge IMNO-Text Vault", enableIO: isIOEnabled)
            guard generationAtStart == securityStateGeneration else { return }
            engineSessionAuthorized = true
            beginVaultSessionTimeouts()
            let openPanel = NSOpenPanel()
            openPanel.canChooseFiles = true
            openPanel.canChooseDirectories = false
            openPanel.allowsMultipleSelection = false
            guard await openPanel.begin() == .OK, let url = openPanel.url else { return }
            guard generationAtStart == securityStateGeneration else { return }
            pendingMergeFileURL = url
            superPasswordInput = ""
            activeModal = .mergeSuperPassword
        } catch {
            let diagnostic = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            NSLog("[IMNO-Text] Open merge panel failed: %@", diagnostic)
            triggerPulse(.red)
        }
    }

    public func executeMergeWithSuperPassword() async {
        let generationAtStart = securityStateGeneration
        guard let fileURL = pendingMergeFileURL else { return }
        let password = superPasswordInput
        superPasswordInput = ""
        pendingMergeFileURL = nil
        activeModal = nil

        do {
            // AppKit's Open panel grants a temporary security scope for its selected URL.
            // Keep that scope alive across the background read, then release it exactly once.
            defer { fileURL.stopAccessingSecurityScopedResource() }
            let externalData = try await Task.detached(priority: .userInitiated) {
                try Data(contentsOf: fileURL)
            }.value
            guard generationAtStart == securityStateGeneration else { return }
            let mergedRecords = try await IMNOTextVaultEngine.shared.importAndMergeVaultData(
                externalData,
                superPassword: password
            )
            guard generationAtStart == securityStateGeneration else { return }
            if isUnlocked {
                decryptedRecords = mergedRecords
            }
            triggerPulse(.green)
        } catch {
            let diagnostic = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            NSLog("[IMNO-Text] Portable merge failed: %@", diagnostic)
            triggerPulse(.red)
        }
    }

    // MARK: - Thanh Tìm Kiếm 4 Chiều Ẩn Mặc Định & Cú Pháp Truy Vết Độc Quyền

    /// Bấm biểu tượng Con Mắt: Bắt buộc xác thực Sinh trắc học mới hiển thị rõ chữ trên thanh tìm kiếm
    public func toggleSearchVisibilityWithBiometrics() async {
        if isSearchTextRevealed {
            isSearchTextRevealed = false
            return
        }
        let generationAtStart = securityStateGeneration
        do {
            try await BiometricSecurityManager.shared.authenticateLiveBiometrics(reason: "Reveal Search Query")
            guard generationAtStart == securityStateGeneration else { return }
            isSearchTextRevealed = true
        } catch {
            triggerPulse(.red)
        }
    }

    /// Bộ lọc 4 chiều: Mã_Gửi -> Mã_Nhận, Mã_Gửi ->, -> Mã_Nhận, Thời gian (ms), Nội dung UTF-8
    public var filteredRecords: [IMNOTextRecord] {
        let rawQuery = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rawQuery.isEmpty else { return decryptedRecords }

        // Kiểm tra cú pháp truy vết độc quyền chứa "->"
        if rawQuery.contains("->") {
            let parts = rawQuery.components(separatedBy: "->")
            let leftSender = parts.first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let rightReceiver = parts.dropFirst().joined(separator: "->").trimmingCharacters(in: .whitespacesAndNewlines)

            return decryptedRecords.filter { record in
                let matchSender = leftSender.isEmpty ||
                    record.senderCode.localizedCaseInsensitiveContains(leftSender)
                let matchReceiver = rightReceiver.isEmpty ||
                    record.firstReceiverCode.localizedCaseInsensitiveContains(rightReceiver)
                return matchSender && matchReceiver
            }
        }

        // Tìm kiếm đồng thời trên cả 4 trường: Mã gửi, Mã nhận đầu tiên, Thời gian (ms), và Nội dung văn bản
        return decryptedRecords.filter { record in
            String(record.timestampMs).contains(rawQuery) ||
            record.rawText.localizedCaseInsensitiveContains(rawQuery) ||
            record.senderCode.localizedCaseInsensitiveContains(rawQuery) ||
            record.firstReceiverCode.localizedCaseInsensitiveContains(rawQuery)
        }
    }

    private func triggerPulse(_ color: Color) {
        withAnimation(.easeInOut(duration: 0.2)) {
            statusPulseColor = color
        }
        Task {
            try? await Task.sleep(for: .milliseconds(900))
            withAnimation(.easeOut(duration: 0.4)) {
                statusPulseColor = .clear
            }
        }
    }
}

// MARK: - 7. GIAO DIỆN APPLE LIQUID GLASS & CỬA SỐ TỈ LỆ VÀNG (ZERO-TEXT UI)

/// Bảng màu & Chất liệu chuẩn Apple Liquid Glass (Khúc xạ đa lớp, Specular Rim & Tán sắc sâu)
public enum LiquidGlassTheme {
    // Tỉ lệ vàng chuẩn xác (760 / 470 = 1.61702 ≈ φ 1.61803)
    public static let goldenWidth: CGFloat = 760
    public static let goldenHeight: CGFloat = 470
    public static let windowCornerRadius: CGFloat = 28

    // Lớp phủ bề mặt kính lỏng chính (Tán sắc chéo từ sương trắng nhẹ xuống xanh lam sâu)
    public static let primarySurfaceTint = LinearGradient(
        stops: [
            .init(color: Color.white.opacity(0.14), location: 0.0),
            .init(color: Color(red: 0.55, green: 0.78, blue: 1.0).opacity(0.05), location: 0.45),
            .init(color: Color(red: 0.04, green: 0.07, blue: 0.14).opacity(0.28), location: 1.0)
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    // Viền phản quang kính lỏng (Specular Highlight: Đỉnh bắt sáng mạnh, đáy phản chiếu dịu)
    public static let outerWindowRim = LinearGradient(
        stops: [
            .init(color: Color.white.opacity(0.62), location: 0.0),
            .init(color: Color(red: 0.72, green: 0.92, blue: 1.0).opacity(0.24), location: 0.35),
            .init(color: Color.white.opacity(0.06), location: 0.75),
            .init(color: Color(red: 0.45, green: 0.82, blue: 1.0).opacity(0.28), location: 1.0)
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    // Viền khúc xạ cho các thẻ nổi & nút bấm bên trong (Card / Capsule Rim)
    public static let cardSpecularRim = LinearGradient(
        stops: [
            .init(color: Color.white.opacity(0.48), location: 0.0),
            .init(color: Color.white.opacity(0.12), location: 0.5),
            .init(color: Color(red: 0.60, green: 0.88, blue: 1.0).opacity(0.22), location: 1.0)
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    // Bề mặt kính nổi cho các ô dữ liệu và nút bấm
    public static let elevatedGlassFill = LinearGradient(
        colors: [
            Color.white.opacity(0.12),
            Color(red: 0.65, green: 0.85, blue: 1.0).opacity(0.03)
        ],
        startPoint: .top,
        endPoint: .bottom
    )

    // Màu điểm nhấn phát quang trong kính lỏng (Liquid Luminescent Accents)
    public static let iceCyan = Color(red: 0.38, green: 0.88, blue: 1.0)
    public static let bioEmerald = Color(red: 0.25, green: 0.95, blue: 0.68)
    public static let amethystGlow = Color(red: 0.76, green: 0.52, blue: 1.0)
    public static let mintRefraction = Color(red: 0.42, green: 0.96, blue: 0.84)
}

/// Cầu nối NSVisualEffectView kết hợp mở khóa độ trong suốt thực sự cho NSWindow và bo góc chuẩn Liquid Glass
public struct GlassmorphicBackground: NSViewRepresentable {
    public var material: NSVisualEffectView.Material
    public var blendingMode: NSVisualEffectView.BlendingMode
    public var isMainWindow: Bool

    public init(
        material: NSVisualEffectView.Material = .hudWindow,
        blendingMode: NSVisualEffectView.BlendingMode = .behindWindow,
        isMainWindow: Bool = true
    ) {
        self.material = material
        self.blendingMode = blendingMode
        self.isMainWindow = isMainWindow
    }

    public func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .active
        view.isEmphasized = true
        view.appearance = NSAppearance(named: .vibrantDark)

        if isMainWindow {
            DispatchQueue.main.async {
                configureLiquidGlassWindow(for: view.window)
            }
        }
        return view
    }

    public func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
        nsView.state = .active
        if isMainWindow {
            DispatchQueue.main.async {
                configureLiquidGlassWindow(for: nsView.window)
            }
        }
    }

    private func configureLiquidGlassWindow(for window: NSWindow?) {
        guard let window else { return }
        window.isOpaque = false
        window.backgroundColor = .clear
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = true
        window.hasShadow = true
    }
}

/// Màn hình chính của IMNO-Text tuân thủ Nguyên tắc Zero-Text & Thiết kế Apple Liquid Glass Tỉ Lệ Vàng
public struct IMNOTextRootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var vm = IMNOTextViewModel.shared
    @StateObject private var clipboard = SecureClipboardManager.shared

    public init() {}

    public var body: some View {
        GeometryReader { geo in
            ZStack {
                // Lớp 1: Kính mờ xuyên thấu trực tiếp xuống nền macOS phía sau cửa sổ
                GlassmorphicBackground(
                    material: .hudWindow,
                    blendingMode: .behindWindow,
                    isMainWindow: true
                )
                .ignoresSafeArea()

                // Lớp 2: Khúc xạ ánh sáng bề mặt Liquid Glass (Không dùng màu đen đục gây bệt kính)
                LiquidGlassTheme.primarySurfaceTint
                    .ignoresSafeArea()

                // Lớp 3: Ánh sáng vòm trên (Top Specular Bloom) tạo hiệu ứng kính uốn cong 3D
                RadialGradient(
                    colors: [
                        Color.white.opacity(0.16),
                        Color(red: 0.45, green: 0.80, blue: 1.0).opacity(0.04),
                        Color.clear
                    ],
                    center: .topLeading,
                    startRadius: 10,
                    endRadius: geo.size.width * 0.75
                )
                .ignoresSafeArea()
                .allowsHitTesting(false)

                // Lớp 4: Viền ngoài Liquid Glass kép + Phản hồi xung trạng thái (Zero-Text Status Pulse)
                RoundedRectangle(cornerRadius: LiquidGlassTheme.windowCornerRadius, style: .continuous)
                    .strokeBorder(LiquidGlassTheme.outerWindowRim, lineWidth: 1.2)
                    .overlay(
                        RoundedRectangle(cornerRadius: LiquidGlassTheme.windowCornerRadius, style: .continuous)
                            .strokeBorder(vm.statusPulseColor.opacity(0.85), lineWidth: 2.2)
                            .shadow(color: vm.statusPulseColor.opacity(0.6), radius: 12)
                    )
                    .ignoresSafeArea()
                    .allowsHitTesting(false)

                if vm.isUnlocked {
                    unlockedVaultListView(in: geo.size)
                        .transition(.opacity.combined(with: .scale(scale: 0.98)))
                } else {
                    startupLogoGateView(in: geo.size)
                        .transition(.opacity.combined(with: .scale(scale: 1.02)))
                }

                // Cửa sổ đè 3/4 (Đường Input 1: Mở khi nhấn vào ô Logo - Giữ nguyên tỉ lệ 0.75 chờ chỉnh sau)
                if vm.isOverlayInputPresented {
                    threeQuarterInputOverlay(in: geo.size)
                        .transition(.opacity.combined(with: .scale(scale: 0.95)))
                        .zIndex(20)
                }

                // Hộp thoại bảo mật tối giản cho 3 tùy chọn vệ tinh
                if let modal = vm.activeModal {
                    satelliteSecurityModalView(modal: modal, in: geo.size)
                        .zIndex(30)
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: LiquidGlassTheme.windowCornerRadius, style: .continuous))
        }
        .preferredColorScheme(.dark)
        // Khung cửa sổ chính tỉ lệ vàng: 760 x 470 (≈ 1.618 : 1)
        .frame(
            minWidth: LiquidGlassTheme.goldenWidth,
            idealWidth: LiquidGlassTheme.goldenWidth,
            minHeight: LiquidGlassTheme.goldenHeight,
            idealHeight: LiquidGlassTheme.goldenHeight
        )
        .alert("Không thể mở khóa Vault", isPresented: Binding(
            get: { vm.unlockFailureMessage != nil },
            set: { isPresented in
                if !isPresented { vm.dismissUnlockFailure() }
            }
        )) {
            Button("Đóng", role: .cancel) { vm.dismissUnlockFailure() }
        } message: {
            Text(vm.unlockFailureMessage ?? "Lỗi không xác định")
        }
        .onChange(of: scenePhase) { newPhase in
            guard newPhase == .background else { return }
            Task { await vm.lockVault(disableIO: true) }
        }
    }

    // MARK: - 7.1. Màn Hình Khởi Động (Cổng Logo & Sinh Trắc Học Chuẩn Liquid Glass)

    private func startupLogoGateView(in size: CGSize) -> some View {
        ZStack {
            // Chấm trạng thái góc trên bên phải báo hiệu công tắc I/O đồng bộ Nhận + Rút (ON = Xanh Ngọc, OFF = Sương Mờ)
            VStack {
                HStack {
                    Spacer()
                    Circle()
                        .fill(vm.isUnlocked ? LiquidGlassTheme.bioEmerald : (vm.isIOEnabled ? Color.orange : Color.white.opacity(0.22)))
                        .frame(width: 9, height: 9)
                        .overlay(
                            Circle()
                                .strokeBorder(Color.white.opacity(0.45), lineWidth: 0.6)
                        )
                        .shadow(color: vm.isUnlocked ? LiquidGlassTheme.bioEmerald.opacity(0.85) : (vm.isIOEnabled ? Color.orange.opacity(0.65) : .clear), radius: 8)
                        .padding(24)
                        .onTapGesture(count: 2) {
                            Task { await vm.requestIOShutdownWithBiometrics() }
                        }
                }
                Spacer()
            }

            // Ô Logo trung tâm kèm biểu tượng Sinh trắc học Apple ES sẵn sàng
            VStack(spacing: 26) {
                // Nhấn trực tiếp vào ô Logo -> Bung cửa sổ đè 3/4 để nạp nhanh dữ liệu
                Button {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) {
                        vm.isOverlayInputPresented = true
                    }
                } label: {
                    ZStack {
                        RoundedRectangle(cornerRadius: 32, style: .continuous)
                            .fill(.ultraThinMaterial)
                            .frame(width: 120, height: 120)
                            .overlay(
                                RoundedRectangle(cornerRadius: 32, style: .continuous)
                                    .fill(LiquidGlassTheme.elevatedGlassFill)
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 32, style: .continuous)
                                    .strokeBorder(LiquidGlassTheme.cardSpecularRim, lineWidth: 1.4)
                            )
                            .shadow(color: Color.black.opacity(0.32), radius: 24, y: 12)
                            .shadow(color: LiquidGlassTheme.iceCyan.opacity(0.12), radius: 16, y: -2)

                        Image(systemName: "cube.transparent.fill")
                            .font(.system(size: 46, weight: .light))
                            .foregroundStyle(
                                LinearGradient(
                                    colors: [
                                        .white,
                                        Color(red: 0.72, green: 0.92, blue: 1.0).opacity(0.88)
                                    ],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .shadow(color: LiquidGlassTheme.iceCyan.opacity(0.35), radius: 10)
                    }
                }
                .buttonStyle(.plain)

                // Nút chạm Sinh trắc học Apple ES (Mở khóa danh sách + Bật đồng thời Cổng Nhận và Rút)
                Button {
                    Task { await vm.unlockVaultWithBiometrics() }
                } label: {
                    ZStack {
                        Circle()
                            .fill(.ultraThinMaterial)
                            .frame(width: 50, height: 50)
                            .overlay(
                                Circle()
                                    .fill(LiquidGlassTheme.elevatedGlassFill)
                            )
                            .overlay(
                                Circle()
                                    .strokeBorder(LiquidGlassTheme.cardSpecularRim, lineWidth: 1.1)
                            )
                            .shadow(color: Color.black.opacity(0.28), radius: 12, y: 6)

                        Image(systemName: "touchid")
                            .font(.system(size: 23, weight: .regular))
                            .foregroundStyle(LiquidGlassTheme.iceCyan)
                            .shadow(color: LiquidGlassTheme.iceCyan.opacity(0.5), radius: 6)
                    }
                }
                .disabled(vm.isUnlocking)
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - 7.2. Cửa Sổ Đè 3/4 (Giữ nguyên kích thước 0.75x0.75, đồng bộ màu Liquid Glass)

    private func threeQuarterInputOverlay(in size: CGSize) -> some View {
        ZStack {
            // Vùng 1/4 viền xung quanh: Nhấn chuột ra vùng ngoài lập tức đóng cửa sổ đè
            Color.black.opacity(0.22)
                .ignoresSafeArea()
                .contentShape(Rectangle())
                .onTapGesture {
                    withAnimation(.spring(response: 0.25, dampingFraction: 0.85)) {
                        vm.isOverlayInputPresented = false
                    }
                }

            // Cửa sổ đè kích thước đúng bằng 3/4 cửa sổ ứng dụng chính (Giữ nguyên chờ điều chỉnh sau)
            VStack(spacing: 14) {
                // Khung soạn thảo văn bản tối giản trong suốt, nhận mọi phông chữ/ký tự UTF-8
                TextEditor(text: $vm.overlayDraftText)
                    .font(.system(size: 15, weight: .regular, design: .monospaced))
                    .scrollContentBackground(.hidden)
                    .foregroundStyle(.white.opacity(0.96))
                    .padding(18)
                    .background(Color.clear)

                // Chỉ số byte UTF-8 tối giản + 1 nút tròn nhỏ duy nhất ở phía dưới để lưu vào imno_text.vault
                ZStack {
                    HStack {
                        Text("\(Data(vm.overlayDraftText.utf8).count) B")
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.45))
                        Spacer()
                    }
                    .padding(.horizontal, 20)

                    Button {
                        Task { await vm.commitOverlayTextToVault() }
                    } label: {
                        Circle()
                            .fill(vm.overlayDraftText.isEmpty ? Color.white.opacity(0.16) : LiquidGlassTheme.iceCyan)
                            .frame(width: 28, height: 28)
                            .overlay(
                                Circle()
                                    .strokeBorder(.white.opacity(0.65), lineWidth: 1.1)
                            )
                            .shadow(
                                color: vm.overlayDraftText.isEmpty ? .clear : LiquidGlassTheme.iceCyan.opacity(0.75),
                                radius: 10
                            )
                    }
                    .buttonStyle(.plain)
                    .disabled(vm.overlayDraftText.isEmpty)
                }
                .padding(.bottom, 16)
            }
            .frame(width: size.width * 0.75, height: size.height * 0.75)
            .background(
                ZStack {
                    GlassmorphicBackground(
                        material: .popover,
                        blendingMode: .withinWindow,
                        isMainWindow: false
                    )
                    LiquidGlassTheme.primarySurfaceTint
                }
            )
            .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .strokeBorder(LiquidGlassTheme.outerWindowRim, lineWidth: 1.3)
            )
            .shadow(color: .black.opacity(0.45), radius: 32, y: 14)
        }
    }

    // MARK: - 7.3. Màn Hình Danh Sách Đã Mở Khóa, Thanh Tìm Kiếm 4 Chiều & Nút Góc Phải

    private func unlockedVaultListView(in size: CGSize) -> some View {
        ZStack(alignment: .topTrailing) {
            VStack(spacing: 16) {
                // Thanh công cụ phía trên: Thanh tìm kiếm 4 chiều ẩn + Khoảng trống cho nút điều khiển góc phải
                HStack(spacing: 12) {
                    fourDimensionalHiddenSearchBar
                    Spacer(minLength: 160)
                }
                .padding(.horizontal, 24)
                .padding(.top, 22)

                // Danh sách dữ liệu sắp xếp theo mili-giây từ gần nhất đến xa nhất
                ScrollView(.vertical, showsIndicators: false) {
                    LazyVStack(spacing: 10) {
                        ForEach(vm.filteredRecords) { record in
                            vaultDataRowView(record: record)
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.bottom, 26)
                }
            }

            // Nút điều khiển duy nhất góc trên bên phải & 3 tùy chọn vệ tinh khi Hover
            topRightControlCluster
                .padding(.top, 20)
                .padding(.trailing, 24)
        }
    }

    // MARK: - 7.4. Thanh Tìm Kiếm 4 Chiều Ẩn Mặc Định (•••• + Con Mắt Sinh Trắc Học)

    private var fourDimensionalHiddenSearchBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.white.opacity(0.55))

            Group {
                if vm.isSearchTextRevealed {
                    TextField("", text: $vm.searchQuery)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13, weight: .regular, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.96))
                } else {
                    SecureField("", text: $vm.searchQuery)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13, weight: .regular, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.96))
                }
            }

            if !vm.searchQuery.isEmpty {
                Button {
                    vm.searchQuery = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(.white.opacity(0.45))
                }
                .buttonStyle(.plain)
            }

            // Biểu tượng Con Mắt: Bắt buộc xác thực Sinh trắc học mới hiển thị rõ chữ
            Button {
                Task { await vm.toggleSearchVisibilityWithBiometrics() }
            } label: {
                Image(systemName: vm.isSearchTextRevealed ? "eye.fill" : "eye.slash.fill")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(vm.isSearchTextRevealed ? LiquidGlassTheme.iceCyan : .white.opacity(0.55))
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 14)
        .frame(height: 36)
        .background(.ultraThinMaterial, in: Capsule())
        .overlay(
            Capsule()
                .fill(LiquidGlassTheme.elevatedGlassFill)
                .allowsHitTesting(false)
        )
        .overlay(
            Capsule()
                .strokeBorder(LiquidGlassTheme.cardSpecularRim, lineWidth: 1)
                .allowsHitTesting(false)
        )
        .shadow(color: .black.opacity(0.2), radius: 10, y: 4)
    }

    // MARK: - 7.5. Nút Điều Khiển Duy Nhất Góc Trên Bên Phải & 3 Tùy Chọn Vệ Tinh

    private var topRightControlCluster: some View {
        HStack(spacing: 8) {
            if vm.isControlSatelliteExpanded {
                HStack(spacing: 8) {
                    // Vệ tinh 1: Xem & đổi Mã Thành Viên (Quét Sinh trắc học ngay khi ấn)
                    satelliteButton(icon: "key.radiowaves.forward.fill", tint: LiquidGlassTheme.amethystGlow) {
                        Task { await vm.openMemberCodeSatellite() }
                    }

                    // Vệ tinh 2: Xuất (Export) toàn bộ .vault mã hóa
                    satelliteButton(icon: "arrow.down.doc.fill", tint: LiquidGlassTheme.iceCyan) {
                        Task { await vm.openExportSatellite() }
                    }

                    // Vệ tinh 3: Tải lên (Import & Merge) tệp .vault
                    satelliteButton(icon: "arrow.triangle.merge", tint: LiquidGlassTheme.mintRefraction) {
                        Task { await vm.openMergeSatellite() }
                    }
                }
                .transition(.move(edge: .trailing).combined(with: .opacity))
            }

            // Nút chính góc phải: Single Click -> Khóa RAM; Double Click -> sinh trắc rồi tắt cả Nhận + Rút.
            ZStack {
                Circle()
                    .fill(.ultraThinMaterial)
                    .frame(width: 36, height: 36)
                    .overlay(
                        Circle()
                            .fill(LiquidGlassTheme.elevatedGlassFill)
                    )
                    .overlay(
                        Circle()
                            .strokeBorder(
                                vm.isIOEnabled
                                    ? LiquidGlassTheme.bioEmerald.opacity(0.75)
                                    : Color.white.opacity(0.35),
                                lineWidth: 1.2
                            )
                    )
                    .shadow(color: .black.opacity(0.25), radius: 8, y: 4)

                Circle()
                    .fill(vm.isUnlocked ? LiquidGlassTheme.bioEmerald : (vm.isIOEnabled ? Color.orange : Color.white.opacity(0.45)))
                    .frame(width: 10, height: 10)
                    .shadow(color: vm.isUnlocked ? LiquidGlassTheme.bioEmerald.opacity(0.9) : (vm.isIOEnabled ? Color.orange.opacity(0.65) : .clear), radius: 6)
            }
            .contentShape(Circle())
            .onTapGesture {
                vm.handleTopRightControlTap()
            }
        }
        .padding(4)
        .onHover { hovering in
            withAnimation(.spring(response: 0.24, dampingFraction: 0.8)) {
                vm.isControlSatelliteExpanded = hovering
            }
        }
    }

    private func satelliteButton(icon: String, tint: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(.ultraThinMaterial)
                    .frame(width: 32, height: 32)
                    .overlay(
                        Circle()
                            .fill(LiquidGlassTheme.elevatedGlassFill)
                    )
                    .overlay(
                        Circle()
                            .strokeBorder(tint.opacity(0.55), lineWidth: 1)
                    )
                    .shadow(color: tint.opacity(0.2), radius: 6)

                Image(systemName: icon)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(tint)
            }
        }
        .buttonStyle(.plain)
    }

    // MARK: - 7.6. Dòng Dữ Liệu ([Ô Thời Gian ms] + [Ô Nội Dung Ẩn Byte UTF-8]) & Copy Tự Hủy 15s

    private func vaultDataRowView(record: IMNOTextRecord) -> some View {
        let timeTag = "TIME_\(record.id.uuidString)"
        let contentTag = "CONTENT_\(record.id.uuidString)"
        let isTimeCopied = clipboard.activeCopiedTag == timeTag
        let isContentCopied = clipboard.activeCopiedTag == contentTag

        return HStack(spacing: 12) {
            // Ô Thời gian (mili-giây): Click -> Copy chuỗi mili-giây (tự xóa sau 15s)
            Button {
                clipboard.copySecurely(String(record.timestampMs), tag: timeTag)
            } label: {
                HStack(spacing: 8) {
                    Circle()
                        .fill(isTimeCopied ? LiquidGlassTheme.bioEmerald : Color.white.opacity(0.32))
                        .frame(width: 6, height: 6)
                        .shadow(color: isTimeCopied ? LiquidGlassTheme.bioEmerald.opacity(0.8) : .clear, radius: 4)

                    Text("\(record.timestampMs)")
                        .font(.system(size: 13, weight: .medium, design: .monospaced))
                        .foregroundStyle(isTimeCopied ? LiquidGlassTheme.bioEmerald : Color.white.opacity(0.90))

                    if isTimeCopied {
                        Text("\(clipboard.remainingSeconds)s")
                            .font(.system(size: 10, weight: .bold, design: .monospaced))
                            .foregroundStyle(LiquidGlassTheme.bioEmerald)
                    }
                }
                .padding(.horizontal, 14)
                .frame(width: 205, height: 40, alignment: .leading)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .fill(LiquidGlassTheme.elevatedGlassFill)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .strokeBorder(
                            isTimeCopied
                                ? AnyShapeStyle(LiquidGlassTheme.bioEmerald.opacity(0.75))
                                : AnyShapeStyle(LiquidGlassTheme.cardSpecularRim),
                            lineWidth: 1
                        )
                )
            }
            .buttonStyle(.plain)

            // Ô Nội dung ẩn: Chỉ hiện dung lượng Byte của chuỗi UTF-8 (Tuyệt đối không hiện nội dung & Mã Thành Viên)
            Button {
                clipboard.copySecurely(record.rawText, tag: contentTag)
            } label: {
                HStack {
                    Image(systemName: isContentCopied ? "checkmark.shield.fill" : "lock.doc.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(isContentCopied ? LiquidGlassTheme.iceCyan : Color.white.opacity(0.45))

                    Spacer()

                    Text("\(record.byteSize) B")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundStyle(isContentCopied ? LiquidGlassTheme.iceCyan : Color.white.opacity(0.72))

                    if isContentCopied {
                        Text("• \(clipboard.remainingSeconds)s")
                            .font(.system(size: 10, weight: .bold, design: .monospaced))
                            .foregroundStyle(LiquidGlassTheme.iceCyan)
                    }
                }
                .padding(.horizontal, 16)
                .frame(maxWidth: .infinity)
                .frame(height: 40)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .fill(LiquidGlassTheme.elevatedGlassFill)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .strokeBorder(
                            isContentCopied
                                ? AnyShapeStyle(LiquidGlassTheme.iceCyan.opacity(0.75))
                                : AnyShapeStyle(LiquidGlassTheme.cardSpecularRim),
                            lineWidth: 1
                        )
                )
            }
            .buttonStyle(.plain)
        }
        .shadow(color: .black.opacity(0.18), radius: 8, y: 3)
    }

    // MARK: - 7.7. Hộp Thoại Kính Lỏng Cho 3 Tùy Chọn Vệ Tinh (Mã Thành Viên / Siêu Mật Khẩu)

    private func satelliteSecurityModalView(modal: IMNOTextViewModel.ActiveSecurityModal, in size: CGSize) -> some View {
        ZStack {
            Color.black.opacity(0.25)
                .ignoresSafeArea()
                .onTapGesture {
                    vm.activeModal = nil
                }

            HStack(spacing: 12) {
                switch modal {
                case .memberCodeEditor:
                    Image(systemName: "key.fill")
                        .foregroundStyle(LiquidGlassTheme.amethystGlow)
                    TextField("", text: $vm.editableMemberCode)
                        .textFieldStyle(.plain)
                        .font(.system(size: 14, weight: .medium, design: .monospaced))
                        .foregroundStyle(.white)
                    Button {
                        Task { await vm.saveUpdatedMemberCode() }
                    } label: {
                        Circle()
                            .fill(LiquidGlassTheme.amethystGlow)
                            .frame(width: 24, height: 24)
                            .overlay(Circle().strokeBorder(.white.opacity(0.5), lineWidth: 1))
                    }
                    .buttonStyle(.plain)

                case .exportSuperPassword:
                    Image(systemName: "arrow.down.doc.fill")
                        .foregroundStyle(LiquidGlassTheme.iceCyan)
                    SecureField("", text: $vm.superPasswordInput)
                        .textFieldStyle(.plain)
                        .font(.system(size: 14, weight: .medium, design: .monospaced))
                        .foregroundStyle(.white)
                    Button {
                        Task { await vm.executeExportWithSuperPassword() }
                    } label: {
                        Circle()
                            .fill(LiquidGlassTheme.iceCyan)
                            .frame(width: 24, height: 24)
                            .overlay(Circle().strokeBorder(.white.opacity(0.5), lineWidth: 1))
                    }
                    .buttonStyle(.plain)

                case .mergeSuperPassword:
                    Image(systemName: "arrow.triangle.merge")
                        .foregroundStyle(LiquidGlassTheme.mintRefraction)
                    SecureField("", text: $vm.superPasswordInput)
                        .textFieldStyle(.plain)
                        .font(.system(size: 14, weight: .medium, design: .monospaced))
                        .foregroundStyle(.white)
                    Button {
                        Task { await vm.executeMergeWithSuperPassword() }
                    } label: {
                        Circle()
                            .fill(LiquidGlassTheme.mintRefraction)
                            .frame(width: 24, height: 24)
                            .overlay(Circle().strokeBorder(.white.opacity(0.5), lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 18)
            .frame(width: min(size.width * 0.65, 390), height: 48)
            .background(.ultraThinMaterial, in: Capsule())
            .overlay(
                Capsule()
                    .fill(LiquidGlassTheme.elevatedGlassFill)
                    .allowsHitTesting(false)
            )
            .overlay(
                Capsule()
                    .strokeBorder(LiquidGlassTheme.outerWindowRim, lineWidth: 1.2)
                    .allowsHitTesting(false)
            )
            .shadow(color: .black.opacity(0.45), radius: 24, y: 10)
        }
    }
}

// MARK: - 8. ĐIỂM KHỞI CHẠY ỨNG DỤNG NATIVE TRÊN APPLE SILICON (BẬT/TẮT TRỰC TIẾP)

@main
public struct IMNOTextApp: App {
    public init() {}

    public var body: some Scene {
        WindowGroup {
            IMNOTextRootView()
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(
            width: LiquidGlassTheme.goldenWidth,
            height: LiquidGlassTheme.goldenHeight
        )
        .windowResizability(.contentMinSize)
    }
}

