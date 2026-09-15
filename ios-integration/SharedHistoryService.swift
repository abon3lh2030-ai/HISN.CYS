import Foundation
import Security
import SwiftData

enum SharedHistoryService {
    private static let account = "hisn.shared-vault.v1"

    static var vaultKey: String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.abdullahfahad.hisn", kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func setVaultKey(_ key: String?) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.abdullahfahad.hisn", kSecAttrAccount as String: account]
        if let key {
            guard key.range(of: #"^hisn_[a-f0-9]{64}$"#, options: .regularExpression) != nil else { throw SharedHistoryError.invalidKey }
            let update = [kSecValueData as String: Data(key.utf8)]
            let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            if status == errSecItemNotFound {
                var add = query
                add[kSecValueData as String] = Data(key.utf8)
                add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw SharedHistoryError.keychain }
            } else if status != errSecSuccess { throw SharedHistoryError.keychain }
        } else { SecItemDelete(query as CFDictionary) }
    }

    private static func request(method: String, payload: Data? = nil, key: String? = vaultKey) throws -> URLRequest {
        guard let key, let base = HISNBackendConfiguration.baseURL else { throw SharedHistoryError.invalidKey }
        var request = URLRequest(url: base.appending(path: "v1/history"))
        request.httpMethod = method
        request.timeoutInterval = 80
        request.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = payload
        return request
    }

    private static func perform(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw SharedHistoryError.unavailable }
        return data
    }

    static func verify(key: String) async throws {
        _ = try await perform(request(method: "GET", key: key))
    }

    @MainActor static func upload(_ records: [ScanRecord]) async throws {
        guard vaultKey != nil, !records.isEmpty else { return }
        let snapshots = records.map(SharedScanSnapshot.init)
        for start in stride(from: 0, to: snapshots.count, by: 500) {
            let payload = try JSONEncoder().encode(SharedHistoryEnvelope(records: Array(snapshots[start..<min(start + 500, snapshots.count)])))
            _ = try await perform(request(method: "POST", payload: payload))
        }
    }

    @MainActor static func pull(into context: ModelContext) async throws -> Int {
        let data = try await perform(request(method: "GET"))
        let envelope = try JSONDecoder().decode(SharedHistoryEnvelope.self, from: data)
        let local = try context.fetch(FetchDescriptor<ScanRecord>())
        let removed = Set(envelope.deletedIds ?? [])
        for record in local where removed.contains(record.id) { context.delete(record) }
        let existing = Set(local.filter { !removed.contains($0.id) }.map(\.id))
        var added = 0
        for snapshot in envelope.records where !existing.contains(snapshot.id) {
            let result = AnalysisResult(scanType: ScanType(rawValue: snapshot.scanTypeRaw) ?? .message, score: snapshot.riskScore, signals: snapshot.signals, recommendationKeys: snapshot.recommendations, date: snapshot.parsedDate)
            let record = ScanRecord(result: result, contentPreview: snapshot.contentPreview, source: ScanSource(rawValue: snapshot.sourceRaw) ?? .manual)
            record.id = snapshot.id
            context.insert(record)
            added += 1
        }
        try context.save()
        return added
    }

    static func remove(ids: [UUID]) async throws {
        guard vaultKey != nil, !ids.isEmpty else { return }
        for start in stride(from: 0, to: ids.count, by: 500) {
            let data = try JSONEncoder().encode(["ids": Array(ids[start..<min(start + 500, ids.count)]).map(\.uuidString)])
            _ = try await perform(request(method: "DELETE", payload: data))
        }
    }
}

private struct SharedHistoryEnvelope: Codable {
    let records: [SharedScanSnapshot]
    var deletedIds: [UUID]? = nil
}
private struct SharedScanSnapshot: Codable {
    let id: UUID
    let date: String
    let scanTypeRaw: String
    let contentPreview: String
    let riskScore: Int
    let riskLevelRaw: String
    let signals: [RiskSignal]
    let recommendations: [String]
    let sourceRaw: String

    @MainActor init(_ record: ScanRecord) {
        id = record.id
        date = ISO8601DateFormatter().string(from: record.date)
        scanTypeRaw = record.scanTypeRaw
        contentPreview = String(record.contentPreview.prefix(100)).replacingOccurrences(of: #"\d{4,}"#, with: "••••", options: .regularExpression)
        riskScore = record.riskScore
        riskLevelRaw = record.riskLevelRaw
        signals = record.signals
        recommendations = record.recommendations
        sourceRaw = record.sourceRaw
    }
    var parsedDate: Date {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: date) ?? ISO8601DateFormatter().date(from: date) ?? .now
    }
}

enum SharedHistoryError: LocalizedError {
    case invalidKey, keychain, unavailable
    var errorDescription: String? {
        switch self {
        case .invalidKey: "مفتاح الربط غير صالح. انسخه كاملًا من موقع حصن."
        case .keychain: "تعذر حفظ مفتاح الربط بأمان."
        case .unavailable: "تعذر الوصول إلى السجل السحابي. تحقق من اتصالك ثم حاول مجددًا."
        }
    }
}
