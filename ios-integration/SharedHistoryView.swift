import SwiftData
import SwiftUI
import UIKit

struct SharedHistoryView: View {
    @Environment(\.modelContext) private var modelContext
    @Query private var records: [ScanRecord]
    @State private var key = ""
    @State private var connected = SharedHistoryService.vaultKey != nil
    @State private var consent = false
    @State private var busy = false
    @State private var status = ""

    var body: some View {
        Form {
            Section("السجل المشترك مع موقع حصن") {
                Text("استخدم مفتاح الربط نفسه في الموقع والتطبيق. الربط اختياري، ولا يرفع رسائلك القديمة تلقائيًا.")
                Text(connected ? "هذا الجهاز مرتبط" : "هذا الجهاز غير مرتبط").foregroundStyle(connected ? .green : .secondary)
                SecureField("مفتاح الربط hisn_…", text: $key).textInputAutocapitalization(.never).autocorrectionDisabled()
                Toggle("أوافق على حفظ الدرجة والمؤشرات ومعاينة قصيرة منقحة في Supabase", isOn: $consent)
                Button("ربط هذا الجهاز") {
                    work {
                        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
                        try await SharedHistoryService.verify(key: trimmed)
                        try SharedHistoryService.setVaultKey(trimmed)
                        connected = true
                        key = ""
                        let count = try await SharedHistoryService.pull(into: modelContext)
                        status = "تم الربط. استُورد \(count) فحوصات. الفحوصات الجديدة ستُرفع عند إجرائها."
                    }
                }.disabled(!consent || key.isEmpty || busy)
            }
            if connected {
                Section("المزامنة") {
                    Button("تنزيل الفحوصات من الموقع") { work { let count = try await SharedHistoryService.pull(into: modelContext); status = "استُورد \(count) فحوصات جديدة." } }.disabled(busy)
                    Button("رفع السجل المحلي الحالي") { work { try await SharedHistoryService.upload(records); status = "رُفع السجل الحالي بعد تنقيح المعاينات." } }.disabled(busy || !consent)
                    Button("نسخ مفتاح الربط") { UIPasteboard.general.string = SharedHistoryService.vaultKey; status = "تم النسخ. لا تشارك المفتاح مع أي شخص." }
                    Button("فصل هذا الجهاز", role: .destructive) { do { try SharedHistoryService.setVaultKey(nil); connected = false; status = "فُصل الجهاز دون حذف بيانات السجل." } catch { status = error.localizedDescription } }
                }
            }
            Section("الخصوصية") {
                Text("مفتاح الربط بمثابة كلمة مرور للسجل، ويُحفظ في سلسلة مفاتيح iOS. الأرقام الطويلة تُخفى في المعاينات. لا تُرفع الصور ولا محادثات المساعد إلى السجل.").font(.footnote).foregroundStyle(.secondary)
                Link("فتح موقع حصن", destination: URL(string: "https://hisn-secure-api.onrender.com")!)
                if busy { ProgressView("جارٍ الاتصال…") }
                if !status.isEmpty { Text(status).font(.footnote) }
            }
        }.navigationTitle("ربط الأجهزة")
    }
    private func work(_ action: @escaping @MainActor () async throws -> Void) {
        busy = true
        Task { @MainActor in
            defer { busy = false }
            do { try await action() } catch { status = error.localizedDescription }
        }
    }
}
