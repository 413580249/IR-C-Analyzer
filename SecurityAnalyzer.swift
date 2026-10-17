import Foundation

// C 模組：接收 B 提供的 [SecurityEvent]，回傳整批事件的規則分析結果。
// 請把本檔與既有的 SecurityEvent.swift 加入同一個 iOS App target。
// 第一版只做規則判斷，尚未呼叫 Apple Foundation Models。
//
// 呼叫方式：
// do {
//     let report = try SecurityAnalyzer.analyze(events: collector.events)
//     print(try report.jsonString())
// } catch {
//     print(error.localizedDescription)
// }

struct SecurityAnalysisRule: Codable {
    let windowSeconds: Int
    let threshold: Int
    let comparison: String

    enum CodingKeys: String, CodingKey {
        case windowSeconds = "window_seconds"
        case threshold, comparison
    }
}

struct SecurityFinding: Codable, Identifiable {
    let ruleID: String
    let source: String
    let risk: String
    let count: Int
    let windowStart: String
    let windowEnd: String
    let reason: String
    let recommendation: String

    // 每次分析對同一來源最多產生一筆 finding，方便 B 用 ForEach 顯示。
    var id: String { "\(ruleID):\(source)" }

    enum CodingKeys: String, CodingKey {
        case ruleID = "rule_id"
        case source, risk, count
        case windowStart = "window_start"
        case windowEnd = "window_end"
        case reason, recommendation
    }
}

struct SecurityAnalysisResult: Codable {
    let status: String
    let totalEvents: Int
    let rule: SecurityAnalysisRule
    let findings: [SecurityFinding]

    enum CodingKeys: String, CodingKey {
        case status
        case totalEvents = "total_events"
        case rule, findings
    }

    // 保留你原本 result.json 的欄位名稱，可讓 B 輸出到 Console。
    // 這個方法只轉換成文字；它不會自行建立 result.json 檔案。
    func jsonString() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        return String(decoding: data, as: UTF8.self)
    }
}

enum SecurityAnalysisError: LocalizedError {
    case invalidTimestamp(eventID: String, timestamp: String)

    var errorDescription: String? {
        switch self {
        case let .invalidTimestamp(eventID, timestamp):
            return "事件 \(eventID) 的時間格式錯誤：\(timestamp)。請使用含時區的 ISO 8601 格式，例如 2026-10-11T18:00:00+08:00。"
        }
    }
}


enum SecurityAnalyzer {
    // MARK: - 規則設定

    static let windowSeconds = 60
    static let threshold = 10

    // 測試用敏感檔案清單
    static let sensitiveTargets: Set<String> = [
        "test_private_file.txt"
    ]

    // 新增兩條規則的門檻
    static let multiFileThreshold = 5
    static let failedReadThreshold = 5

    private struct TimedEvent {
        let event: SecurityEvent
        let date: Date
    }

    private struct Peak {
        let count: Int
        let start: String
        let end: String
    }

    // MARK: - 時間解析

    private static func parseDate(
        _ event: SecurityEvent
    ) throws -> Date {

        let hasTimeZone = event.timestamp.range(
            of: "(Z|[+-][0-9]{2}:[0-9]{2})$",
            options: .regularExpression
        ) != nil

        let standard = ISO8601DateFormatter()
        standard.formatOptions = [.withInternetDateTime]

        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [
            .withInternetDateTime,
            .withFractionalSeconds
        ]

        guard hasTimeZone,
              let date = fractional.date(from: event.timestamp)
                ?? standard.date(from: event.timestamp) else {
            throw SecurityAnalysisError.invalidTimestamp(
                eventID: event.eventID,
                timestamp: event.timestamp
            )
        }

        return date
    }

    // MARK: - 原始敏感資料規則

    static func shouldCount(_ event: SecurityEvent) -> Bool {
        event.action == "read"
            && event.result == "allowed"
            && sensitiveTargets.contains(event.target)
    }

    // MARK: - 60 秒滑動視窗

    private static func findPeak(
        _ events: [TimedEvent],
        score: (ArraySlice<TimedEvent>) -> Int
    ) -> Peak? {

        guard !events.isEmpty else { return nil }

        let sorted = events.sorted { $0.date < $1.date }

        var left = 0
        var best: Peak?

        for right in sorted.indices {

            while sorted[right].date
                .timeIntervalSince(sorted[left].date)
                > Double(windowSeconds) {
                left += 1
            }

            let window = sorted[left...right]
            let count = score(window)

            if count > (best?.count ?? 0) {
                best = Peak(
                    count: count,
                    start: sorted[left].event.timestamp,
                    end: sorted[right].event.timestamp
                )
            }
        }

        return best
    }

    // MARK: - 分析入口

    static func analyze(
        events: [SecurityEvent]
    ) throws -> SecurityAnalysisResult {

        var grouped: [String: [TimedEvent]] = [:]

        for event in events {
            let date = try parseDate(event)

            grouped[event.source, default: []].append(
                TimedEvent(event: event, date: date)
            )
        }

        var findings: [SecurityFinding] = []

        for source in grouped.keys.sorted() {

            guard let sourceEvents = grouped[source] else {
                continue
            }

            // 規則 1：敏感資料大量讀取
            let sensitiveReads = sourceEvents.filter {
                shouldCount($0.event)
            }

            if let peak = findPeak(
                sensitiveReads,
                score: { $0.count }
            ), peak.count > threshold {

                findings.append(SecurityFinding(
                    ruleID: "sensitive_read_burst",
                    source: source,
                    risk: "medium",
                    count: peak.count,
                    windowStart: peak.start,
                    windowEnd: peak.end,
                    reason: "60 秒內成功讀取敏感資料 \(peak.count) 次，超過門檻 \(threshold) 次。",
                    recommendation: "確認敏感資料存取是否符合預期。"
                ))
            }

            // 規則 2：短時間讀取多個不同檔案
            let successfulReads = sourceEvents.filter {
                $0.event.action == "read"
                    && $0.event.result == "allowed"
            }

            if let peak = findPeak(
                successfulReads,
                score: { window in
                    Set(window.map { $0.event.target }).count
                }
            ), peak.count >= multiFileThreshold {

                findings.append(SecurityFinding(
                    ruleID: "multi_file_read",
                    source: source,
                    risk: "medium",
                    count: peak.count,
                    windowStart: peak.start,
                    windowEnd: peak.end,
                    reason: "60 秒內成功讀取 \(peak.count) 個不同檔案，達到多檔案偵測門檻。",
                    recommendation: "檢查是否存在非預期的批次檔案存取。"
                ))
            }

            // 規則 3：短時間大量讀取失敗
            let failedReads = sourceEvents.filter {
                $0.event.action == "read"
                    && $0.event.result == "failed"
            }

            if let peak = findPeak(
                failedReads,
                score: { $0.count }
            ), peak.count >= failedReadThreshold {

                findings.append(SecurityFinding(
                    ruleID: "repeated_read_failure",
                    source: source,
                    risk: "medium",
                    count: peak.count,
                    windowStart: peak.start,
                    windowEnd: peak.end,
                    reason: "60 秒內讀取失敗 \(peak.count) 次，達到連續失敗偵測門檻。",
                    recommendation: "檢查檔案是否存在、操作權限及失敗原因。"
                ))
            }
        }

        // 保留第一版 JSON 介面供 B 使用。
        // rule 欄位仍描述原本的敏感讀取規則；
        // 新規則透過 findings.rule_id 區分。
        return SecurityAnalysisResult(
            status: findings.isEmpty
                ? "no_rule_triggered"
                : "suspicious",
            totalEvents: events.count,
            rule: SecurityAnalysisRule(
                windowSeconds: windowSeconds,
                threshold: threshold,
                comparison: "greater_than"
            ),
            findings: findings
        )
    }
}
