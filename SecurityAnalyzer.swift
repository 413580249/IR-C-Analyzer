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
    static let windowSeconds = 60
    static let threshold = 10

    // B 的 SecurityEvent 沒有 sensitive 欄位。
    // 第一版由我們明確指定這個檔案為「測試用敏感目標」。
    // 這是專題的測試設定，不是 iOS 自動判定檔案具有敏感性。
    static let sensitiveTargets: Set<String> = ["test_private_file.txt"]

    private struct TimedEvent {
        let date: Date
        let timestamp: String
    }

    static func shouldCount(_ event: SecurityEvent) -> Bool {
        event.action == "read"
            && event.result == "allowed"
            && sensitiveTargets.contains(event.target)
    }

    static func analyze(events: [SecurityEvent]) throws -> SecurityAnalysisResult {
        var grouped: [String: [TimedEvent]] = [:]

        // B 目前產生的時間不含小數秒；也接受未來含小數秒的時間。
        let standardFormatter = ISO8601DateFormatter()
        standardFormatter.formatOptions = [.withInternetDateTime]
        let fractionalFormatter = ISO8601DateFormatter()
        fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        // 1. 只計入「成功讀取指定敏感目標」，再依來源分組。
        for event in events {
            guard shouldCount(event) else { continue }

            // 與 Python 一樣要求時間帶時區，避免把本地時間誤當成 UTC。
            let hasTimeZone = event.timestamp.range(
                of: "(Z|[+-][0-9]{2}:[0-9]{2})$",
                options: .regularExpression
            ) != nil

            guard hasTimeZone,
                  let date = fractionalFormatter.date(from: event.timestamp)
                    ?? standardFormatter.date(from: event.timestamp) else {
                throw SecurityAnalysisError.invalidTimestamp(
                    eventID: event.eventID,
                    timestamp: event.timestamp
                )
            }

            grouped[event.source, default: []].append(
                TimedEvent(date: date, timestamp: event.timestamp)
            )
        }

        var findings: [SecurityFinding] = []

        // 2. 對每個來源找出「這批事件中，任意 60 秒內」的最大次數。
        // 不是只查看目前時間往前 60 秒；保留你原本 Python 的行為。
        for source in grouped.keys.sorted() {
            guard let sourceEvents = grouped[source] else { continue }
            let timestamps = sourceEvents.sorted { $0.date < $1.date }
            var left = 0
            var maxCount = 0
            var peakStart: String?
            var peakEnd: String?

            for right in timestamps.indices {
                // 剛好相隔 60 秒仍包含在同一時間範圍內。
                while timestamps[right].date.timeIntervalSince(timestamps[left].date)
                    > Double(windowSeconds) {
                    left += 1
                }

                let count = right - left + 1
                if count > maxCount {
                    maxCount = count
                    peakStart = timestamps[left].timestamp
                    peakEnd = timestamps[right].timestamp
                }
            }

            // 3. 保留原規則的 >，而不是 >=：10 次不觸發，11 次才觸發。
            if maxCount > threshold, let start = peakStart, let end = peakEnd {
                findings.append(SecurityFinding(
                    ruleID: "sensitive_read_burst",
                    source: source,
                    risk: "medium",
                    count: maxCount,
                    windowStart: start,
                    windowEnd: end,
                    reason: "同一來源在 \(windowSeconds) 秒內，成功讀取敏感資料 \(maxCount) 次，超過設定門檻 \(threshold) 次。",
                    recommendation: "確認操作是否符合預期，並檢查相關存取紀錄。"
                ))
            }
        }

        // 模擬事件照常參與計算，才能使用 B 的測試按鈕驗證這項規則。
        // status 表示有沒有觸發本規則，不是整個 App 是否安全的判定。
        // 只能分析傳入且仍保留的事件；EventStore 的 50 筆上限仍然適用。
        return SecurityAnalysisResult(
            status: findings.isEmpty ? "no_rule_triggered" : "suspicious",
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
