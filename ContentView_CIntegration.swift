import SwiftUI

// 完整替換版本：請把內容貼進 B 既有的 ContentView.swift。
// 請勿把本檔與原 ContentView.swift 同時加入 target，否則會重複定義 View。
// 另外把 SecurityAnalyzer.swift 加入同一個 App target。

struct ContentView: View {
    @StateObject private var collector = EventCollector()
    @State private var events: [SecurityEvent] = []
    @State private var analysisResult: SecurityAnalysisResult?
    @State private var analysisError: String?

    var body: some View {
        NavigationStack {
            // 用 List 讓操作、分析結果與事件一起捲動，方便在手機查看。
            List {
                Section {
                    VStack(spacing: 10) {
                        Image(systemName: "shield.checkered")
                            .font(.system(size: 50))
                            .foregroundStyle(.blue)

                        Text("AI 資安事件監控系統")
                            .font(.title2)
                            .bold()

                        Text("A、B、C 模組整合測試")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }

                Section("事件操作") {
                    Button(role: .destructive) {
                        collector.clearEvents()
                        refreshEvents()
                    } label: {
                        Label("清除所有事件", systemImage: "trash")
                    }
                    .buttonStyle(.borderless)

                    Button {
                        collector.readFile(
                            named: TestFileService.defaultFileName,
                            target: TestFileService.defaultFileName
                        )
                        refreshEvents()
                    } label: {
                        Label("產生測試事件", systemImage: "plus.circle")
                    }
                    .buttonStyle(.borderless)

                    Button {
                        collector.readFile(named: "missing_file", target: "missing_file")
                        refreshEvents()
                    } label: {
                        Label("讀取不存在的檔案", systemImage: "xmark.circle")
                    }
                    .buttonStyle(.borderless)

                    Button {
                        collector.printStoredEvents()
                    } label: {
                        Label("輸出所有事件 JSON", systemImage: "doc.text")
                    }
                    .buttonStyle(.borderless)

                    Button {
                        runAnalysis()
                    } label: {
                        Label("分析已儲存事件", systemImage: "magnifyingglass")
                    }
                    .buttonStyle(.borderless)
                }

                Section("C 模組：規則分析") {
                    Text("同一來源在任意 60 秒內，成功讀取測試用敏感檔案超過 10 次才觸發。")
                        .font(.subheadline)

                    if let analysisError = analysisError {
                        Text(analysisError)
                            .foregroundStyle(.red)
                    } else if let report = analysisResult {
                        LabeledContent("已分析事件", value: "\(report.totalEvents) 筆")

                        if report.findings.isEmpty {
                            Text("未觸發大量讀取規則")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(report.findings) { finding in
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("觸發來源：\(finding.source)")
                                        .font(.headline)
                                    Text(finding.reason)
                                    Text(finding.recommendation)
                                        .foregroundStyle(.secondary)
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    } else {
                        Text("請按「分析已儲存事件」查看結果。")
                            .foregroundStyle(.secondary)
                    }

                    Text("目前是規則分析；尚未連接本地 AI 產生說明。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("事件紀錄：\(events.count) 筆") {
                    ForEach(events, id: \.eventID) { event in
                        NavigationLink {
                            EventDetailView(event: event, analysisResult: analysisResult)
                        } label: {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(event.action.uppercased())
                                    .font(.headline)
                                Text("來源：\(event.source)")
                                Text("目標：\(event.target)")
                                Text("結果：\(event.result)")
                                Text("時間：\(event.timestamp)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(event.isSimulated ? "模擬事件" : "非模擬事件")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                            }
                            .padding(.vertical, 5)
                        }
                    }
                }
            }
            .navigationTitle("Security Monitor")
        }
        .onAppear {
            TestFileService.prepare()
            refreshEvents()
        }
    }

    private func refreshEvents() {
        events = Array(collector.events.reversed())
        // 資料改變後，要求重新分析，避免顯示上一批資料的結果。
        analysisResult = nil
        analysisError = nil
    }

    private func runAnalysis() {
        do {
            // 這裡把整批事件交給 C，而不是只交一筆。
            let report = try SecurityAnalyzer.analyze(events: collector.events)
            analysisResult = report
            analysisError = nil
        } catch {
            analysisResult = nil
            analysisError = error.localizedDescription
        }
    }
}

struct EventDetailView: View {
    let event: SecurityEvent
    let analysisResult: SecurityAnalysisResult?

    private var sourceFindings: [SecurityFinding] {
        analysisResult?.findings.filter { $0.source == event.source } ?? []
    }

    var body: some View {
        Form {
            Section("事件基本資訊") {
                LabeledContent("事件 ID", value: event.eventID)
                LabeledContent("時間", value: event.timestamp)
                LabeledContent("來源", value: event.source)
            }

            Section("事件內容") {
                LabeledContent("動作", value: event.action)
                LabeledContent("目標", value: event.target)
                LabeledContent("結果", value: event.result)
            }

            Section("測試資訊") {
                Text(event.isSimulated ? "模擬事件" : "非模擬事件")
            }

            Section("規則分析：同來源的事件") {
                if let report = analysisResult {
                    Text("分析範圍是已儲存的 \(report.totalEvents) 筆事件；以下顯示同來源的批次結果。")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Text(SecurityAnalyzer.shouldCount(event)
                         ? "這筆事件符合成功讀取敏感目標的計數條件。"
                         : "這筆事件不符合成功讀取敏感目標的計數條件。")

                    if sourceFindings.isEmpty {
                        Text("此來源未觸發大量讀取規則。")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(sourceFindings) { finding in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(finding.reason)
                                Text("規則風險等級：\(finding.risk)")
                                Text("時間範圍：\(finding.windowStart) ～ \(finding.windowEnd)")
                                    .font(.caption)
                                Text(finding.recommendation)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Text("同來源的批次警示，不代表這筆事件單獨構成攻擊。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("請先回主畫面，按「分析已儲存事件」。")
                        .foregroundStyle(.secondary)
                }
            }

            Section("本地 AI 說明") {
                Text("尚未連接本地 AI；以上內容由固定規則產生。")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("事件詳細資訊")
    }
}

#Preview {
    ContentView()
}
