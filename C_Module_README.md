# C 模組：大量成功讀取測試用敏感檔案

這一版把原本 Python 的規則分析移到 Swift，直接接收 B 的 `[SecurityEvent]`。它沒有呼叫 Python，也還沒有呼叫本地 AI。

## 本次檔案

- `SecurityAnalyzer.swift`：C 的分析模組；新增到既有 iOS App 專案。
- `ContentView_CIntegration.swift`：B 原本畫面的完整替換內容；把內容貼進既有 `ContentView.swift`，不要另加一份同名結構。
- 本說明：接法、規則和驗證步驟。

你原本的 `analyzer.py` 可以保留作為舊版規則參考，但它不能直接分析 B 的原始 JSON，因為欄位和成功結果值不同。

## 為什麼要調整

| 項目 | 原本 Python | B 的資料與本次 Swift 處理 |
|---|---|---|
| 成功讀取 | `result == "success"` | B 用 `"allowed"`，Swift 也用 `"allowed"` |
| 敏感性 | `sensitive == true` | B 沒有此欄位；第一版明確指定 `test_private_file.txt` 為測試用敏感目標 |
| 輸入 | `events.json` | `collector.events`，型別為 `[SecurityEvent]` |
| 輸出 | 寫入 `result.json` | 回傳 `SecurityAnalysisResult`，由 B 顯示；也可以呼叫 `jsonString()` 輸出文字 |

`allowed` 在目前收集器裡代表讀檔成功，`failed` 代表讀檔出錯。`failed` 不直接代表攻擊或被安全機制阻擋。

## 規則保持不變的部分

1. 按來源 `source` 分組。
2. 只計入 `read`、`allowed`、指定敏感目標三項條件都符合的事件。
3. 把時間轉成日期後排序，找出整批資料中任意 60 秒內的最大次數。
4. 恰好相隔 60 秒仍計入同一時間範圍。
5. 判斷是 `次數 > 10`：10 次不觸發，11 次才觸發。
6. 模擬事件參與計算，方便使用現有的測試按鈕驗證。
7. 每個符合門檻的來源最多回傳一筆 finding；欄位沿用原本 `result.json` 的名稱。

時間視窗不是「現在往前 60 秒」。例如昨天某段 60 秒內有 11 次符合事件，只要那些事件仍在傳入資料裡，這次分析仍會回傳那個歷史警示。

敏感目標清單是你們第一版的測試設定，不是 iOS 自動替檔案加上的敏感分類。日後要擴充，再由 A、B、C 一起約定分類或欄位。

## 加入現有專案

1. 保留既有 `ContentView.swift` 的備份。
2. 在 Xcode 的 iOS App 專案新增 `SecurityAnalyzer.swift`，確認它與 `SecurityEvent.swift` 屬於相同 App target。
3. 把 `ContentView_CIntegration.swift` 的完整內容貼入既有 `ContentView.swift`。原本的 `ContentView` 和 `EventDetailView` 應各保留一個定義。
4. 既有 `SecurityEvent.swift`、`EventCollector.swift`、`EventStore.swift`、`TestFileService.swift`、App 入口維持現有版本即可。
5. 若 `SecurityEvent.swift` 原檔第一行真的寫成 `mport Foundation`，先改成 `import Foundation`。
6. 在 Xcode 編譯並執行。

你可以在 Windows 用 VS Code 查看與修改這兩份程式；iOS App 的 Xcode 編譯及執行交由有 Mac 的組員完成。

## 目前如何使用

- 主畫面新增「分析已儲存事件」按鈕。
- 按下後，C 收到整批事件，結果顯示在「C 模組：規則分析」。
- 點開事件可看到同來源的批次結果，以及這筆事件是否符合計數條件。
- 讀取新事件或清除事件後，舊結果會被清掉，請重新按分析。
- 操作與結果放在可捲動的列表中，方便在手機查看。
- 本次不另外寫出 `result.json`；若需要交換 JSON，可使用 `try report.jsonString()`。

最小呼叫方式：

```swift
do {
    let report = try SecurityAnalyzer.analyze(events: collector.events)
    print(try report.jsonString())
} catch {
    print(error.localizedDescription)
}
```

## 先完成這些驗證

每個情境先按「清除所有事件」，避免舊紀錄影響測試。要成功產生事件，測試檔應已由 App 啟動時的 `TestFileService.prepare()` 建立。

| 情境 | 操作 | 預期 |
|---|---|---|
| 空資料 | 清除後直接按分析 | 已分析 0 筆，未觸發 |
| 10 次 | 60 秒內按成功讀取 10 次，再分析 | 未觸發 |
| 11 次 | 60 秒內按成功讀取 11 次，再分析 | `TestApp` 觸發，次數為 11 |
| 失敗不計入 | 60 秒內成功 10 次，加讀取不存在檔案 1 次，再分析 | 總事件 11 筆，仍未觸發 |
| 清除舊結果 | 先觸發，再按清除 | 列表 0 筆，舊分析結果消失 |

## 驗證狀態與範圍

已依本次貼出的 Python 與 A、B 程式逐項對照輸入值、輸出欄位及時間門檻。產製環境沒有 Swift／Xcode，尚未完成 Swift 編譯、iOS 真機或模擬器執行；上表是需要在 Xcode 驗證的預期結果，不是已通過的測試紀錄。

分析只能看到傳入且仍保留的事件。現有 `EventStore` 最多保存 50 筆，60 秒內若有大量其他事件或超過 50 筆，舊資料可能被刪除而漏算。這一版保留既有儲存方式，適合先接通目前的少量測試。

目前 `source` 固定為 `TestApp`，所有事件 `isSimulated` 為 `true`；警示反映的是專題測試規則。未觸發只表示這項規則沒有符合條件。

時間解析使用 Apple 的 `ISO8601DateFormatter`：https://developer.apple.com/documentation/foundation/iso8601dateformatter
