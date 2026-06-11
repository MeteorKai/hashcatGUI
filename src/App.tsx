import { Component, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open, save } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  AlertTriangle,
  Bot,
  Activity,
  Copy,
  Cpu,
  Download,
  FileClock,
  FileText,
  FolderOpen,
  Hash,
  HelpCircle,
  History,
  Library,
  Play,
  RefreshCcw,
  Settings,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  Thermometer,
  Trash2,
  Upload,
  Zap,
  X,
} from "lucide-react";
import { AboutDialog } from "./components/AboutDialog";
import { Notice } from "./components/Notice";
import { SakuraMascot3D } from "./components/SakuraMascot3D";
import { ZH_TEXT_OVERRIDES } from "./i18n/zhText";
import { explainError } from "./lib/errorExplain";
import "./App.css";

type AttackMode = 0 | 3 | 6 | 7 | 9;
type TabKey = "config" | "resources" | "queue" | "history" | "logs";
type Language = "zh" | "en";

type HashcatInfo = {
  available: boolean;
  version?: string | null;
  hashcatPath?: string | null;
  resourceRoot?: string | null;
  backendInfo?: Record<string, unknown> | null;
  backendRaw?: string;
  error?: string | null;
};

type HashcatPathStatus = {
  customInstallDir?: string | null;
  effectiveDir?: string | null;
  effectiveExe?: string | null;
  usingCustom: boolean;
  available: boolean;
};

type HashModeInfo = {
  mode: number;
  name: string;
  category: string;
  keywords: string[];
};

type ResourceInfo = {
  kind: "rule" | "mask" | "charset" | "dictionary";
  name: string;
  path: string;
  size: number;
};

type UserDictionary = {
  name: string;
  path: string;
  size: number;
  addedAt: string;
};

type CustomResource = {
  id: string;
  type: "mask" | "template" | "dictionary" | "charset";
  name: string;
  description: string;
  mask?: string;
  prefixMask?: string;
  suffixMask?: string;
  charsetSlot?: "1" | "2" | "3" | "4";
  charsetValue?: string;
  path?: string;
  size?: number;
  createdAt: string;
};

type AttackConfig = {
  hashMode: string;
  attackMode: AttackMode;
  hashText?: string | null;
  hashFile?: string | null;
  dictionaryPath?: string | null;
  mask?: string | null;
  maskFile?: string | null;
  templatePrefixMask?: string | null;
  templateSuffixMask?: string | null;
  increment?: boolean | null;
  incrementMin?: number | null;
  incrementMax?: number | null;
  customCharset1?: string | null;
  customCharset2?: string | null;
  customCharset3?: string | null;
  customCharset4?: string | null;
  rulePaths: string[];
  taskName?: string | null;
  optimizedKernel?: boolean | null;
  workloadProfile?: number | null;
  deviceTypes: string[];
  deviceIds?: string | null;
};

type QueueStatus = "pending" | "running" | "finished" | "failed" | "skipped";

type QueueItem = {
  id: string;
  name: string;
  config: AttackConfig;
  status: QueueStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  taskId?: string;
  error?: string;
};

type StatusPayload = {
  taskId: string;
  data: Record<string, unknown>;
};

type TaskManifest = {
  taskId: string;
  taskName: string;
  createdAt: string;
  status: string;
  exitCode?: number | null;
  exitReason?: string | null;
  canRestore: boolean;
  commandPreview: string;
  config: AttackConfig;
  paths: {
    taskDir: string;
    outfilePath: string;
    potfilePath?: string;
    logPath: string;
  };
};

type StartResponse = {
  taskId: string;
  commandPreview: string;
  outfilePath: string;
};

type LogPayload = {
  taskId: string;
  stream: string;
  line: string;
};

type ExitPayload = {
  taskId: string;
  code?: number | null;
  reason: string;
};

type ResultsResponse = {
  path: string;
  content: string;
};

type FilePreviewResponse = {
  path: string;
  content: string;
  truncated: boolean;
  lineCount: number;
  fileSize: number;
  previewLimit: number;
};

type DictionaryDedupeResponse = {
  path: string;
  originalLines: number;
  uniqueLines: number;
  removedLines: number;
  size: number;
};

type AiSettings = {
  baseUrl: string;
  apiKey: string;
  model: string;
};

type AiModelsResponse = {
  models: string[];
};

type AiHashConsultConfig = {
  hashMode: string;
  attackMode: AttackMode;
  hashText?: string;
  hashFile?: string;
  mask?: string;
  dictionaryPath?: string;
  rulePaths: string[];
  question: string;
};

type AiSuggestedConfig = Partial<{
  hashMode: string;
  attackMode: AttackMode;
  hashText: string;
  hashFile: string;
  mask: string;
  dictionaryPath: string;
  rulePaths: string[];
}>;

type AiAnalysisEvent = {
  taskId: string;
  text?: string;
  error?: string;
};

type HashcatUpdateInfo = {
  currentVersion?: string | null;
  latestVersion: string;
  latestName: string;
  assetName: string;
  assetUrl: string;
  releaseUrl: string;
  upToDate: boolean;
};

type HashcatUpdateEvent = {
  phase: string;
  line: string;
};

type HashcatUpdateFinishEvent = {
  ok: boolean;
  info?: HashcatUpdateInfo | null;
  error?: string | null;
};

type MaskEstimate = {
  candidates?: bigint;
  estimatedSeconds?: number;
  speedHps?: number;
  warning?: string;
  error?: string;
};

type HashModeSuggestion = {
  mode: string;
  name: string;
  reason: string;
  confidence: "high" | "medium" | "low";
};

type IdentifyResponse = {
  raw: string;
  modes: HashModeInfo[];
};

type DialogErrorBoundaryProps = {
  fallback: string;
  children: ReactNode;
};

type DialogErrorBoundaryState = {
  error: string;
};

class DialogErrorBoundary extends Component<DialogErrorBoundaryProps, DialogErrorBoundaryState> {
  state: DialogErrorBoundaryState = { error: "" };

  static getDerivedStateFromError(error: unknown) {
    return { error: String(error) };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="modal-backdrop" role="presentation">
          <section className="settings-modal" role="dialog" aria-modal="true">
            <div className="settings-test warn">{this.props.fallback}: {this.state.error}</div>
          </section>
        </div>
      );
    }
    return this.props.children;
  }
}

const TABS: Array<{ key: TabKey; icon: ReactNode }> = [
  { key: "config", icon: <Terminal size={18} /> },
  { key: "resources", icon: <Library size={18} /> },
  { key: "queue", icon: <FileClock size={18} /> },
  { key: "history", icon: <History size={18} /> },
  { key: "logs", icon: <FileText size={18} /> },
];

const LANGUAGE_STORAGE_KEY = "hashcatgui-language";
const CUSTOM_RESOURCES_STORAGE_KEY = "hashcatgui-custom-resources";
const FIRST_GUIDE_STORAGE_KEY = "hashcatgui-first-guide-dismissed";
const TASK_QUEUE_STORAGE_KEY = "hashcatgui-task-queue";

const UI_TEXT = {
  zh: {
    appReady: "Ready",
    appMissing: "Missing",
    taskHealth: "任务",
    taskBusy: "努力中",
    taskIdle: "休息中",
    settingsTitle: "设置",
    helpTitle: "帮助",
    helpSubtitle: "攻击教程与 AI 咨询",
    attackTutorials: "攻击方式速查",
    aiHashAdvisor: "询问 AI",
    helpDictionaryTitle: "字典攻击 -a 0",
    helpDictionaryBody: "用字典里的候选密码逐个尝试，适合已知密码可能来自常见词、泄露密码、姓名、手机号片段等场景。可以叠加规则文件 -r 批量变形。",
    helpMaskTitle: "掩码攻击 -a 3",
    helpMaskBody: "用 ?d、?l、?u、?s 等字符集枚举固定结构。例如 2015?d?d?d?d 会尝试 20150000 到 20159999。",
    helpHybridTitle: "混合攻击 -a 6 / -a 7",
    helpHybridBody: "-a 6 是 字典词 + 掩码，例如 admin?d?d；-a 7 是 掩码 + 字典词，例如 ?d?dadmin。",
    helpTemplateTitle: "模板候选",
    helpTemplateBody: "适合 ?d?d + 字典词 + ?d?d 这类中间夹字典词的结构。工具会先生成临时候选字典，再用 -a 0 破解。",
    helpRuleTitle: "规则攻击",
    helpRuleBody: "规则只配合字典攻击使用，用来把字典词自动变形，例如首字母大写、末尾追加数字、替换字符等。",
    aiQuestion: "你的问题",
    aiQuestionPlaceholder: "例如：这个 hash 看起来像什么类型？现在的 mask 是否合理？下一步应该怎么跑？",
    useCurrentConfig: "已带入当前任务配置",
    chooseHashTxt: "选择 hash.txt",
    askAi: "询问 AI",
    aiThinking: "AI 分析中",
    aiAnswer: "AI 回答",
    aiStartedInWindow: "AI 分析已在独立窗口后台运行，可以最小化或继续操作主界面。",
    applyAiSuggestion: "应用到任务",
    noAiSuggestion: "AI 结果里没有可应用的任务配置。",
    aiSuggestionApplied: "已根据 AI 建议填充任务配置。",
    refresh: "刷新",
    hashcatUpdate: "Hashcat 更新",
    hashcatUpdateHint: "检查 GitHub 官方发布，安装到工具目录 resources/hashcat-current；内置 hashcat 保留为备用。",
    checkUpdate: "检查更新",
    installUpdate: "更新 hashcat",
    updateCurrent: "当前版本",
    updateLatest: "最新版本",
    updatePackage: "发布包",
    updateUpToDate: "已经是最新版本",
    updateAvailable: "发现新版本",
    updateNotChecked: "尚未检查",
    updateRunning: "更新中",
    updateLog: "更新回显",
    openRelease: "打开发布页",
    tabConfig: "任务",
    tabResources: "资源",
    tabHistory: "历史",
    tabLogs: "日志",
    attackConfigTitle: "任务配置",
    dictionary: "字典",
    mask: "掩码",
    hybridDictMask: "字典+掩码",
    hybridMaskDict: "掩码+字典",
    templateAttack: "模板候选",
    prefixMask: "前缀掩码",
    suffixMask: "后缀掩码",
    templateHint: "生成：前缀掩码 + 字典词 + 后缀掩码，再用 -a 0 破解。",
    templatePreviewWord: "字典词",
    start: "启动",
    stop: "停止",
    taskName: "任务名",
    taskNamePlaceholder: "可选，便于历史中识别",
    hashMode: "Hash 模式",
    hashModePlaceholder: "例如 0 / 1000 / 1400",
    workload: "负载",
    performanceMode: "性能模式",
    deviceControl: "设备选择与性能控制",
    deviceControlHint: "选择 CPU/GPU、指定设备编号，并实时观察速度、温度、利用率和显存。",
    scanDevices: "扫描设备",
    deviceTypes: "设备类型",
    cpuDevice: "CPU",
    gpuDevice: "GPU",
    deviceIds: "设备编号",
    deviceIdsPlaceholder: "例如 1 或 1,2；留空为 hashcat 自动选择",
    noDeviceStatus: "任务运行后显示实时设备状态。",
    backendDeviceInfo: "后端设备信息",
    backendRawSummary: "原始摘要",
    deviceIdLabel: "设备编号",
    deviceMemory: "内存",
    deviceBackend: "后端",
    deviceVendor: "厂商",
    deviceProcessor: "处理器",
    deviceScanReady: "点击扫描设备查看 hashcat 后端信息。",
    deviceScanning: "正在扫描设备...",
    deviceScanDone: "设备扫描完成。",
    deviceScanFailed: "设备扫描失败。",
    deviceAuto: "自动",
    speed: "速度",
    temperature: "温度",
    utilization: "利用率",
    memory: "显存",
    performanceLowDesc: "轻量巡航",
    performanceDefaultDesc: "均衡调度",
    performanceHighDesc: "高速模式",
    performanceExtremeDesc: "满载冲刺",
    workloadLow: "1 低",
    workloadDefault: "2 默认",
    workloadHigh: "3 高",
    workloadExtreme: "4 极限",
    hashModePicker: "Hash 类型选择器",
    hashModeSearch: "搜索 md5、ntlm、1000、sha256...",
    noHashModes: "没有匹配的 Hash 类型",
    hashInput: "Hash 输入",
    hashInputHint: "粘贴文本或拖入 hash 文件",
    hashInputPlaceholder: "每行一个 hash；留空则使用右侧 Hash 文件",
    hashRecommendTitle: "Hash 类型推荐",
    hashRecommendHint: "根据样本格式推测，仅供参考，不能保证准确。",
    hashRecommendEmpty: "粘贴 hash 后显示可能的 -m 模式。",
    hashOfficialIdentify: "官方识别",
    hashIdentifyRunning: "识别中",
    hashIdentifyEmpty: "hashcat 官方识别暂无结果。",
    applyRecommendation: "应用",
    confidenceHigh: "较高",
    confidenceMedium: "中等",
    confidenceLow: "较低",
    hashFile: "Hash 文件",
    notSelected: "未选择",
    dictionaryFile: "字典文件",
    rulesFile: "规则文件",
    add: "添加",
    noRules: "无规则",
    help: "帮助",
    file: "文件",
    maskPlaceholder: "?l?l?l?l?d?d",
    maskHelp: "?l 小写，?u 大写，?d 数字，?s 符号，?a 全集。普通字符会原样参与破解。",
    maskEstimate: "掩码预估",
    maskCandidates: "候选空间",
    maskEstimatedTime: "预计耗时",
    maskEstimateSpeed: "参考速度",
    maskEstimateUnknown: "等待运行速度",
    maskEstimateUnsupported: "包含自定义字符集或未知 token，暂不能准确估算。",
    maskEstimatePartial: "该模式只估算掩码部分，字典行数未计入。",
    longTaskConfirm: "这个任务预计需要 {time}，候选空间 {candidates}。确认启动吗？",
    taskMayRunLong: "可能较久",
    incrementMask: "递增掩码",
    incrementRange: "长度范围",
    incrementMin: "最小",
    incrementMax: "最大",
    commandPreview: "命令预览",
    liveTerminal: "实时终端输出",
    running: "运行中",
    waitingStart: "等待启动",
    waitingTask: "等待任务",
    crackFound: "发现破解结果",
    resultReport: "结果报告",
    resultCount: "条",
    resultEmptyForTask: "当前任务还没有写入 cracked.txt。",
    resultEmpty: "启动任务后，破解结果会显示在这里。",
    moreResults: "还有 {count} 条结果，可到历史页查看完整内容。",
    copyResults: "复制结果",
    openDir: "打开目录",
    resourcesTitle: "资源库",
    importDictionary: "导入字典",
    resourceSearch: "搜索 rockyou.txt、rules、masks...",
    customResources: "自定义资源",
    saveCurrentMask: "保存当前掩码",
    saveCurrentTemplate: "保存当前模板",
    customName: "名称",
    customDescription: "说明",
    customMaskName: "自定义掩码",
    customTemplateName: "模板候选方案",
    customDictionaryName: "自定义字典",
    customCharsetName: "自定义字符集",
    customCharset: "自定义字符集",
    charsetSlot: "位置",
    charsetValue: "字符集内容",
    charsetHint: "mask 中可使用 ?1 ?2 ?3 ?4，例如 ?1?1?1?1。",
    manageCustomResources: "管理自定义资源",
    addMaskResource: "新增掩码",
    addTemplateResource: "新增模板",
    addCharsetResource: "新增字符集",
    importCustomDictionary: "导入字典副本",
    edit: "编辑",
    content: "内容",
    noCustomResources: "暂无自定义资源。点击管理按钮新增掩码、模板候选方案或导入字典。",
    delete: "删除",
    builtinResources: "内置资源",
    userDictionaries: "用户字典",
    recommendedResources: "当前模式推荐",
    resourceRuleHelp: "规则文件：只用于字典攻击，会批量变形字典词，例如追加数字、大小写变化。",
    resourceMaskHelp: "掩码文件：用于掩码攻击，里面保存常见 mask 模板。",
    resourceCharsetHelp: "字符集文件：给高级掩码使用，自定义 ?1/?2 这类字符范围。",
    resourceDictionaryHelp: "字典文件：用于字典、Hybrid 和模板候选攻击，作为中间词或基础词表。",
    resourceRecommendedBecause: "适合当前攻击模式",
    resourceNoRecommendations: "当前模式暂无特别推荐资源。",
    preview: "预览",
    resourcePreviewTitle: "资源预览",
    previewTruncated: "仅显示前 {count} 行，文件较大未完全加载。",
    previewEmpty: "文件为空或没有可显示内容。",
    copiedDictionaryOnly: "用户字典为只读预览；如需修改，请在自定义资源中导入字典副本。",
    largeDictionaryAppendOnly: "该字典较大，当前只载入预览内容。为避免误覆盖整本字典，本次只能追加新词条。",
    appendDictionaryLines: "追加词条",
    appendDictionaryPlaceholder: "每行一个新候选词，会追加到字典末尾。",
    use: "使用",
    noUserDictionaries: "暂无用户字典",
    historyTitle: "历史任务",
    load: "载入",
    rerun: "重跑",
    restore: "恢复",
    noHistory: "暂无历史任务",
    copy: "复制",
    export: "导出",
    directory: "目录",
    noResults: "暂无结果",
    selectHistoryForResult: "选择一个历史任务查看结果",
    logsTitle: "任务日志",
    selectTask: "选择任务",
    aiAnalyzing: "分析中",
    aiAnalyze: "AI 分析",
    noLogs: "暂无日志",
    selectTaskForLog: "选择一个任务查看日志",
    aiSettingsTitle: "AI 设置",
    language: "界面语言",
    chinese: "中文",
    english: "English",
    model: "模型",
    availableModels: "可用模型",
    chooseModel: "选择模型",
    connectionOk: "连接成功，获取到 {count} 个模型",
    testing: "测试中",
    testConnection: "测试连接",
    cancel: "取消",
    save: "保存",
    aiAnalysisTitle: "日志分析",
    helpAiAnalysisTitle: "帮助分析",
    noTaskSelected: "未选择任务",
    minimize: "最小化",
    aiConnecting: "正在连接 AI，分析内容会在这里实时出现...",
    noAiContent: "暂无分析内容",
    errorLabel: "错误",
    aiStreaming: "流式分析中，主界面可继续使用",
    aiFinished: "分析结束",
    terminalWaiting: "等待 hashcat 输出",
    stopRequested: "已请求检查点停止",
    resultsCopied: "结果已复制",
    resultsExported: "结果已导出",
    deleteConfirm: "删除该任务及本地结果文件？",
    taskFinished: "任务结束：{status}",
    sideRunningTitle: "努力计算中",
    sideIdleTitle: "正在休息中",
    sideRunningText: "别急，结果在路上",
    sideIdleText: "准备好开跑啦",
  },
  en: {
    appReady: "Ready",
    appMissing: "Missing",
    taskHealth: "Task",
    taskBusy: "Working",
    taskIdle: "Idle",
    settingsTitle: "Settings",
    helpTitle: "Help",
    helpSubtitle: "Attack guides and AI advisor",
    attackTutorials: "Attack Quick Guide",
    aiHashAdvisor: "Ask AI",
    helpDictionaryTitle: "Dictionary Attack -a 0",
    helpDictionaryBody: "Tries candidates from a wordlist. Useful when passwords may come from common words, leaks, names, phone fragments, or targeted lists. Rule files can mutate words in bulk.",
    helpMaskTitle: "Mask Attack -a 3",
    helpMaskBody: "Enumerates a fixed pattern with charsets like ?d, ?l, ?u, ?s. Example: 2015?d?d?d?d tries 20150000 through 20159999.",
    helpHybridTitle: "Hybrid Attack -a 6 / -a 7",
    helpHybridBody: "-a 6 is wordlist + mask, such as admin?d?d. -a 7 is mask + wordlist, such as ?d?dadmin.",
    helpTemplateTitle: "Template Candidates",
    helpTemplateBody: "For patterns like ?d?d + dictionary word + ?d?d. The app generates a temporary candidate dictionary, then runs hashcat with -a 0.",
    helpRuleTitle: "Rule Attack",
    helpRuleBody: "Rules work with dictionary attacks and mutate words automatically, such as capitalization, appending digits, or character replacement.",
    aiQuestion: "Question",
    aiQuestionPlaceholder: "Example: What hash type does this look like? Is my mask reasonable? What should I try next?",
    useCurrentConfig: "Current task config included",
    chooseHashTxt: "Choose hash.txt",
    askAi: "Ask AI",
    aiThinking: "AI thinking",
    aiAnswer: "AI Answer",
    aiStartedInWindow: "AI analysis is running in a separate window. You can minimize it or keep using the main UI.",
    applyAiSuggestion: "Apply to Task",
    noAiSuggestion: "No applicable task config was found in the AI result.",
    aiSuggestionApplied: "Task config filled from AI suggestion.",
    refresh: "Refresh",
    hashcatUpdate: "Hashcat Update",
    hashcatUpdateHint: "Check GitHub releases, install to resources/hashcat-current in the tool folder, and keep the embedded hashcat as fallback.",
    checkUpdate: "Check Update",
    installUpdate: "Update hashcat",
    updateCurrent: "Current",
    updateLatest: "Latest",
    updatePackage: "Package",
    updateUpToDate: "Already latest",
    updateAvailable: "Update available",
    updateNotChecked: "Not checked",
    updateRunning: "Updating",
    updateLog: "Update Log",
    openRelease: "Open Release",
    tabConfig: "Task",
    tabResources: "Resources",
    tabHistory: "History",
    tabLogs: "Logs",
    attackConfigTitle: "Task Config",
    dictionary: "Dictionary",
    mask: "Mask",
    hybridDictMask: "Dict+Mask",
    hybridMaskDict: "Mask+Dict",
    templateAttack: "Template",
    prefixMask: "Prefix Mask",
    suffixMask: "Suffix Mask",
    templateHint: "Generate prefix mask + dictionary word + suffix mask, then crack with -a 0.",
    templatePreviewWord: "word",
    start: "Start",
    stop: "Stop",
    taskName: "Task Name",
    taskNamePlaceholder: "Optional, useful in history",
    hashMode: "Hash Mode",
    hashModePlaceholder: "e.g. 0 / 1000 / 1400",
    workload: "Workload",
    performanceMode: "Performance Mode",
    deviceControl: "Device & Performance Control",
    deviceControlHint: "Choose CPU/GPU, pin device IDs, and watch speed, temperature, utilization, and VRAM.",
    scanDevices: "Scan Devices",
    deviceTypes: "Device Types",
    cpuDevice: "CPU",
    gpuDevice: "GPU",
    deviceIds: "Device IDs",
    deviceIdsPlaceholder: "e.g. 1 or 1,2. Leave empty for hashcat auto selection",
    noDeviceStatus: "Live device status appears after a task starts.",
    backendDeviceInfo: "Backend Device Info",
    backendRawSummary: "Raw Summary",
    deviceIdLabel: "Device ID",
    deviceMemory: "Memory",
    deviceBackend: "Backend",
    deviceVendor: "Vendor",
    deviceProcessor: "Processor",
    deviceScanReady: "Click Scan Devices to inspect hashcat backend info.",
    deviceScanning: "Scanning devices...",
    deviceScanDone: "Device scan complete.",
    deviceScanFailed: "Device scan failed.",
    deviceAuto: "Auto",
    speed: "Speed",
    temperature: "Temp",
    utilization: "Utilization",
    memory: "VRAM",
    performanceLowDesc: "Light cruise",
    performanceDefaultDesc: "Balanced",
    performanceHighDesc: "High speed",
    performanceExtremeDesc: "Full sprint",
    workloadLow: "1 Low",
    workloadDefault: "2 Default",
    workloadHigh: "3 High",
    workloadExtreme: "4 Extreme",
    hashModePicker: "Hash Type Picker",
    hashModeSearch: "Search md5, ntlm, 1000, sha256...",
    noHashModes: "No matching hash types",
    hashInput: "Hash Input",
    hashInputHint: "Paste text or drop a hash file",
    hashInputPlaceholder: "One hash per line; leave empty to use the hash file",
    hashRecommendTitle: "Hash Type Suggestions",
    hashRecommendHint: "Guessed from sample format only. Not guaranteed.",
    hashRecommendEmpty: "Paste a hash to see possible -m modes.",
    hashOfficialIdentify: "Official Identify",
    hashIdentifyRunning: "Identifying",
    hashIdentifyEmpty: "No official hashcat identify result.",
    applyRecommendation: "Apply",
    confidenceHigh: "High",
    confidenceMedium: "Medium",
    confidenceLow: "Low",
    hashFile: "Hash File",
    notSelected: "Not selected",
    dictionaryFile: "Dictionary File",
    rulesFile: "Rule Files",
    add: "Add",
    noRules: "No rules",
    help: "Help",
    file: "File",
    maskPlaceholder: "?l?l?l?l?d?d",
    maskHelp: "?l lowercase, ?u uppercase, ?d digit, ?s symbol, ?a all printable. Literal characters are used as-is.",
    maskEstimate: "Mask Estimate",
    maskCandidates: "Candidates",
    maskEstimatedTime: "Estimated Time",
    maskEstimateSpeed: "Reference Speed",
    maskEstimateUnknown: "Waiting for runtime speed",
    maskEstimateUnsupported: "Contains custom charsets or unknown tokens, so it cannot be estimated accurately yet.",
    maskEstimatePartial: "This mode estimates the mask portion only; dictionary line count is not included.",
    longTaskConfirm: "This task is estimated to take {time} with {candidates} candidates. Start anyway?",
    taskMayRunLong: "May run long",
    incrementMask: "Increment Mask",
    incrementRange: "Length Range",
    incrementMin: "Min",
    incrementMax: "Max",
    commandPreview: "Command Preview",
    liveTerminal: "Live Terminal Output",
    running: "Running",
    waitingStart: "Waiting to start",
    waitingTask: "Waiting for task",
    crackFound: "Cracked Result Found",
    resultReport: "Result Report",
    resultCount: "results",
    resultEmptyForTask: "This task has not written cracked.txt yet.",
    resultEmpty: "Results will appear here after a task starts.",
    moreResults: "{count} more results. Open History to view all.",
    copyResults: "Copy Results",
    openDir: "Open Folder",
    resourcesTitle: "Resource Library",
    importDictionary: "Import Dictionary",
    resourceSearch: "Search rockyou.txt, rules, masks...",
    customResources: "Custom Resources",
    saveCurrentMask: "Save Current Mask",
    saveCurrentTemplate: "Save Current Template",
    customName: "Name",
    customDescription: "Description",
    customMaskName: "Custom Mask",
    customTemplateName: "Template Candidate Plan",
    customDictionaryName: "Custom Dictionary",
    customCharsetName: "Custom Charset",
    customCharset: "Custom Charset",
    charsetSlot: "Slot",
    charsetValue: "Charset",
    charsetHint: "Use ?1 ?2 ?3 ?4 in masks, such as ?1?1?1?1.",
    manageCustomResources: "Manage Custom Resources",
    addMaskResource: "Add Mask",
    addTemplateResource: "Add Template",
    addCharsetResource: "Add Charset",
    importCustomDictionary: "Import Dictionary Copy",
    edit: "Edit",
    content: "Content",
    noCustomResources: "No custom resources yet. Open the manager to add masks, template plans, or dictionaries.",
    delete: "Delete",
    builtinResources: "Built-in Resources",
    userDictionaries: "User Dictionaries",
    recommendedResources: "Recommended",
    resourceRuleHelp: "Rule file: dictionary attack only. Mutates words, such as appending digits or changing case.",
    resourceMaskHelp: "Mask file: used by mask attack. Stores common mask templates.",
    resourceCharsetHelp: "Charset file: advanced mask usage for custom ?1/?2 character ranges.",
    resourceDictionaryHelp: "Dictionary file: used by dictionary, Hybrid, and template attacks as base words.",
    resourceRecommendedBecause: "Recommended for current mode",
    resourceNoRecommendations: "No specific recommendations for this mode.",
    preview: "Preview",
    resourcePreviewTitle: "Resource Preview",
    previewTruncated: "Showing the first {count} lines only. The file was not fully loaded.",
    previewEmpty: "The file is empty or has no displayable content.",
    copiedDictionaryOnly: "User dictionaries are read-only here. Import a dictionary copy in Custom Resources to edit it.",
    largeDictionaryAppendOnly: "This dictionary is large, so only a preview was loaded. To avoid overwriting the full file, this edit can only append new lines.",
    appendDictionaryLines: "Append Lines",
    appendDictionaryPlaceholder: "One candidate per line. New lines will be appended to the dictionary.",
    use: "Use",
    noUserDictionaries: "No user dictionaries",
    historyTitle: "Task History",
    load: "Load",
    rerun: "Rerun",
    restore: "Restore",
    noHistory: "No task history",
    copy: "Copy",
    export: "Export",
    directory: "Folder",
    noResults: "No results",
    selectHistoryForResult: "Select a history task to view results",
    logsTitle: "Task Logs",
    selectTask: "Select task",
    aiAnalyzing: "Analyzing",
    aiAnalyze: "AI Analyze",
    noLogs: "No logs",
    selectTaskForLog: "Select a task to view logs",
    aiSettingsTitle: "AI Settings",
    language: "Interface Language",
    chinese: "中文",
    english: "English",
    model: "Model",
    availableModels: "Available Models",
    chooseModel: "Choose model",
    connectionOk: "Connected. Found {count} models",
    testing: "Testing",
    testConnection: "Test Connection",
    cancel: "Cancel",
    save: "Save",
    aiAnalysisTitle: "Log Analysis",
    helpAiAnalysisTitle: "Help Analysis",
    noTaskSelected: "No task selected",
    minimize: "Minimize",
    aiConnecting: "Connecting to AI. Analysis will stream here...",
    noAiContent: "No analysis yet",
    errorLabel: "Error",
    aiStreaming: "Streaming analysis. You can keep using the main window",
    aiFinished: "Analysis finished",
    terminalWaiting: "Waiting for hashcat output",
    stopRequested: "Checkpoint stop requested",
    resultsCopied: "Results copied",
    resultsExported: "Results exported",
    deleteConfirm: "Delete this task and local result files?",
    taskFinished: "Task finished: {status}",
    sideRunningTitle: "Calculating",
    sideIdleTitle: "Resting",
    sideRunningText: "Results are on the way",
    sideIdleText: "Ready when you are",
  },
} as const;

type UiText = Record<keyof typeof UI_TEXT.zh, string>;

const ZH_TEXT: UiText = {
  ...UI_TEXT.en,
  ...ZH_TEXT_OVERRIDES,
};

const STATUS_TEXT: Record<Language, Record<string, string>> = {
  zh: {
    cracked: "已破解",
    exhausted: "已耗尽",
    aborted: "已中止",
    checkpoint: "检查点中止",
    finished: "已完成",
    running: "运行中",
    error: "错误",
  },
  en: {
    cracked: "Cracked",
    exhausted: "Exhausted",
    aborted: "Aborted",
    checkpoint: "Checkpoint",
    finished: "Finished",
    running: "Running",
    error: "Error",
  },
};

export default function App() {
  const [language, setLanguage] = useState<Language>(() => getInitialLanguage());
  const [activeTab, setActiveTab] = useState<TabKey>("config");
  const [info, setInfo] = useState<HashcatInfo | null>(null);
  const [hashModes, setHashModes] = useState<HashModeInfo[]>([]);
  const [resources, setResources] = useState<ResourceInfo[]>([]);
  const [userDictionaries, setUserDictionaries] = useState<UserDictionary[]>([]);
  const [customResources, setCustomResources] = useState<CustomResource[]>(() => loadCustomResources());
  const [queueItems, setQueueItems] = useState<QueueItem[]>(() => loadQueueItems());
  const [queuePaused, setQueuePaused] = useState(true);
  const [tasks, setTasks] = useState<TaskManifest[]>([]);
  const [selectedTaskId, setSelectedTaskId] = useState("");
  const [taskId, setTaskId] = useState("");
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<LogPayload[]>([]);
  const [taskLog, setTaskLog] = useState<ResultsResponse | null>(null);
  const [taskLogTaskId, setTaskLogTaskId] = useState("");
  const [results, setResults] = useState<ResultsResponse | null>(null);
  const [resultsTaskId, setResultsTaskId] = useState("");
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [guideDismissed, setGuideDismissed] = useState(() => localStorage.getItem(FIRST_GUIDE_STORAGE_KEY) === "1");
  const [updateOpen, setUpdateOpen] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<HashcatUpdateInfo | null>(null);
  const [updateLogs, setUpdateLogs] = useState<HashcatUpdateEvent[]>([]);
  const [updateRunning, setUpdateRunning] = useState(false);
  const [hashcatPathStatus, setHashcatPathStatus] = useState<HashcatPathStatus | null>(null);

  const [taskName, setTaskName] = useState("");
  const [hashMode, setHashMode] = useState("0");
  const [modeQuery, setModeQuery] = useState("");
  const [attackMode, setAttackMode] = useState<AttackMode>(0);
  const [hashText, setHashText] = useState("");
  const [hashFile, setHashFile] = useState("");
  const [dictionaryPath, setDictionaryPath] = useState("");
  const [mask, setMask] = useState("");
  const [maskFile, setMaskFile] = useState("");
  const [templatePrefixMask, setTemplatePrefixMask] = useState("");
  const [templateSuffixMask, setTemplateSuffixMask] = useState("");
  const [increment, setIncrement] = useState(false);
  const [incrementMin, setIncrementMin] = useState("");
  const [incrementMax, setIncrementMax] = useState("");
  const [customCharset1, setCustomCharset1] = useState("");
  const [customCharset2, setCustomCharset2] = useState("");
  const [customCharset3, setCustomCharset3] = useState("");
  const [customCharset4, setCustomCharset4] = useState("");
  const [rulePaths, setRulePaths] = useState<string[]>([]);
  const [optimizedKernel, setOptimizedKernel] = useState(true);
  const [workloadProfile, setWorkloadProfile] = useState(3);
  const [deviceTypes, setDeviceTypes] = useState<string[]>(["2"]);
  const [deviceIds, setDeviceIds] = useState("");
  const [latestStatus, setLatestStatus] = useState<Record<string, unknown> | null>(null);
  const [lastSpeedHps, setLastSpeedHps] = useState<number | undefined>(undefined);
  const [deviceScanState, setDeviceScanState] = useState<"idle" | "scanning" | "done" | "error">("idle");
  const [backendCommand, setBackendCommand] = useState("");
  const [resourceQuery, setResourceQuery] = useState("");
  const [identifyModes, setIdentifyModes] = useState<HashModeInfo[]>([]);
  const [identifyRaw, setIdentifyRaw] = useState("");
  const [identifyRunning, setIdentifyRunning] = useState(false);

  const [aiSettings, setAiSettings] = useState<AiSettings>({
    baseUrl: "https://api.openai.com/v1",
    apiKey: "",
    model: "gpt-4o-mini",
  });
  const [aiOpen, setAiOpen] = useState(false);
  const [aiMinimized, setAiMinimized] = useState(false);
  const [aiRunningTaskIds, setAiRunningTaskIds] = useState<string[]>([]);
  const [aiTaskId, setAiTaskId] = useState("");
  const [aiTextByTask, setAiTextByTask] = useState<Record<string, string>>({});
  const [aiErrorByTask, setAiErrorByTask] = useState<Record<string, string>>({});

  const selectedTask = tasks.find((task) => task.taskId === selectedTaskId);
  const selectedResults = selectedTaskId && resultsTaskId === selectedTaskId ? results : null;
  const selectedTaskLog = taskLogTaskId === selectedTaskId ? taskLog : null;
  const aiText = normalizeAiAnalysisText(aiTextByTask[aiTaskId] ?? "").trimStart();
  const aiError = aiErrorByTask[aiTaskId] ?? "";
  const aiWindowRunning = aiRunningTaskIds.includes(aiTaskId);
  const queueStartingRef = useRef(false);
  const text = useMemo<UiText>(() => language === "zh" ? ZH_TEXT : UI_TEXT.en, [language]);
  const filteredModes = useMemo(() => filterModes(hashModes, modeQuery), [hashModes, modeQuery]);
  const filteredResources = useMemo(
    () => resources.filter((item) => `${item.kind} ${item.name}`.toLowerCase().includes(resourceQuery.toLowerCase())),
    [resources, resourceQuery],
  );
  const hashSuggestions = useMemo(
    () => recommendHashModes(hashText, hashModes),
    [hashText, hashModes],
  );
  const preview = backendCommand || buildPreview({
    attackMode,
    dictionaryPath,
    hashFile,
    hashMode,
    hashText,
    mask,
    maskFile,
    templatePrefixMask,
    templateSuffixMask,
    increment,
    incrementMin: numberOrNull(incrementMin),
    incrementMax: numberOrNull(incrementMax),
    customCharset1,
    customCharset2,
    customCharset3,
    customCharset4,
    optimizedKernel,
    rulePaths,
    workloadProfile,
    deviceTypes,
    deviceIds,
  });
  const maskEstimate = useMemo(
    () => estimateAttackMask({
      attackMode,
      mask,
      templatePrefixMask,
      templateSuffixMask,
      customCharsets: [customCharset1, customCharset2, customCharset3, customCharset4],
      speedHps: lastSpeedHps,
      text,
    }),
    [attackMode, mask, templatePrefixMask, templateSuffixMask, customCharset1, customCharset2, customCharset3, customCharset4, lastSpeedHps, text],
  );

  useEffect(() => {
    void refreshStartup();
  }, []);

  useEffect(() => {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
    document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  }, [language]);

  useEffect(() => {
    localStorage.setItem(CUSTOM_RESOURCES_STORAGE_KEY, JSON.stringify(customResources));
  }, [customResources]);

  useEffect(() => {
    localStorage.setItem(TASK_QUEUE_STORAGE_KEY, JSON.stringify(queueItems));
  }, [queueItems]);

  useEffect(() => {
    if (queuePaused || running || queueStartingRef.current) return;
    const next = queueItems.find((item) => item.status === "pending");
    if (next) void startQueuedItem(next);
  }, [queueItems, queuePaused, running]);

  useEffect(() => {
    const unlisteners: UnlistenFn[] = [];
    let unlistenDrop: UnlistenFn | undefined;
    let disposed = false;

    function register<T>(eventName: string, handler: (event: Event<T>) => void | Promise<void>) {
      listen<T>(eventName, handler).then((unlisten) => {
        if (disposed) {
          unlisten();
          return;
        }
        unlisteners.push(unlisten);
      }).catch((err) => setError(String(err)));
    }

    register<LogPayload>("hashcat-log", (event) => {
      setLogs((current) => [...current.slice(-400), event.payload]);
    });

    register<StatusPayload>("hashcat-status", (event) => {
      if (event.payload.taskId === taskId || event.payload.taskId === selectedTaskId) {
        setLatestStatus(event.payload.data);
        const speed = extractStatusSpeed(event.payload.data);
        if (speed) setLastSpeedHps(speed);
      }
    });

    register<ExitPayload>("hashcat-exit", async (event) => {
      setRunning(false);
      setTaskId("");
      setSelectedTaskId(event.payload.taskId);
      const queueStatus: QueueStatus = event.payload.reason === "error" || event.payload.reason === "backend-error" || event.payload.reason === "runtime" ? "failed" : "finished";
      setQueueItems((current) => current.map((item) => item.taskId === event.payload.taskId && item.status === "running"
        ? { ...item, status: queueStatus, finishedAt: new Date().toISOString() }
        : item));
      await Promise.all([refreshTasks(), readResultsFor(event.payload.taskId), readTaskLogFor(event.payload.taskId)]);
      showToast(text.taskFinished.replace("{status}", statusLabel(event.payload.reason, language)));
    });

    register<AiAnalysisEvent>("ai-analysis-start", (event) => {
      setAiTaskId(event.payload.taskId);
      setAiTextByTask((current) => ({ ...current, [event.payload.taskId]: "" }));
      setAiErrorByTask((current) => ({ ...current, [event.payload.taskId]: "" }));
      setAiRunningTaskIds((current) =>
        current.includes(event.payload.taskId) ? current : [...current, event.payload.taskId],
      );
      setAiOpen(true);
      setAiMinimized(false);
    });

    register<AiAnalysisEvent>("ai-analysis-delta", (event) => {
      setAiTaskId(event.payload.taskId);
      setAiTextByTask((current) => ({
        ...current,
        [event.payload.taskId]: appendAiDelta(current[event.payload.taskId] ?? "", event.payload.text ?? ""),
      }));
    });

    register<AiAnalysisEvent>("ai-analysis-error", (event) => {
      setAiTaskId(event.payload.taskId);
      setAiErrorByTask((current) => ({ ...current, [event.payload.taskId]: event.payload.error ?? `${text.aiAnalyze} failed` }));
      setAiRunningTaskIds((current) => current.filter((taskId) => taskId !== event.payload.taskId));
      setAiOpen(true);
      setAiMinimized(false);
    });

    register<AiAnalysisEvent>("ai-analysis-finish", (event) => {
      setAiRunningTaskIds((current) => current.filter((taskId) => taskId !== event.payload.taskId));
    });

    register<HashcatUpdateEvent>("hashcat-update-log", (event) => {
      setUpdateLogs((current) => mergeUpdateLog(current, event.payload));
    });

    register<HashcatUpdateFinishEvent>("hashcat-update-finish", async (event) => {
      setUpdateRunning(false);
      if (!event.payload.ok) {
        setError(event.payload.error ?? "hashcat update failed");
        return;
      }
      if (event.payload.info) setUpdateInfo(event.payload.info);
      await Promise.all([refreshInfo(), refreshHashcatPathStatus()]);
      showToast(text.hashcatUpdate);
    });
    getCurrentWebview().onDragDropEvent((event) => {
      if (event.payload.type !== "drop") return;
      for (const path of event.payload.paths) applyDroppedPath(path);
    }).then((unlisten) => {
      if (disposed) {
        unlisten();
        return;
      }
      unlistenDrop = unlisten;
    });

    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
      unlistenDrop?.();
    };
  }, [attackMode, dictionaryPath, selectedTaskId, language, text]);

  async function refreshStartup() {
    setResults(null);
    setResultsTaskId("");
    setTaskLog(null);
    setTaskLogTaskId("");
    await refreshTasks();
    setSelectedTaskId("");
    await Promise.all([refreshInfo(), refreshResources(), refreshAiSettings(), refreshHashcatPathStatus()]);
    window.setTimeout(() => void refreshHashModes(), 300);
  }

  async function refreshCurrentData() {
    const nextTasks = await refreshTasks();
    const nextSelectedTaskId = selectedTaskId || nextTasks[0]?.taskId || "";
    await Promise.all([refreshInfo(), refreshResources(), refreshAiSettings(), refreshHashcatPathStatus()]);
    if (nextSelectedTaskId) await Promise.all([readResultsFor(nextSelectedTaskId), readTaskLogFor(nextSelectedTaskId)]);
    window.setTimeout(() => void refreshHashModes(), 300);
  }

  async function refreshInfo() {
    try {
      const next = await invoke<HashcatInfo>("get_hashcat_info", { includeBackendInfo: false });
      setInfo(next);
      if (next.error) setError(next.error);
    } catch (err) {
      setError(String(err));
    }
  }

  async function refreshDeviceInfo() {
    setDeviceScanState("scanning");
    try {
      const next = await invoke<HashcatInfo>("get_hashcat_info", { includeBackendInfo: true });
      setInfo(next);
      if (next.error) setError(next.error);
      setDeviceScanState(next.error ? "error" : "done");
    } catch (err) {
      setError(String(err));
      setDeviceScanState("error");
    }
  }

  async function checkHashcatUpdate() {
    setUpdateLogs((current) => mergeUpdateLog(current, { phase: "check", line: text.checkUpdate }));
    try {
      const next = await invoke<HashcatUpdateInfo>("check_hashcat_update");
      setUpdateInfo(next);
      setUpdateLogs((current) => mergeUpdateLog(current, {
        phase: "check",
        line: `${text.updateCurrent}: ${next.currentVersion ?? "-"} / ${text.updateLatest}: ${next.latestVersion}`,
      }));
    } catch (err) {
      setError(String(err));
      setUpdateLogs((current) => mergeUpdateLog(current, { phase: "error", line: String(err) }));
    }
  }

  async function installHashcatUpdate() {
    setUpdateRunning(true);
    setUpdateLogs([{ phase: "start", line: text.updateRunning }]);
    try {
      await invoke("install_hashcat_update");
    } catch (err) {
      setUpdateRunning(false);
      setError(String(err));
      setUpdateLogs((current) => mergeUpdateLog(current, { phase: "error", line: String(err) }));
    }
  }

  async function refreshHashModes() {
    try {
      setHashModes(await invoke<HashModeInfo[]>("get_hash_modes"));
    } catch (err) {
      setError(String(err));
    }
  }

  async function identifyHash() {
    setIdentifyRunning(true);
    setIdentifyRaw("");
    setIdentifyModes([]);
    try {
      const response = await invoke<IdentifyResponse>("identify_hash", { hashText, hashFile });
      setIdentifyRaw(response.raw);
      setIdentifyModes(response.modes);
    } catch (err) {
      setError(String(err));
    } finally {
      setIdentifyRunning(false);
    }
  }

  async function refreshResources() {
    try {
      const [builtin, user] = await Promise.all([
        invoke<ResourceInfo[]>("list_builtin_resources"),
        invoke<UserDictionary[]>("list_user_dictionaries"),
      ]);
      setResources(builtin);
      setUserDictionaries(user);
    } catch (err) {
      setError(String(err));
    }
  }

  async function refreshTasks() {
    try {
      const next = await invoke<TaskManifest[]>("list_tasks");
      setTasks(next);
      return next;
    } catch (err) {
      setError(String(err));
      return [];
    }
  }

  async function refreshAiSettings() {
    try {
      setAiSettings(await invoke<AiSettings>("get_ai_settings"));
    } catch (err) {
      setError(String(err));
    }
  }

  async function refreshHashcatPathStatus() {
    try {
      setHashcatPathStatus(await invoke<HashcatPathStatus>("get_hashcat_path_status"));
    } catch (err) {
      setError(String(err));
    }
  }

  async function chooseHashFile() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      setHashFile(selected);
      setHashText("");
    }
  }

  async function chooseDictionary(remember = true) {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") await useDictionary(selected, remember);
  }

  async function chooseRules() {
    const selected = await open({ multiple: true, directory: false });
    const paths = Array.isArray(selected) ? selected : typeof selected === "string" ? [selected] : [];
    setRulePaths((current) => [...new Set([...current, ...paths])]);
    if (paths.length) setAttackMode(0);
  }

  async function chooseMaskFile() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      if (attackMode === 0) setAttackMode(3);
      setMaskFile(selected);
    }
  }

  async function useDictionary(path: string, remember: boolean) {
    if (attackMode === 3) setAttackMode(0);
    setDictionaryPath(path);
    if (!remember) return;
    try {
      setUserDictionaries(await invoke<UserDictionary[]>("add_user_dictionary", { path }));
    } catch (err) {
      setError(String(err));
    }
  }

  async function removeDictionary(path: string) {
    try {
      setUserDictionaries(await invoke<UserDictionary[]>("remove_user_dictionary", { path }));
      if (dictionaryPath === path) setDictionaryPath("");
    } catch (err) {
      setError(String(err));
    }
  }

  async function startAttack() {
    setError("");
    setLogs([]);
    setLatestStatus(null);
    setBackendCommand("");
    if (shouldConfirmLongTask(maskEstimate)) {
      const confirmed = window.confirm(text.longTaskConfirm
        .replace("{time}", formatDuration(maskEstimate?.estimatedSeconds ?? 0))
        .replace("{candidates}", maskEstimate?.candidates ? formatBigInt(maskEstimate.candidates) : "-"));
      if (!confirmed) return;
    }
    try {
      const response = await invoke<StartResponse>("start_attack", { config: currentConfig() });
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      setActiveTab("logs");
      await refreshTasks();
    } catch (err) {
      setError(String(err));
    }
  }

  async function stopAttack() {
    if (!taskId) return;
    try {
      await invoke("stop_attack", { taskId });
      showToast(text.stopRequested);
    } catch (err) {
      setError(String(err));
    }
  }

  async function rerunTask(id: string) {
    try {
      const response = await invoke<StartResponse>("rerun_task", { taskId: id });
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      setActiveTab("logs");
      await refreshTasks();
    } catch (err) {
      setError(String(err));
    }
  }

  async function restoreTask(id: string) {
    try {
      const response = await invoke<StartResponse>("restore_attack", { taskId: id });
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      setActiveTab("logs");
      await refreshTasks();
    } catch (err) {
      setError(String(err));
    }
  }

  async function deleteTask(id: string) {
    if (!window.confirm(text.deleteConfirm)) return;
    try {
      const next = await invoke<TaskManifest[]>("delete_task", { taskId: id });
      setTasks(next);
      const nextSelectedId = next[0]?.taskId ?? "";
      setSelectedTaskId(nextSelectedId);
      setResults(null);
      setResultsTaskId("");
      setTaskLog(null);
      setTaskLogTaskId("");
      if (nextSelectedId) await Promise.all([readResultsFor(nextSelectedId), readTaskLogFor(nextSelectedId)]);
    } catch (err) {
      setError(String(err));
    }
  }

  async function readResultsFor(id = selectedTaskId) {
    if (!id) return;
    try {
      setResults(null);
      setResultsTaskId(id);
      setResults(await invoke<ResultsResponse>("read_results", { taskId: id }));
      setSelectedTaskId(id);
    } catch (err) {
      setError(String(err));
    }
  }

  async function readTaskLogFor(id = selectedTaskId) {
    if (!id) return;
    try {
      setTaskLog(null);
      setTaskLogTaskId(id);
      setTaskLog(await invoke<ResultsResponse>("read_task_log", { taskId: id }));
      setSelectedTaskId(id);
    } catch (err) {
      setError(String(err));
    }
  }

  async function analyzeLog(id = selectedTaskId) {
    if (!id) return;
    setAiTaskId(id);
    setAiTextByTask((current) => ({ ...current, [id]: "" }));
    setAiErrorByTask((current) => ({ ...current, [id]: "" }));
    setAiRunningTaskIds((current) => (current.includes(id) ? current : [...current, id]));
    setAiOpen(true);
    setAiMinimized(false);
    try {
      await invoke("start_ai_log_analysis", { taskId: id });
    } catch (err) {
      setAiErrorByTask((current) => ({ ...current, [id]: String(err) }));
      setAiRunningTaskIds((current) => current.filter((taskId) => taskId !== id));
    }
  }

  async function startHelpAi(config: AiHashConsultConfig) {
    const localId = `help-ai-${Date.now()}`;
    setAiTaskId(localId);
    setAiTextByTask((current) => ({ ...current, [localId]: "" }));
    setAiErrorByTask((current) => ({ ...current, [localId]: "" }));
    setAiRunningTaskIds((current) => (current.includes(localId) ? current : [...current, localId]));
    setAiOpen(true);
    setAiMinimized(false);
    try {
      const backendId = await invoke<string>("start_ai_hash_consult", { config });
      setAiTaskId(backendId);
      setAiTextByTask((current) => ({ ...current, [backendId]: current[localId] ?? "" }));
      setAiErrorByTask((current) => ({ ...current, [backendId]: current[localId] ?? "" }));
      setAiRunningTaskIds((current) => [...current.filter((id) => id !== localId), backendId]);
    } catch (err) {
      setAiErrorByTask((current) => ({ ...current, [localId]: String(err) }));
      setAiRunningTaskIds((current) => current.filter((id) => id !== localId));
    }
  }

  async function copyResults() {
    if (!selectedResults?.content) return;
    await writeText(selectedResults.content);
    showToast(text.resultsCopied);
  }

  async function exportResults() {
    if (!selectedTaskId) return;
    const destination = await save({ defaultPath: `${selectedTaskId}-cracked.txt` });
    if (typeof destination !== "string") return;
    try {
      await invoke("export_results", { taskId: selectedTaskId, destination });
      showToast(text.resultsExported);
    } catch (err) {
      setError(String(err));
    }
  }

  async function openTaskDir() {
    if (!selectedTaskId) return;
    try {
      await invoke("open_task_dir", { taskId: selectedTaskId });
    } catch (err) {
      setError(String(err));
    }
  }

  async function deleteCustomResource(resource: CustomResource) {
    if (resource.type === "dictionary" && resource.path) {
      try {
        await invoke("delete_custom_dictionary_file", { path: resource.path });
      } catch {
        // Remove the library entry even if its copied file was already deleted.
      }
    }
    setCustomResources((current) => current.filter((item) => item.id !== resource.id));
  }

  function loadTask(task: TaskManifest) {
    setTaskName(task.taskName);
    setHashMode(task.config.hashMode);
    setAttackMode(task.config.attackMode);
    setHashText(task.config.hashText ?? "");
    setHashFile(task.config.hashFile ?? "");
    setDictionaryPath(task.config.dictionaryPath ?? "");
    setMask(task.config.mask ?? "");
    setMaskFile(task.config.maskFile ?? "");
    setTemplatePrefixMask(task.config.templatePrefixMask ?? "");
    setTemplateSuffixMask(task.config.templateSuffixMask ?? "");
    setIncrement(Boolean(task.config.increment));
    setIncrementMin(task.config.incrementMin ? String(task.config.incrementMin) : "");
    setIncrementMax(task.config.incrementMax ? String(task.config.incrementMax) : "");
    setCustomCharset1(task.config.customCharset1 ?? "");
    setCustomCharset2(task.config.customCharset2 ?? "");
    setCustomCharset3(task.config.customCharset3 ?? "");
    setCustomCharset4(task.config.customCharset4 ?? "");
    setRulePaths(task.config.rulePaths ?? []);
    setOptimizedKernel(Boolean(task.config.optimizedKernel));
    setWorkloadProfile(task.config.workloadProfile ?? 3);
    setDeviceTypes(task.config.deviceTypes?.length ? task.config.deviceTypes : ["2"]);
    setDeviceIds(task.config.deviceIds ?? "");
    setActiveTab("config");
  }

  function currentConfig(): AttackConfig {
    return {
      attackMode,
      dictionaryPath,
      hashFile,
      hashMode,
      hashText,
      mask,
      maskFile,
      templatePrefixMask,
      templateSuffixMask,
      increment,
      incrementMin: numberOrNull(incrementMin),
      incrementMax: numberOrNull(incrementMax),
      customCharset1,
      customCharset2,
      customCharset3,
      customCharset4,
      optimizedKernel,
      rulePaths,
      taskName,
      workloadProfile,
      deviceTypes,
      deviceIds,
    };
  }

  function addCurrentTaskToQueue() {
    const config = currentConfig();
    const createdAt = new Date().toISOString();
    const name = taskName.trim() || `${attackModeLabel(attackMode, text)} -m ${hashMode}`;
    setQueueItems((current) => [
      ...current,
      {
        id: `queue-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        name,
        config: structuredClone(config),
        status: "pending",
        createdAt,
      },
    ]);
    setActiveTab("queue");
    showToast(queueText(language).added);
  }

  function startQueue() {
    setQueueItems((current) => current.map((item) => item.status === "failed" ? { ...item, status: "pending", error: undefined } : item));
    setQueuePaused(false);
    showToast(queueText(language).resumed);
  }

  function pauseQueue() {
    setQueuePaused(true);
    showToast(queueText(language).paused);
  }

  function skipQueuedTask(id: string) {
    setQueueItems((current) => current.map((item) => item.id === id && item.status === "pending"
      ? { ...item, status: "skipped", finishedAt: new Date().toISOString() }
      : item));
  }

  function removeQueuedTask(id: string) {
    setQueueItems((current) => current.filter((item) => !(item.id === id && item.status !== "running")));
  }

  function clearCompletedQueueItems() {
    setQueueItems((current) => current.filter((item) => item.status === "pending" || item.status === "running"));
    showToast(queueText(language).clearDone);
  }

  async function startQueuedItem(item: QueueItem) {
    if (queueStartingRef.current) return;
    queueStartingRef.current = true;
    setQueueItems((current) => current.map((entry) => entry.id === item.id
      ? { ...entry, status: "running", startedAt: new Date().toISOString(), error: undefined }
      : entry));
    setLogs([]);
    setLatestStatus(null);
    setBackendCommand("");
    try {
      const response = await invoke<StartResponse>("start_attack", { config: item.config });
      setQueueItems((current) => current.map((entry) => entry.id === item.id ? { ...entry, taskId: response.taskId } : entry));
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      setActiveTab("logs");
      await refreshTasks();
    } catch (err) {
      setQueueItems((current) => current.map((entry) => entry.id === item.id
        ? { ...entry, status: "failed", finishedAt: new Date().toISOString(), error: String(err) }
        : entry));
      setError(String(err));
    } finally {
      queueStartingRef.current = false;
    }
  }

  function applyAiSuggestionFromText(content: string) {
    const suggestion = parseAiSuggestedConfig(content);
    if (!suggestion) {
      showToast(text.noAiSuggestion);
      return;
    }

    if (typeof suggestion.hashMode === "string") setHashMode(suggestion.hashMode);
    if (typeof suggestion.attackMode === "number") setAttackMode(suggestion.attackMode);
    if (typeof suggestion.hashText === "string") setHashText(suggestion.hashText);
    if (typeof suggestion.hashFile === "string") setHashFile(suggestion.hashFile);
    if (typeof suggestion.mask === "string") setMask(suggestion.mask);
    if (typeof suggestion.dictionaryPath === "string") setDictionaryPath(suggestion.dictionaryPath);
    if (Array.isArray(suggestion.rulePaths)) setRulePaths(suggestion.rulePaths);
    setActiveTab("config");
    showToast(text.aiSuggestionApplied);
  }

  function applyDroppedPath(path: string) {
    const lower = path.toLowerCase();
    if (lower.endsWith(".rule")) {
      setRulePaths((current) => current.includes(path) ? current : [...current, path]);
      setAttackMode(0);
    } else if (lower.endsWith(".hcmask")) {
      setMaskFile(path);
      if (attackMode === 0) setAttackMode(3);
    } else if (lower.endsWith(".dict") || lower.endsWith(".lst")) {
      void useDictionary(path, true);
    } else {
      setHashFile(path);
      setHashText("");
    }
  }

  function showToast(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(""), 1600);
  }

  function dismissFirstGuide() {
    localStorage.setItem(FIRST_GUIDE_STORAGE_KEY, "1");
    setGuideDismissed(true);
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><Hash size={22} /></div>
          <div>
            <p className="eyebrow">hashcatGUI</p>
            <h1>hashcatGUI</h1>
          </div>
        </div>
        <div className="health-strip">
          <HealthItem icon={<ShieldCheck size={15} />} label="Hashcat" value={info?.available ? info.version ?? text.appReady : text.appMissing} tone={info?.available ? "ok" : "warn"} />
          <HealthItem icon={<Cpu size={15} />} label={text.taskHealth} value={running ? text.taskBusy : text.taskIdle} tone={running ? "warn" : "ok"} />
          <button className="topbar-help-button" type="button" onClick={() => setHelpOpen(true)}><HelpCircle size={16} />{text.helpTitle}</button>
          <button className="icon-button" type="button" onClick={() => setSettingsOpen(true)} title={text.settingsTitle}><Settings size={17} /></button>
          <button className="icon-button" type="button" onClick={() => void refreshCurrentData()} title={text.refresh}><RefreshCcw size={17} /></button>
        </div>
      </header>

      {info && !info.available && !guideDismissed && (
        <section className="first-guide">
          <div>
            <strong>{language === "zh" ? "首次启动提示" : "First Start Guide"}</strong>
            <span>
              {language === "zh"
                ? "当前未检测到 hashcat。打开设置里的 Hashcat 更新，可下载安装到工具目录；也可以使用完整版便携包自带的 hashcat。"
                : "hashcat was not detected. Open Hashcat Update in Settings to install it into the tool folder, or use the full portable package with bundled hashcat."}
            </span>
          </div>
          <button className="ghost-button" type="button" onClick={() => {
            setSettingsOpen(false);
            setUpdateOpen(true);
            if (!updateInfo) void checkHashcatUpdate();
          }}>{text.hashcatUpdate}</button>
          <button className="icon-button" type="button" onClick={dismissFirstGuide} aria-label={language === "zh" ? "关闭引导" : "Close guide"}><X size={14} /></button>
        </section>
      )}
      {error && <Notice message={error} details={explainError(error, language)} onClose={() => setError("")} />}
      {toast && <div className="toast">{toast}</div>}
      {settingsOpen && (
        <DialogErrorBoundary fallback={text.settingsTitle}>
          <AiSettingsDialog language={language} setLanguage={setLanguage} text={text} settings={aiSettings} onClose={() => setSettingsOpen(false)} onOpenUpdate={() => {
            setSettingsOpen(false);
            setUpdateOpen(true);
            if (!updateInfo) void checkHashcatUpdate();
          }} hashcatPathStatus={hashcatPathStatus} onHashcatPathChange={async (path) => {
            try {
              const next = path
                ? await invoke<HashcatPathStatus>("set_hashcat_install_dir", { path })
                : await invoke<HashcatPathStatus>("clear_hashcat_install_dir");
              setHashcatPathStatus(next);
              await refreshInfo();
              setUpdateInfo(null);
            } catch (err) {
              setError(String(err));
            }
          }} onSave={async (settings) => {
            try {
              const saved = await invoke<AiSettings>("save_ai_settings", { settings });
              setAiSettings(saved);
              setSettingsOpen(false);
            } catch (err) {
              setError(String(err));
            }
          }} />
        </DialogErrorBoundary>
      )}
      {updateOpen && (
        <DialogErrorBoundary fallback={text.hashcatUpdate}>
          <HashcatUpdateDialog
            info={updateInfo}
            logs={updateLogs}
            running={updateRunning}
            text={text}
            onCheck={checkHashcatUpdate}
            onClose={() => setUpdateOpen(false)}
            onInstall={installHashcatUpdate}
          />
        </DialogErrorBoundary>
      )}
      {helpOpen && (
        <DialogErrorBoundary fallback={text.helpTitle}>
          <HelpDialog
            config={{
              hashMode,
              attackMode,
              hashText,
              hashFile,
              mask,
              dictionaryPath,
              rulePaths,
              question: "",
            }}
            text={text}
            onClose={() => setHelpOpen(false)}
            onStartAi={startHelpAi}
          />
        </DialogErrorBoundary>
      )}
      {aiOpen && (
        <AiAnalysisWindow
          content={aiText}
          error={aiError}
          minimized={aiMinimized}
          running={aiWindowRunning}
          taskId={aiTaskId}
          title={isHelpAiTask(aiTaskId) ? text.helpAiAnalysisTitle : text.aiAnalysisTitle}
          text={text}
          canApplySuggestion={isHelpAiTask(aiTaskId) && !aiWindowRunning && Boolean(aiText.trim())}
          onApplySuggestion={() => applyAiSuggestionFromText(aiText)}
          onClose={() => setAiOpen(false)}
          onMinimize={() => setAiMinimized(true)}
          onRestore={() => setAiMinimized(false)}
        />
      )}

      <section className="workspace">
        <nav className="side-tabs">
          {TABS.map((tab) => (
            <button className={activeTab === tab.key ? "active" : ""} key={tab.key} type="button" onClick={() => setActiveTab(tab.key)}>
              {tab.icon}
          <span>{tabLabel(tab.key, text)}</span>
            </button>
          ))}
        </nav>

        <section className="panel main-panel">
          {activeTab === "config" && (
            <ConfigTab
              attackMode={attackMode}
              dictionaryPath={dictionaryPath}
              filteredModes={filteredModes}
              hashFile={hashFile}
              hashMode={hashMode}
              hashText={hashText}
              hashSuggestions={hashSuggestions}
              identifyModes={identifyModes}
              identifyRaw={identifyRaw}
              identifyRunning={identifyRunning}
              mask={mask}
              maskFile={maskFile}
              maskEstimate={maskEstimate}
              customCharsets={[customCharset1, customCharset2, customCharset3, customCharset4]}
              deviceIds={deviceIds}
              deviceTypes={deviceTypes}
              templatePrefixMask={templatePrefixMask}
              templateSuffixMask={templateSuffixMask}
              modeQuery={modeQuery}
              optimizedKernel={optimizedKernel}
              preview={preview}
              results={selectedResults}
              rulePaths={rulePaths}
              running={running}
              selectedTask={selectedTask}
              logs={logs}
              taskName={taskName}
              workloadProfile={workloadProfile}
              language={language}
              text={text}
              chooseDictionary={() => void chooseDictionary(true)}
              chooseHashFile={chooseHashFile}
              chooseMaskFile={chooseMaskFile}
              chooseRules={chooseRules}
              copyResults={copyResults}
              openTaskDir={openTaskDir}
              readResultsFor={readResultsFor}
              setAttackMode={setAttackMode}
              setHashMode={setHashMode}
              setHashText={setHashText}
              setMask={setMask}
              setModeQuery={setModeQuery}
              setOptimizedKernel={setOptimizedKernel}
              setTaskName={setTaskName}
              setTemplatePrefixMask={setTemplatePrefixMask}
              setTemplateSuffixMask={setTemplateSuffixMask}
              increment={increment}
              incrementMin={incrementMin}
              incrementMax={incrementMax}
              setIncrement={setIncrement}
              setIncrementMin={setIncrementMin}
              setIncrementMax={setIncrementMax}
              setCustomCharset={(slot, value) => {
                [setCustomCharset1, setCustomCharset2, setCustomCharset3, setCustomCharset4][slot - 1](value);
              }}
              setWorkloadProfile={setWorkloadProfile}
              startAttack={startAttack}
              addToQueue={addCurrentTaskToQueue}
              stopAttack={stopAttack}
              identifyHash={() => void identifyHash()}
              clearDictionary={() => setDictionaryPath("")}
              clearHashFile={() => setHashFile("")}
              clearMaskFile={() => setMaskFile("")}
              removeRule={(path) => setRulePaths((current) => current.filter((item) => item !== path))}
            />
          )}

          {activeTab === "resources" && (
            <ResourcesTab
              filteredResources={filteredResources}
              query={resourceQuery}
              setQuery={setResourceQuery}
              userDictionaries={userDictionaries}
              customResources={customResources}
              attackMode={attackMode}
              importDictionary={() => void chooseDictionary(true)}
              removeDictionary={removeDictionary}
              saveCustomResource={(resource) => setCustomResources((current) => [resource, ...current.filter((item) => item.id !== resource.id)])}
              deleteCustomResource={(resource) => void deleteCustomResource(resource)}
              useCustomResource={(resource) => {
                if (resource.type === "mask") {
                  setAttackMode(3);
                  setMask(resource.mask ?? "");
                  setMaskFile("");
                } else if (resource.type === "template") {
                  setAttackMode(9);
                  setTemplatePrefixMask(resource.prefixMask ?? "");
                  setTemplateSuffixMask(resource.suffixMask ?? "");
                } else if (resource.type === "charset") {
                  const slot = Number(resource.charsetSlot ?? "1");
                  [setCustomCharset1, setCustomCharset2, setCustomCharset3, setCustomCharset4][slot - 1]?.(resource.charsetValue ?? "");
                  if (attackMode === 0) setAttackMode(3);
                } else {
                  setAttackMode(0);
                }
                if (resource.type === "dictionary" && resource.path) void useDictionary(resource.path, false);
                setActiveTab("config");
              }}
              useResource={(resource) => {
                if (resource.kind === "dictionary") void useDictionary(resource.path, false);
                if (resource.kind === "rule") setRulePaths((current) => current.includes(resource.path) ? current : [...current, resource.path]);
                if (resource.kind === "mask") {
                  setAttackMode(3);
                  setMaskFile(resource.path);
                }
                setActiveTab("config");
              }}
              text={text}
            />
          )}

          {activeTab === "queue" && (
            <QueueTab
              items={queueItems}
              language={language}
              paused={queuePaused}
              running={running}
              onClearDone={clearCompletedQueueItems}
              onPause={pauseQueue}
              onRemove={removeQueuedTask}
              onSkip={skipQueuedTask}
              onStart={startQueue}
              text={text}
            />
          )}

          {activeTab === "history" && (
            <HistoryTab
              copyResults={copyResults}
              deleteTask={deleteTask}
              exportResults={exportResults}
              loadTask={loadTask}
              openTaskDir={openTaskDir}
              readResultsFor={readResultsFor}
              rerunTask={rerunTask}
              restoreTask={restoreTask}
              results={selectedResults}
              selectedTask={selectedTask}
              selectedTaskId={selectedTaskId}
              setSelectedTaskId={setSelectedTaskId}
              tasks={tasks}
              language={language}
              text={text}
            />
          )}

          {activeTab === "logs" && (
            <LogsTab
              analyzeLog={analyzeLog}
              liveLogs={logs}
              readTaskLogFor={readTaskLogFor}
              selectedTask={selectedTask}
              selectedTaskId={selectedTaskId}
              setSelectedTaskId={setSelectedTaskId}
              taskId={taskId}
              taskLog={selectedTaskLog}
              tasks={tasks}
              aiRunningTaskIds={aiRunningTaskIds}
              language={language}
              text={text}
            />
          )}
        </section>

        <aside className="status-rail">
          <SakuraMascot3D running={running} />
          <div className="progress-card">
            <div className="progress-orb">
              <div>
                <strong>{running ? text.sideRunningTitle : text.sideIdleTitle}</strong>
                <span>{running ? text.sideRunningText : text.sideIdleText}</span>
              </div>
            </div>
          </div>
          <DevicePerformancePanel
            backendInfo={info?.backendInfo ?? null}
            backendRaw={info?.backendRaw ?? ""}
            deviceIds={deviceIds}
            deviceTypes={deviceTypes}
            latestStatus={latestStatus}
            scanState={deviceScanState}
            onDeviceIdsChange={setDeviceIds}
            onRefreshDevices={refreshDeviceInfo}
            onToggleDeviceType={(type) => setDeviceTypes((current) => current.includes(type) ? current.filter((item) => item !== type) : [...current, type])}
            onWorkloadChange={setWorkloadProfile}
            text={text}
            workloadProfile={workloadProfile}
          />
        </aside>
      </section>
    </main>
  );
}

function ConfigTab(props: {
  attackMode: AttackMode;
  dictionaryPath: string;
  filteredModes: HashModeInfo[];
  hashFile: string;
  hashMode: string;
  hashText: string;
  hashSuggestions: HashModeSuggestion[];
  identifyModes: HashModeInfo[];
  identifyRaw: string;
  identifyRunning: boolean;
  mask: string;
  maskFile: string;
  maskEstimate: MaskEstimate | null;
  customCharsets: string[];
  deviceIds: string;
  deviceTypes: string[];
  templatePrefixMask: string;
  templateSuffixMask: string;
  modeQuery: string;
  optimizedKernel: boolean;
  preview: string;
  results: ResultsResponse | null;
  rulePaths: string[];
  running: boolean;
  selectedTask?: TaskManifest;
  logs: LogPayload[];
  taskName: string;
  workloadProfile: number;
  language: Language;
  text: UiText;
  chooseDictionary: () => void;
  chooseHashFile: () => void;
  chooseMaskFile: () => void;
  chooseRules: () => void;
  copyResults: () => void;
  openTaskDir: () => void;
  readResultsFor: (id?: string) => void;
  setAttackMode: (mode: AttackMode) => void;
  setHashMode: (mode: string) => void;
  setHashText: (text: string) => void;
  setMask: (mask: string) => void;
  setModeQuery: (query: string) => void;
  setOptimizedKernel: (enabled: boolean) => void;
  setTaskName: (name: string) => void;
  setTemplatePrefixMask: (mask: string) => void;
  setTemplateSuffixMask: (mask: string) => void;
  increment: boolean;
  incrementMin: string;
  incrementMax: string;
  setIncrement: (enabled: boolean) => void;
  setIncrementMin: (value: string) => void;
  setIncrementMax: (value: string) => void;
  setCustomCharset: (slot: 1 | 2 | 3 | 4, value: string) => void;
  setWorkloadProfile: (value: number) => void;
  startAttack: () => void;
  addToQueue: () => void;
  stopAttack: () => void;
  identifyHash: () => void;
  clearDictionary: () => void;
  clearHashFile: () => void;
  clearMaskFile: () => void;
  removeRule: (path: string) => void;
}) {
  const [maskHelp, setMaskHelp] = useState(false);
  const text = props.text;
  return (
    <div className="tab-content config-tab">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Attack Config</p>
          <h2>{text.attackConfigTitle}</h2>
        </div>
        <div className="mode-switch">
          <button className={props.attackMode === 0 ? "active" : ""} type="button" onClick={() => props.setAttackMode(0)}>{text.dictionary}</button>
          <button className={props.attackMode === 3 ? "active" : ""} type="button" onClick={() => props.setAttackMode(3)}>{text.mask}</button>
          <button className={props.attackMode === 6 ? "active" : ""} type="button" onClick={() => props.setAttackMode(6)}>{text.hybridDictMask}</button>
          <button className={props.attackMode === 7 ? "active" : ""} type="button" onClick={() => props.setAttackMode(7)}>{text.hybridMaskDict}</button>
          <button className={props.attackMode === 9 ? "active" : ""} type="button" onClick={() => props.setAttackMode(9)}>{text.templateAttack}</button>
        </div>
        <div className="action-row compact-actions">
          <button className="primary-button" type="button" onClick={props.startAttack} disabled={props.running}><Play size={17} />{text.start}</button>
          <button className="ghost-button" type="button" onClick={props.addToQueue} disabled={props.running}><FileClock size={16} />{queueText(props.language).add}</button>
          <button className="danger-button" type="button" onClick={props.stopAttack} disabled={!props.running}><Square size={15} />{text.stop}</button>
        </div>
      </div>

      <div className="config-grid">
        <label className="field">
          <span>{text.taskName}</span>
          <input value={props.taskName} onChange={(event) => props.setTaskName(event.currentTarget.value)} placeholder={text.taskNamePlaceholder} />
        </label>
        <label className="field">
          <span>{text.hashMode}</span>
          <input value={props.hashMode} onChange={(event) => props.setHashMode(event.currentTarget.value)} placeholder={text.hashModePlaceholder} />
        </label>
      </div>

      <section className="hash-mode-picker">
        <div className="line-title">
          <Hash size={16} />
          <span>{text.hashModePicker}</span>
          <strong>-m {props.hashMode}</strong>
        </div>
        <div className="hash-search-row">
          <input value={props.modeQuery} onChange={(event) => props.setModeQuery(event.currentTarget.value)} placeholder={text.hashModeSearch} />
          {props.modeQuery && <button className="hash-search-clear" type="button" onClick={() => props.setModeQuery("")}><X size={14} /></button>}
        </div>
        <div className="hash-mode-list">
          {props.filteredModes.slice(0, 120).map((mode) => (
            <button className={String(mode.mode) === props.hashMode ? "active" : ""} key={`${mode.mode}-${mode.name}`} type="button" onClick={() => {
              props.setHashMode(String(mode.mode));
              props.setModeQuery("");
            }}>
              <strong>{mode.mode}</strong>
              <span>{mode.name}</span>
              <em>{mode.category}</em>
            </button>
          ))}
          {!props.filteredModes.length && <div className="empty-state mode-empty">{text.noHashModes}</div>}
        </div>
      </section>

      <div className="input-layout">
        <div className="hash-input-column">
          <label className="field hash-field drop-zone">
            <div className="hash-field-header">
              <span>{text.hashInput}</span>
              <em>{text.hashInputHint}</em>
            </div>
            <textarea value={props.hashText} onChange={(event) => props.setHashText(event.currentTarget.value)} placeholder={text.hashInputPlaceholder} spellCheck={false} />
          </label>
        </div>

        <div className="resource-stack">
          <FileButton label={text.hashFile} value={props.hashFile} empty={text.notSelected} onClick={props.chooseHashFile} onClear={props.clearHashFile} clearText={text.cancel} />
          {(props.attackMode === 0 || props.attackMode === 6 || props.attackMode === 7 || props.attackMode === 9) && (
            <>
              <FileButton label={text.dictionaryFile} value={props.dictionaryPath} empty={text.notSelected} onClick={props.chooseDictionary} onClear={props.clearDictionary} clearText={text.cancel} />
              {props.attackMode === 0 && <div className="rule-box">
                <div className="line-title"><span>{text.rulesFile}</span><button type="button" onClick={props.chooseRules}>{text.add}</button></div>
                <div className="pill-list">
                  {props.rulePaths.length ? props.rulePaths.map((path) => (
                    <span className="path-pill" key={path} title={path}>{shortPath(path)}<button type="button" onClick={() => props.removeRule(path)}><X size={12} /></button></span>
                  )) : <span className="muted">{text.noRules}</span>}
                </div>
              </div>}
            </>
          )}
          {(props.attackMode === 3 || props.attackMode === 6 || props.attackMode === 7) && (
            <div className="mask-card">
              <div className="line-title"><span>{text.mask}</span><button type="button" onClick={() => setMaskHelp((value) => !value)}>{text.help}</button><button type="button" onClick={props.chooseMaskFile}>{text.file}</button></div>
              <input className="mask-input" value={props.mask} onChange={(event) => props.setMask(event.currentTarget.value)} placeholder={text.maskPlaceholder} spellCheck={false} />
              {props.maskFile && <span className="path-pill" title={props.maskFile}>{shortPath(props.maskFile)}<button type="button" onClick={props.clearMaskFile}><X size={12} /></button></span>}
              <IncrementMaskControl enabled={props.increment} min={props.incrementMin} max={props.incrementMax} text={text} onEnabledChange={props.setIncrement} onMinChange={props.setIncrementMin} onMaxChange={props.setIncrementMax} />
              <CustomCharsetEditor values={props.customCharsets} onChange={props.setCustomCharset} text={text} />
              <MaskEstimateCard estimate={props.maskEstimate} text={text} />
              {maskHelp && <div className="mask-help"><p>{text.maskHelp}</p><code>JinriPIN_Salt_2015?d?d?d?d</code></div>}
            </div>
          )}
          {props.attackMode === 9 && (
            <div className="mask-card">
              <div className="line-title"><span>{text.templateAttack}</span></div>
              <label className="field">
                <span>{text.prefixMask}</span>
                <input className="mask-input" value={props.templatePrefixMask} onChange={(event) => props.setTemplatePrefixMask(event.currentTarget.value)} placeholder="?d?d" spellCheck={false} />
              </label>
              <label className="field">
                <span>{text.suffixMask}</span>
                <input className="mask-input" value={props.templateSuffixMask} onChange={(event) => props.setTemplateSuffixMask(event.currentTarget.value)} placeholder="?d?d" spellCheck={false} />
              </label>
              <div className="mask-help"><p>{text.templateHint}</p><code>{props.templatePrefixMask || "?d?d"} + {text.templatePreviewWord} + {props.templateSuffixMask || "?d?d"}</code></div>
              <CustomCharsetEditor values={props.customCharsets} onChange={props.setCustomCharset} text={text} />
            </div>
          )}
        </div>
        <HashSuggestionPanel
          suggestions={props.hashSuggestions}
          identifyModes={props.identifyModes}
          identifyRaw={props.identifyRaw}
          identifyRunning={props.identifyRunning}
          text={text}
          onApply={props.setHashMode}
          onIdentify={props.identifyHash}
        />
      </div>

      <div className="command-box"><div className="line-title"><Terminal size={16} /><span>{text.commandPreview}</span></div><code>{props.preview}</code></div>

      <div className="run-console-card">
        <div className="run-console-header">
          <div className="line-title"><Terminal size={16} /><span>{text.liveTerminal}</span><strong>{props.running ? text.running : text.waitingStart}</strong></div>
        </div>
        <TerminalOutput logs={props.logs} text={text} />
      </div>

      <ResultReport
        copyResults={props.copyResults}
        openTaskDir={props.openTaskDir}
        readResultsFor={props.readResultsFor}
        results={props.results}
        selectedTask={props.selectedTask}
        language={props.language}
        text={text}
      />
    </div>
  );
}

function ResultReport(props: {
  copyResults: () => void;
  openTaskDir: () => void;
  readResultsFor: (id?: string) => void;
  results: ResultsResponse | null;
  selectedTask?: TaskManifest;
  language: Language;
  text: UiText;
}) {
  const content = props.results?.content.trim() ?? "";
  const firstLine = content.split(/\r?\n/).find(Boolean) ?? "";
  const crackedCount = content ? content.split(/\r?\n/).filter(Boolean).length : 0;
  const status = props.selectedTask ? statusLabel(props.selectedTask.status, props.language) : props.text.waitingTask;

  return (
    <section className={content ? "result-report cracked" : "result-report"}>
      <div className="result-report-head">
        <div>
          <p className="eyebrow">Crack Report</p>
          <h2>{content ? props.text.crackFound : props.text.resultReport}</h2>
        </div>
        <strong>{content ? `${crackedCount} ${props.text.resultCount}` : status}</strong>
      </div>

      <div className="result-answer-box">
        {content ? (
          <code>{firstLine}</code>
        ) : (
          <span>{props.selectedTask ? props.text.resultEmptyForTask : props.text.resultEmpty}</span>
        )}
      </div>

      {content && crackedCount > 1 && <span className="result-report-note">{props.text.moreResults.replace("{count}", String(crackedCount - 1))}</span>}

      <div className="result-report-actions">
        <button type="button" onClick={() => props.readResultsFor()} disabled={!props.selectedTask}><RefreshCcw size={15} />{props.text.refresh}</button>
        <button type="button" onClick={props.copyResults} disabled={!content}><Copy size={15} />{props.text.copyResults}</button>
        <button type="button" onClick={props.openTaskDir} disabled={!props.selectedTask}><FolderOpen size={15} />{props.text.openDir}</button>
      </div>
    </section>
  );
}

function MaskEstimateCard({ estimate, text }: { estimate: MaskEstimate | null; text: UiText }) {
  if (!estimate) return null;
  const candidates = estimate.candidates ? formatBigInt(estimate.candidates) : "--";
  const speed = estimate.speedHps ? `${formatNumber(Math.round(estimate.speedHps))} H/s` : text.maskEstimateUnknown;
  const time = estimate.estimatedSeconds !== undefined ? formatDuration(estimate.estimatedSeconds) : "--";
  const long = shouldConfirmLongTask(estimate);
  return (
    <div className={long ? "mask-estimate-card warn" : "mask-estimate-card"}>
      <div className="line-title"><Activity size={14} /><span>{text.maskEstimate}</span>{long && <strong>{text.taskMayRunLong}</strong>}</div>
      <div className="mask-estimate-grid">
        <span>{text.maskCandidates}<strong>{candidates}</strong></span>
        <span>{text.maskEstimateSpeed}<strong>{speed}</strong></span>
        <span>{text.maskEstimatedTime}<strong>{time}</strong></span>
      </div>
      {(estimate.error || estimate.warning) && <em>{estimate.error || estimate.warning}</em>}
    </div>
  );
}

function HashSuggestionPanel({ suggestions, identifyModes, identifyRaw, identifyRunning, text, onApply, onIdentify }: {
  suggestions: HashModeSuggestion[];
  identifyModes: HashModeInfo[];
  identifyRaw: string;
  identifyRunning: boolean;
  text: UiText;
  onApply: (mode: string) => void;
  onIdentify: () => void;
}) {
  return (
    <div className="hash-suggestion-panel">
      <div className="line-title"><Sparkles size={14} /><span>{text.hashRecommendTitle}</span><strong>{text.hashRecommendHint}</strong><button type="button" onClick={onIdentify} disabled={identifyRunning}>{identifyRunning ? text.hashIdentifyRunning : text.hashOfficialIdentify}</button></div>
      {suggestions.length ? (
        <div className="hash-suggestion-list">
          {suggestions.slice(0, 5).map((suggestion) => (
            <button type="button" key={`${suggestion.mode}-${suggestion.name}`} onClick={() => onApply(suggestion.mode)}>
              <strong>-m {suggestion.mode}</strong>
              <span>{suggestion.name}</span>
              <em>{confidenceLabel(suggestion.confidence, text)} · {suggestion.reason}</em>
              <b>{text.applyRecommendation}</b>
            </button>
          ))}
        </div>
      ) : <p>{text.hashRecommendEmpty}</p>}
      {(identifyModes.length > 0 || identifyRaw) && (
        <div className="official-identify-list">
          <div className="line-title"><span>{text.hashOfficialIdentify}</span><strong>{identifyModes.length ? `${identifyModes.length}` : text.hashIdentifyEmpty}</strong></div>
          {identifyModes.slice(0, 5).map((mode) => (
            <button type="button" key={`identify-${mode.mode}`} onClick={() => onApply(String(mode.mode))}>
              <strong>-m {mode.mode}</strong><span>{mode.name}</span><em>{mode.category}</em><b>{text.applyRecommendation}</b>
            </button>
          ))}
          {!identifyModes.length && <pre>{identifyRaw}</pre>}
        </div>
      )}
    </div>
  );
}

function IncrementMaskControl(props: {
  enabled: boolean;
  min: string;
  max: string;
  text: UiText;
  onEnabledChange: (enabled: boolean) => void;
  onMinChange: (value: string) => void;
  onMaxChange: (value: string) => void;
}) {
  return (
    <div className="increment-mask-card">
      <label className="toggle-line">
        <input type="checkbox" checked={props.enabled} onChange={(event) => props.onEnabledChange(event.currentTarget.checked)} />
        <span>{props.text.incrementMask}</span>
      </label>
      {props.enabled && (
        <div className="increment-range-grid">
          <label className="field"><span>{props.text.incrementMin}</span><input value={props.min} onChange={(event) => props.onMinChange(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="1" /></label>
          <label className="field"><span>{props.text.incrementMax}</span><input value={props.max} onChange={(event) => props.onMaxChange(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="8" /></label>
        </div>
      )}
    </div>
  );
}

function CustomCharsetEditor({ values, onChange, text }: {
  values: string[];
  onChange: (slot: 1 | 2 | 3 | 4, value: string) => void;
  text: UiText;
}) {
  return (
    <div className="custom-charset-card">
      <div className="line-title"><span>{text.customCharset}</span><strong>{text.charsetHint}</strong></div>
      <div className="charset-grid">
        {[1, 2, 3, 4].map((slot) => (
          <label className="field" key={slot}>
            <span>?{slot}</span>
            <input value={values[slot - 1] ?? ""} onChange={(event) => onChange(slot as 1 | 2 | 3 | 4, event.currentTarget.value)} placeholder={slot === 1 ? "?l?d" : ""} spellCheck={false} />
          </label>
        ))}
      </div>
    </div>
  );
}

function DevicePerformancePanel(props: {
  backendInfo: Record<string, unknown> | null;
  backendRaw: string;
  deviceIds: string;
  deviceTypes: string[];
  latestStatus: Record<string, unknown> | null;
  scanState: "idle" | "scanning" | "done" | "error";
  onDeviceIdsChange: (ids: string) => void;
  onRefreshDevices: () => void;
  onToggleDeviceType: (type: string) => void;
  onWorkloadChange: (value: number) => void;
  text: UiText;
  workloadProfile: number;
}) {
  const devices = extractStatusDevices(props.latestStatus);
  const backendDevices = extractBackendDevices(props.backendInfo, props.backendRaw);
  const backendLines = props.backendRaw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(0, 4);
  const performance = workloadInfo(props.workloadProfile, props.text);
  const scanMessage = props.scanState === "scanning"
    ? props.text.deviceScanning
    : props.scanState === "done"
      ? props.text.deviceScanDone
      : props.scanState === "error"
        ? props.text.deviceScanFailed
        : props.text.deviceScanReady;

  return (
    <section className="device-performance-panel">
      <div className="device-panel-head">
        <div>
          <p className="eyebrow">Sakura Boost Deck</p>
          <h2>{props.text.deviceControl}</h2>
          <span>{props.text.deviceControlHint}</span>
        </div>
        <button className="ghost-button" type="button" onClick={props.onRefreshDevices} disabled={props.scanState === "scanning"}><Sparkles size={15} />{props.scanState === "scanning" ? props.text.deviceScanning : props.text.scanDevices}</button>
      </div>

      <div className="device-control-grid">
        <div className="device-type-card">
          <div className="line-title"><Cpu size={15} /><span>{props.text.deviceTypes}</span><strong>-D {props.deviceTypes.length ? props.deviceTypes.join(",") : props.text.deviceAuto}</strong></div>
          <div className="device-toggle-row">
            <button className={props.deviceTypes.includes("1") ? "active" : ""} type="button" onClick={() => props.onToggleDeviceType("1")}><Cpu size={15} />{props.text.cpuDevice}</button>
            <button className={props.deviceTypes.includes("2") ? "active" : ""} type="button" onClick={() => props.onToggleDeviceType("2")}><Zap size={15} />{props.text.gpuDevice}</button>
          </div>
          <label className="field">
            <span>{props.text.deviceIds}</span>
            <input value={props.deviceIds} onChange={(event) => props.onDeviceIdsChange(event.currentTarget.value)} placeholder={props.text.deviceIdsPlaceholder} />
          </label>
        </div>

        <div className="performance-card">
          <div className="line-title"><Activity size={15} /><span>{props.text.performanceMode}</span><strong>-w {props.workloadProfile}</strong></div>
          <div className="performance-mode-row">
            {[1, 2, 3, 4].map((value) => (
              <button className={props.workloadProfile === value ? "active" : ""} key={value} type="button" onClick={() => props.onWorkloadChange(value)}>
                <strong>{value}</strong>
                <span>{workloadInfo(value, props.text).label}</span>
              </button>
            ))}
          </div>
          <p>{performance.description}</p>
        </div>
      </div>

      <div className="device-telemetry-grid">
        {devices.length ? devices.map((device, index) => (
          <div className="telemetry-card" key={`${device.name}-${index}`}>
            <div className="telemetry-title"><strong>{device.name || `${props.text.gpuDevice} ${index + 1}`}</strong><span>{device.type || props.text.deviceAuto}</span></div>
            <Metric icon={<Zap size={14} />} label={props.text.speed} value={device.speed || "--"} />
            <Metric icon={<Thermometer size={14} />} label={props.text.temperature} value={device.temperature || "--"} />
            <Metric icon={<Activity size={14} />} label={props.text.utilization} value={device.utilization || "--"} />
            <Metric icon={<Cpu size={14} />} label={props.text.memory} value={device.memory || "--"} />
          </div>
        )) : (
          <div className="telemetry-empty">{props.text.noDeviceStatus}</div>
        )}
        <div className="backend-info-card">
          <div className="line-title"><ShieldCheck size={15} /><span>{props.text.backendDeviceInfo}</span></div>
          <em className={props.scanState === "error" ? "scan-state error" : "scan-state"}>{scanMessage}</em>
          {backendDevices.length ? (
            <div className="backend-device-list">
              {backendDevices.map((device, index) => (
                <div className="backend-device-card" key={`${device.name}-${index}`}>
                  <div className="backend-device-head">
                    <strong>{device.name}</strong>
                    <span>{device.backend || props.text.deviceBackend}</span>
                  </div>
                  <div className="backend-chip-row">
                    {device.id && <em>{props.text.deviceIdLabel}: -d {device.id}</em>}
                    {device.vendor && <em>{props.text.deviceVendor}: {device.vendor}</em>}
                    {device.type && <em>{device.type}</em>}
                    {device.memory && <em>{props.text.deviceMemory}: {device.memory}</em>}
                    {device.processor && <em>{props.text.deviceProcessor}: {device.processor}</em>}
                  </div>
                </div>
              ))}
            </div>
          ) : backendLines.length ? (
            <details className="backend-raw-details">
              <summary>{props.text.backendRawSummary}</summary>
              {backendLines.map((line, index) => <code key={`${line}-${index}`}>{line}</code>)}
            </details>
          ) : <span>{props.text.scanDevices}</span>}
        </div>
      </div>
    </section>
  );
}

function Metric(props: { icon: ReactNode; label: string; value: string }) {
  return <div className="metric">{props.icon}<span>{props.label}</span><strong>{props.value}</strong></div>;
}

function ResourcesTab(props: {
  filteredResources: ResourceInfo[];
  query: string;
  setQuery: (query: string) => void;
  userDictionaries: UserDictionary[];
  customResources: CustomResource[];
  attackMode: AttackMode;
  importDictionary: () => void;
  removeDictionary: (path: string) => void;
  saveCustomResource: (resource: CustomResource) => void;
  deleteCustomResource: (resource: CustomResource) => void;
  useCustomResource: (resource: CustomResource) => void;
  useResource: (resource: ResourceInfo) => void;
  text: UiText;
}) {
  const recommended = recommendResources(props.filteredResources, props.attackMode);
  const [preview, setPreview] = useState<FilePreviewResponse | null>(null);
  const [previewName, setPreviewName] = useState("");
  const [managerOpen, setManagerOpen] = useState(false);

  async function previewResource(resource: Pick<ResourceInfo, "name" | "path">, allowFull = false) {
    try {
      setPreviewName(resource.name);
      setPreview(await invoke<FilePreviewResponse>("preview_text_file", { path: resource.path, allowFull }));
    } catch (err) {
      setPreviewName(resource.name);
      setPreview({ path: resource.path, content: String(err), truncated: false, lineCount: 1, fileSize: 0, previewLimit: 0 });
    }
  }

  return (
    <div className="tab-content resources-tab">
      {managerOpen && (
        <CustomResourceManager
          resources={props.customResources}
          text={props.text}
          onClose={() => setManagerOpen(false)}
          onSave={props.saveCustomResource}
          onDelete={props.deleteCustomResource}
          onUse={props.useCustomResource}
        />
      )}
      {preview && (
        <ResourcePreviewDialog
          name={previewName}
          preview={preview}
          text={props.text}
          onClose={() => setPreview(null)}
        />
      )}
      <div className="panel-heading">
        <div><p className="eyebrow">Resources</p><h2>{props.text.resourcesTitle}</h2></div>
        <button className="ghost-button" type="button" onClick={props.importDictionary}><Upload size={15} />{props.text.importDictionary}</button>
      </div>
      <input value={props.query} onChange={(event) => props.setQuery(event.currentTarget.value)} placeholder={props.text.resourceSearch} />
      <section className="custom-resource-panel">
        <div className="line-title"><span>{props.text.customResources}</span><button type="button" onClick={() => setManagerOpen(true)}>{props.text.manageCustomResources}</button></div>
        <div className="resource-list compact">
          {props.customResources.length ? props.customResources.map((resource) => (
            <div className="resource-row" key={resource.id}>
              <div>
                <strong>{resource.name}</strong>
                <span>{customResourceTypeLabel(resource, props.text)} · {customResourceValue(resource)}</span>
                <em>{resource.description || (resource.type === "mask" ? props.text.resourceMaskHelp : props.text.templateHint)}</em>
              </div>
              <div className="resource-actions">
                <button type="button" onClick={() => props.useCustomResource(resource)}>{props.text.use}</button>
                <button type="button" onClick={() => props.deleteCustomResource(resource)}>{props.text.delete}</button>
              </div>
            </div>
          )) : <div className="empty-state">{props.text.noCustomResources}</div>}
        </div>
      </section>
      <section className="resource-recommendations">
        <div className="line-title"><span>{props.text.recommendedResources}</span><strong>{attackModeLabel(props.attackMode, props.text)}</strong></div>
        <div className="resource-list compact">
          {recommended.length ? recommended.map((resource) => (
            <ResourceRow
              key={`recommended-${resource.path}`}
              name={resource.name}
              meta={`${resourceKindLabel(resource.kind, props.text)} · ${props.text.resourceRecommendedBecause} · ${formatSize(resource.size)}`}
              description={resourceDescription(resource, props.text)}
              onUse={() => props.useResource(resource)}
              onPreview={canPreviewResource(resource) ? () => void previewResource(resource) : undefined}
              useText={props.text.use}
              previewText={props.text.preview}
            />
          )) : <div className="empty-state">{props.text.resourceNoRecommendations}</div>}
        </div>
      </section>
      <div className="split-list">
        <section>
          <div className="line-title"><span>{props.text.builtinResources}</span></div>
          <div className="resource-list">
            {props.filteredResources.map((resource) => (
              <ResourceRow
                key={resource.path}
                name={resource.name}
                meta={`${resourceKindLabel(resource.kind, props.text)} · ${formatSize(resource.size)}`}
                description={resourceDescription(resource, props.text)}
                onUse={() => props.useResource(resource)}
                onPreview={canPreviewResource(resource) ? () => void previewResource(resource) : undefined}
                useText={props.text.use}
                previewText={props.text.preview}
              />
            ))}
          </div>
        </section>
        <section>
          <div className="line-title"><span>{props.text.userDictionaries}</span></div>
          <div className="resource-list">
            {props.userDictionaries.length ? props.userDictionaries.map((dict) => (
              <div className="resource-row" key={dict.path}>
                <div><strong>{dict.name}</strong><span>{formatSize(dict.size)} · {shortPath(dict.path)}</span><em>{props.text.resourceDictionaryHelp}</em></div>
                <div className="resource-actions">
                  <button type="button" onClick={() => props.useResource({ kind: "dictionary", name: dict.name, path: dict.path, size: dict.size })}>{props.text.use}</button>
                  <button type="button" onClick={() => void previewResource(dict, true)}>{props.text.preview}</button>
                  <button type="button" onClick={() => props.removeDictionary(dict.path)}><Trash2 size={14} /></button>
                </div>
              </div>
            )) : <div className="empty-state">{props.text.noUserDictionaries}</div>}
          </div>
        </section>
      </div>
    </div>
  );
}

function QueueTab(props: {
  items: QueueItem[];
  language: Language;
  paused: boolean;
  running: boolean;
  text: UiText;
  onClearDone: () => void;
  onPause: () => void;
  onRemove: (id: string) => void;
  onSkip: (id: string) => void;
  onStart: () => void;
}) {
  const labels = queueText(props.language);
  const [detailItem, setDetailItem] = useState<QueueItem | null>(null);
  const pending = props.items.filter((item) => item.status === "pending").length;
  const active = props.items.some((item) => item.status === "running");

  return (
    <div className="tab-content queue-tab">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Task Queue</p>
          <h2>{labels.title}</h2>
          <span>{labels.hint}</span>
        </div>
        <div className="action-row compact-actions">
          <button className="primary-button" type="button" onClick={props.onStart} disabled={!props.paused || (!pending && !active)}>
            <Play size={16} />{labels.start}
          </button>
          <button className="ghost-button" type="button" onClick={props.onPause} disabled={props.paused}>
            <Square size={14} />{labels.pause}
          </button>
          <button className="ghost-button" type="button" onClick={props.onClearDone} disabled={!props.items.some((item) => item.status === "finished" || item.status === "failed" || item.status === "skipped")}>
            <Trash2 size={14} />{labels.clearDoneButton}
          </button>
        </div>
      </div>

      <div className="queue-summary">
        <div><span>{labels.pending}</span><strong>{pending}</strong></div>
        <div><span>{labels.running}</span><strong>{props.items.filter((item) => item.status === "running").length}</strong></div>
        <div><span>{labels.finished}</span><strong>{props.items.filter((item) => item.status === "finished").length}</strong></div>
        <div className={props.paused ? "warn" : "ok"}><span>{props.paused ? labels.pausedState : labels.activeState}</span><strong>{props.running ? labels.running : labels.ready}</strong></div>
      </div>

      <div className="queue-list">
        {props.items.length ? props.items.map((item, index) => (
          <div className={`queue-row ${item.status}`} key={item.id} role="button" tabIndex={0} onClick={() => setDetailItem(item)} onKeyDown={(event) => { if (event.key === "Enter") setDetailItem(item); }}>
            <div className="queue-index">{index + 1}</div>
            <div className="queue-main">
              <strong>{item.name}</strong>
              <span>-m {item.config.hashMode} · -a {item.config.attackMode} · {queueStatusLabel(item.status, props.language)}</span>
              <code>{buildPreview(item.config)}</code>
              {item.error && <em>{item.error}</em>}
            </div>
            <div className="queue-actions">
              {item.status === "pending" && <button type="button" onClick={(event) => { event.stopPropagation(); props.onSkip(item.id); }}>{labels.skip}</button>}
              {item.status !== "running" && <button type="button" onClick={(event) => { event.stopPropagation(); props.onRemove(item.id); }}>{labels.remove}</button>}
            </div>
          </div>
        )) : <div className="empty-state">{labels.empty}</div>}
      </div>
      {detailItem && <QueueDetailDialog item={detailItem} language={props.language} text={props.text} onClose={() => setDetailItem(null)} />}
    </div>
  );
}

function QueueDetailDialog(props: {
  item: QueueItem;
  language: Language;
  text: UiText;
  onClose: () => void;
}) {
  const config = props.item.config;
  const zh = props.language === "zh";
  const charsetText = [
    config.customCharset1 ? `-1 ${config.customCharset1}` : "",
    config.customCharset2 ? `-2 ${config.customCharset2}` : "",
    config.customCharset3 ? `-3 ${config.customCharset3}` : "",
    config.customCharset4 ? `-4 ${config.customCharset4}` : "",
  ].filter(Boolean).join("\n") || "-";
  const rows = [
    [zh ? "任务状态" : "Status", queueStatusLabel(props.item.status, props.language)],
    [zh ? "Hash 类型" : "Hash Mode", `-m ${config.hashMode}`],
    [zh ? "攻击方式" : "Attack Mode", `${attackModeLabel(config.attackMode, props.text)} (-a ${config.attackMode === 9 ? "0 / template" : config.attackMode})`],
    [zh ? "Hash 文件" : "Hash File", config.hashFile || "-"],
    [zh ? "字典文件" : "Dictionary", config.dictionaryPath || "-"],
    [zh ? "掩码" : "Mask", config.maskFile || config.mask || "-"],
    [zh ? "模板前缀" : "Template Prefix", config.templatePrefixMask || "-"],
    [zh ? "模板后缀" : "Template Suffix", config.templateSuffixMask || "-"],
    [zh ? "规则文件" : "Rules", config.rulePaths?.length ? config.rulePaths.join("\n") : "-"],
    [zh ? "自定义字符集" : "Custom Charsets", charsetText],
    [zh ? "递增掩码" : "Increment", config.increment ? `${config.incrementMin || "-"} ~ ${config.incrementMax || "-"}` : "-"],
    [zh ? "性能/设备" : "Performance / Devices", `-w ${config.workloadProfile ?? 3}${config.deviceTypes?.length ? `, -D ${config.deviceTypes.join(",")}` : ""}${config.deviceIds ? `, -d ${config.deviceIds}` : ""}`],
    [zh ? "创建时间" : "Created", formatDateTime(props.item.createdAt)],
    [zh ? "开始时间" : "Started", formatDateTime(props.item.startedAt)],
    [zh ? "结束时间" : "Finished", formatDateTime(props.item.finishedAt)],
    [zh ? "后端任务 ID" : "Backend Task ID", props.item.taskId || "-"],
  ];

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="queue-detail-modal" role="dialog" aria-modal="true" aria-label={zh ? "队列任务详情" : "Queue Task Detail"}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Queue Detail</p>
            <h2>{props.item.name}</h2>
            <span>{queueStatusLabel(props.item.status, props.language)}</span>
          </div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>

        <div className="queue-detail-grid">
          {rows.map(([label, value]) => (
            <div className="queue-detail-row" key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>

        <section className="queue-detail-block">
          <div className="line-title"><Hash size={15} /><span>{zh ? "Hash 内容" : "Hash Text"}</span></div>
          <pre>{config.hashText?.trim() || "-"}</pre>
        </section>

        <section className="queue-detail-block">
          <div className="line-title"><Terminal size={15} /><span>{props.text.commandPreview}</span></div>
          <pre>{buildPreview(config)}</pre>
        </section>

        {props.item.error && (
          <section className="queue-detail-block warn">
            <div className="line-title"><AlertTriangle size={15} /><span>{props.text.errorLabel}</span></div>
            <pre>{props.item.error}</pre>
          </section>
        )}
      </section>
    </div>,
    document.body,
  );
}

function HistoryTab(props: {
  copyResults: () => void;
  deleteTask: (id: string) => void;
  exportResults: () => void;
  loadTask: (task: TaskManifest) => void;
  openTaskDir: () => void;
  readResultsFor: (id?: string) => void;
  rerunTask: (id: string) => void;
  restoreTask: (id: string) => void;
  results: ResultsResponse | null;
  selectedTask?: TaskManifest;
  selectedTaskId: string;
  setSelectedTaskId: (id: string) => void;
  tasks: TaskManifest[];
  language: Language;
  text: UiText;
}) {
  function select(id: string) {
    props.setSelectedTaskId(id);
    props.readResultsFor(id);
  }
  return (
    <div className="tab-content history-tab">
      <div className="panel-heading"><div><p className="eyebrow">History</p><h2>{props.text.historyTitle}</h2></div></div>
      <div className="history-layout">
        <div className="task-list">
          {props.tasks.length ? props.tasks.map((task) => (
            <div className={props.selectedTaskId === task.taskId ? "task-row active" : "task-row"} key={task.taskId} role="button" tabIndex={0} onClick={() => select(task.taskId)}>
              <div className="task-main"><strong>{task.taskName || task.taskId}</strong><span>-m {task.config.hashMode} · -a {task.config.attackMode} · {statusLabel(task.status, props.language)}</span><code>{task.commandPreview}</code></div>
              <div className="task-actions">
                <button type="button" onClick={() => props.loadTask(task)}>{props.text.load}</button>
                <button type="button" onClick={() => props.rerunTask(task.taskId)}>{props.text.rerun}</button>
                <button type="button" disabled={!task.canRestore} onClick={() => props.restoreTask(task.taskId)}><FileClock size={14} />{props.text.restore}</button>
                <button type="button" onClick={() => props.deleteTask(task.taskId)}><Trash2 size={14} /></button>
              </div>
            </div>
          )) : <div className="empty-state">{props.text.noHistory}</div>}
        </div>
        <section className="history-detail">
          {props.selectedTask ? (
            <>
              <div className="history-detail-head">
                <div><p className="eyebrow">Task Result</p><h2>{props.selectedTask.taskName || props.selectedTask.taskId}</h2><span>{statusLabel(props.selectedTask.status, props.language)}</span></div>
                <div className="result-actions">
                  <button type="button" onClick={props.copyResults} disabled={!props.results?.content}><Copy size={15} />{props.text.copy}</button>
                  <button type="button" onClick={props.exportResults} disabled={!props.results?.content}><Download size={15} />{props.text.export}</button>
                  <button type="button" onClick={props.openTaskDir}><FolderOpen size={15} />{props.text.directory}</button>
                  <button type="button" onClick={() => props.readResultsFor()}><RefreshCcw size={15} />{props.text.refresh}</button>
                </div>
              </div>
              <pre className="results-output">{props.results?.content || props.text.noResults}</pre>
            </>
          ) : <div className="empty-state">{props.text.selectHistoryForResult}</div>}
        </section>
      </div>
    </div>
  );
}

function LogsTab(props: {
  analyzeLog: (id?: string) => void;
  aiRunningTaskIds: string[];
  liveLogs: LogPayload[];
  readTaskLogFor: (id?: string) => void;
  selectedTask?: TaskManifest;
  selectedTaskId: string;
  setSelectedTaskId: (id: string) => void;
  taskId: string;
  taskLog: ResultsResponse | null;
  tasks: TaskManifest[];
  language: Language;
  text: UiText;
}) {
  const selectedLiveLogs = props.liveLogs.filter((log) => log.taskId === props.selectedTaskId);
  const showLive = props.selectedTaskId === props.taskId && selectedLiveLogs.length > 0;
  const selectedAiRunning = props.selectedTask ? props.aiRunningTaskIds.includes(props.selectedTask.taskId) : false;
  function select(id: string) {
    props.setSelectedTaskId(id);
    props.readTaskLogFor(id);
  }
  return (
    <div className="tab-content logs-tab">
      <div className="panel-heading">
        <div><p className="eyebrow">Console</p><h2>{props.text.logsTitle}</h2></div>
        <button className="ghost-button" type="button" onClick={() => props.readTaskLogFor()} disabled={!props.selectedTask}><RefreshCcw size={15} />{props.text.refresh}</button>
      </div>
      <div className="log-layout">
        <div className="task-list log-task-list">
          {props.tasks.length ? props.tasks.map((task) => (
            <button className={props.selectedTaskId === task.taskId ? "log-task-row active" : "log-task-row"} key={task.taskId} type="button" onClick={() => select(task.taskId)}>
              <strong>{task.taskName || task.taskId}</strong>
              <span>-m {task.config.hashMode} · {statusLabel(task.status, props.language)}</span>
            </button>
          )) : <div className="empty-state">{props.text.noHistory}</div>}
        </div>
        <section className="log-detail">
          <div className="log-detail-head">
            <div><p className="eyebrow">Run Log</p><h2>{props.selectedTask?.taskName || props.selectedTask?.taskId || props.text.selectTask}</h2>{props.selectedTask && <span>{shortPath(props.selectedTask.paths.logPath)}</span>}</div>
            <button className="primary-button ai-analyze-button" type="button" onClick={() => props.analyzeLog()} disabled={!props.selectedTask || selectedAiRunning}><Bot size={16} />{selectedAiRunning ? props.text.aiAnalyzing : props.text.aiAnalyze}</button>
          </div>
          {props.selectedTask ? showLive ? <TerminalOutput logs={selectedLiveLogs} text={props.text} /> : <pre className="log-window task-log-output">{props.taskLog?.content || props.text.noLogs}</pre> : <div className="empty-state">{props.text.selectTaskForLog}</div>}
        </section>
      </div>
    </div>
  );
}

function HelpDialog(props: {
  config: AiHashConsultConfig;
  text: UiText;
  onClose: () => void;
  onStartAi: (config: AiHashConsultConfig) => Promise<void>;
}) {
  const [draft, setDraft] = useState<AiHashConsultConfig>(() => normalizeHelpConfig(props.config));
  const [message, setMessage] = useState("");
  const [asking, setAsking] = useState(false);
  const tutorials = [
    { title: props.text.helpDictionaryTitle, body: props.text.helpDictionaryBody },
    { title: props.text.helpMaskTitle, body: props.text.helpMaskBody },
    { title: props.text.helpHybridTitle, body: props.text.helpHybridBody },
    { title: props.text.helpTemplateTitle, body: props.text.helpTemplateBody },
    { title: props.text.helpRuleTitle, body: props.text.helpRuleBody },
  ];

  async function chooseHashTxt() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      setDraft((current) => ({ ...current, hashFile: selected, hashText: "" }));
    }
  }

  async function askAi() {
    setAsking(true);
    setMessage("");
    try {
      await props.onStartAi(draft);
      setMessage(props.text.aiStartedInWindow);
      props.onClose();
    } catch (err) {
      setMessage(String(err));
    } finally {
      setAsking(false);
    }
  }

  function updateDraft(field: keyof AiHashConsultConfig, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="help-modal" role="dialog" aria-modal="true" aria-label={props.text.helpTitle}>
        <div className="panel-heading">
          <div><p className="eyebrow">{props.text.helpSubtitle}</p><h2>{props.text.helpTitle}</h2></div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>
        <div className="help-layout">
          <section className="help-guides">
            <div className="line-title"><span>{props.text.attackTutorials}</span></div>
            {tutorials.map((item) => (
              <article className="help-guide-card" key={item.title}>
                <strong>{item.title}</strong>
                <p>{item.body}</p>
              </article>
            ))}
          </section>
          <section className="help-ai-panel">
            <div className="line-title"><span>{props.text.aiHashAdvisor}</span><strong>{props.text.useCurrentConfig}</strong></div>
            <div className="help-config-grid">
              <label className="field"><span>{props.text.hashMode}</span><input value={draft.hashMode ?? ""} onChange={(event) => updateDraft("hashMode", event.currentTarget.value)} /></label>
              <label className="field"><span>{props.text.file}</span><input value={draft.hashFile ?? ""} onChange={(event) => updateDraft("hashFile", event.currentTarget.value)} /></label>
            </div>
            <button className="ghost-button" type="button" onClick={chooseHashTxt}><FileText size={15} />{props.text.chooseHashTxt}</button>
            <label className="field">
              <span>{props.text.hashInput}</span>
              <textarea value={draft.hashText ?? ""} onChange={(event) => updateDraft("hashText", event.currentTarget.value)} placeholder={props.text.hashInputPlaceholder} spellCheck={false} />
            </label>
            <label className="field">
              <span>{props.text.aiQuestion}</span>
              <textarea value={draft.question ?? ""} onChange={(event) => updateDraft("question", event.currentTarget.value)} placeholder={props.text.aiQuestionPlaceholder} />
            </label>
            {message && <div className="settings-test warn">{message}</div>}
            <div className="settings-actions">
              <button className="primary-button" type="button" onClick={() => void askAi()} disabled={asking}><Bot size={16} />{asking ? props.text.aiThinking : props.text.askAi}</button>
            </div>
            <pre className="help-ai-answer">{props.text.aiStartedInWindow}</pre>
          </section>
        </div>
      </section>
    </div>,
    document.body,
  );
}

function AiSettingsDialog(props: {
  language: Language;
  setLanguage: (language: Language) => void;
  text: UiText;
  settings: AiSettings;
  hashcatPathStatus: HashcatPathStatus | null;
  onClose: () => void;
  onHashcatPathChange: (path: string) => Promise<void>;
  onOpenUpdate: () => void;
  onSave: (settings: AiSettings) => void;
}) {
  const [draft, setDraft] = useState<AiSettings>(() => normalizeAiSettings(props.settings));
  const [models, setModels] = useState<string[]>([]);
  const [testing, setTesting] = useState(false);
  const [message, setMessage] = useState("");
  const [aboutOpen, setAboutOpen] = useState(false);
  function updateDraft(field: keyof AiSettings, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }
  async function testConnection() {
    setTesting(true);
    setMessage("");
    try {
      const response = await invoke<AiModelsResponse>("list_ai_models", { settings: draft });
      setModels(response.models);
      setMessage(props.text.connectionOk.replace("{count}", String(response.models.length)));
      if (!draft.model && response.models[0]) updateDraft("model", response.models[0]);
    } catch (err) {
      setModels([]);
      setMessage(String(err));
    } finally {
      setTesting(false);
    }
  }
  async function chooseHashcatInstallDir() {
    const selected = await open({ multiple: false, directory: true });
    if (typeof selected === "string") await props.onHashcatPathChange(selected);
  }
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="settings-modal" role="dialog" aria-modal="true" aria-label={props.text.settingsTitle}>
        <div className="panel-heading"><div><p className="eyebrow">Settings</p><h2>{props.text.settingsTitle}</h2></div><button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button></div>
        <label className="field">
          <span>{props.text.language}</span>
          <select value={props.language} onChange={(event) => props.setLanguage(event.currentTarget.value as Language)}>
            <option value="zh">{props.text.chinese}</option>
            <option value="en">{props.text.english}</option>
          </select>
        </label>
        <label className="field"><span>Base URL</span><input value={draft.baseUrl} onChange={(event) => updateDraft("baseUrl", event.currentTarget.value)} placeholder="https://api.openai.com/v1" /></label>
        <label className="field"><span>API Key</span><input type="password" value={draft.apiKey} onChange={(event) => updateDraft("apiKey", event.currentTarget.value)} placeholder="sk-..." /></label>
        <label className="field"><span>{props.text.model}</span><input value={draft.model} onChange={(event) => updateDraft("model", event.currentTarget.value)} placeholder="gpt-4o-mini" /></label>
        {models.length > 0 && <label className="field"><span>{props.text.availableModels}</span><select value={models.includes(draft.model) ? draft.model : ""} onChange={(event) => updateDraft("model", event.currentTarget.value)}><option value="">{props.text.chooseModel}</option>{models.map((model) => <option value={model} key={model}>{model}</option>)}</select></label>}
        <div className="settings-tool-card hashcat-path-card">
          <div>
            <strong>{props.language === "zh" ? "Hashcat 安装目录" : "Hashcat Install Folder"}</strong>
            <span title={props.hashcatPathStatus?.customInstallDir || props.hashcatPathStatus?.effectiveDir || ""}>
              {props.hashcatPathStatus?.customInstallDir
                ? props.hashcatPathStatus.customInstallDir
                : props.language === "zh" ? "默认：工具目录 resources/hashcat-current" : "Default: tool folder resources/hashcat-current"}
            </span>
            {props.hashcatPathStatus?.effectiveDir && <em>{props.language === "zh" ? "当前使用：" : "Using: "}{props.hashcatPathStatus.effectiveDir}</em>}
          </div>
          <div className="settings-card-actions">
            <button className="ghost-button" type="button" onClick={chooseHashcatInstallDir}><FolderOpen size={15} />{props.language === "zh" ? "选择" : "Choose"}</button>
            <button className="ghost-button" type="button" onClick={() => props.onHashcatPathChange("")} disabled={!props.hashcatPathStatus?.customInstallDir}>{props.language === "zh" ? "默认" : "Default"}</button>
          </div>
        </div>
        <div className="settings-tool-card">
          <div>
            <strong>{props.text.hashcatUpdate}</strong>
            <span>{props.text.hashcatUpdateHint}</span>
          </div>
          <button className="ghost-button" type="button" onClick={props.onOpenUpdate}><Download size={15} />{props.text.hashcatUpdate}</button>
        </div>
        <div className="settings-tool-card">
          <div>
            <strong>{props.language === "zh" ? "关于 hashcatGUI" : "About hashcatGUI"}</strong>
            <span>{props.language === "zh" ? "开发者、联系方式与免责声明" : "Developer, contact, and disclaimer"}</span>
          </div>
          <button className="ghost-button" type="button" onClick={() => setAboutOpen(true)}><HelpCircle size={15} />{props.language === "zh" ? "关于" : "About"}</button>
        </div>
        {message && <div className={models.length ? "settings-test ok" : "settings-test warn"}>{message}</div>}
        <div className="settings-actions">
          <button className="ghost-button" type="button" onClick={testConnection} disabled={testing}><Bot size={16} />{testing ? props.text.testing : props.text.testConnection}</button>
          <button className="ghost-button" type="button" onClick={props.onClose}>{props.text.cancel}</button>
          <button className="primary-button" type="button" onClick={() => props.onSave(draft)}>{props.text.save}</button>
        </div>
        {aboutOpen && <AboutDialog language={props.language} onClose={() => setAboutOpen(false)} />}
      </section>
    </div>
  );
}

function HashcatUpdateDialog(props: {
  info: HashcatUpdateInfo | null;
  logs: HashcatUpdateEvent[];
  running: boolean;
  text: UiText;
  onCheck: () => void;
  onClose: () => void;
  onInstall: () => void;
}) {
  const status = props.info
    ? props.info.upToDate ? props.text.updateUpToDate : props.text.updateAvailable
    : props.text.updateNotChecked;
  const latestLog = props.logs[props.logs.length - 1];

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="settings-modal hashcat-update-modal" role="dialog" aria-modal="true" aria-label={props.text.hashcatUpdate}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Hashcat Release Channel</p>
            <h2>{props.text.hashcatUpdate}</h2>
            <span>{props.text.hashcatUpdateHint}</span>
          </div>
          <button className="icon-button" type="button" onClick={props.onClose} disabled={props.running}><X size={15} /></button>
        </div>

        <div className="update-version-grid">
          <div className="update-version-card">
            <span>{props.text.updateCurrent}</span>
            <strong>{props.info?.currentVersion ?? "-"}</strong>
          </div>
          <div className="update-version-card accent">
            <span>{props.text.updateLatest}</span>
            <strong>{props.info?.latestVersion ?? "-"}</strong>
          </div>
          <div className={`update-version-card ${props.info?.upToDate ? "ok" : "warn"}`}>
            <span>Status</span>
            <strong>{props.running ? props.text.updateRunning : status}</strong>
          </div>
        </div>

        <div className="update-package-card">
          <span>{props.text.updatePackage}</span>
          <strong>{props.info?.assetName ?? "-"}</strong>
          {props.info?.releaseUrl && <button className="ghost-button" type="button" onClick={() => window.open(props.info?.releaseUrl, "_blank")}><FolderOpen size={15} />{props.text.openRelease}</button>}
        </div>

        <div className="settings-actions">
          <button className="ghost-button" type="button" onClick={props.onCheck} disabled={props.running}><RefreshCcw size={15} />{props.text.checkUpdate}</button>
          <button className="primary-button" type="button" onClick={props.onInstall} disabled={props.running || !props.info || props.info.upToDate}><Download size={15} />{props.running ? props.text.updateRunning : props.text.installUpdate}</button>
        </div>

        <div className="update-log-card">
          <div className="line-title"><Terminal size={15} /><span>{props.text.updateLog}</span></div>
          <div className="update-log-stream">
            {latestLog ? <code><span>{latestLog.phase}</span>{latestLog.line}</code> : <em>{props.text.updateNotChecked}</em>}
          </div>
        </div>
      </section>
    </div>,
    document.body,
  );
}

function AiAnalysisWindow(props: {
  canApplySuggestion: boolean;
  content: string;
  error: string;
  minimized: boolean;
  running: boolean;
  taskId: string;
  title: string;
  text: UiText;
  onApplySuggestion: () => void;
  onClose: () => void;
  onMinimize: () => void;
  onRestore: () => void;
}) {
  const outputRef = useRef<HTMLPreElement | null>(null);
  const autoFollowRef = useRef(true);

  function updateAutoFollow() {
    const output = outputRef.current;
    if (!output) return;
    const distanceToBottom = output.scrollHeight - output.scrollTop - output.clientHeight;
    autoFollowRef.current = distanceToBottom < 40;
  }

  useEffect(() => {
    const output = outputRef.current;
    if (output && autoFollowRef.current) output.scrollTop = output.scrollHeight;
  }, [props.content, props.error]);

  async function copyAnalysis() {
    const content = props.error ? `${props.content}\n\n[${props.text.errorLabel}]\n${props.error}` : props.content;
    if (content.trim()) await writeText(content);
  }

  if (props.minimized) {
    return (
      <button className="ai-mini-window" type="button" onClick={props.onRestore}>
        <Bot size={16} />
        <span>{props.running ? props.text.aiAnalyzing : props.title}</span>
      </button>
    );
  }

  return (
    <div className="ai-window-backdrop" role="presentation">
      <section className="ai-window" role="dialog" aria-modal="true" aria-label={props.title}>
        <header className="ai-window-head">
          <div>
            <p className="eyebrow">AI Analysis</p>
            <h2>{props.title}</h2>
            <span>{props.taskId || props.text.noTaskSelected}</span>
          </div>
          <div className="ai-window-actions">
            {props.canApplySuggestion && <button className="primary-button" type="button" onClick={props.onApplySuggestion}><Bot size={15} />{props.text.applyAiSuggestion}</button>}
            <button className="ghost-button" type="button" onClick={copyAnalysis} disabled={!props.content && !props.error}><Copy size={15} />{props.text.copy}</button>
            <button className="ghost-button" type="button" onClick={props.onMinimize}>{props.text.minimize}</button>
            <button className="icon-button" type="button" onClick={props.onClose}><X size={16} /></button>
          </div>
        </header>
        <pre className="ai-window-output" ref={outputRef} onScroll={updateAutoFollow}>{props.content || (props.running ? props.text.aiConnecting : props.text.noAiContent)}{props.error ? `\n\n[${props.text.errorLabel}]\n${props.error}` : ""}</pre>
        <footer className="ai-window-foot"><span className={props.running ? "live-dot on" : "live-dot"} />{props.running ? props.text.aiStreaming : props.text.aiFinished}</footer>
      </section>
    </div>
  );
}
function TerminalOutput({ logs, text }: { logs: LogPayload[]; text: UiText }) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const element = ref.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [logs.length]);
  return (
    <div className="log-window" ref={ref}>
      {logs.length ? logs.slice(-260).map((log, index) => <p className={log.stream} key={`${log.taskId}-${index}`}><span>{log.stream}</span>{log.line}</p>) : <div className="empty-state">{text.terminalWaiting}</div>}
    </div>
  );
}

function FileButton(props: {
  label: string;
  value: string;
  empty: string;
  onClick: () => void;
  onClear: () => void;
  clearText: string;
}) {
  return (
    <div className="resource-line">
      <div className="line-title"><span>{props.label}</span></div>
      <button className="file-button" type="button" onClick={props.onClick} title={props.value || props.label}><FolderOpen size={15} /><span>{props.value ? shortPath(props.value) : props.empty}</span></button>
      {props.value && <button className="clear-file-button" type="button" onClick={props.onClear}><X size={13} />{props.clearText}</button>}
    </div>
  );
}

function ResourceRow(props: { name: string; meta: string; description: string; onUse: () => void; onPreview?: () => void; useText: string; previewText: string }) {
  return (
    <div className="resource-row">
      <div><strong>{props.name}</strong><span>{props.meta}</span><em>{props.description}</em></div>
      <div className="resource-actions">
        <button type="button" onClick={props.onUse}>{props.useText}</button>
        {props.onPreview && <button type="button" onClick={props.onPreview}>{props.previewText}</button>}
      </div>
    </div>
  );
}

function ResourcePreviewDialog(props: {
  name: string;
  preview: FilePreviewResponse;
  text: UiText;
  onClose: () => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="resource-preview-modal" role="dialog" aria-modal="true" aria-label={props.text.resourcePreviewTitle}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">{props.text.resourcePreviewTitle}</p>
            <h2>{props.name}</h2>
            <span>{shortPath(props.preview.path)}</span>
          </div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>
        {props.preview.truncated && <div className="settings-test warn">{props.text.previewTruncated.replace("{count}", String(props.preview.lineCount))}</div>}
        <div className="settings-test warn">{props.text.copiedDictionaryOnly}</div>
        <pre className="resource-preview-output">{props.preview.content || props.text.previewEmpty}</pre>
      </section>
    </div>
  );
}

function CustomResourceManager(props: {
  resources: CustomResource[];
  text: UiText;
  onClose: () => void;
  onSave: (resource: CustomResource) => void;
  onDelete: (resource: CustomResource) => void;
  onUse: (resource: CustomResource) => void;
}) {
  const [type, setType] = useState<CustomResource["type"]>("mask");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [mask, setMaskValue] = useState("");
  const [prefixMask, setPrefixMask] = useState("");
  const [suffixMask, setSuffixMask] = useState("");
  const [charsetSlot, setCharsetSlot] = useState<"1" | "2" | "3" | "4">("1");
  const [charsetValue, setCharsetValue] = useState("");
  const [editing, setEditing] = useState<CustomResource | null>(null);
  const [editContent, setEditContent] = useState("");
  const [editTruncated, setEditTruncated] = useState(false);
  const [appendContent, setAppendContent] = useState("");
  const [message, setMessage] = useState("");
  const [dedupingPath, setDedupingPath] = useState("");
  const isZh = props.text.settingsTitle === "设置";

  function resetForm() {
    setName("");
    setDescription("");
    setMaskValue("");
    setPrefixMask("");
    setSuffixMask("");
    setCharsetSlot("1");
    setCharsetValue("");
  }

  function saveManualResource() {
    if (type === "mask" && !mask.trim()) return;
    if (type === "template" && !prefixMask.trim() && !suffixMask.trim()) return;
    if (type === "charset" && !charsetValue.trim()) return;
    props.onSave({
      id: editing && editing.type !== "dictionary" ? editing.id : `custom-${Date.now()}`,
      type,
      name: name.trim() || (type === "mask" ? mask.trim() : type === "charset" ? `?${charsetSlot} ${charsetValue.trim()}` : `${prefixMask || "<empty>"} + word + ${suffixMask || "<empty>"}`),
      description: description.trim(),
      mask: type === "mask" ? mask.trim() : undefined,
      prefixMask: type === "template" ? prefixMask.trim() : undefined,
      suffixMask: type === "template" ? suffixMask.trim() : undefined,
      charsetSlot: type === "charset" ? charsetSlot : undefined,
      charsetValue: type === "charset" ? charsetValue.trim() : undefined,
      createdAt: editing?.createdAt ?? new Date().toISOString(),
    });
    setEditing(null);
    resetForm();
  }

  function editManualResource(resource: CustomResource) {
    setEditing(resource);
    setType(resource.type);
    setName(resource.name);
    setDescription(resource.description);
    setMaskValue(resource.mask ?? "");
    setPrefixMask(resource.prefixMask ?? "");
    setSuffixMask(resource.suffixMask ?? "");
    setCharsetSlot(resource.charsetSlot ?? "1");
    setCharsetValue(resource.charsetValue ?? "");
    setEditContent("");
    setEditTruncated(false);
    setAppendContent("");
    setMessage("");
  }

  async function importDictionaryCopy() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected !== "string") return;
    try {
      const imported = await invoke<UserDictionary>("import_custom_dictionary", { source: selected });
      props.onSave({
        id: `custom-${Date.now()}`,
        type: "dictionary",
        name: name.trim() || imported.name,
        description: description.trim(),
        path: imported.path,
        size: imported.size,
        createdAt: new Date().toISOString(),
      });
      resetForm();
    } catch (err) {
      setMessage(String(err));
    }
  }

  async function editDictionary(resource: CustomResource) {
    if (!resource.path) return;
    try {
      const preview = await invoke<FilePreviewResponse>("preview_text_file", { path: resource.path, allowFull: true });
      setEditing(resource);
      setEditContent(preview.content);
      setEditTruncated(preview.truncated);
      setAppendContent("");
      setMessage(preview.truncated ? props.text.previewTruncated.replace("{count}", String(preview.lineCount)) : "");
    } catch (err) {
      setMessage(String(err));
    }
  }

  async function saveDictionaryEdit() {
    if (!editing?.path) return;
    try {
      const content = editTruncated ? appendContent : editContent;
      if (!content.trim()) return;
      const saved = editTruncated
        ? await invoke<UserDictionary>("append_custom_dictionary_content", { path: editing.path, content: content.endsWith("\n") ? content : `${content}\n` })
        : await invoke<UserDictionary>("save_custom_dictionary_content", { path: editing.path, content });
      props.onSave({ ...editing, size: saved.size });
      setEditing(null);
      setEditContent("");
      setEditTruncated(false);
      setAppendContent("");
      setMessage("");
    } catch (err) {
      setMessage(String(err));
    }
  }

  function deleteResource(resource: CustomResource) {
    if (editing?.id === resource.id) {
      setEditing(null);
      setEditContent("");
      setEditTruncated(false);
      setAppendContent("");
    }
    props.onDelete(resource);
  }

  async function dedupeDictionary(resource: CustomResource) {
    if (!resource.path) return;
    const confirmed = window.confirm(isZh
      ? "将对这个自定义字典副本去重，保留第一次出现的词条。不会修改你的原始本地字典。继续吗？"
      : "This will deduplicate this custom dictionary copy and keep the first occurrence of each entry. Your original local dictionary will not be changed. Continue?");
    if (!confirmed) return;
    setDedupingPath(resource.path);
    setMessage("");
    try {
      const result = await invoke<DictionaryDedupeResponse>("dedupe_custom_dictionary", { path: resource.path });
      props.onSave({ ...resource, size: result.size });
      setMessage(isZh
        ? `去重完成：原 ${result.originalLines} 行，保留 ${result.uniqueLines} 行，移除 ${result.removedLines} 行。`
        : `Deduplicated: ${result.originalLines} original lines, ${result.uniqueLines} kept, ${result.removedLines} removed.`);
      if (editing?.id === resource.id) {
        const preview = await invoke<FilePreviewResponse>("preview_text_file", { path: resource.path, allowFull: true });
        setEditContent(preview.content);
        setEditTruncated(preview.truncated);
        setAppendContent("");
      }
    } catch (err) {
      setMessage(String(err));
    } finally {
      setDedupingPath("");
    }
  }

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="custom-manager-modal" role="dialog" aria-modal="true" aria-label={props.text.manageCustomResources}>
        <div className="panel-heading">
          <div><p className="eyebrow">Custom Library</p><h2>{props.text.manageCustomResources}</h2></div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>
        {message && <div className="settings-test warn">{message}</div>}
        <div className="custom-manager-form">
          <select value={type} onChange={(event) => setType(event.currentTarget.value as CustomResource["type"])}>
            <option value="mask">{props.text.customMaskName}</option>
            <option value="template">{props.text.customTemplateName}</option>
            <option value="charset">{props.text.customCharsetName}</option>
            <option value="dictionary">{props.text.customDictionaryName}</option>
          </select>
          <input value={name} onChange={(event) => setName(event.currentTarget.value)} placeholder={props.text.customName} />
          <input value={description} onChange={(event) => setDescription(event.currentTarget.value)} placeholder={props.text.customDescription} />
          {type === "mask" && <input value={mask} onChange={(event) => setMaskValue(event.currentTarget.value)} placeholder="?d?d?d?d" />}
          {type === "template" && <input value={prefixMask} onChange={(event) => setPrefixMask(event.currentTarget.value)} placeholder={props.text.prefixMask} />}
          {type === "template" && <input value={suffixMask} onChange={(event) => setSuffixMask(event.currentTarget.value)} placeholder={props.text.suffixMask} />}
          {type === "charset" && <select value={charsetSlot} onChange={(event) => setCharsetSlot(event.currentTarget.value as "1" | "2" | "3" | "4")}><option value="1">?1</option><option value="2">?2</option><option value="3">?3</option><option value="4">?4</option></select>}
          {type === "charset" && <input value={charsetValue} onChange={(event) => setCharsetValue(event.currentTarget.value)} placeholder="?l?d" />}
          {type === "dictionary" ? (
            <button type="button" onClick={importDictionaryCopy}>{props.text.importCustomDictionary}</button>
          ) : (
            <button type="button" onClick={saveManualResource}>{editing && editing.type !== "dictionary" ? props.text.save : type === "mask" ? props.text.addMaskResource : type === "charset" ? props.text.addCharsetResource : props.text.addTemplateResource}</button>
          )}
        </div>
        <div className="custom-manager-list">
          {props.resources.length ? props.resources.map((resource) => (
            <div className="resource-row" key={resource.id}>
              <div>
                <strong>{resource.name}</strong>
                <span>{customResourceTypeLabel(resource, props.text)} · {customResourceValue(resource)}</span>
                <em>{resource.description || (resource.type === "dictionary" ? props.text.resourceDictionaryHelp : resource.type === "charset" ? props.text.charsetHint : props.text.templateHint)}</em>
              </div>
              <div className="resource-actions">
                <button type="button" onClick={() => props.onUse(resource)}>{props.text.use}</button>
                {resource.type === "dictionary" ? <button type="button" onClick={() => void editDictionary(resource)}>{props.text.edit}</button> : <button type="button" onClick={() => editManualResource(resource)}>{props.text.edit}</button>}
                {resource.type === "dictionary" && <button type="button" onClick={() => void dedupeDictionary(resource)} disabled={dedupingPath === resource.path}>{dedupingPath === resource.path ? (isZh ? "去重中" : "Deduping") : (isZh ? "去重" : "Dedupe")}</button>}
                <button type="button" onClick={() => deleteResource(resource)}>{props.text.delete}</button>
              </div>
            </div>
          )) : <div className="empty-state">{props.text.noCustomResources}</div>}
        </div>
        {editing && (
          <section className="dictionary-editor">
            <div className="line-title"><span>{props.text.edit}: {editing.name}</span></div>
            {editTruncated && <div className="settings-test warn">{props.text.largeDictionaryAppendOnly}</div>}
            {editTruncated && <pre className="resource-preview-output dictionary-edit-preview">{editContent || props.text.previewEmpty}</pre>}
            <textarea
              value={editTruncated ? appendContent : editContent}
              onChange={(event) => editTruncated ? setAppendContent(event.currentTarget.value) : setEditContent(event.currentTarget.value)}
              placeholder={editTruncated ? props.text.appendDictionaryPlaceholder : undefined}
              spellCheck={false}
            />
            <div className="settings-actions">
              <button className="ghost-button" type="button" onClick={() => { setEditing(null); setEditTruncated(false); setAppendContent(""); }}>{props.text.cancel}</button>
              <button className="primary-button" type="button" onClick={() => void saveDictionaryEdit()}>{editTruncated ? props.text.appendDictionaryLines : props.text.save}</button>
            </div>
          </section>
        )}
      </section>
    </div>,
    document.body,
  );
}

function HealthItem(props: { icon: ReactNode; label: string; value: string; tone: "ok" | "warn" }) {
  return <div className={`health-item ${props.tone}`}>{props.icon}<span>{props.label}</span><strong>{props.value}</strong></div>;
}

function filterModes(modes: HashModeInfo[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return modes;
  return modes.filter((mode) => `${mode.mode} ${mode.name} ${mode.category} ${mode.keywords.join(" ")}`.toLowerCase().includes(normalized));
}

function recommendHashModes(hashText: string, modes: HashModeInfo[]): HashModeSuggestion[] {
  const sample = firstHashSample(hashText);
  if (!sample) return [];
  const add = (items: Array<Omit<HashModeSuggestion, "name">>) => items
    .map((item) => ({
      ...item,
      name: modes.find((mode) => String(mode.mode) === item.mode)?.name || fallbackHashModeName(item.mode),
    }))
    .filter((item, index, list) => list.findIndex((other) => other.mode === item.mode) === index)
    .slice(0, 4);

  if (/^WPA\*0[12]\*/i.test(sample)) {
    return add([{ mode: "22000", confidence: "high", reason: "WPA*01/WPA*02 hash line" }]);
  }
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(sample)) {
    return add([{ mode: "3200", confidence: "high", reason: "bcrypt $2a/$2b/$2y format" }]);
  }
  if (/^sha256:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/i.test(sample)) {
    return add([{ mode: "10900", confidence: "medium", reason: "sha256:iterations:base64-salt:base64-hash format" }]);
  }
  if (/^\$1\$/.test(sample)) {
    return add([{ mode: "500", confidence: "high", reason: "md5crypt $1$ prefix" }]);
  }
  if (/^\$5\$/.test(sample)) {
    return add([{ mode: "7400", confidence: "high", reason: "sha256crypt $5$ prefix" }]);
  }
  if (/^\$6\$/.test(sample)) {
    return add([{ mode: "1800", confidence: "high", reason: "sha512crypt $6$ prefix" }]);
  }
  if (/^\$(P|H)\$/.test(sample)) {
    return add([{ mode: "400", confidence: "medium", reason: "phpass/phpBB style prefix" }]);
  }
  if (/^[a-f0-9]{32}$/i.test(sample)) {
    return add([
      { mode: "0", confidence: "medium", reason: "32 hex characters" },
      { mode: "1000", confidence: "low", reason: "NTLM is also 32 hex characters" },
    ]);
  }
  if (/^[a-f0-9]{40}$/i.test(sample)) {
    return add([{ mode: "100", confidence: "medium", reason: "40 hex characters" }]);
  }
  if (/^[a-f0-9]{64}$/i.test(sample)) {
    return add([{ mode: "1400", confidence: "medium", reason: "64 hex characters" }]);
  }
  if (/^[a-f0-9]{128}$/i.test(sample)) {
    return add([{ mode: "1700", confidence: "medium", reason: "128 hex characters" }]);
  }
  return [];
}

function firstHashSample(hashText: string) {
  const line = hashText
    .split(/\r?\n/)
    .map((item) => item.trim())
    .find((item) => item && !item.startsWith("#"));
  if (!line) return "";
  const withoutUsername = line.match(/^[^:$]{1,80}:([a-f0-9]{32,128})$/i)?.[1];
  return withoutUsername || line;
}

function fallbackHashModeName(mode: string) {
  const names: Record<string, string> = {
    "0": "MD5",
    "100": "SHA1",
    "400": "phpass / WordPress",
    "500": "md5crypt",
    "1000": "NTLM",
    "1400": "SHA2-256",
    "1700": "SHA2-512",
    "1800": "sha512crypt",
    "3200": "bcrypt",
    "7400": "sha256crypt",
    "10900": "PBKDF2-HMAC-SHA256",
    "22000": "WPA-PBKDF2-PMKID+EAPOL",
  };
  return names[mode] || `Hash mode ${mode}`;
}

function confidenceLabel(value: HashModeSuggestion["confidence"], text: UiText) {
  if (value === "high") return text.confidenceHigh;
  if (value === "medium") return text.confidenceMedium;
  return text.confidenceLow;
}

function buildPreview(config: Pick<AttackConfig, "attackMode" | "increment" | "incrementMin" | "incrementMax" | "customCharset1" | "customCharset2" | "customCharset3" | "customCharset4" | "deviceIds" | "deviceTypes" | "dictionaryPath" | "hashFile" | "hashMode" | "hashText" | "mask" | "maskFile" | "templatePrefixMask" | "templateSuffixMask" | "optimizedKernel" | "rulePaths" | "workloadProfile">) {
  const parts = ["hashcat.exe", "--status", "--status-json", "--status-timer=1", "-m", config.hashMode || "<mode>", "-a", config.attackMode === 9 ? "0" : String(config.attackMode)];
  if (config.optimizedKernel) parts.push("-O");
  parts.push("-w", String(config.workloadProfile ?? 3));
  if (config.increment && [3, 6, 7].includes(config.attackMode)) {
    parts.push("--increment");
    if (config.incrementMin) parts.push("--increment-min", String(config.incrementMin));
    if (config.incrementMax) parts.push("--increment-max", String(config.incrementMax));
  }
  if (config.deviceTypes?.length) parts.push("-D", config.deviceTypes.join(","));
  if (config.deviceIds?.trim()) parts.push("-d", config.deviceIds.trim());
  [config.customCharset1, config.customCharset2, config.customCharset3, config.customCharset4].forEach((value, index) => {
    if (value?.trim()) parts.push(`-${index + 1}`, quote(value.trim()));
  });
  if (config.attackMode === 0) config.rulePaths?.forEach((rule) => parts.push("-r", quote(rule)));
  parts.push(config.hashText?.trim() ? "<pasted-hash.tmp>" : quote(config.hashFile || "<hash-file>"));
  const wordlist = quote(config.dictionaryPath || "<wordlist>");
  const mask = quote(config.maskFile || config.mask || "<mask>");
  if (config.attackMode === 0) parts.push(wordlist);
  if (config.attackMode === 3) parts.push(mask);
  if (config.attackMode === 6) parts.push(wordlist, mask);
  if (config.attackMode === 7) parts.push(mask, wordlist);
  if (config.attackMode === 9) parts.push("<generated_candidates.txt>");
  return parts.join(" ");
}

function quote(value: string) {
  return value.includes(" ") ? `"${value}"` : value;
}

function shortPath(path: string) {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts.length <= 3 ? path : `${parts[0]}/.../${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
}

function formatSize(size: number) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

function formatDateTime(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function mergeUpdateLog(current: HashcatUpdateEvent[], next: HashcatUpdateEvent) {
  const normalized = {
    ...next,
    line: compactUpdateLine(next.line),
  };
  const index = current.findIndex((item) => item.phase === normalized.phase);
  if (index < 0) return [...current.slice(-8), normalized];
  return current.map((item, itemIndex) => itemIndex === index ? normalized : item);
}

function compactUpdateLine(line: string) {
  return line.replace(/\s+/g, " ").trim();
}

function appendAiDelta(current: string, delta: string) {
  if (!delta) return current;
  if (current.endsWith(delta)) return current;
  if (delta.startsWith(current) && delta.length > current.length) return delta;
  return current + delta;
}

function normalizeAiAnalysisText(text: string) {
  if (!text) return "";

  let next = text.replace(/\r\n?/g, "\n");
  if (hasAiDuplicateArtifacts(next)) {
    next = collapseRepeatedCjk(next);
    next = collapseRepeatedTechnicalTokens(next);
    next = collapseRepeatedTextRuns(next);
    next = collapseRepeatedTechnicalTokens(next);
  }

  next = next
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, "").replace(/[ \t]{2,}/g, " "))
    .join("\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n");

  return collapseRepeatedAdjacentLines(next);
}

function hasAiDuplicateArtifacts(text: string) {
  const cjkPairs = countMatches(text, /([\u3400-\u9fff])\1/g);
  const repeatedWords = countMatches(text, /\b([A-Za-z][A-Za-z0-9_-]{1,24})\s+\1\b/g);
  const repeatedFragments = countMatches(text, /([A-Za-z][A-Za-z0-9_.-]{1,15})\1/g);
  return cjkPairs >= 3
    || repeatedWords >= 2
    || repeatedFragments >= 3
    || /\b(task|hash|attack|status|mode|rockyou)\s+\1_/i.test(text);
}

function countMatches(text: string, pattern: RegExp) {
  return text.match(pattern)?.length ?? 0;
}

function collapseRepeatedCjk(text: string) {
  return text
    .replace(/([\u3400-\u9fff])\s+\1(?=[\u3400-\u9fff])/g, "$1")
    .replace(/([\u3400-\u9fff])\1/g, "$1")
    .replace(/([：，。、；！？])\1/g, "$1");
}

function collapseRepeatedTechnicalTokens(text: string) {
  return text
    .replace(/\b([A-Za-z][A-Za-z0-9-]{1,24})\s+\1_([A-Za-z0-9_]+)/g, "$1_$2")
    .replace(/_([A-Za-z0-9]{2,24})_\1\b/g, "_$1")
    .replace(/\.([A-Za-z0-9]{1,8})\.\1\b/g, ".$1")
    .replace(/\b([A-Za-z][A-Za-z0-9_-]{1,24})\s+\1\b/g, "$1")
    .replace(/(^|[\s：:])--([mawDOr])\2\b/g, "$1-$2")
    .replace(/(^|[\s：:])-([mawDOr])\s+([0-9])\3\b/g, "$1-$2 $3")
    .replace(/\btask--/g, "task-");
}

function collapseRepeatedTextRuns(text: string) {
  const chars = Array.from(text);
  let output = "";
  let index = 0;

  while (index < chars.length) {
    let replaced = false;
    const maxLen = Math.min(24, Math.floor((chars.length - index) / 2));
    for (let len = maxLen; len >= 2; len -= 1) {
      const left = chars.slice(index, index + len).join("");
      if (!/[A-Za-z0-9_.-]|[\u3400-\u9fff]/.test(left)) continue;
      const right = chars.slice(index + len, index + len * 2).join("");
      if (left === right) {
        output += left;
        index += len * 2;
        replaced = true;
        break;
      }
    }
    if (!replaced) {
      output += chars[index];
      index += 1;
    }
  }

  return output;
}

function collapseRepeatedAdjacentLines(text: string) {
  const lines = text.split("\n");
  const output: string[] = [];
  let previous = "";

  for (const line of lines) {
    const normalized = line.trim();
    if (normalized && normalized === previous) continue;
    output.push(line);
    previous = normalized || "";
  }

  return output.join("\n");
}

function attackModeLabel(mode: AttackMode, text: UiText) {
  const labels: Record<AttackMode, string> = {
    0: text.dictionary,
    3: text.mask,
    6: text.hybridDictMask,
    7: text.hybridMaskDict,
    9: text.templateAttack,
  };
  return labels[mode];
}

function resourceKindLabel(kind: ResourceInfo["kind"], text: UiText) {
  const labels: Record<ResourceInfo["kind"], string> = {
    rule: text.rulesFile,
    mask: text.mask,
    charset: "Charset",
    dictionary: text.dictionaryFile,
  };
  return labels[kind];
}

function resourceDescription(resource: ResourceInfo, text: UiText) {
  if (resource.kind === "rule") return text.resourceRuleHelp;
  if (resource.kind === "mask") return text.resourceMaskHelp;
  if (resource.kind === "charset") return text.resourceCharsetHelp;
  return text.resourceDictionaryHelp;
}

function canPreviewResource(resource: ResourceInfo) {
  return resource.kind === "rule" || resource.kind === "dictionary" || resource.kind === "mask" || resource.kind === "charset";
}

function normalizeHelpConfig(config: AiHashConsultConfig): AiHashConsultConfig {
  return {
    hashMode: config.hashMode ?? "",
    attackMode: config.attackMode,
    hashText: config.hashText ?? "",
    hashFile: config.hashFile ?? "",
    mask: config.mask ?? "",
    dictionaryPath: config.dictionaryPath ?? "",
    rulePaths: Array.isArray(config.rulePaths) ? config.rulePaths : [],
    question: config.question ?? "",
  };
}

function normalizeAiSettings(settings: AiSettings): AiSettings {
  return {
    baseUrl: settings.baseUrl ?? "",
    apiKey: settings.apiKey ?? "",
    model: settings.model ?? "",
  };
}

function parseAiSuggestedConfig(content: string): AiSuggestedConfig | null {
  const blocks = [...content.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map((match) => match[1]);
  for (const block of blocks.reverse()) {
    const parsed = parseAiSuggestionObject(block);
    if (parsed) return parsed;
  }

  const looseConfigIndex = content.lastIndexOf("hashcatGuiTaskConfig");
  if (looseConfigIndex >= 0) {
    const jsonText = extractJsonObjectAround(content, looseConfigIndex);
    if (jsonText) {
      const parsed = parseAiSuggestionObject(jsonText);
      if (parsed) return parsed;
    }
  }

  const marker = "HASHCAT_GUI_TASK_CONFIG:";
  const markerIndex = content.lastIndexOf(marker);
  if (markerIndex >= 0) {
    const parsed = parseAiSuggestionObject(content.slice(markerIndex + marker.length));
    if (parsed) return parsed;
  }

  return null;
}

function extractJsonObjectAround(text: string, index: number) {
  const start = text.lastIndexOf("{", index);
  if (start < 0) return "";

  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i += 1) {
    const char = text[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === "\"") {
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (char === "{") depth += 1;
    if (char === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }

  return "";
}

function parseAiSuggestionObject(text: string): AiSuggestedConfig | null {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return null;

  try {
    const value = JSON.parse(text.slice(start, end + 1));
    const raw = value.hashcatGuiTaskConfig ?? value.taskConfig ?? value;
    const suggestion: AiSuggestedConfig = {};
    if (typeof raw.hashMode === "string" || typeof raw.hashMode === "number") suggestion.hashMode = String(raw.hashMode);
    if (isAttackMode(raw.attackMode)) suggestion.attackMode = raw.attackMode;
    if (typeof raw.hashText === "string") suggestion.hashText = raw.hashText;
    if (typeof raw.hashFile === "string") suggestion.hashFile = raw.hashFile;
    if (typeof raw.mask === "string") suggestion.mask = raw.mask;
    if (typeof raw.dictionaryPath === "string") suggestion.dictionaryPath = raw.dictionaryPath;
    if (Array.isArray(raw.rulePaths)) suggestion.rulePaths = raw.rulePaths.filter((path: unknown): path is string => typeof path === "string");
    return Object.keys(suggestion).length ? suggestion : null;
  } catch {
    return null;
  }
}

function isAttackMode(value: unknown): value is AttackMode {
  return value === 0 || value === 3 || value === 6 || value === 7 || value === 9;
}

function isHelpAiTask(taskId: string) {
  return taskId.startsWith("help-ai-");
}

function workloadInfo(value: number, text: UiText) {
  const data: Record<number, { label: string; description: string }> = {
    1: { label: text.workloadLow, description: text.performanceLowDesc },
    2: { label: text.workloadDefault, description: text.performanceDefaultDesc },
    3: { label: text.workloadHigh, description: text.performanceHighDesc },
    4: { label: text.workloadExtreme, description: text.performanceExtremeDesc },
  };
  return data[value] ?? data[3];
}

type TelemetryDevice = {
  name: string;
  type: string;
  speed: string;
  temperature: string;
  utilization: string;
  memory: string;
};

type BackendDevice = {
  id: string;
  name: string;
  type: string;
  backend: string;
  vendor: string;
  memory: string;
  processor: string;
};

function extractBackendDevices(info: Record<string, unknown> | null, raw: string): BackendDevice[] {
  const fromJson = findObjectDevices(info)
    .map((item, index) => normalizeBackendDevice(item, index, {}))
    .filter(Boolean) as BackendDevice[];
  if (fromJson.length) return dedupeBackendDevices(fromJson).slice(0, 8);

  return parseBackendRawDevices(raw).slice(0, 8);
}

function findObjectDevices(value: unknown, context: Partial<BackendDevice> = {}): Record<string, unknown>[] {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) {
    return value.flatMap((item) => findObjectDevices(item, context));
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).map((key) => key.toLowerCase());
  const looksLikeDevice = keys.some((key) => key.includes("deviceid") || key === "device" || key.includes("adapter") || key.includes("memory") || key.includes("processor"))
    && keys.some((key) => key.includes("name") || key.includes("type") || key.includes("memory") || key.includes("vendor"));
  const nextContext = {
    ...context,
    backend: inferBackendFromObject(object) || context.backend || "",
    vendor: stringifyMetric(pickValue(object, ["vendor", "vendor_name", "vendorName"])) || context.vendor || "",
  };
  const current = looksLikeDevice ? [{ ...object, __backend: nextContext.backend, __vendor: nextContext.vendor }] : [];
  return [
    ...current,
    ...Object.entries(object).flatMap(([key, item]) => findObjectDevices(item, {
      ...nextContext,
      backend: inferBackendFromKey(key) || nextContext.backend,
    })),
  ];
}

function normalizeBackendDevice(item: Record<string, unknown>, index: number, fallback: Partial<BackendDevice>): BackendDevice | null {
  const id = normalizeDeviceId(stringifyMetric(pickValue(item, ["device_id", "deviceId", "DeviceID", "id"])));
  const name = stringifyMetric(pickValue(item, ["name", "device_name", "deviceName", "alias", "device"])) || (id ? `hashcat 设备 ${id}` : `hashcat 设备 ${index + 1}`);
  const type = stringifyMetric(pickValue(item, ["type", "device_type", "deviceType"])) || inferDeviceType(name);
  const backend = stringifyMetric(pickValue(item, ["backend", "backend_type", "backendType", "api", "__backend"])) || fallback.backend || "";
  const vendor = stringifyMetric(pickValue(item, ["vendor", "vendor_name", "vendorName", "__vendor"])) || fallback.vendor || inferVendor(name);
  const memory = formatBackendMemory(pickValue(item, ["memory", "memory_total", "memoryTotal", "global_mem", "globalMemory", "vram", "MemoryTotal"]));
  const processor = stringifyMetric(pickValue(item, ["processor", "processors", "cores", "compute_units", "computeUnits"]));
  if (!name && !type && !backend && !vendor && !memory) return null;
  return { id, name, type, backend, vendor, memory, processor };
}

function parseBackendRawDevices(raw: string): BackendDevice[] {
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const interesting = lines.filter((line) => /device|backend|cuda|opencl|vulkan|nvidia|intel|amd|memory|processor/i.test(line));
  const chunks = interesting.length ? interesting : lines;
  return chunks.slice(0, 8).map((line, index) => ({
    id: normalizeDeviceId(line.match(/(?:device\s*(?:id)?|#)\s*[:#]?\s*(\d+)/i)?.[1] ?? ""),
    name: prettifyBackendLine(line) || `Device ${index + 1}`,
    type: /cpu/i.test(line) ? "CPU" : /gpu|cuda|opencl|vulkan/i.test(line) ? "GPU" : "",
    backend: line.match(/CUDA|OpenCL|Vulkan|HIP/i)?.[0] ?? "",
    vendor: line.match(/NVIDIA|Intel|AMD|Apple/i)?.[0] ?? "",
    memory: line.match(/\d+(?:\.\d+)?\s*(?:MB|GB|MiB|GiB)/i)?.[0] ?? "",
    processor: line.match(/\d+\s*(?:MCU|CU|processors?|cores?)/i)?.[0] ?? "",
  }));
}

function prettifyBackendLine(line: string) {
  return line
    .replace(/[{}[\]",]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/^\d+\s*[:|-]\s*/, "")
    .trim()
    .slice(0, 96);
}

function dedupeBackendDevices(devices: BackendDevice[]) {
  const seen = new Set<string>();
  return devices.filter((device) => {
    const key = `${device.id}|${device.name}|${device.backend}|${device.vendor}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatBackendMemory(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatBackendMemory).filter(Boolean).join(" / ");
  if (typeof value === "number") return value > 1024 * 1024 ? formatSize(value) : `${value} MB`;
  return stringifyMetric(value);
}

function estimateAttackMask(config: {
  attackMode: AttackMode;
  mask: string;
  templatePrefixMask: string;
  templateSuffixMask: string;
  customCharsets: string[];
  speedHps?: number;
  text: UiText;
}): MaskEstimate | null {
  if (![3, 6, 7, 9].includes(config.attackMode)) return null;
  const maskText = config.attackMode === 9
    ? `${config.templatePrefixMask}${config.templateSuffixMask}`
    : config.mask;
  if (!maskText.trim()) return null;
  const parsed = estimateMaskCandidates(maskText, config.customCharsets);
  const speed = config.speedHps && config.speedHps > 0 ? config.speedHps : undefined;
  const estimatedSeconds = parsed.candidates && speed ? bigIntToSeconds(parsed.candidates, speed) : undefined;
  const partial = config.attackMode === 6 || config.attackMode === 7 || config.attackMode === 9;
  return {
    candidates: parsed.candidates,
    estimatedSeconds,
    speedHps: speed,
    error: parsed.error ? config.text.maskEstimateUnsupported : undefined,
    warning: partial ? config.text.maskEstimatePartial : undefined,
  };
}

function estimateMaskCandidates(maskText: string, customCharsets: string[] = []): { candidates?: bigint; error?: boolean } {
  const sizes: Record<string, bigint> = {
    l: 26n,
    u: 26n,
    d: 10n,
    h: 16n,
    H: 16n,
    s: 33n,
    a: 95n,
    b: 256n,
  };
  let total = 1n;
  for (let index = 0; index < maskText.length; index += 1) {
    const char = maskText[index];
    if (char !== "?") continue;
    const token = maskText[index + 1];
    if (!token) return { error: true };
    if (token === "?") {
      index += 1;
      continue;
    }
    const size = sizes[token] ?? customCharsetSize(customCharsets[Number(token) - 1], sizes);
    if (!size) return { error: true };
    total *= size;
    index += 1;
  }
  return { candidates: total };
}

function customCharsetSize(value: string | undefined, baseSizes: Record<string, bigint>): bigint | undefined {
  const text = value?.trim();
  if (!text) return undefined;
  let total = 0n;
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] !== "?") {
      total += 1n;
      continue;
    }
    const token = text[index + 1];
    if (!token) return undefined;
    if (token === "?") {
      total += 1n;
      index += 1;
      continue;
    }
    const size = baseSizes[token];
    if (!size) return undefined;
    total += size;
    index += 1;
  }
  return total || undefined;
}

function extractStatusSpeed(status: Record<string, unknown> | null): number | undefined {
  if (!status) return undefined;
  const values: number[] = [];
  collectSpeedValues(status, values);
  const positive = values.filter((value) => Number.isFinite(value) && value > 0);
  return positive.length ? positive.reduce((sum, value) => sum + value, 0) : undefined;
}

function collectSpeedValues(value: unknown, output: number[]) {
  if (Array.isArray(value)) {
    for (const item of value) collectSpeedValues(item, output);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const lower = key.toLowerCase();
    if (lower.includes("speed")) {
      const speed = numericSpeed(item);
      if (speed) output.push(speed);
    }
    collectSpeedValues(item, output);
  }
}

function numericSpeed(value: unknown): number | undefined {
  if (typeof value === "number") return value;
  if (Array.isArray(value)) {
    const values = value.map(numericSpeed).filter((item): item is number => Boolean(item));
    return values.length ? values.reduce((sum, item) => sum + item, 0) : undefined;
  }
  if (typeof value !== "string") return undefined;
  const match = value.replace(/,/g, "").match(/([\d.]+)\s*([kmgth]?)[hH]?\/?s?/);
  if (!match) return undefined;
  const base = Number(match[1]);
  if (!Number.isFinite(base)) return undefined;
  const unit = match[2].toLowerCase();
  const factor = unit === "t" ? 1_000_000_000_000 : unit === "g" ? 1_000_000_000 : unit === "m" ? 1_000_000 : unit === "k" ? 1_000 : 1;
  return base * factor;
}

function bigIntToSeconds(candidates: bigint, speedHps: number): number {
  if (candidates <= 0n || speedHps <= 0) return 0;
  const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
  if (candidates > maxSafe) {
    const digits = candidates.toString().length;
    const approximate = Number(candidates.toString().slice(0, 15)) * 10 ** (digits - 15);
    return approximate / speedHps;
  }
  return Number(candidates) / speedHps;
}

function shouldConfirmLongTask(estimate: MaskEstimate | null) {
  return Boolean(estimate?.estimatedSeconds && estimate.estimatedSeconds >= 3600);
}

function extractStatusDevices(status: Record<string, unknown> | null): TelemetryDevice[] {
  if (!status) return [];
  const candidates = findArrays(status).filter((array) =>
    array.some((item) => item && typeof item === "object" && (
      "speed" in item || "speed_dev" in item || "temperature" in item || "temp" in item || "util" in item || "device_name" in item
    )),
  );
  const source = candidates[0] ?? [];
  return source
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    .slice(0, 8)
    .map((item, index) => ({
      name: stringifyMetric(pickValue(item, ["device_name", "name", "device", "alias"])) || `Device ${index + 1}`,
      type: stringifyMetric(pickValue(item, ["device_type", "type", "backend"])) || "",
      speed: formatSpeed(pickValue(item, ["speed", "speed_dev", "speed_sec", "speed_raw"])),
      temperature: formatTemperature(pickValue(item, ["temperature", "temp", "temp_dev", "hardware_monitor_temperature"])),
      utilization: formatPercent(pickValue(item, ["util", "utilization", "util_dev", "hardware_monitor_utilization"])),
      memory: formatMemory(pickValue(item, ["memory", "memory_used", "vram", "vram_used", "hardware_monitor_memory"])),
    }));
}

function findArrays(value: unknown): Array<Record<string, unknown>[]> {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) return [value as Record<string, unknown>[]];
  return Object.values(value as Record<string, unknown>).flatMap(findArrays);
}

function pickValue(object: Record<string, unknown>, keys: string[]) {
  const entries = Object.entries(object);
  for (const key of keys) {
    const value = object[key] ?? entries.find(([entryKey]) => entryKey.toLowerCase() === key.toLowerCase())?.[1];
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return undefined;
}

function inferBackendFromObject(object: Record<string, unknown>) {
  const keys = Object.keys(object).join(" ").toLowerCase();
  const text = `${keys} ${stringifyMetric(pickValue(object, ["name", "version", "backend"]))}`.toLowerCase();
  if (text.includes("cuda")) return "CUDA";
  if (text.includes("opencl")) return "OpenCL";
  if (text.includes("vulkan")) return "Vulkan";
  if (text.includes("hip")) return "HIP";
  return "";
}

function inferBackendFromKey(key: string) {
  if (/cuda/i.test(key)) return "CUDA";
  if (/opencl/i.test(key)) return "OpenCL";
  if (/vulkan/i.test(key)) return "Vulkan";
  if (/hip/i.test(key)) return "HIP";
  return "";
}

function inferDeviceType(name: string) {
  return /gpu|nvidia|radeon|geforce|intel\(r\) uhd|arc/i.test(name) ? "GPU" : /cpu|processor/i.test(name) ? "CPU" : "";
}

function inferVendor(name: string) {
  if (/nvidia|geforce|cuda/i.test(name)) return "NVIDIA";
  if (/intel/i.test(name)) return "Intel";
  if (/amd|radeon/i.test(name)) return "AMD";
  return "";
}

function normalizeDeviceId(value: string) {
  return value.replace(/^0+(\d)/, "$1");
}

function stringifyMetric(value: unknown): string {
  if (Array.isArray(value)) return value.map(stringifyMetric).filter(Boolean).join(" / ");
  if (typeof value === "number" || typeof value === "string") return String(value);
  return "";
}

function formatSpeed(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatSpeed).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") return `${formatNumber(value)} H/s`;
  const text = stringifyMetric(value);
  return text || "--";
}

function formatTemperature(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatTemperature).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") return `${value} °C`;
  const text = stringifyMetric(value);
  return text ? (text.includes("°") || text.toLowerCase().includes("c") ? text : `${text} °C`) : "--";
}

function formatPercent(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatPercent).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") return `${value}%`;
  const text = stringifyMetric(value);
  return text ? (text.includes("%") ? text : `${text}%`) : "--";
}

function formatMemory(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatMemory).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") return value > 1024 * 1024 ? formatSize(value) : `${value} MB`;
  return stringifyMetric(value) || "--";
}

function formatNumber(value: number) {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)}G`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)}K`;
  return String(value);
}

function numberOrNull(value: string) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function formatBigInt(value: bigint) {
  return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds)) return "> 999 days";
  if (seconds < 1) return "< 1s";
  const rounded = Math.ceil(seconds);
  const days = Math.floor(rounded / 86400);
  const hours = Math.floor((rounded % 86400) / 3600);
  const minutes = Math.floor((rounded % 3600) / 60);
  const secs = rounded % 60;
  if (days > 999) return "> 999 days";
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

function customResourceValue(resource: CustomResource) {
  if (resource.type === "mask") return resource.mask || "";
  if (resource.type === "charset") return `?${resource.charsetSlot ?? "1"} = ${resource.charsetValue ?? ""}`;
  if (resource.type === "dictionary") return resource.path ? shortPath(resource.path) : "";
  return `${resource.prefixMask || "<empty>"} + word + ${resource.suffixMask || "<empty>"}`;
}

function customResourceTypeLabel(resource: CustomResource, text: UiText) {
  if (resource.type === "mask") return text.customMaskName;
  if (resource.type === "charset") return text.customCharsetName;
  if (resource.type === "dictionary") return text.customDictionaryName;
  return text.customTemplateName;
}

function recommendResources(resources: ResourceInfo[], attackMode: AttackMode) {
  const preferredKinds: Array<ResourceInfo["kind"]> =
    attackMode === 0 ? ["dictionary", "rule"] :
    attackMode === 3 ? ["mask", "charset"] :
    ["dictionary", "mask"];
  return resources
    .filter((resource) => preferredKinds.includes(resource.kind))
    .sort((a, b) => preferredKinds.indexOf(a.kind) - preferredKinds.indexOf(b.kind) || resourcePriority(a) - resourcePriority(b) || a.name.localeCompare(b.name))
    .slice(0, 6);
}

function resourcePriority(resource: ResourceInfo) {
  const name = resource.name.toLowerCase();
  if (resource.kind === "dictionary" && name === "rockyou.txt") return 0;
  if (resource.kind === "rule" && name === "best66.rule") return 1;
  return 5;
}

function getInitialLanguage(): Language {
  const saved = localStorage.getItem(LANGUAGE_STORAGE_KEY);
  return saved === "en" || saved === "zh" ? saved : "zh";
}

function loadCustomResources(): CustomResource[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(CUSTOM_RESOURCES_STORAGE_KEY) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is CustomResource =>
      typeof item?.id === "string" &&
      (item.type === "mask" || item.type === "template" || item.type === "dictionary" || item.type === "charset") &&
      typeof item.name === "string",
    );
  } catch {
    return [];
  }
}

function loadQueueItems(): QueueItem[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(TASK_QUEUE_STORAGE_KEY) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is QueueItem =>
      typeof item?.id === "string" &&
      typeof item.name === "string" &&
      item.config &&
      typeof item.config.hashMode === "string" &&
      (item.status === "pending" || item.status === "running" || item.status === "finished" || item.status === "failed" || item.status === "skipped"),
    ).map((item) => item.status === "running" ? { ...item, status: "pending", taskId: undefined } : item);
  } catch {
    return [];
  }
}

function tabLabel(tab: TabKey, text: UiText) {
  const labels: Record<Exclude<TabKey, "queue">, string> = {
    config: text.tabConfig,
    resources: text.tabResources,
    history: text.tabHistory,
    logs: text.tabLogs,
  };
  if (tab === "queue") return text.settingsTitle === "设置" ? "队列" : "Queue";
  return labels[tab];
}

function queueText(language: Language) {
  if (language === "zh") {
    return {
      add: "加入队列",
      title: "任务队列",
      hint: "多个任务按顺序串行运行，一个结束后自动跑下一个。",
      start: "开始队列",
      pause: "暂停队列",
      skip: "跳过",
      remove: "移除",
      pending: "等待",
      running: "运行中",
      finished: "已完成",
      failed: "失败",
      skipped: "已跳过",
      empty: "队列暂无任务。在任务配置页点击加入队列。",
      added: "已加入队列",
      paused: "队列已暂停",
      resumed: "队列已开始",
      clearDone: "已清理完成项",
      clearDoneButton: "清理完成",
      pausedState: "队列暂停",
      activeState: "队列运行",
      ready: "就绪",
    };
  }
  return {
    add: "Add to Queue",
    title: "Task Queue",
    hint: "Run multiple tasks serially. The next task starts after the current one finishes.",
    start: "Start Queue",
    pause: "Pause Queue",
    skip: "Skip",
    remove: "Remove",
    pending: "Pending",
    running: "Running",
    finished: "Finished",
    failed: "Failed",
    skipped: "Skipped",
    empty: "No queued tasks. Add one from Task Config.",
    added: "Added to queue",
    paused: "Queue paused",
    resumed: "Queue started",
    clearDone: "Cleared completed tasks",
    clearDoneButton: "Clear Done",
    pausedState: "Paused",
    activeState: "Active",
    ready: "Ready",
  };
}

function queueStatusLabel(status: QueueStatus, language: Language) {
  const labels = queueText(language);
  const map: Record<QueueStatus, string> = {
    pending: labels.pending,
    running: labels.running,
    finished: labels.finished,
    failed: labels.failed,
    skipped: labels.skipped,
  };
  return map[status];
}

function statusLabel(status: string, language: Language) {
  const zhStatus: Record<string, string> = {
    cracked: "已破解",
    exhausted: "已耗尽",
    aborted: "已中止",
    checkpoint: "检查点中止",
    finished: "已完成",
    running: "运行中",
    error: "错误",
  };
  return (language === "zh" ? zhStatus : STATUS_TEXT.en)[status] ?? status;
}
