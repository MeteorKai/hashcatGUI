use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{path::BaseDirectory, AppHandle, Emitter, Manager, State};

#[derive(Default)]
struct AppState {
    active_task: Arc<Mutex<Option<RunningTask>>>,
    active_update: Arc<Mutex<bool>>,
}

struct RunningTask {
    task_id: String,
    stop_tx: mpsc::Sender<StopSignal>,
}

enum StopSignal {
    Checkpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttackConfig {
    hash_mode: String,
    attack_mode: u8,
    hash_text: Option<String>,
    hash_file: Option<String>,
    dictionary_path: Option<String>,
    mask: Option<String>,
    mask_file: Option<String>,
    template_prefix_mask: Option<String>,
    template_suffix_mask: Option<String>,
    increment: Option<bool>,
    increment_min: Option<u8>,
    increment_max: Option<u8>,
    custom_charset1: Option<String>,
    custom_charset2: Option<String>,
    custom_charset3: Option<String>,
    custom_charset4: Option<String>,
    #[serde(default)]
    rule_paths: Vec<String>,
    task_name: Option<String>,
    optimized_kernel: Option<bool>,
    workload_profile: Option<u8>,
    #[serde(default)]
    device_types: Vec<String>,
    device_ids: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentifyResponse {
    raw: String,
    modes: Vec<HashModeInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HashcatInfo {
    available: bool,
    version: Option<String>,
    hashcat_path: Option<String>,
    resource_root: Option<String>,
    backend_info: Option<Value>,
    backend_raw: String,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashcatUpdateInfo {
    current_version: Option<String>,
    latest_version: String,
    latest_name: String,
    asset_name: String,
    asset_url: String,
    release_url: String,
    up_to_date: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashcatUpdateEvent {
    phase: String,
    line: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashcatUpdateFinishEvent {
    ok: bool,
    info: Option<HashcatUpdateInfo>,
    error: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashcatPathConfig {
    custom_install_dir: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HashcatPathStatus {
    custom_install_dir: Option<String>,
    effective_dir: Option<String>,
    effective_exe: Option<String>,
    using_custom: bool,
    available: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashModeInfo {
    mode: u32,
    name: String,
    category: String,
    keywords: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct HashModesCache {
    version: String,
    modes: Vec<HashModeInfo>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceInfo {
    kind: String,
    name: String,
    path: String,
    size: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDictionary {
    name: String,
    path: String,
    size: u64,
    added_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartResponse {
    task_id: String,
    command_preview: String,
    outfile_path: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogPayload {
    task_id: String,
    stream: String,
    line: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusPayload {
    task_id: String,
    data: Value,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExitPayload {
    task_id: String,
    code: Option<i32>,
    reason: String,
    outfile_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultsResponse {
    path: String,
    content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FilePreviewResponse {
    path: String,
    content: String,
    truncated: bool,
    line_count: usize,
    file_size: u64,
    preview_limit: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DictionaryDedupeResponse {
    path: String,
    original_lines: u64,
    unique_lines: u64,
    removed_lines: u64,
    size: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiSettings {
    base_url: String,
    api_key: String,
    model: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiModelsResponse {
    models: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisResponse {
    content: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AiHashConsultConfig {
    hash_mode: String,
    attack_mode: u8,
    hash_text: Option<String>,
    hash_file: Option<String>,
    mask: Option<String>,
    dictionary_path: Option<String>,
    rule_paths: Vec<String>,
    question: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisPayload {
    task_id: String,
    text: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiAnalysisErrorPayload {
    task_id: String,
    error: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskManifest {
    task_id: String,
    task_name: String,
    created_at: String,
    updated_at: String,
    started_at: String,
    ended_at: Option<String>,
    status: String,
    exit_code: Option<i32>,
    exit_reason: Option<String>,
    can_restore: bool,
    command_preview: String,
    session_name: String,
    config: AttackConfig,
    paths: TaskPaths,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskPaths {
    task_dir: String,
    hash_path: String,
    outfile_path: String,
    potfile_path: String,
    restore_path: String,
    log_path: String,
}

#[tauri::command]
fn get_hashcat_info(app: AppHandle, include_backend_info: Option<bool>) -> HashcatInfo {
    match find_hashcat_dir(&app) {
        Ok(hashcat_dir) => {
            let exe = hashcat_dir.join("hashcat.exe");
            let version = hashcat_version(&hashcat_dir, &exe).ok();
            let (backend_raw, backend_info) = if include_backend_info.unwrap_or(false) {
                let raw = command_text(
                    &hashcat_dir,
                    &exe,
                    &["--backend-info", "--machine-readable"],
                )
                .unwrap_or_else(|err| err);
                let info = extract_json_object(&raw);
                (raw, info)
            } else {
                (String::new(), None)
            };

            HashcatInfo {
                available: exe.is_file(),
                version,
                hashcat_path: Some(path_string(&exe)),
                resource_root: Some(path_string(&hashcat_dir)),
                backend_info,
                backend_raw,
                error: None,
            }
        }
        Err(error) => HashcatInfo {
            available: false,
            version: None,
            hashcat_path: None,
            resource_root: None,
            backend_info: None,
            backend_raw: String::new(),
            error: Some(error),
        },
    }
}

#[tauri::command]
fn check_hashcat_update(app: AppHandle) -> Result<HashcatUpdateInfo, String> {
    build_hashcat_update_info(&app)
}

#[tauri::command]
fn get_hashcat_path_status(app: AppHandle) -> Result<HashcatPathStatus, String> {
    hashcat_path_status(&app)
}

#[tauri::command]
fn set_hashcat_install_dir(app: AppHandle, path: String) -> Result<HashcatPathStatus, String> {
    let dir = PathBuf::from(path.trim());
    validate_hashcat_install_dir(&dir)?;
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    write_json(
        &hashcat_path_config_path(&app)?,
        &HashcatPathConfig {
            custom_install_dir: Some(path_string(&dir)),
        },
    )?;
    hashcat_path_status(&app)
}

#[tauri::command]
fn clear_hashcat_install_dir(app: AppHandle) -> Result<HashcatPathStatus, String> {
    write_json(
        &hashcat_path_config_path(&app)?,
        &HashcatPathConfig {
            custom_install_dir: None,
        },
    )?;
    hashcat_path_status(&app)
}

#[tauri::command]
fn install_hashcat_update(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    ensure_no_active_task(&state.active_task)?;
    {
        let mut active = state
            .active_update
            .lock()
            .map_err(|_| "更新状态锁定失败。".to_string())?;
        if *active {
            return Err("已有 hashcat 更新正在进行。".into());
        }
        *active = true;
    }

    let update_flag = state.active_update.clone();
    thread::spawn(move || {
        let result = install_hashcat_update_inner(app.clone());
        match &result {
            Ok(info) => {
                emit_update_event(
                    &app,
                    "finish",
                    &format!("更新完成，当前 hashcat 版本：{}", info.current_version.clone().unwrap_or_else(|| info.latest_version.clone())),
                );
            }
            Err(error) => emit_update_event(&app, "error", error),
        }
        let _ = app.emit(
            "hashcat-update-finish",
            match result {
                Ok(info) => HashcatUpdateFinishEvent {
                    ok: true,
                    info: Some(info),
                    error: None,
                },
                Err(error) => HashcatUpdateFinishEvent {
                    ok: false,
                    info: None,
                    error: Some(error),
                },
            },
        );
        if let Ok(mut active) = update_flag.lock() {
            *active = false;
        }
    });

    Ok(())
}

#[tauri::command]
fn get_hash_modes(app: AppHandle) -> Result<Vec<HashModeInfo>, String> {
    let hashcat_dir = find_hashcat_dir(&app)?;
    let exe = hashcat_dir.join("hashcat.exe");
    let version = hashcat_version(&hashcat_dir, &exe)?;
    let cache_path = app_data_dir(&app)?.join("hash_modes_cache.json");

    if let Ok(cache_text) = fs::read_to_string(&cache_path) {
        if let Ok(cache) = serde_json::from_str::<HashModesCache>(&cache_text) {
            if cache.version == version && !cache.modes.is_empty() {
                return Ok(cache.modes);
            }
        }
    }

    let help = command_text(&hashcat_dir, &exe, &["-hh"])?;
    let modes = parse_hash_modes(&help);
    if modes.is_empty() {
        return Err("未能从 hashcat -hh 解析 hash 类型。".into());
    }

    write_json(
        &cache_path,
        &HashModesCache {
            version,
            modes: modes.clone(),
        },
    )?;

    Ok(modes)
}

#[tauri::command]
fn identify_hash(app: AppHandle, hash_text: Option<String>, hash_file: Option<String>) -> Result<IdentifyResponse, String> {
    let hashcat_dir = find_hashcat_dir(&app)?;
    let exe = hashcat_dir.join("hashcat.exe");
    let input_path = if let Some(text) = hash_text.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        let dir = app_data_dir(&app)?.join("identify");
        fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
        let path = dir.join("input.hash");
        fs::write(&path, format!("{text}\n")).map_err(|err| err.to_string())?;
        path
    } else {
        required_existing_file(hash_file.as_deref(), "请选择 hash 文件或粘贴 hash。")?
    };
    let raw = command_text(&hashcat_dir, &exe, &["--identify", &path_string(&input_path)])?;
    Ok(IdentifyResponse {
        modes: parse_identify_modes(&raw),
        raw,
    })
}

#[tauri::command]
fn list_builtin_resources(app: AppHandle) -> Result<Vec<ResourceInfo>, String> {
    let mut resources = Vec::new();

    for root in wordlist_resource_roots(&app) {
        collect_named_resources(&mut resources, "dictionary", &root, &["rockyou.txt"])?;
    }

    let hashcat_dir = find_hashcat_dir(&app).ok();
    let roots = hashcat_resource_roots(&app, hashcat_dir.as_deref());

    // Compatibility with older portable builds that placed dictionaries under hashcat.
    for root in &roots {
        collect_named_resources(&mut resources, "dictionary", &root.join("wordlists"), &["rockyou.txt"])?;
        push_resource_if_file(&mut resources, "dictionary", &root.join("rockyou.txt"))?;
    }

    for root in &roots {
        collect_named_resources(
            &mut resources,
            "rule",
            &root.join("rules"),
            &[
                "best66.rule",
                "dive.rule",
                "rockyou-30000.rule",
                "T0XlC.rule",
                "T0XlCv2.rule",
                "leetspeak.rule",
                "combinator.rule",
            ],
        )?;
        collect_named_resources(
            &mut resources,
            "mask",
            &root.join("masks"),
            &[
                "hashcat-default.hcmask",
                "rockyou-1-60.hcmask",
                "rockyou-2-1800.hcmask",
                "rockyou-3-3600.hcmask",
            ],
        )?;
        collect_named_resources(
            &mut resources,
            "charset",
            &root.join("charsets"),
            &["base58.hcchr", "DES_full.hcchr"],
        )?;
    }

    resources.sort_by(|a, b| resource_kind_order(&a.kind).cmp(&resource_kind_order(&b.kind)).then(a.name.cmp(&b.name)));
    Ok(resources)
}

#[tauri::command]
fn list_user_dictionaries(app: AppHandle) -> Result<Vec<UserDictionary>, String> {
    read_user_dictionaries(&app)
}

#[tauri::command]
fn add_user_dictionary(app: AppHandle, path: String) -> Result<Vec<UserDictionary>, String> {
    let file = required_existing_file(Some(path.as_str()), "请选择有效的字典文件。")?;
    let mut dictionaries = read_user_dictionaries(&app)?;
    let canonical = path_string(&file);

    if !dictionaries.iter().any(|item| item.path == canonical) {
        let metadata = fs::metadata(&file).map_err(|err| err.to_string())?;
        dictionaries.push(UserDictionary {
            name: file
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| canonical.clone()),
            path: canonical,
            size: metadata.len(),
            added_at: now_string(),
        });
        write_json(&library_path(&app)?, &dictionaries)?;
    }

    Ok(dictionaries)
}

#[tauri::command]
fn remove_user_dictionary(app: AppHandle, path: String) -> Result<Vec<UserDictionary>, String> {
    let mut dictionaries = read_user_dictionaries(&app)?;
    dictionaries.retain(|item| item.path != path);
    write_json(&library_path(&app)?, &dictionaries)?;
    Ok(dictionaries)
}

#[tauri::command]
fn start_attack(
    app: AppHandle,
    state: State<'_, AppState>,
    config: AttackConfig,
) -> Result<StartResponse, String> {
    start_attack_inner(app, Arc::clone(&state.active_task), config)
}

#[tauri::command]
fn rerun_task(
    app: AppHandle,
    state: State<'_, AppState>,
    task_id: String,
) -> Result<StartResponse, String> {
    let manifest = get_task(app.clone(), task_id)?;
    start_attack_inner(app, Arc::clone(&state.active_task), manifest.config)
}

#[tauri::command]
fn restore_attack(
    app: AppHandle,
    state: State<'_, AppState>,
    task_id: String,
) -> Result<StartResponse, String> {
    validate_task_id(&task_id)?;
    ensure_no_active_task(&state.active_task)?;

    let mut manifest = get_task(app.clone(), task_id.clone())?;
    let restore_path = PathBuf::from(&manifest.paths.restore_path);
    if !restore_path.is_file() {
        return Err("该任务没有可恢复的 session。".into());
    }

    let hashcat_dir = find_hashcat_dir(&app)?;
    let hashcat_exe = hashcat_dir.join("hashcat.exe");
    let log_path = PathBuf::from(&manifest.paths.log_path);
    let outfile_path = PathBuf::from(&manifest.paths.outfile_path);
    let args = vec![
        "--restore".to_string(),
        "--session".to_string(),
        manifest.session_name.clone(),
        "--restore-file-path".to_string(),
        manifest.paths.restore_path.clone(),
    ];
    let command_preview = preview_command(&hashcat_exe, &args);

    manifest.status = "running".into();
    manifest.updated_at = now_string();
    manifest.started_at = manifest.updated_at.clone();
    manifest.ended_at = None;
    manifest.exit_code = None;
    manifest.exit_reason = None;
    manifest.command_preview = command_preview.clone();
    manifest.can_restore = true;
    save_manifest(&manifest)?;

    spawn_hashcat_process(
        app,
        Arc::clone(&state.active_task),
        hashcat_dir,
        hashcat_exe,
        args,
        manifest.task_id.clone(),
        outfile_path.clone(),
        log_path,
        command_preview.clone(),
    )?;

    Ok(StartResponse {
        task_id: manifest.task_id,
        command_preview,
        outfile_path: path_string(&outfile_path),
    })
}

#[tauri::command]
fn stop_attack(state: State<'_, AppState>, task_id: String) -> Result<bool, String> {
    let active = state
        .active_task
        .lock()
        .map_err(|_| "任务状态锁定失败。".to_string())?;

    let Some(task) = active.as_ref() else {
        return Ok(false);
    };

    if task.task_id != task_id {
        return Err("任务 ID 不匹配。".into());
    }

    task.stop_tx
        .send(StopSignal::Checkpoint)
        .map_err(|_| "停止信号发送失败，任务可能已经结束。".to_string())?;
    Ok(true)
}

#[tauri::command]
fn list_tasks(app: AppHandle) -> Result<Vec<TaskManifest>, String> {
    let tasks_dir = app_tasks_dir(&app)?;
    fs::create_dir_all(&tasks_dir).map_err(|err| err.to_string())?;
    let mut tasks = Vec::new();

    for entry in fs::read_dir(&tasks_dir).map_err(|err| err.to_string())? {
        let entry = entry.map_err(|err| err.to_string())?;
        let manifest_path = entry.path().join("manifest.json");
        if manifest_path.is_file() {
            if let Ok(text) = fs::read_to_string(&manifest_path) {
                if let Ok(mut manifest) = serde_json::from_str::<TaskManifest>(&text) {
                    manifest.can_restore = PathBuf::from(&manifest.paths.restore_path).is_file();
                    tasks.push(manifest);
                }
            }
        }
    }

    tasks.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(tasks)
}

#[tauri::command]
fn get_task(app: AppHandle, task_id: String) -> Result<TaskManifest, String> {
    validate_task_id(&task_id)?;
    let manifest_path = app_task_dir(&app, &task_id)?.join("manifest.json");
    let text = fs::read_to_string(&manifest_path).map_err(|_| format!("未找到任务：{task_id}"))?;
    let mut manifest =
        serde_json::from_str::<TaskManifest>(&text).map_err(|err| err.to_string())?;
    manifest.can_restore = PathBuf::from(&manifest.paths.restore_path).is_file();
    Ok(manifest)
}

#[tauri::command]
fn delete_task(
    app: AppHandle,
    state: State<'_, AppState>,
    task_id: String,
) -> Result<Vec<TaskManifest>, String> {
    validate_task_id(&task_id)?;
    if let Ok(active) = state.active_task.lock() {
        if active
            .as_ref()
            .map(|task| task.task_id == task_id)
            .unwrap_or(false)
        {
            return Err("不能删除正在运行的任务。".into());
        }
    }

    let task_dir = app_task_dir(&app, &task_id)?;
    if task_dir.is_dir() {
        fs::remove_dir_all(&task_dir).map_err(|err| err.to_string())?;
    }
    list_tasks(app)
}

#[tauri::command]
fn read_results(app: AppHandle, task_id: String) -> Result<ResultsResponse, String> {
    let manifest = get_task(app, task_id)?;
    let path = PathBuf::from(&manifest.paths.outfile_path);
    let content = if path.is_file() {
        fs::read_to_string(&path).map_err(|err| err.to_string())?
    } else {
        String::new()
    };

    Ok(ResultsResponse {
        path: path_string(&path),
        content,
    })
}

#[tauri::command]
fn read_task_log(app: AppHandle, task_id: String) -> Result<ResultsResponse, String> {
    let manifest = get_task(app, task_id)?;
    let path = PathBuf::from(&manifest.paths.log_path);
    let content = if path.is_file() {
        fs::read_to_string(&path).map_err(|err| err.to_string())?
    } else {
        String::new()
    };

    Ok(ResultsResponse {
        path: path_string(&path),
        content,
    })
}

#[tauri::command]
fn preview_text_file(path: String, allow_full: Option<bool>) -> Result<FilePreviewResponse, String> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err("预览文件不存在。".into());
    }

    const FULL_PREVIEW_LIMIT: u64 = 2 * 1024 * 1024;
    const PARTIAL_PREVIEW_LIMIT: u64 = 256 * 1024;
    const BUILTIN_PREVIEW_LIMIT: u64 = 96 * 1024;
    const PARTIAL_LINE_LIMIT: usize = 300;
    const BUILTIN_LINE_LIMIT: usize = 120;

    let metadata = fs::metadata(&path).map_err(|err| err.to_string())?;
    let file_size = metadata.len();
    let allow_full = allow_full.unwrap_or(false);

    if allow_full && file_size <= FULL_PREVIEW_LIMIT {
        let bytes = fs::read(&path).map_err(|err| err.to_string())?;
        let content = String::from_utf8_lossy(&bytes).to_string();
        let line_count = content.lines().count();
        return Ok(FilePreviewResponse {
            path: path_string(&path),
            content,
            truncated: false,
            line_count,
            file_size,
            preview_limit: FULL_PREVIEW_LIMIT,
        });
    }

    let max_bytes = if allow_full {
        PARTIAL_PREVIEW_LIMIT
    } else {
        BUILTIN_PREVIEW_LIMIT
    };
    let max_lines = if allow_full {
        PARTIAL_LINE_LIMIT
    } else {
        BUILTIN_LINE_LIMIT
    };
    let (content, line_count, truncated) = read_text_preview(&path, max_bytes as usize, max_lines)?;
    Ok(FilePreviewResponse {
        path: path_string(&path),
        content,
        truncated,
        line_count,
        file_size,
        preview_limit: max_bytes,
    })
}

fn read_text_preview(path: &Path, max_bytes: usize, max_lines: usize) -> Result<(String, usize, bool), String> {
    let file = fs::File::open(path).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    let mut content = String::new();
    let mut raw_line = Vec::new();
    let mut line_count = 0usize;
    let mut raw_bytes = 0usize;
    let mut truncated = false;

    loop {
        raw_line.clear();
        let read = reader.read_until(b'\n', &mut raw_line).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        if line_count >= max_lines || raw_bytes.saturating_add(read) > max_bytes {
            truncated = true;
            break;
        }
        raw_bytes += read;
        line_count += 1;
        content.push_str(&String::from_utf8_lossy(&raw_line));
    }

    Ok((content, line_count, truncated))
}

#[tauri::command]
fn import_custom_dictionary(app: AppHandle, source: String) -> Result<UserDictionary, String> {
    let source = required_existing_file(Some(source.as_str()), "请选择有效的字典文件。")?;
    let dest_dir = custom_dictionaries_dir(&app)?;
    let source_name = source
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "dictionary.txt".into());
    let dest_name = format!("{}-{source_name}", now_millis());
    let dest = dest_dir.join(dest_name);
    fs::copy(&source, &dest).map_err(|err| err.to_string())?;
    let metadata = fs::metadata(&dest).map_err(|err| err.to_string())?;
    Ok(UserDictionary {
        name: source_name,
        path: path_string(&dest),
        size: metadata.len(),
        added_at: now_string(),
    })
}

#[tauri::command]
fn save_custom_dictionary_content(app: AppHandle, path: String, content: String) -> Result<UserDictionary, String> {
    let path = PathBuf::from(path);
    ensure_custom_dictionary_path(&app, &path)?;
    fs::write(&path, content).map_err(|err| err.to_string())?;
    let metadata = fs::metadata(&path).map_err(|err| err.to_string())?;
    Ok(UserDictionary {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "dictionary.txt".into()),
        path: path_string(&path),
        size: metadata.len(),
        added_at: now_string(),
    })
}

#[tauri::command]
fn append_custom_dictionary_content(app: AppHandle, path: String, content: String) -> Result<UserDictionary, String> {
    let path = PathBuf::from(path);
    ensure_custom_dictionary_path(&app, &path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| err.to_string())?;
    file.write_all(content.as_bytes()).map_err(|err| err.to_string())?;
    let metadata = fs::metadata(&path).map_err(|err| err.to_string())?;
    Ok(UserDictionary {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "dictionary.txt".into()),
        path: path_string(&path),
        size: metadata.len(),
        added_at: now_string(),
    })
}

#[tauri::command]
fn delete_custom_dictionary_file(app: AppHandle, path: String) -> Result<(), String> {
    let path = PathBuf::from(path);
    ensure_custom_dictionary_path(&app, &path)?;
    if path.is_file() {
        fs::remove_file(path).map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn dedupe_custom_dictionary(app: AppHandle, path: String) -> Result<DictionaryDedupeResponse, String> {
    let path = PathBuf::from(path);
    ensure_custom_dictionary_path(&app, &path)?;
    if !path.is_file() {
        return Err("字典文件不存在。".into());
    }

    let input = fs::File::open(&path).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(input);
    let temp_path = path.with_extension(format!(
        "{}.dedupe.tmp",
        path.extension()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "txt".into())
    ));
    let output = fs::File::create(&temp_path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(output);
    let mut seen = HashSet::new();
    let mut line = String::new();
    let mut original_lines = 0u64;
    let mut unique_lines = 0u64;

    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        original_lines += 1;
        let candidate = line.trim_end_matches(['\r', '\n']).to_string();
        if seen.insert(candidate.clone()) {
            writer
                .write_all(candidate.as_bytes())
                .and_then(|_| writer.write_all(b"\n"))
                .map_err(|err| err.to_string())?;
            unique_lines += 1;
        }
    }

    writer.flush().map_err(|err| err.to_string())?;
    fs::rename(&temp_path, &path).map_err(|err| {
        let _ = fs::remove_file(&temp_path);
        err.to_string()
    })?;
    let metadata = fs::metadata(&path).map_err(|err| err.to_string())?;

    Ok(DictionaryDedupeResponse {
        path: path_string(&path),
        original_lines,
        unique_lines,
        removed_lines: original_lines.saturating_sub(unique_lines),
        size: metadata.len(),
    })
}

#[tauri::command]
fn get_ai_settings(app: AppHandle) -> Result<AiSettings, String> {
    let path = ai_settings_path(&app)?;
    if !path.is_file() {
        return Ok(default_ai_settings());
    }
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    serde_json::from_str(&text).map_err(|err| err.to_string())
}

#[tauri::command]
fn save_ai_settings(app: AppHandle, settings: AiSettings) -> Result<AiSettings, String> {
    let settings = normalize_ai_settings(settings);
    if settings.base_url.is_empty() {
        return Err("请填写 AI Base URL。".into());
    }
    if settings.model.is_empty() {
        return Err("请填写模型名称。".into());
    }

    write_json(&ai_settings_path(&app)?, &settings)?;
    Ok(settings)
}

#[tauri::command]
fn list_ai_models(settings: AiSettings) -> Result<AiModelsResponse, String> {
    let settings = normalize_ai_settings(settings);
    if settings.base_url.is_empty() {
        return Err("请填写 AI Base URL。".into());
    }
    if settings.api_key.trim().is_empty() {
        return Err("请填写 API Key。".into());
    }

    let mut command = Command::new("curl.exe");
    hide_console(&mut command);
    let output = command
        .arg("-sS")
        .arg("--ssl-no-revoke")
        .arg("--max-time")
        .arg("45")
        .arg("-H")
        .arg(format!("Authorization: Bearer {}", settings.api_key))
        .arg(models_url(&settings.base_url))
        .output()
        .map_err(|err| format!("调用 curl.exe 失败：{err}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!("模型列表请求失败：{stderr}{stdout}"));
    }

    let value: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("模型列表响应不是有效 JSON：{err}\n{stdout}"))?;
    let mut models = value
        .get("data")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    models.sort();
    models.dedup();
    if models.is_empty() {
        return Err(format!("模型列表为空或响应格式不兼容：{stdout}"));
    }

    Ok(AiModelsResponse { models })
}

#[tauri::command]
fn analyze_task_log(app: AppHandle, task_id: String) -> Result<AiAnalysisResponse, String> {
    let settings = get_ai_settings(app.clone())?;
    if settings.api_key.trim().is_empty() {
        return Err("请先在 AI 设置中填写 API Key。".into());
    }

    let manifest = get_task(app.clone(), task_id)?;
    let log_path = PathBuf::from(&manifest.paths.log_path);
    let log_content = if log_path.is_file() {
        fs::read_to_string(&log_path).map_err(|err| err.to_string())?
    } else {
        String::new()
    };
    if log_content.trim().is_empty() {
        return Err("当前任务暂无日志可分析。".into());
    }

    let max_chars = 16_000;
    let log_for_prompt = if log_content.chars().count() > max_chars {
        let tail = log_content
            .chars()
            .rev()
            .take(max_chars)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        format!("日志较长，以下为最后 {max_chars} 个字符：\n{tail}")
    } else {
        log_content
    };

    let user_prompt = format!(
        "请分析这个 hashcat GUI 任务日志，帮助用户判断任务是否配置正确、失败原因、下一步该怎么做。\n\
         请用中文回答，结构包括：结论、关键证据、可能原因、建议操作。\n\
         任务信息：task_id={}，hash_mode=-m {}，attack_mode=-a {}，status={}。\n\n日志：\n{}",
        manifest.task_id,
        manifest.config.hash_mode,
        manifest.config.attack_mode,
        manifest.status,
        log_for_prompt
    );

    let user_prompt = format!(
        "{user_prompt}\n\nOutput constraints: Chinese only. Use compact plain text, no Markdown code fences, no repeated characters or words, no repeated lines, and no more than one blank line between sections."
    );

    let body = serde_json::json!({
        "model": settings.model,
        "messages": [
            {
                "role": "system",
                "content": "你是 hashcat 使用和日志排错助手。你只根据用户提供的日志和任务参数分析，不编造未出现的输出。"
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.2
    });

    let request_path = app_data_dir(&app)?.join("ai-request.json");
    fs::write(
        &request_path,
        serde_json::to_string(&body).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;

    let endpoint = chat_completions_url(&settings.base_url);
    let mut command = Command::new("curl.exe");
    hide_console(&mut command);
    let output = command
        .arg("-sS")
        .arg("--ssl-no-revoke")
        .arg("--max-time")
        .arg("90")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg(format!("Authorization: Bearer {}", settings.api_key))
        .arg("--data-binary")
        .arg(format!("@{}", path_string(&request_path)))
        .arg(endpoint)
        .output()
        .map_err(|err| format!("调用 curl.exe 失败：{err}"))?;

    let _ = fs::remove_file(&request_path);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!("AI 请求失败：{stderr}{stdout}"));
    }

    let value: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("AI 响应不是有效 JSON：{err}\n{stdout}"))?;
    let content = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("AI 响应中没有 choices[0].message.content：{stdout}"))?;

    Ok(AiAnalysisResponse {
        content: normalize_ai_visible_text(content),
    })
}

#[tauri::command]
fn consult_hash_with_ai(app: AppHandle, config: AiHashConsultConfig) -> Result<AiAnalysisResponse, String> {
    let settings = get_ai_settings(app.clone())?;
    if settings.api_key.trim().is_empty() {
        return Err("请先在 AI 设置中填写 API Key。".into());
    }

    let hash_file_preview = if let Some(path) = config.hash_file.as_deref().filter(|value| !value.trim().is_empty()) {
        let path = PathBuf::from(path);
        if path.is_file() {
            let (content, _, truncated) = read_text_preview(&path, 128 * 1024, 80)?;
            if truncated {
                format!("文件：{}\n以下为前 80 行预览：\n{}", path_string(&path), content)
            } else {
                format!("文件：{}\n内容：\n{}", path_string(&path), content)
            }
        } else {
            format!("用户提供的 hash 文件不存在：{}", path_string(&path))
        }
    } else {
        "未选择 hash 文件。".into()
    };

    let hash_text = config
        .hash_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("未粘贴 hash 文本。");
    let mask = config
        .mask
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("未填写 mask。");
    let dictionary_path = config
        .dictionary_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("未选择字典。");
    let question = config.question.trim();
    let question = if question.is_empty() {
        "请根据这些信息判断 hash 类型、攻击方式和候选设计是否合理，并给出下一步建议。"
    } else {
        question
    };

    let user_prompt = format!(
        "请作为 hashcat 使用助手分析以下信息。只根据用户提供的信息推断，不要编造不存在的日志或结果。\n\
         输出要求：中文；结构包含：结论、关键信息、可能的 hash 类型/模式判断、攻击方式建议、需要用户补充的信息。\n\n\
         用户问题：{question}\n\n\
         当前配置：\n-m {hash_mode}\n-a {attack_mode}\nmask: {mask}\ndictionary: {dictionary_path}\nrules: {rules}\n\n\
         粘贴的 hash 文本：\n{hash_text}\n\nhash 文件信息：\n{hash_file_preview}",
        hash_mode = config.hash_mode,
        attack_mode = config.attack_mode,
        rules = if config.rule_paths.is_empty() { "无".into() } else { config.rule_paths.join(", ") },
    );

    let body = serde_json::json!({
        "model": settings.model,
        "messages": [
            {
                "role": "system",
                "content": "你是 hashcat 使用和哈希识别辅助助手。你可以解释攻击模式、mask、字典和规则，但必须提示用户 hash 类型仅能基于样本格式初步判断，不能保证准确。最终答案必须写入 assistant message content。"
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.2
    });

    let request_path = app_data_dir(&app)?.join("ai-hash-consult-request.json");
    fs::write(
        &request_path,
        serde_json::to_string(&body).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;

    let endpoint = chat_completions_url(&settings.base_url);
    let mut command = Command::new("curl.exe");
    hide_console(&mut command);
    let output = command
        .arg("-sS")
        .arg("--ssl-no-revoke")
        .arg("--max-time")
        .arg("90")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg(format!("Authorization: Bearer {}", settings.api_key))
        .arg("--data-binary")
        .arg(format!("@{}", path_string(&request_path)))
        .arg(endpoint)
        .output()
        .map_err(|err| format!("调用 curl.exe 失败：{err}"))?;

    let _ = fs::remove_file(&request_path);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!("AI 请求失败：{stderr}{stdout}"));
    }

    let value: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("AI 响应不是有效 JSON：{err}\n{stdout}"))?;
    let content = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .filter(|content| !content.trim().is_empty())
        .ok_or_else(|| format!("AI 响应中没有 choices[0].message.content：{stdout}"))?;

    Ok(AiAnalysisResponse {
        content: content.to_string(),
    })
}

#[tauri::command]
fn start_ai_hash_consult(app: AppHandle, config: AiHashConsultConfig) -> Result<String, String> {
    let settings = get_ai_settings(app.clone())?;
    if settings.api_key.trim().is_empty() {
        return Err("请先在 AI 设置中填写 API Key。".into());
    }

    let task_id = format!("help-ai-{}", now_millis());
    let body = inject_ai_model(build_hash_consult_body(&config, true)?, &settings.model);
    let request_path = app_data_dir(&app)?.join(format!("ai-hash-consult-{task_id}.json"));
    fs::write(
        &request_path,
        serde_json::to_string(&body).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;

    let endpoint = chat_completions_url(&settings.base_url);
    let stream_task_id = task_id.clone();
    thread::spawn(move || {
        let _ = app.emit(
            "ai-analysis-start",
            AiAnalysisPayload {
                task_id: stream_task_id.clone(),
                text: String::new(),
            },
        );

        if let Err(error) = run_ai_log_analysis_stream(
            app.clone(),
            stream_task_id.clone(),
            settings,
            endpoint,
            request_path,
        ) {
            let _ = app.emit(
                "ai-analysis-error",
                AiAnalysisErrorPayload {
                    task_id: stream_task_id.clone(),
                    error,
                },
            );
        }

        let _ = app.emit(
            "ai-analysis-finish",
            AiAnalysisPayload {
                task_id: stream_task_id,
                text: String::new(),
            },
        );
    });

    Ok(task_id)
}

fn build_hash_consult_body(config: &AiHashConsultConfig, stream: bool) -> Result<Value, String> {
    let gui_config_instruction = "At the end, output one standalone JSON object for the GUI to parse. Do not wrap it in Markdown code fences. Use exactly this shape and fill unknown fields with empty strings or empty arrays:\n{\"hashcatGuiTaskConfig\":{\"hashMode\":\"0\",\"attackMode\":3,\"hashText\":\"\",\"hashFile\":\"\",\"mask\":\"\",\"dictionaryPath\":\"\",\"rulePaths\":[]}}";
    let hash_file_preview = if let Some(path) = config.hash_file.as_deref().filter(|value| !value.trim().is_empty()) {
        let path = PathBuf::from(path);
        if path.is_file() {
            let (content, _, truncated) = read_text_preview(&path, 128 * 1024, 80)?;
            if truncated {
                format!("文件：{}\n以下为前 80 行预览：\n{}", path_string(&path), content)
            } else {
                format!("文件：{}\n内容：\n{}", path_string(&path), content)
            }
        } else {
            format!("用户提供的 hash 文件不存在：{}", path_string(&path))
        }
    } else {
        "未选择 hash 文件。".into()
    };

    let hash_text = config
        .hash_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("未粘贴 hash 文本。");
    let mask = config
        .mask
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("未填写 mask。");
    let dictionary_path = config
        .dictionary_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("未选择字典。");
    let question = config.question.trim();
    let question = if question.is_empty() {
        "请根据这些信息判断 hash 类型、攻击方式和候选设计是否合理，并给出下一步建议。"
    } else {
        question
    };

    let user_prompt = format!(
        "请作为 hashcat 使用助手分析以下信息。只根据用户提供的信息推断，不要编造不存在的日志或结果。\n\
         输出要求：中文；结构包含：结论、关键信息、可能的 hash 类型/模式判断、攻击方式建议、需要用户补充的信息。\n\n\
         用户问题：{question}\n\n\
         当前配置：\n-m {hash_mode}\n-a {attack_mode}\nmask: {mask}\ndictionary: {dictionary_path}\nrules: {rules}\n\n\
         粘贴的 hash 文本：\n{hash_text}\n\nhash 文件信息：\n{hash_file_preview}",
        hash_mode = config.hash_mode,
        attack_mode = config.attack_mode,
        rules = if config.rule_paths.is_empty() { "无".into() } else { config.rule_paths.join(", ") },
    );

    let user_prompt = format!("{user_prompt}\n\n{gui_config_instruction}");

    Ok(serde_json::json!({
        "model": get_model_placeholder(),
        "messages": [
            {
                "role": "system",
                "content": "你是 hashcat 使用和哈希识别辅助助手。你可以解释攻击模式、mask、字典和规则，但必须提示用户 hash 类型仅能基于样本格式初步判断，不能保证准确。最终答案必须写入 assistant message content。"
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.2,
        "stream": stream
    }))
}

fn get_model_placeholder() -> String {
    "__HASHCAT_GUI_MODEL__".into()
}

fn inject_ai_model(mut body: Value, model: &str) -> Value {
    if let Some(object) = body.as_object_mut() {
        object.insert("model".into(), Value::String(model.to_string()));
    }
    body
}

#[tauri::command]
fn start_ai_log_analysis(app: AppHandle, task_id: String) -> Result<(), String> {
    let settings = get_ai_settings(app.clone())?;
    if settings.api_key.trim().is_empty() {
        return Err("请先在 AI 设置中填写 API Key。".into());
    }

    let manifest = get_task(app.clone(), task_id.clone())?;
    let log_path = PathBuf::from(&manifest.paths.log_path);
    let log_content = if log_path.is_file() {
        fs::read_to_string(&log_path).map_err(|err| err.to_string())?
    } else {
        String::new()
    };
    if log_content.trim().is_empty() {
        return Err("当前任务暂无日志可分析。".into());
    }

    let max_chars = 16_000;
    let log_for_prompt = if log_content.chars().count() > max_chars {
        let tail = log_content
            .chars()
            .rev()
            .take(max_chars)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        format!("日志较长，以下为最后 {max_chars} 个字符：\n{tail}")
    } else {
        log_content
    };

    let user_prompt = format!(
        "请分析这个 hashcat GUI 任务日志，帮助用户判断任务配置是否正确、失败原因、下一步该怎么做。\n\
         必须用普通文本 content 输出中文分析，不要只返回隐藏 reasoning。结构包括：结论、关键证据、可能原因、建议操作。\n\
         任务信息：task_id={}，hash_mode=-m {}，attack_mode=-a {}，status={}。\n\n日志：\n{}",
        manifest.task_id,
        manifest.config.hash_mode,
        manifest.config.attack_mode,
        manifest.status,
        log_for_prompt
    );

    let user_prompt = format!(
        "{user_prompt}\n\nOutput constraints: Chinese only. Use compact plain text, no Markdown code fences, no repeated characters or words, no repeated lines, and no more than one blank line between sections."
    );

    let body = serde_json::json!({
        "model": settings.model,
        "messages": [
            {
                "role": "system",
                "content": "你是 hashcat 使用和日志排错助手。只根据用户提供的日志和任务参数分析，不编造未出现的输出。最终答案必须写入 assistant message content。"
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.2,
        "stream": true
    });

    let request_path = app_data_dir(&app)?.join(format!("ai-request-{task_id}.json"));
    fs::write(
        &request_path,
        serde_json::to_string(&body).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;

    let endpoint = chat_completions_url(&settings.base_url);
    thread::spawn(move || {
        let _ = app.emit(
            "ai-analysis-start",
            AiAnalysisPayload {
                task_id: task_id.clone(),
                text: String::new(),
            },
        );

        if let Err(error) = run_ai_log_analysis_stream(
            app.clone(),
            task_id.clone(),
            settings,
            endpoint,
            request_path,
        ) {
            let _ = app.emit(
                "ai-analysis-error",
                AiAnalysisErrorPayload {
                    task_id: task_id.clone(),
                    error,
                },
            );
        }

        let _ = app.emit(
            "ai-analysis-finish",
            AiAnalysisPayload {
                task_id,
                text: String::new(),
            },
        );
    });

    Ok(())
}

fn run_ai_log_analysis_stream(
    app: AppHandle,
    task_id: String,
    settings: AiSettings,
    endpoint: String,
    request_path: PathBuf,
) -> Result<(), String> {
    let mut command = Command::new("curl.exe");
    hide_console(&mut command);
    let mut child = command
        .arg("-sS")
        .arg("--no-buffer")
        .arg("--ssl-no-revoke")
        .arg("--max-time")
        .arg("180")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg(format!("Authorization: Bearer {}", settings.api_key))
        .arg("--data-binary")
        .arg(format!("@{}", path_string(&request_path)))
        .arg(endpoint)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("调用 curl.exe 失败：{err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "无法读取 AI 响应流。".to_string())?;
    let stderr_reader = child.stderr.take().map(|mut stream| {
        thread::spawn(move || {
            let mut text = String::new();
            let _ = stream.read_to_string(&mut text);
            text
        })
    });

    let mut full_stdout = String::new();
    let mut emitted_text = String::new();
    let mut last_chunk = String::new();
    let mut received_text = false;
    for line_result in BufReader::new(stdout).lines() {
        let line = line_result.map_err(|err| err.to_string())?;
        full_stdout.push_str(&line);
        full_stdout.push('\n');

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let payload = trimmed.strip_prefix("data:").map(str::trim).unwrap_or(trimmed);
        if payload == "[DONE]" {
            break;
        }

        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            continue;
        };

        if let Some(text) = extract_ai_text(&value) {
            if let Some(text) = normalize_ai_stream_chunk(&text, &mut emitted_text, &mut last_chunk) {
                received_text = true;
                let _ = app.emit(
                    "ai-analysis-delta",
                    AiAnalysisPayload {
                        task_id: task_id.clone(),
                        text,
                    },
                );
            }
        }
    }

    let status = child.wait().map_err(|err| err.to_string())?;
    let stderr = stderr_reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    let _ = fs::remove_file(&request_path);

    if !status.success() {
        return Err(format!("AI 请求失败：{stderr}{full_stdout}"));
    }

    if !received_text {
        if let Ok(value) = serde_json::from_str::<Value>(full_stdout.trim()) {
            if let Some(text) = extract_ai_text(&value) {
                if let Some(text) =
                    normalize_ai_stream_chunk(&text, &mut emitted_text, &mut last_chunk)
                {
                    let _ = app.emit("ai-analysis-delta", AiAnalysisPayload { task_id, text });
                    return Ok(());
                }
            }
        }

        return Err(format!(
            "AI 返回了空内容。这个兼容接口可能只返回了隐藏 reasoning，或者不兼容 chat/completions 的 message.content/delta.content。原始响应：{}",
            full_stdout.trim()
        ));
    }

    Ok(())
}

fn normalize_ai_stream_chunk(
    text: &str,
    emitted_text: &mut String,
    last_chunk: &mut String,
) -> Option<String> {
    if text.is_empty() {
        return None;
    }

    let mut delta = if text.starts_with(emitted_text.as_str()) && text.len() > emitted_text.len() {
        text[emitted_text.len()..].to_string()
    } else if text == emitted_text || text == last_chunk {
        String::new()
    } else {
        text.to_string()
    };

    delta = normalize_ai_stream_delta(&delta);

    if delta.is_empty() {
        return None;
    }

    if delta == *last_chunk {
        return None;
    }

    emitted_text.push_str(&delta);
    *last_chunk = delta.clone();
    Some(delta)
}

fn normalize_ai_stream_delta(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    let mut normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    if has_ai_duplicate_artifacts(&normalized) {
        normalized = collapse_repeated_cjk(&normalized);
        normalized = collapse_repeated_technical_tokens(&normalized);
        normalized = collapse_tripled_short_tokens(&normalized);
        normalized = collapse_repeated_text_runs(&normalized);
        normalized = collapse_repeated_technical_tokens(&normalized);
    }
    collapse_excessive_newlines(&normalized)
}

fn normalize_ai_visible_text(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    let normalized = normalize_ai_stream_delta(text);
    compact_ai_text_lines(&normalized)
}

fn has_ai_duplicate_artifacts(text: &str) -> bool {
    if count_repeated_cjk_pairs(text) >= 3 {
        return true;
    }

    let lower = text.to_ascii_lowercase();
    if [
        "task task_",
        "hash hash_",
        "attack attack_",
        "status status_",
        "mode mode_",
        "rockyou rockyou_",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }

    count_repeated_text_runs(text) >= 3
}

fn count_repeated_cjk_pairs(text: &str) -> usize {
    let mut count = 0;
    let mut previous = None;
    for ch in text.chars() {
        if Some(ch) == previous && is_cjk(ch) {
            count += 1;
        }
        previous = Some(ch);
    }
    count
}

fn collapse_repeated_cjk(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::new();
    let mut previous = None;
    let mut index = 0;

    while index < chars.len() {
        let ch = chars[index];
        if is_cjk(ch)
            && index + 3 < chars.len()
            && chars[index + 1] == ' '
            && chars[index + 2] == ch
            && is_cjk(chars[index + 3])
        {
            output.push(ch);
            previous = Some(ch);
            index += 3;
            continue;
        }
        if Some(ch) == previous && (is_cjk(ch) || is_cjk_punctuation(ch)) {
            index += 1;
            continue;
        }
        output.push(ch);
        previous = Some(ch);
        index += 1;
    }
    output
}

fn collapse_repeated_technical_tokens(text: &str) -> String {
    let mut normalized = text.to_string();
    for token in ["task", "hash", "attack", "status", "mode", "rockyou"] {
        normalized = normalized.replace(&format!("{token} {token}_"), &format!("{token}_"));
    }
    for (from, to) in [
        ("_id_id", "_id"),
        ("_mode_mode", "_mode"),
        ("_status_status", "_status"),
        (".txt.txt", ".txt"),
        ("task--", "task-"),
        ("--mm", "-m"),
        ("--aa", "-a"),
        ("-m 00", "-m 0"),
        ("-a 00", "-a 0"),
    ] {
        normalized = normalized.replace(from, to);
    }
    normalized
}

fn count_repeated_text_runs(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut count = 0;
    let mut index = 0;

    while index < chars.len() {
        let mut found = false;
        let max_len = 16.min((chars.len() - index) / 2);
        for len in (2..=max_len).rev() {
            if chars[index..index + len] == chars[index + len..index + len * 2]
                && has_collapsible_content(&chars[index..index + len])
            {
                count += 1;
                index += len * 2;
                found = true;
                break;
            }
        }
        if !found {
            index += 1;
        }
        if count >= 3 {
            break;
        }
    }

    count
}

fn collapse_repeated_text_runs(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::new();
    let mut index = 0;

    while index < chars.len() {
        let mut replaced = false;
        let max_len = 24.min((chars.len() - index) / 2);
        for len in (2..=max_len).rev() {
            if chars[index..index + len] == chars[index + len..index + len * 2]
                && has_collapsible_content(&chars[index..index + len])
            {
                output.extend(chars[index..index + len].iter());
                index += len * 2;
                replaced = true;
                break;
            }
        }
        if !replaced {
            output.push(chars[index]);
            index += 1;
        }
    }

    output
}

fn has_collapsible_content(chars: &[char]) -> bool {
    chars
        .iter()
        .any(|ch| ch.is_ascii_alphanumeric() || is_cjk(*ch))
}

fn is_cjk(ch: char) -> bool {
    ('\u{3400}'..='\u{9fff}').contains(&ch)
}

fn is_cjk_punctuation(ch: char) -> bool {
    matches!(ch, '：' | '，' | '。' | '、' | '；' | '！' | '？')
}

fn collapse_excessive_newlines(text: &str) -> String {
    let mut output = String::new();
    let mut newline_count = 0;
    for ch in text.chars() {
        if ch == '\n' {
            newline_count += 1;
            if newline_count <= 2 {
                output.push(ch);
            }
        } else {
            newline_count = 0;
            output.push(ch);
        }
    }
    output
}

fn compact_ai_text_lines(text: &str) -> String {
    let mut lines = Vec::new();
    let mut previous = String::new();
    let mut last_was_blank = false;

    for raw_line in text.split('\n') {
        let line = collapse_horizontal_spaces(raw_line.trim_end());
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !lines.is_empty() && !last_was_blank {
                lines.push(String::new());
                last_was_blank = true;
            }
            previous.clear();
            continue;
        }
        if trimmed == previous {
            continue;
        }
        previous = trimmed.to_string();
        lines.push(line);
        last_was_blank = false;
    }

    lines.join("\n")
}

fn collapse_horizontal_spaces(text: &str) -> String {
    let mut output = String::new();
    let mut in_space = false;
    for ch in text.chars() {
        if ch == ' ' || ch == '\t' {
            if !in_space {
                output.push(' ');
                in_space = true;
            }
        } else {
            output.push(ch);
            in_space = false;
        }
    }
    output
}

fn collapse_tripled_short_tokens(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::new();
    let mut index = 0;

    while index < chars.len() {
        let mut replaced = false;
        for len in (1..=8).rev() {
            if index + len * 3 <= chars.len()
                && chars[index..index + len] == chars[index + len..index + len * 2]
                && chars[index..index + len] == chars[index + len * 2..index + len * 3]
            {
                output.extend(chars[index..index + len].iter());
                index += len * 3;
                replaced = true;
                break;
            }
        }
        if !replaced {
            output.push(chars[index]);
            index += 1;
        }
    }

    output
}

fn extract_ai_text(value: &Value) -> Option<String> {
    value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| {
            choice
                .get("delta")
                .and_then(|delta| delta.get("content"))
                .and_then(extract_content_value)
                .or_else(|| {
                    choice
                        .get("message")
                        .and_then(|message| message.get("content"))
                        .and_then(extract_content_value)
                })
        })
        .or_else(|| {
            value
                .get("output_text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

fn extract_content_value(content: &Value) -> Option<String> {
    if let Some(text) = content.as_str() {
        return Some(text.to_string());
    }

    content.as_array().map(|parts| {
        parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join("")
    })
}

#[tauri::command]
fn export_results(app: AppHandle, task_id: String, destination: String) -> Result<String, String> {
    let manifest = get_task(app, task_id)?;
    let source = PathBuf::from(&manifest.paths.outfile_path);
    if !source.is_file() {
        return Err("当前任务暂无结果文件。".into());
    }
    let destination = PathBuf::from(destination);
    fs::copy(&source, &destination).map_err(|err| err.to_string())?;
    Ok(path_string(&destination))
}

#[tauri::command]
fn open_task_dir(app: AppHandle, task_id: String) -> Result<(), String> {
    let manifest = get_task(app, task_id)?;
    let task_dir = PathBuf::from(&manifest.paths.task_dir);
    if !task_dir.is_dir() {
        return Err("任务目录不存在。".into());
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("explorer.exe")
            .arg(&task_dir)
            .spawn()
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = task_dir;
        Err("打开目录当前仅支持 Windows。".into())
    }
}

fn start_attack_inner(
    app: AppHandle,
    active_task: Arc<Mutex<Option<RunningTask>>>,
    config: AttackConfig,
) -> Result<StartResponse, String> {
    validate_config(&config)?;
    ensure_no_active_task(&active_task)?;

    let hashcat_dir = find_hashcat_dir(&app)?;
    let hashcat_exe = hashcat_dir.join("hashcat.exe");
    let task_id = new_task_id();
    let session_name = format!("hashcatgui-{task_id}");
    let task_dir = app_task_dir(&app, &task_id)?;
    fs::create_dir_all(&task_dir).map_err(|err| err.to_string())?;

    let hash_path = prepare_hash_input(&config, &task_dir)?;
    let outfile_path = task_dir.join("cracked.txt");
    let potfile_path = task_dir.join("hashcat.potfile");
    let restore_path = task_dir.join("hashcat.restore");
    let log_path = task_dir.join("run.log");
    let generated_candidates_path = if config.attack_mode == 9 {
        Some(generate_template_candidates(&config, &task_dir, &log_path, &app, &task_id)?)
    } else {
        None
    };

    let args = build_attack_args(
        &config,
        &hash_path,
        &outfile_path,
        &potfile_path,
        &restore_path,
        &session_name,
        generated_candidates_path.as_deref(),
    )?;
    let command_preview = preview_command(&hashcat_exe, &args);
    let now = now_string();

    let manifest = TaskManifest {
        task_id: task_id.clone(),
        task_name: config
            .task_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("Hashcat task")
            .to_string(),
        created_at: now.clone(),
        updated_at: now.clone(),
        started_at: now,
        ended_at: None,
        status: "running".into(),
        exit_code: None,
        exit_reason: None,
        can_restore: false,
        command_preview: command_preview.clone(),
        session_name,
        config,
        paths: TaskPaths {
            task_dir: path_string(&task_dir),
            hash_path: path_string(&hash_path),
            outfile_path: path_string(&outfile_path),
            potfile_path: path_string(&potfile_path),
            restore_path: path_string(&restore_path),
            log_path: path_string(&log_path),
        },
    };
    save_manifest(&manifest)?;

    spawn_hashcat_process(
        app,
        active_task,
        hashcat_dir,
        hashcat_exe,
        args,
        task_id.clone(),
        outfile_path.clone(),
        log_path,
        command_preview.clone(),
    )?;

    Ok(StartResponse {
        task_id,
        command_preview,
        outfile_path: path_string(&outfile_path),
    })
}

fn spawn_hashcat_process(
    app: AppHandle,
    active_task: Arc<Mutex<Option<RunningTask>>>,
    hashcat_dir: PathBuf,
    hashcat_exe: PathBuf,
    args: Vec<String>,
    task_id: String,
    outfile_path: PathBuf,
    log_path: PathBuf,
    command_preview: String,
) -> Result<(), String> {
    let mut command = Command::new(&hashcat_exe);
    hide_console(&mut command);
    let mut child = command
        .current_dir(&hashcat_dir)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("启动 hashcat 失败：{err}"))?;

    emit_log(&app, &task_id, "system", "hashcat process started", &log_path);
    emit_log(
        &app,
        &task_id,
        "system",
        &format!("command: {command_preview}"),
        &log_path,
    );
    emit_log(
        &app,
        &task_id,
        "system",
        &format!("workdir: {}", path_string(&hashcat_dir)),
        &log_path,
    );

    let mut stdin = child.stdin.take();

    if let Some(stdout) = child.stdout.take() {
        spawn_reader(
            app.clone(),
            task_id.clone(),
            "stdout",
            stdout,
            log_path.clone(),
        );
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_reader(
            app.clone(),
            task_id.clone(),
            "stderr",
            stderr,
            log_path.clone(),
        );
    }

    let (stop_tx, stop_rx) = mpsc::channel();
    {
        let mut active = active_task
            .lock()
            .map_err(|_| "任务状态锁定失败。".to_string())?;
        *active = Some(RunningTask {
            task_id: task_id.clone(),
            stop_tx,
        });
    }

    let app_for_wait = app.clone();
    let task_id_for_wait = task_id.clone();
    let outfile_for_wait = outfile_path.clone();
    thread::spawn(move || {
        let mut stop_requested_at: Option<Instant> = None;

        loop {
            if stop_requested_at.is_none() {
                if let Ok(StopSignal::Checkpoint) = stop_rx.try_recv() {
                    stop_requested_at = Some(Instant::now());
                    emit_log(
                        &app_for_wait,
                        &task_id_for_wait,
                        "control",
                        "checkpoint requested",
                        &log_path,
                    );
                    if let Some(stdin) = stdin.as_mut() {
                        let _ = stdin.write_all(b"c");
                        let _ = stdin.flush();
                    } else {
                        let _ = child.kill();
                    }
                }
            }

            if stop_requested_at
                .map(|started| started.elapsed() > Duration::from_secs(12))
                .unwrap_or(false)
            {
                emit_log(
                    &app_for_wait,
                    &task_id_for_wait,
                    "control",
                    "force kill after checkpoint timeout",
                    &log_path,
                );
                let _ = child.kill();
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.code();
                    let reason = exit_reason(code, stop_requested_at.is_some());
                    let _ =
                        update_manifest_on_exit(&app_for_wait, &task_id_for_wait, code, &reason);
                    emit_log(
                        &app_for_wait,
                        &task_id_for_wait,
                        "system",
                        &format!("process exited: code={code:?}, reason={reason}"),
                        &log_path,
                    );
                    let _ = app_for_wait.emit(
                        "hashcat-exit",
                        ExitPayload {
                            task_id: task_id_for_wait.clone(),
                            code,
                            reason,
                            outfile_path: path_string(&outfile_for_wait),
                        },
                    );
                    clear_active_task(&active_task, &task_id_for_wait);
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(250)),
                Err(err) => {
                    let reason = format!("wait-error: {err}");
                    let _ =
                        update_manifest_on_exit(&app_for_wait, &task_id_for_wait, None, &reason);
                    emit_log(
                        &app_for_wait,
                        &task_id_for_wait,
                        "system",
                        &format!("process wait failed: {err}"),
                        &log_path,
                    );
                    let _ = app_for_wait.emit(
                        "hashcat-exit",
                        ExitPayload {
                            task_id: task_id_for_wait.clone(),
                            code: None,
                            reason,
                            outfile_path: path_string(&outfile_for_wait),
                        },
                    );
                    clear_active_task(&active_task, &task_id_for_wait);
                    break;
                }
            }
        }
    });

    Ok(())
}

fn spawn_reader<R>(
    app: AppHandle,
    task_id: String,
    stream: &'static str,
    reader: R,
    log_path: PathBuf,
) where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                if let Ok(data) = serde_json::from_str::<Value>(trimmed) {
                    let _ = app.emit(
                        "hashcat-status",
                        StatusPayload {
                            task_id: task_id.clone(),
                            data,
                        },
                    );
                }
            }

            append_log(&log_path, stream, &line);
            let _ = app.emit(
                "hashcat-log",
                LogPayload {
                    task_id: task_id.clone(),
                    stream: stream.to_string(),
                    line,
                },
            );
        }
    });
}

fn build_attack_args(
    config: &AttackConfig,
    hash_path: &Path,
    outfile_path: &Path,
    potfile_path: &Path,
    restore_path: &Path,
    session_name: &str,
    generated_candidates_path: Option<&Path>,
) -> Result<Vec<String>, String> {
    let hashcat_attack_mode = if config.attack_mode == 9 {
        0
    } else {
        config.attack_mode
    };
    let mut args = vec![
        "--status".to_string(),
        "--status-json".to_string(),
        "--status-timer=1".to_string(),
        "--logfile-disable".to_string(),
        "--session".to_string(),
        session_name.to_string(),
        "--potfile-path".to_string(),
        path_string(potfile_path),
        "--restore-file-path".to_string(),
        path_string(restore_path),
        "--outfile".to_string(),
        path_string(outfile_path),
        "-m".to_string(),
        config.hash_mode.trim().to_string(),
        "-a".to_string(),
        hashcat_attack_mode.to_string(),
    ];

    if config.optimized_kernel.unwrap_or(false) {
        args.push("-O".to_string());
    }

    if let Some(profile) = config.workload_profile {
        args.push("-w".to_string());
        args.push(profile.to_string());
    }

    if config.increment.unwrap_or(false) && matches!(config.attack_mode, 3 | 6 | 7) {
        args.push("--increment".to_string());
        if let Some(value) = config.increment_min {
            args.push("--increment-min".to_string());
            args.push(value.to_string());
        }
        if let Some(value) = config.increment_max {
            args.push("--increment-max".to_string());
            args.push(value.to_string());
        }
    }

    let device_types = config
        .device_types
        .iter()
        .map(|value| value.trim())
        .filter(|value| *value == "1" || *value == "2" || *value == "3")
        .collect::<Vec<_>>();
    if !device_types.is_empty() {
        args.push("-D".to_string());
        args.push(device_types.join(","));
    }

    if let Some(device_ids) = config
        .device_ids
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !device_ids
            .split(',')
            .all(|part| part.trim().parse::<u32>().is_ok())
        {
            return Err("设备编号只能填写数字，并用英文逗号分隔，例如 1,2。".into());
        }
        args.push("-d".to_string());
        args.push(device_ids.to_string());
    }

    push_custom_charsets(config, &mut args);

    if config.attack_mode == 0 {
        for rule in &config.rule_paths {
            let rule_path = required_existing_file(Some(rule.as_str()), "规则文件不存在。")?;
            args.push("-r".to_string());
            args.push(path_string(&rule_path));
        }
    }

    args.push(path_string(hash_path));

    match config.attack_mode {
        0 => {
            let dictionary_path =
                required_existing_file(config.dictionary_path.as_deref(), "请选择字典文件。")?;
            args.push(path_string(&dictionary_path));
        }
        3 => {
            if let Some(mask_file) = config
                .mask_file
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let mask_file = required_existing_file(Some(mask_file), "掩码文件不存在。")?;
                args.push(path_string(&mask_file));
            } else {
                let mask = config
                    .mask
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "请输入掩码，例如 ?l?l?l?l?d?d。".to_string())?;
                args.push(mask.to_string());
            }
        }
        6 => {
            let dictionary_path =
                required_existing_file(config.dictionary_path.as_deref(), "请选择字典文件。")?;
            args.push(path_string(&dictionary_path));
            push_mask_arg(config, &mut args)?;
        }
        7 => {
            push_mask_arg(config, &mut args)?;
            let dictionary_path =
                required_existing_file(config.dictionary_path.as_deref(), "请选择字典文件。")?;
            args.push(path_string(&dictionary_path));
        }
        9 => {
            let candidates = generated_candidates_path
                .ok_or_else(|| "模板候选文件尚未生成。".to_string())?;
            args.push(path_string(candidates));
        }
        _ => unreachable!(),
    }

    Ok(args)
}

fn push_mask_arg(config: &AttackConfig, args: &mut Vec<String>) -> Result<(), String> {
    if let Some(mask_file) = config
        .mask_file
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let mask_file = required_existing_file(Some(mask_file), "掩码文件不存在。")?;
        args.push(path_string(&mask_file));
    } else {
        let mask = config
            .mask
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "请输入掩码，例如 ?l?l?l?l?d?d。".to_string())?;
        args.push(mask.to_string());
    }
    Ok(())
}

fn push_custom_charsets(config: &AttackConfig, args: &mut Vec<String>) {
    for (index, value) in [
        config.custom_charset1.as_deref(),
        config.custom_charset2.as_deref(),
        config.custom_charset3.as_deref(),
        config.custom_charset4.as_deref(),
    ]
    .iter()
    .enumerate()
    {
        if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
            args.push(format!("-{}", index + 1));
            args.push(value.to_string());
        }
    }
}

fn validate_config(config: &AttackConfig) -> Result<(), String> {
    validate_hash_mode(&config.hash_mode)?;

    if !matches!(config.attack_mode, 0 | 3 | 6 | 7 | 9) {
        return Err("当前版本支持字典攻击、掩码攻击、Hybrid 攻击和模板候选攻击。".into());
    }

    if let Some(profile) = config.workload_profile {
        if !(1..=4).contains(&profile) {
            return Err("工作负载只能是 1 到 4。".into());
        }
    }

    if config.increment.unwrap_or(false) {
        if !matches!(config.attack_mode, 3 | 6 | 7) {
            return Err("递增掩码只支持掩码和 Hybrid 攻击。".into());
        }
        if config.increment_min == Some(0) || config.increment_max == Some(0) {
            return Err("递增长度必须大于 0。".into());
        }
        if let (Some(min), Some(max)) = (config.increment_min, config.increment_max) {
            if min > max {
                return Err("递增最小长度不能大于最大长度。".into());
            }
        }
    }

    if matches!(config.attack_mode, 0 | 6 | 7 | 9) {
        required_existing_file(config.dictionary_path.as_deref(), "请选择字典文件。")?;
    }

    if config.attack_mode == 0 {
        for rule in &config.rule_paths {
            required_existing_file(Some(rule.as_str()), "规则文件不存在。")?;
        }
    }

    if matches!(config.attack_mode, 3 | 6 | 7) {
        let has_mask_file = config
            .mask_file
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        if !has_mask_file {
            config
                .mask
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "请输入掩码或选择 .hcmask 文件。".to_string())?;
        }
    }

    if config.attack_mode == 9 {
        validate_template_mask(config.template_prefix_mask.as_deref())?;
        validate_template_mask(config.template_suffix_mask.as_deref())?;
        let has_prefix = config
            .template_prefix_mask
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        let has_suffix = config
            .template_suffix_mask
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        if !has_prefix && !has_suffix {
            return Err("模板候选至少需要填写前缀掩码或后缀掩码。".into());
        }
    }

    Ok(())
}

const MAX_TEMPLATE_CANDIDATES: u64 = 5_000_000;

fn generate_template_candidates(
    config: &AttackConfig,
    task_dir: &Path,
    log_path: &Path,
    app: &AppHandle,
    task_id: &str,
) -> Result<PathBuf, String> {
    let dictionary_path = required_existing_file(config.dictionary_path.as_deref(), "请选择字典文件。")?;
    let prefix_tokens = parse_template_mask(config.template_prefix_mask.as_deref().unwrap_or(""))?;
    let suffix_tokens = parse_template_mask(config.template_suffix_mask.as_deref().unwrap_or(""))?;
    let prefix_count = mask_combination_count(&prefix_tokens)?;
    let suffix_count = mask_combination_count(&suffix_tokens)?;
    let words = read_dictionary_words(&dictionary_path)?;
    if words.is_empty() {
        return Err("字典文件没有可用词条。".into());
    }

    let total = prefix_count
        .checked_mul(words.len() as u64)
        .and_then(|value| value.checked_mul(suffix_count))
        .ok_or_else(|| "模板候选数量过大。".to_string())?;
    if total > MAX_TEMPLATE_CANDIDATES {
        return Err(format!(
            "模板候选数量为 {total}，超过当前上限 {MAX_TEMPLATE_CANDIDATES}。请缩小前缀/后缀掩码或字典。"
        ));
    }

    let output_path = task_dir.join("generated_candidates.txt");
    emit_log(
        app,
        task_id,
        "system",
        &format!("generating template candidates: {total}"),
        log_path,
    );
    let file = fs::File::create(&output_path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);

    write_mask_combinations(&prefix_tokens, |prefix| {
        for word in &words {
            write_mask_combinations(&suffix_tokens, |suffix| {
                writeln!(writer, "{prefix}{word}{suffix}").map_err(|err| err.to_string())
            })?;
        }
        Ok(())
    })?;
    writer.flush().map_err(|err| err.to_string())?;

    emit_log(
        app,
        task_id,
        "system",
        &format!("template candidates written: {}", path_string(&output_path)),
        log_path,
    );
    Ok(output_path)
}

fn read_dictionary_words(path: &Path) -> Result<Vec<String>, String> {
    let file = fs::File::open(path).map_err(|err| err.to_string())?;
    let reader = BufReader::new(file);
    let mut words = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| err.to_string())?;
        let word = line.trim_end_matches(['\r', '\n']);
        if !word.trim().is_empty() {
            words.push(word.to_string());
        }
    }
    Ok(words)
}

fn validate_template_mask(mask: Option<&str>) -> Result<(), String> {
    parse_template_mask(mask.unwrap_or(""))?;
    Ok(())
}

fn parse_template_mask(mask: &str) -> Result<Vec<Vec<char>>, String> {
    let mut tokens = Vec::new();
    let mut chars = mask.trim().chars();
    while let Some(ch) = chars.next() {
        if ch != '?' {
            tokens.push(vec![ch]);
            continue;
        }
        let Some(kind) = chars.next() else {
            return Err("模板掩码不能以单独的 ? 结尾。".into());
        };
        let charset: Vec<char> = match kind {
            '?' => vec!['?'],
            'd' => ('0'..='9').collect(),
            'l' => ('a'..='z').collect(),
            'u' => ('A'..='Z').collect(),
            's' => r##" !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##.chars().collect(),
            'a' => (0x20u8..=0x7eu8).map(char::from).collect(),
            _ => {
                return Err(format!(
                    "模板掩码暂不支持 ?{kind}，首版支持 ?d、?l、?u、?s、?a 和 ??。"
                ))
            }
        };
        tokens.push(charset);
    }
    Ok(tokens)
}

fn mask_combination_count(tokens: &[Vec<char>]) -> Result<u64, String> {
    tokens.iter().try_fold(1u64, |acc, token| {
        acc.checked_mul(token.len() as u64)
            .ok_or_else(|| "模板掩码组合数过大。".to_string())
    })
}

fn write_mask_combinations<F>(tokens: &[Vec<char>], mut on_value: F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    fn walk<F>(
        tokens: &[Vec<char>],
        index: usize,
        current: &mut String,
        on_value: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(&str) -> Result<(), String>,
    {
        if index == tokens.len() {
            return on_value(current);
        }
        for ch in &tokens[index] {
            current.push(*ch);
            walk(tokens, index + 1, current, on_value)?;
            current.pop();
        }
        Ok(())
    }

    let mut current = String::new();
    walk(tokens, 0, &mut current, &mut on_value)
}

fn prepare_hash_input(config: &AttackConfig, task_dir: &Path) -> Result<PathBuf, String> {
    if let Some(text) = config.hash_text.as_deref() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            let path = task_dir.join("input.hash");
            fs::write(&path, format!("{trimmed}\n")).map_err(|err| err.to_string())?;
            return Ok(path);
        }
    }

    required_existing_file(
        config.hash_file.as_deref(),
        "请粘贴 hash 或选择 hash 文件。",
    )
}

fn parse_hash_modes(help: &str) -> Vec<HashModeInfo> {
    let mut modes = Vec::new();
    let mut in_hash_modes = false;

    for line in help.lines() {
        let trimmed = line.trim();
        if trimmed == "- [ Hash Modes ] -" {
            in_hash_modes = true;
            continue;
        }

        if in_hash_modes && trimmed.starts_with("- [") {
            break;
        }

        if !in_hash_modes || !trimmed.contains('|') {
            continue;
        }

        let parts: Vec<_> = trimmed.split('|').map(str::trim).collect();
        if parts.len() < 3 || !parts[0].chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        let Ok(mode) = parts[0].parse::<u32>() else {
            continue;
        };
        let category = parts.last().unwrap_or(&"").to_string();
        let name = parts[1..parts.len() - 1].join(" | ");
        let keywords = build_keywords(mode, &name, &category);

        modes.push(HashModeInfo {
            mode,
            name,
            category,
            keywords,
        });
    }

    modes
}

fn parse_identify_modes(output: &str) -> Vec<HashModeInfo> {
    output
        .lines()
        .filter_map(|line| {
            let parts = line.split('|').map(str::trim).collect::<Vec<_>>();
            if parts.len() < 3 || !parts[0].chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            let mode = parts[0].parse::<u32>().ok()?;
            let name = parts[1].to_string();
            let category = parts[2].to_string();
            Some(HashModeInfo {
                mode,
                keywords: build_keywords(mode, &name, &category),
                name,
                category,
            })
        })
        .collect()
}

fn build_keywords(mode: u32, name: &str, category: &str) -> Vec<String> {
    let mut keywords = vec![mode.to_string()];
    for value in [name, category] {
        keywords.push(value.to_lowercase());
        for token in value
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .filter(|token| !token.is_empty())
        {
            keywords.push(token.to_lowercase());
        }
    }
    keywords.sort();
    keywords.dedup();
    keywords
}

fn resource_info(kind: &str, path: &Path) -> Result<ResourceInfo, String> {
    let metadata = fs::metadata(path).map_err(|err| err.to_string())?;
    Ok(ResourceInfo {
        kind: kind.to_string(),
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| path_string(path)),
        path: path_string(path),
        size: metadata.len(),
    })
}

fn collect_named_resources(
    resources: &mut Vec<ResourceInfo>,
    kind: &str,
    dir: &Path,
    names: &[&str],
) -> Result<(), String> {
    for name in names {
        push_resource_if_file(resources, kind, &dir.join(name))?;
    }
    Ok(())
}

fn push_resource_if_file(resources: &mut Vec<ResourceInfo>, kind: &str, path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path_string(path));
    if resources.iter().any(|item| item.kind == kind && item.name.eq_ignore_ascii_case(&name)) {
        return Ok(());
    }

    resources.push(resource_info(kind, path)?);
    Ok(())
}

fn resource_kind_order(kind: &str) -> u8 {
    match kind {
        "dictionary" => 0,
        "rule" => 1,
        "mask" => 2,
        "charset" => 3,
        _ => 4,
    }
}

fn hashcat_resource_roots(app: &AppHandle, active_hashcat_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(active_hashcat_dir) = active_hashcat_dir {
        push_unique_path(&mut roots, active_hashcat_dir.to_path_buf());
    }

    for path in [
        app.path().resolve("resources/hashcat", BaseDirectory::Resource),
        app.path().resolve("hashcat", BaseDirectory::Resource),
    ]
    .into_iter()
    .flatten()
    {
        push_unique_path(&mut roots, path);
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_unique_path(&mut roots, cwd.join("src-tauri/resources/hashcat"));
        push_unique_path(&mut roots, cwd.join("resources/hashcat"));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push_unique_path(&mut roots, dir.join("resources/hashcat"));
            push_unique_path(&mut roots, dir.join("hashcat"));
        }
    }

    roots
}

fn wordlist_resource_roots(app: &AppHandle) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    for path in [
        app.path().resolve("resources/wordlists", BaseDirectory::Resource),
        app.path().resolve("wordlists", BaseDirectory::Resource),
    ]
    .into_iter()
    .flatten()
    {
        push_unique_path(&mut roots, path);
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_unique_path(&mut roots, cwd.join("src-tauri/resources/wordlists"));
        push_unique_path(&mut roots, cwd.join("resources/wordlists"));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push_unique_path(&mut roots, dir.join("resources/wordlists"));
            push_unique_path(&mut roots, dir.join("wordlists"));
        }
    }

    roots
}

fn stable_wordlists_dir() -> Result<PathBuf, String> {
    Ok(portable_root_dir()?.join("resources").join("wordlists"))
}

fn preserve_hashcat_wordlists(hashcat_dir: &Path) -> Result<(), String> {
    let source = hashcat_dir.join("wordlists").join("rockyou.txt");
    if !source.is_file() {
        return Ok(());
    }

    let target_dir = stable_wordlists_dir()?;
    fs::create_dir_all(&target_dir).map_err(|err| err.to_string())?;
    let target = target_dir.join("rockyou.txt");
    if target.is_file() {
        return Ok(());
    }

    fs::copy(&source, &target).map_err(|err| err.to_string())?;
    Ok(())
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !path.exists() {
        return;
    }
    if paths.iter().any(|item| same_path(item, &path)) {
        return;
    }
    paths.push(path);
}

fn find_hashcat_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();

    if let Ok(Some(path)) = configured_hashcat_install_dir(app) {
        candidates.push(path.join("hashcat.exe"));
    }

    if let Ok(path) = portable_hashcat_update_dir() {
        candidates.push(path.join("hashcat.exe"));
    }

    if let Ok(path) = app
        .path()
        .resolve("resources/hashcat/hashcat.exe", BaseDirectory::Resource)
    {
        candidates.push(path);
    }

    if let Ok(path) = app
        .path()
        .resolve("hashcat/hashcat.exe", BaseDirectory::Resource)
    {
        candidates.push(path);
    }

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("src-tauri/resources/hashcat/hashcat.exe"));
        candidates.push(cwd.join("resources/hashcat/hashcat.exe"));
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("resources/hashcat/hashcat.exe"));
            candidates.push(dir.join("hashcat/hashcat.exe"));
        }
    }

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .ok_or_else(|| "未找到内置 hashcat.exe。".to_string())
}

fn portable_hashcat_update_dir() -> Result<PathBuf, String> {
    Ok(portable_root_dir()?.join("resources").join("hashcat-current"))
}

fn hashcat_install_target_dir(app: &AppHandle) -> Result<PathBuf, String> {
    if let Some(path) = configured_hashcat_install_dir(app)? {
        validate_hashcat_install_dir(&path)?;
        fs::create_dir_all(&path).map_err(|err| err.to_string())?;
        return Ok(path);
    }
    portable_hashcat_update_dir()
}

fn hashcat_path_status(app: &AppHandle) -> Result<HashcatPathStatus, String> {
    let custom_install_dir = configured_hashcat_install_dir(app)?.map(|path| path_string(&path));
    let effective = find_hashcat_dir(app).ok();
    let effective_exe = effective.as_ref().map(|dir| path_string(&dir.join("hashcat.exe")));
    let effective_dir = effective.as_ref().map(|dir| path_string(dir));
    let using_custom = match (&custom_install_dir, &effective_dir) {
        (Some(custom), Some(effective)) => same_path(Path::new(custom), Path::new(effective)),
        _ => false,
    };
    Ok(HashcatPathStatus {
        custom_install_dir,
        effective_dir,
        effective_exe,
        using_custom,
        available: effective.is_some(),
    })
}

fn configured_hashcat_install_dir(app: &AppHandle) -> Result<Option<PathBuf>, String> {
    let path = hashcat_path_config_path(app)?;
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let config: HashcatPathConfig = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    Ok(config
        .custom_install_dir
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from))
}

fn validate_hashcat_install_dir(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("请选择 hashcat 安装目录。".into());
    }
    if path.is_file() {
        return Err("请选择文件夹，不要选择文件。".into());
    }
    if path.exists() {
        let has_hashcat = path.join("hashcat.exe").is_file();
        let is_empty = fs::read_dir(path)
            .map_err(|err| err.to_string())?
            .next()
            .is_none();
        if !has_hashcat && !is_empty {
            return Err("选择的目录不是空目录，也不是 hashcat 目录。为避免覆盖普通文件夹，请选择空目录或已有 hashcat.exe 的目录。".into());
        }
    }
    Ok(())
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn portable_update_work_dir() -> Result<PathBuf, String> {
    Ok(portable_root_dir()?.join("resources").join("hashcat-update-work"))
}

fn portable_root_dir() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return Ok(dir.to_path_buf());
        }
    }
    std::env::current_dir().map_err(|err| err.to_string())
}

fn command_text(cwd: &Path, exe: &Path, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(exe);
    hide_console(&mut command);
    let output = command
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|err| err.to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format!("{stdout}{stderr}"))
}

fn hide_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

fn hashcat_version(cwd: &Path, exe: &Path) -> Result<String, String> {
    command_text(cwd, exe, &["--version"]).map(|text| text.trim().to_string())
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    name: Option<String>,
    html_url: String,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn build_hashcat_update_info(app: &AppHandle) -> Result<HashcatUpdateInfo, String> {
    let current_version = find_hashcat_dir(app)
        .ok()
        .and_then(|dir| hashcat_version(&dir, &dir.join("hashcat.exe")).ok())
        .map(|version| normalize_version_text(&version));
    let release = fetch_latest_hashcat_release()?;
    let asset = release
        .assets
        .iter()
        .find(|asset| {
            let name = asset.name.to_ascii_lowercase();
            name.starts_with("hashcat-") && name.ends_with(".7z")
        })
        .or_else(|| release.assets.iter().find(|asset| asset.name.to_ascii_lowercase().ends_with(".7z")))
        .ok_or_else(|| "GitHub 最新发布中没有找到 Windows 可用的 hashcat .7z 包。".to_string())?;
    let latest_version = normalize_version_text(&release.tag_name);
    let up_to_date = current_version
        .as_deref()
        .map(|current| compare_versions(current, &latest_version) >= 0)
        .unwrap_or(false);

    Ok(HashcatUpdateInfo {
        current_version,
        latest_version,
        latest_name: release.name.unwrap_or(release.tag_name),
        asset_name: asset.name.clone(),
        asset_url: asset.browser_download_url.clone(),
        release_url: release.html_url,
        up_to_date,
    })
}

fn install_hashcat_update_inner(app: AppHandle) -> Result<HashcatUpdateInfo, String> {
    let info = build_hashcat_update_info(&app)?;
    let hashcat_dir = hashcat_install_target_dir(&app)?;
    let update_root = portable_update_work_dir()?;
    let download_dir = update_root.join("download");
    let extract_dir = update_root.join("extracted");
    let archive_path = download_dir.join(&info.asset_name);

    emit_update_event(&app, "check", &format!("最新版本：{}，发布包：{}", info.latest_version, info.asset_name));
    recreate_dir(&download_dir)?;
    recreate_dir(&extract_dir)?;

    emit_update_event(&app, "download", "开始下载 hashcat 官方发布包。");
    curl_download_with_progress(&app, &info.asset_url, &archive_path)?;
    emit_update_event(&app, "download", &format!("下载完成：{}", path_string(&archive_path)));

    emit_update_event(&app, "extract", "开始解压发布包。");
    extract_archive(&app, &archive_path, &extract_dir)?;
    let new_exe = find_file_recursive(&extract_dir, "hashcat.exe")
        .ok_or_else(|| "解压完成，但没有找到 hashcat.exe。".to_string())?;
    let new_root = new_exe
        .parent()
        .ok_or_else(|| "无法识别新 hashcat 目录。".to_string())?
        .to_path_buf();
    emit_update_event(&app, "extract", &format!("已识别新目录：{}", path_string(&new_root)));

    let backup_dir = update_root.join(format!("backup-{}", timestamp_id()));
    if hashcat_dir.exists() {
        emit_update_event(&app, "replace", "备份当前工具目录 hashcat。");
        copy_dir_all(&hashcat_dir, &backup_dir)?;
    }

    emit_update_event(&app, "replace", &format!("安装到：{}", path_string(&hashcat_dir)));
    preserve_hashcat_wordlists(&hashcat_dir)?;
    if let Err(error) = replace_hashcat_dir(&hashcat_dir, &new_root) {
        let _ = fs::remove_dir_all(&hashcat_dir);
        if backup_dir.exists() {
            let _ = copy_dir_all(&backup_dir, &hashcat_dir);
        }
        return Err(format!("安装失败，已尝试恢复备份：{error}"));
    }

    let refreshed = build_hashcat_update_info(&app)?;
    emit_update_event(&app, "replace", "hashcat 更新流程完成。");
    Ok(refreshed)
}

fn fetch_latest_hashcat_release() -> Result<GithubRelease, String> {
    let text = curl_text("https://api.github.com/repos/hashcat/hashcat/releases/latest")?;
    serde_json::from_str(&text).map_err(|err| format!("解析 GitHub 发布信息失败：{err}"))
}

fn curl_text(url: &str) -> Result<String, String> {
    let mut command = Command::new("curl.exe");
    hide_console(&mut command);
    let output = command
        .args([
            "-fsSL",
            "--ssl-no-revoke",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "User-Agent: HashcatGUI",
            url,
        ])
        .output()
        .map_err(|err| format!("无法调用 curl.exe：{err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn curl_download_with_progress(app: &AppHandle, url: &str, destination: &Path) -> Result<(), String> {
    let mut command = Command::new("curl.exe");
    hide_console(&mut command);
    let destination_text = path_string(destination);
    emit_update_event(app, "download", "下载中，请稍等。");
    let mut child = command
        .args([
            "-fL",
            "--ssl-no-revoke",
            "--no-progress-meter",
            "-H",
            "User-Agent: HashcatGUI",
            "-o",
            destination_text.as_str(),
            url,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("无法启动下载：{err}"))?;

    if let Some(mut stderr) = child.stderr.take() {
        let mut buffer = [0_u8; 512];
        let mut last = String::new();
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    let chunk = String::from_utf8_lossy(&buffer[..size]);
                    for part in chunk.split(['\r', '\n']) {
                        let line = part.trim();
                        if line.is_empty() || line == last {
                            continue;
                        }
                        last = line.to_string();
                        emit_update_event(app, "download", line);
                    }
                }
                Err(_) => break,
            }
        }
    }

    let status = child.wait().map_err(|err| err.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("下载失败，curl 退出码：{status}"))
    }
}

fn extract_archive(app: &AppHandle, archive_path: &Path, extract_dir: &Path) -> Result<(), String> {
    let mut command = Command::new("tar.exe");
    hide_console(&mut command);
    let archive_text = path_string(archive_path);
    let extract_text = path_string(extract_dir);
    let output = command
        .args(["-xf", archive_text.as_str(), "-C", extract_text.as_str()])
        .output()
        .map_err(|err| format!("无法调用 tar.exe 解压 .7z：{err}"))?;
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !message.trim().is_empty() {
        emit_update_event(app, "extract", message.trim());
    }
    if output.status.success() {
        Ok(())
    } else {
        Err("解压失败。Windows tar.exe 无法处理该 .7z 时，请先安装 7-Zip，后续可改为自动调用 7z.exe。".into())
    }
}

fn replace_hashcat_dir(target: &Path, source: &Path) -> Result<(), String> {
    if target.exists() {
        fs::remove_dir_all(target).map_err(|err| err.to_string())?;
    }
    match fs::rename(source, target) {
        Ok(_) => Ok(()),
        Err(_) => copy_dir_all(source, target),
    }
}

fn recreate_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|err| err.to_string())?;
    }
    fs::create_dir_all(path).map_err(|err| err.to_string())
}

fn copy_dir_all(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|err| err.to_string())?;
    for entry in fs::read_dir(source).map_err(|err| err.to_string())? {
        let entry = entry.map_err(|err| err.to_string())?;
        let file_type = entry.file_type().map_err(|err| err.to_string())?;
        let next_target = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &next_target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), next_target).map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

fn find_file_recursive(root: &Path, file_name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.eq_ignore_ascii_case(file_name))
                .unwrap_or(false)
        {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, file_name) {
                return Some(found);
            }
        }
    }
    None
}

fn normalize_version_text(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('v')
        .trim_start_matches("hashcat-")
        .to_string()
}

fn compare_versions(left: &str, right: &str) -> i8 {
    let left_parts = version_numbers(left);
    let right_parts = version_numbers(right);
    let max_len = left_parts.len().max(right_parts.len());
    for index in 0..max_len {
        let left_value = *left_parts.get(index).unwrap_or(&0);
        let right_value = *right_parts.get(index).unwrap_or(&0);
        if left_value > right_value {
            return 1;
        }
        if left_value < right_value {
            return -1;
        }
    }
    0
}

fn version_numbers(value: &str) -> Vec<u32> {
    value
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u32>().ok())
        .collect()
}

fn timestamp_id() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "now".into())
}

fn emit_update_event(app: &AppHandle, phase: &str, line: &str) {
    let _ = app.emit(
        "hashcat-update-log",
        HashcatUpdateEvent {
            phase: phase.to_string(),
            line: line.to_string(),
        },
    );
}

fn extract_json_object(raw: &str) -> Option<Value> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    serde_json::from_str(&raw[start..=end]).ok()
}

fn required_existing_file(value: Option<&str>, message: &str) -> Result<PathBuf, String> {
    let path = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| message.to_string())?;

    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("文件不存在：{}", path_string(&path)))
    }
}

fn validate_hash_mode(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("Hash 类型必须是 hashcat 的 -m 数字。".into());
    }
    Ok(())
}

fn validate_task_id(task_id: &str) -> Result<(), String> {
    if task_id.is_empty()
        || !task_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("任务 ID 非法。".into());
    }
    Ok(())
}

fn ensure_no_active_task(active_task: &Arc<Mutex<Option<RunningTask>>>) -> Result<(), String> {
    let active = active_task
        .lock()
        .map_err(|_| "任务状态锁定失败。".to_string())?;
    if active.is_some() {
        Err("已有任务正在运行，请先停止当前任务。".into())
    } else {
        Ok(())
    }
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("无法获取应用数据目录：{err}"))?;
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    Ok(dir)
}

fn app_tasks_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app_data_dir(app)?.join("tasks");
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    Ok(dir)
}

fn app_task_dir(app: &AppHandle, task_id: &str) -> Result<PathBuf, String> {
    Ok(app_tasks_dir(app)?.join(task_id))
}

fn library_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("library.json"))
}

fn hashcat_path_config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("hashcat_path.json"))
}

fn custom_dictionaries_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app_data_dir(app)?.join("custom-dictionaries");
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    Ok(dir)
}

fn ensure_custom_dictionary_path(app: &AppHandle, path: &Path) -> Result<(), String> {
    let root = custom_dictionaries_dir(app)?
        .canonicalize()
        .map_err(|err| err.to_string())?;
    let path = path.canonicalize().map_err(|err| err.to_string())?;
    if !path.starts_with(root) {
        return Err("只能编辑应用资源库内的字典副本。".into());
    }
    Ok(())
}

fn ai_settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("ai_settings.json"))
}

fn default_ai_settings() -> AiSettings {
    AiSettings {
        base_url: "https://api.openai.com/v1".into(),
        api_key: String::new(),
        model: "gpt-4o-mini".into(),
    }
}

fn normalize_ai_settings(settings: AiSettings) -> AiSettings {
    AiSettings {
        base_url: settings.base_url.trim().trim_end_matches('/').to_string(),
        api_key: settings.api_key.trim().to_string(),
        model: settings.model.trim().to_string(),
    }
}

fn chat_completions_url(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.ends_with("/chat/completions") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/chat/completions")
    }
}

fn models_url(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.ends_with("/chat/completions") {
        format!("{}/models", trimmed.trim_end_matches("/chat/completions"))
    } else if trimmed.ends_with("/models") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/models")
    }
}

fn read_user_dictionaries(app: &AppHandle) -> Result<Vec<UserDictionary>, String> {
    let path = library_path(app)?;
    if !path.is_file() {
        return Ok(Vec::new());
    }

    let text = fs::read_to_string(&path).map_err(|err| err.to_string())?;
    serde_json::from_str(&text).map_err(|err| err.to_string())
}

fn save_manifest(manifest: &TaskManifest) -> Result<(), String> {
    let path = PathBuf::from(&manifest.paths.task_dir).join("manifest.json");
    write_json(&path, manifest)
}

fn update_manifest_on_exit(
    app: &AppHandle,
    task_id: &str,
    code: Option<i32>,
    reason: &str,
) -> Result<(), String> {
    let mut manifest = get_task(app.clone(), task_id.to_string())?;
    let ended_at = now_string();
    manifest.status = reason.to_string();
    manifest.updated_at = ended_at.clone();
    manifest.ended_at = Some(ended_at);
    manifest.exit_code = code;
    manifest.exit_reason = Some(reason.to_string());
    manifest.can_restore = PathBuf::from(&manifest.paths.restore_path).is_file();
    save_manifest(&manifest)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|err| err.to_string())?;
    fs::write(path, text).map_err(|err| err.to_string())
}

fn append_log(path: &Path, stream: &str, line: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "[{stream}] {line}");
    }
}

fn emit_log(app: &AppHandle, task_id: &str, stream: &str, line: &str, log_path: &Path) {
    append_log(log_path, stream, line);
    let _ = app.emit(
        "hashcat-log",
        LogPayload {
            task_id: task_id.to_string(),
            stream: stream.to_string(),
            line: line.to_string(),
        },
    );
}

fn new_task_id() -> String {
    format!("task-{}", now_millis())
}

fn now_millis() -> u128 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    millis
}

fn now_string() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    millis.to_string()
}

fn preview_command(exe: &Path, args: &[String]) -> String {
    std::iter::once(path_string(exe))
        .chain(args.iter().cloned())
        .map(|arg| quote_arg(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_arg(arg: &str) -> String {
    if arg
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\'' | '&' | '(' | ')' | '[' | ']'))
    {
        format!("\"{}\"", arg.replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

fn path_string(path: &Path) -> String {
    let value = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{stripped}");
        }
        if let Some(stripped) = value.strip_prefix(r"\\?\") {
            return stripped.to_string();
        }
    }
    value.to_string()
}

fn exit_reason(code: Option<i32>, stopped_by_user: bool) -> String {
    if stopped_by_user && code == Some(3) {
        return "checkpoint".into();
    }
    if stopped_by_user {
        return "stopped".into();
    }

    match code {
        Some(0) => "cracked".into(),
        Some(1) => "exhausted".into(),
        Some(2) => "aborted".into(),
        Some(3) => "checkpoint".into(),
        Some(4) => "runtime".into(),
        Some(5) => "finished".into(),
        Some(value) if value < 0 => "backend-error".into(),
        Some(_) => "error".into(),
        None => "unknown".into(),
    }
}

fn clear_active_task(active_task: &Arc<Mutex<Option<RunningTask>>>, task_id: &str) {
    if let Ok(mut active) = active_task.lock() {
        if active
            .as_ref()
            .map(|task| task.task_id.as_str() == task_id)
            .unwrap_or(false)
        {
            *active = None;
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            get_hashcat_info,
            check_hashcat_update,
            get_hashcat_path_status,
            set_hashcat_install_dir,
            clear_hashcat_install_dir,
            install_hashcat_update,
            get_hash_modes,
            identify_hash,
            list_builtin_resources,
            list_user_dictionaries,
            add_user_dictionary,
            remove_user_dictionary,
            start_attack,
            rerun_task,
            restore_attack,
            stop_attack,
            list_tasks,
            get_task,
            delete_task,
            read_results,
            read_task_log,
            preview_text_file,
            import_custom_dictionary,
            save_custom_dictionary_content,
            append_custom_dictionary_content,
            delete_custom_dictionary_file,
            dedupe_custom_dictionary,
            get_ai_settings,
            save_ai_settings,
            list_ai_models,
            consult_hash_with_ai,
            start_ai_hash_consult,
            analyze_task_log,
            start_ai_log_analysis,
            export_results,
            open_task_dir
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
