<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch, type Component } from 'vue'
import {
  Activity, AirVent, AlertTriangle, ArrowDown, ArrowUp, ArrowUpRight, Baby, BatteryCharging, Bot, Camera, Car, Check, CheckCircle2, ChevronRight,
  CircleHelp, Cpu, Fan, Gamepad2, Gauge, Globe2, HardDrive, Headphones, HeartPulse, House,
  Lamp, Laptop, LayoutDashboard, Lightbulb, Menu, Microwave, Monitor, Moon, MoreHorizontal, Network, Pencil, Refrigerator,
  Plus, Printer, RefreshCw, Router, Search, Server, Settings2, ShieldCheck,
  SlidersHorizontal, Smartphone, Sparkles, Speaker, Sun, Tablet, Thermometer,
  Trash2, Tv, Users, WashingMachine, Watch, Wifi, X, Zap,
} from '@lucide/vue'
import { toDataURL as qrToDataURL } from 'qrcode'

type JsonRecord = Record<string, any>

type Device = {
  ip: string
  mac: string
  name?: string
  router_name?: string
  custom_name?: string
  icon?: string
  homekit_direct?: boolean
  homekit_route_active?: boolean
  status?: string
  static?: boolean
  managed?: boolean
  favorite?: boolean
  effective?: boolean
  fixed?: boolean
  packets?: number
  connections?: number
  egress?: string
}

type DevicePayload = {
  summary?: Record<string, unknown>
  devices?: Device[]
  mode?: string
}

type SummaryPayload = {
  ready?: boolean
  mode?: string
  netwatch?: string
  router?: string
  drift?: string[]
  version?: string
  build_id?: string
  proxy_ip?: string
  checks?: Record<string, unknown>
  detail?: { proxy?: string }
  router_resource?: { available?: boolean; version?: string; board_name?: string; uptime?: string; cpu_percent?: number; memory_percent?: number }
}

type SetupPayload = { pending?: boolean; url?: string; mode?: string }

const deviceIconOptions: Array<{ key: string; label: string; icon: Component }> = [
  { key: 'phone', label: '手机', icon: Smartphone },
  { key: 'laptop', label: '笔记本', icon: Laptop },
  { key: 'desktop', label: '台式机', icon: Monitor },
  { key: 'tablet', label: '平板', icon: Tablet },
  { key: 'tv', label: '电视', icon: Tv },
  { key: 'camera', label: '摄像头', icon: Camera },
  { key: 'gamepad', label: '游戏机', icon: Gamepad2 },
  { key: 'speaker', label: '音箱', icon: Speaker },
  { key: 'router', label: '路由器', icon: Router },
  { key: 'home', label: '家庭设备', icon: House },
  { key: 'watch', label: '手表', icon: Watch },
  { key: 'server', label: '服务器', icon: Server },
  { key: 'printer', label: '打印机', icon: Printer },
  { key: 'ac', label: '空调', icon: AirVent },
  { key: 'light', label: '灯', icon: Lightbulb },
  { key: 'car', label: '汽车', icon: Car },
  { key: 'earphone', label: '耳机', icon: Headphones },
  { key: 'nas', label: 'NAS', icon: HardDrive },
  { key: 'robot', label: '机器人', icon: Bot },
  { key: 'baby', label: '婴儿', icon: Baby },
  { key: 'washer', label: '洗衣机', icon: WashingMachine },
  { key: 'fridge', label: '冰箱', icon: Refrigerator },
  { key: 'microwave', label: '微波炉', icon: Microwave },
  { key: 'lamp', label: '台灯', icon: Lamp },
  { key: 'power', label: '充电宝', icon: BatteryCharging },
  { key: 'fan', label: '风扇', icon: Fan },
]

function iconFor(key?: string) {
  return deviceIconOptions.find((item) => item.key === key)?.icon || Smartphone
}

type StatusPayload = {
  mode?: string
  healthy?: boolean
  updated_at?: number
  router_resource?: { available?: boolean; version?: string; board_name?: string; uptime?: string; cpu_percent?: number; memory_percent?: number }
  uptime_seconds?: number
  cpu?: { percent?: number; cores?: number; load_1m?: number; load_5m?: number }
  memory?: { percent?: number; used?: number; total?: number; swap_percent?: number }
  disk?: { percent?: number; used?: number; total?: number }
  temperature?: { cpu_c?: number; nvme_c?: number; hdd?: Array<{ name?: string; temperature_c?: number }> }
  docker?: { running?: number; total?: number; unhealthy?: number }
  kernel?: string
}

type WireGuardPeer = { id?: string; name?: string; display_name?: string; default_label?: string; alias?: string; alias_key?: string; endpoint?: string; last_handshake_seconds?: number; active?: boolean; state?: string; state_text?: string; allowed_address?: string; rx_bytes?: number; tx_bytes?: number }
type WireGuardInterface = { name?: string; label?: string; default_label?: string; alias?: string; alias_key?: string; kind?: string; running?: boolean; probe?: { reachable?: boolean; latency_ms?: number }; peers?: WireGuardPeer[]; state?: string; state_text?: string; listen_port?: string; peer_total?: number; peer_active?: number; last_handshake_seconds?: number; rx_bytes?: number; tx_bytes?: number }
type WireGuardPayload = { interfaces?: WireGuardInterface[] }
type RemoteWireGuardClient = { id?: string; name?: string; address?: string; active?: boolean; last_handshake_seconds?: number; rx_bytes?: number; tx_bytes?: number }
type RemoteWireGuardPayload = { mode?: string; supported?: boolean; routeros_version?: string; message?: string; interface?: { name?: string; listen_port?: number; address?: string; network?: string; running?: boolean; client_count?: number } | null; clients?: RemoteWireGuardClient[] }
type UpdatePayload = { state?: string; status?: string; current?: string; latest?: string; current_version?: string; latest_version?: string; checked_at?: number; message?: string }
type PlatformPayload = { mode?: string; checked_at?: number; host?: UpdatePayload; routeros?: UpdatePayload; z4pro?: UpdatePayload; mihomo?: UpdatePayload; mosdns?: UpdatePayload }
type DnsLog = JsonRecord & { query_name?: string; client_ip?: string; query_type?: string; duration_ms?: number; response_code?: string; query_time?: string }
type AirportSource = { slot: string; label: string; imported?: boolean; nodes?: number; updated_at?: string }
type AirportState = { slots?: AirportSource[]; nodes?: Array<{ name?: string; source?: string; label?: string }>; pools?: Record<string, string[]>; settings?: Record<string, JsonRecord>; tests?: JsonRecord; suggestions?: JsonRecord; derived_exits?: JsonRecord }
type RulePayload = { rules?: string[]; version?: string; policies?: string[]; protected?: string[]; rule_sets?: JsonRecord[]; rule_sets_version?: string; rule_card_labels?: Record<string, string>; rule_card_labels_version?: string }

const views = [
  { id: 'overview', label: '总览', caption: '网络概况', icon: LayoutDashboard },
  { id: 'members', label: '接管设备', caption: '设备与策略', icon: Users },
  { id: 'traffic', label: '流量观察', caption: '实时快照', icon: Activity },
  { id: 'dns', label: 'DNS 管理', caption: '解析与数据', icon: Globe2 },
  { id: 'airport', label: '机场候选池', caption: '订阅与出口', icon: Server },
  { id: 'rules', label: '规则配置', caption: '分流与策略', icon: SlidersHorizontal },
  { id: 'setup', label: '首次配置', caption: '安装与状态', icon: Sparkles },
  { id: 'ops', label: '系统维护', caption: '运行与更新', icon: Settings2 },
]

const activeView = ref(window.location.hash.slice(1) || 'overview')
const isDark = ref(localStorage.getItem('family-proxy-theme') !== 'light')
const loading = ref(false)
const busy = ref('')
const errorMessage = ref('')
const toastMessage = ref('')
const csrf = ref('')
const devicePayload = ref<DevicePayload>({ devices: [] })
const system = ref<StatusPayload>({})
const setupState = ref<SetupPayload>({})
const wireguard = ref<WireGuardPayload>({})
const mihomo = ref<Record<string, unknown>>({})
const updateStatus = ref<UpdatePayload>({})
const platformStatus = ref<PlatformPayload>({})
const remoteWireguard = ref<RemoteWireGuardPayload>({})
const remoteWireguardName = ref('')
const remoteWireguardEndpoint = ref('')
const remoteWireguardPort = ref('51820')
const remoteWireguardDns = ref('')
const remoteWireguardConfig = ref<{ name: string; address: string; config: string; qr: string } | null>(null)
const mosdnsStatus = ref<JsonRecord>({})
const alertConfig = ref<JsonRecord>({})
const alertToken = ref('')
const alertChat = ref('')
const searchQuery = ref('')
const filter = ref('managed')
const consoleSettingsOpen = ref(false)
const renameTarget = ref<Device | null>(null)
const renameDraft = ref('')
const iconDraft = ref('phone')
const iconPickerTarget = ref<Device | null>(null)
const wireguardRenameTarget = ref<{ key: string; label: string; defaultLabel: string; alias: string } | null>(null)
const wireguardRenameDraft = ref('')
let poller: number | undefined
let toastTimer: number | undefined
const dnsTab = ref('overview')
const dnsStats = ref<JsonRecord>({})
const dnsWindows = ref<JsonRecord>({})
const dnsDomains = ref<JsonRecord[]>([])
const dnsClients = ref<JsonRecord[]>([])
const dnsEffective = ref<JsonRecord[]>([])
const dnsSlowest = ref<JsonRecord[]>([])
const dnsDomestic = ref<JsonRecord>({})
const dnsForeign = ref<JsonRecord>({})
const dnsPerformance = ref<JsonRecord>({})
const dnsRaceOpen = ref<string | null>(null)
const dnsLogs = ref<DnsLog[]>([])
const dnsLogQuery = ref('')
const dnsLogFilter = ref('all')
const dnsCapture = ref<JsonRecord>({})
const dnsCapacity = ref<JsonRecord>({})
const dnsRuleData = ref<JsonRecord>({})
const dnsAdblock = ref<JsonRecord>({})
const dnsRuleUpdate = ref<JsonRecord>({})
const dnsRuleBusy = ref(false)
const dnsVerify = ref<JsonRecord>({})
const dnsUpstreamsOpen = ref(false)
const dnsUpstreamEditSide = ref<'domestic' | 'foreign' | null>(null)
const dnsDomesticDraft = ref('')
const dnsForeignDraft = ref('')
const dnsAllowlistOpen = ref(false)
const dnsAllowlistDraft = ref('')

const airportTab = ref('sources')
const airportState = ref<AirportState>({})
const airportPools = ref<Record<string, string[]>>({})
const airportSettings = ref<Record<string, JsonRecord>>({})
const airportUrls = ref<Record<string, string>>({})
const airportStatus = ref<JsonRecord>({})
const airportProbes = ref<JsonRecord>({})
const airportFilter = ref('')
const airportPoolEditor = ref('')
const airportPoolMode = ref('fallback')
const airportCsrf = ref('')

const rulesPayload = ref<RulePayload>({ rules: [] })
const ruleDraft = ref<string[]>([])
const ruleDirty = ref(false)
const ruleAdvanced = ref(false)
const ruleCardLabels = ref<Record<string, string>>({})
const ruleCardLabelsVersion = ref('')
const draggingRuleItem = ref('')
const dropTargetRuleItem = ref('')
const ruleCardEditorOpen = ref(false)
const ruleCardEditorKey = ref('')
const rulePreviewTarget = ref('')
const rulePreview = ref<JsonRecord | null>(null)
const ruleSetEditorOpen = ref(false)
const ruleSetName = ref('')
const ruleSetUrls = ref('')
const ruleSetPolicy = ref('Proxy-Auto')
const ruleSetPriority = ref('normal')
const ruleSetInterval = ref('86400')
const ruleSetBehavior = ref('domain')
const ruleSetFormat = ref('mrs')
const ruleSetEditorIndex = ref(-1)

const ruleSetPresetItems: JsonRecord[] = [
  { id: 'telegram-ip', name: 'Telegram IP', group: 'Telegram', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs', behavior: 'ipcidr', format: 'mrs', policy: 'TG-Auto', priority: 'high', interval: 86400 },
  { id: 'telegram-domain', name: 'Telegram 域名', group: 'Telegram', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs', behavior: 'domain', format: 'mrs', policy: 'TG-Auto', priority: 'high', interval: 86400 },
  { id: 'google-domain', name: 'Google', group: 'Google', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'github-domain', name: 'GitHub', group: 'GitHub', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'youtube-domain', name: 'YouTube', group: 'YouTube', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs', behavior: 'domain', format: 'mrs', policy: 'HK-视频', priority: 'high', interval: 86400 },
  { id: 'netflix-domain', name: 'Netflix', group: 'Netflix', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/netflix.mrs', behavior: 'domain', format: 'mrs', policy: 'HK-视频', priority: 'high', interval: 86400 },
  { id: 'disney-domain', name: 'Disney+', group: 'Disney+', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/disney.mrs', behavior: 'domain', format: 'mrs', policy: 'HK-视频', priority: 'high', interval: 86400 },
  { id: 'spotify-domain', name: 'Spotify', group: 'Spotify', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/spotify.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'tiktok-domain', name: 'TikTok', group: 'TikTok', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tiktok.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'overseas-ai-domain', name: '海外 AI', group: '海外 AI', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs', behavior: 'domain', format: 'mrs', policy: 'AI-Auto', priority: 'high', interval: 86400 },
  { id: 'microsoft-domain', name: 'Microsoft', group: 'Microsoft', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.mrs', behavior: 'domain', format: 'mrs', policy: 'DIRECT', priority: 'normal', interval: 86400 },
  { id: 'apple-domain', name: 'Apple', group: 'Apple', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple.mrs', behavior: 'domain', format: 'mrs', policy: 'DIRECT', priority: 'normal', interval: 86400 },
  { id: 'discord-domain', name: 'Discord', group: 'Discord', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'facebook-domain', name: 'Facebook', group: 'Facebook', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/facebook.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'instagram-domain', name: 'Instagram', group: 'Instagram', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/instagram.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'twitter-domain', name: 'X (Twitter)', group: 'X (Twitter)', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitter.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
  { id: 'steam-domain', name: 'Steam', group: 'Steam', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam.mrs', behavior: 'domain', format: 'mrs', policy: 'Proxy-Auto', priority: 'high', interval: 86400 },
]

function setTheme(value: boolean) {
  isDark.value = value
  document.documentElement.dataset.theme = value ? 'dark' : 'light'
  localStorage.setItem('family-proxy-theme', value ? 'dark' : 'light')
}

function normalizeView(value: string) {
  return views.some((item) => item.id === value) ? value : 'overview'
}

function selectView(value: string) {
  const next = normalizeView(value)
  activeView.value = next
  if (window.location.hash !== `#${next}`) window.location.hash = next
  void loadFeatureView(next)
}

function formatBytes(value?: number) {
  if (!Number.isFinite(value)) return '不可用'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let amount = Number(value)
  let index = 0
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024
    index += 1
  }
  return `${amount.toFixed(index ? 1 : 0)} ${units[index]}`
}

function formatUptime(seconds?: number) {
  if (!Number.isFinite(seconds)) return '不可用'
  const days = Math.floor(Number(seconds) / 86400)
  const hours = Math.floor((Number(seconds) % 86400) / 3600)
  return days ? `${days} 天 ${hours} 小时` : `${hours} 小时`
}

function number(value: unknown, fallback = 0) {
  return Number.isFinite(Number(value)) ? Number(value) : fallback
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')
  if (options.body) headers.set('Content-Type', 'application/json')
  if (method !== 'GET') {
    if (!csrf.value) csrf.value = (await api<{ csrf: string }>('/api/csrf')).csrf
    headers.set('X-CSRF', csrf.value)
  }
  const response = await fetch(path, { ...options, headers })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error || `请求失败（${response.status}）`)
  return body as T
}

async function serviceApi<T>(path: string, options: RequestInit = {}, serviceCsrf = ''): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')
  if (options.body) headers.set('Content-Type', 'application/json')
  if ((options.method || 'GET').toUpperCase() !== 'GET' && serviceCsrf) headers.set('X-CSRF', serviceCsrf)
  const response = await fetch(path, { ...options, headers, cache: 'no-store' })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error || body.message || `请求失败（${response.status}）`)
  return body as T
}

async function dnsApi<T>(path: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers)
  headers.set('X-Requested-With', 'family-dns')
  return serviceApi<T>(`/dns${path}`, { ...options, headers })
}

async function dnsMaintenanceApi<T>(path: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers)
  headers.set('X-Requested-With', 'family-dns')
  return serviceApi<T>(`/dns/maintenance-api${path}`, { ...options, headers })
}

async function ensureAirportCsrf() {
  if (airportCsrf.value) return airportCsrf.value
  const response = await fetch('/airport/', { cache: 'no-store' })
  const html = await response.text()
  const match = html.match(/(?:const|let)\s+csrf\s*=\s*['"]([^'"]+)/)
  if (!response.ok || !match) throw new Error('机场服务安全状态不可用，请刷新页面后重试')
  airportCsrf.value = match[1]
  return airportCsrf.value
}

async function airportApi<T>(path: string, options: RequestInit = {}) {
  const method = (options.method || 'GET').toUpperCase()
  return serviceApi<T>(`/airport${path}`, options, method === 'GET' ? '' : await ensureAirportCsrf())
}

function arrayFrom(value: unknown, keys: string[] = []) {
  if (Array.isArray(value)) return value as JsonRecord[]
  if (value && typeof value === 'object') {
    for (const key of keys) {
      const nested = (value as JsonRecord)[key]
      if (Array.isArray(nested)) return nested as JsonRecord[]
      if (nested && typeof nested === 'object') return Object.values(nested) as JsonRecord[]
    }
  }
  return []
}

function textValue(value: unknown, fallback = '不可用') {
  return value === undefined || value === null || value === '' ? fallback : String(value)
}

function timeValue(value: unknown) {
  if (!value) return '尚无记录'
  const numeric = typeof value === 'number' ? value : Number(value)
  const dateValue = Number.isFinite(numeric) ? (Math.abs(numeric) < 100000000000 ? numeric * 1000 : numeric) : String(value)
  const date = new Date(dateValue)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}

function msValue(value: unknown) {
  const amount = Number(value || 0)
  return `${amount < 10 ? amount.toFixed(2) : amount.toFixed(1)} ms`
}

function normalizeDevicePayload(payload: DevicePayload): DevicePayload {
  return {
    ...payload,
    devices: (payload.devices || []).map((device) => {
      const rawCustomName = device.custom_name as unknown
      return {
        ...device,
        custom_name: typeof rawCustomName === 'boolean'
          ? (rawCustomName ? device.name : undefined)
          : typeof rawCustomName === 'string' ? rawCustomName : undefined,
      }
    }),
  }
}

function notify(message: string) {
  toastMessage.value = message
  window.clearTimeout(toastTimer)
  toastTimer = window.setTimeout(() => { toastMessage.value = '' }, 3200)
}

async function load() {
  loading.value = true
  errorMessage.value = ''
  const results = await Promise.allSettled([
    api<DevicePayload>('/api/devices'),
    api<StatusPayload>('/api/system/status'),
    api<WireGuardPayload>('/api/wireguard/status'),
    api<Record<string, unknown>>('/api/mihomo'),
    api<UpdatePayload>('/api/mihomo/upgrade'),
    api<PlatformPayload>('/api/platform/updates'),
    api<SetupPayload>('/api/setup-status'),
  ])
  const [devices, status, wg, groups, mihomoUpdate, platformUpdate, setup] = results
  if (devices.status === 'fulfilled') devicePayload.value = normalizeDevicePayload(devices.value)
  if (status.status === 'fulfilled') system.value = status.value
  if (wg.status === 'fulfilled') wireguard.value = wg.value
  if (groups.status === 'fulfilled') mihomo.value = groups.value
  if (mihomoUpdate.status === 'fulfilled') updateStatus.value = mihomoUpdate.value
  if (platformUpdate.status === 'fulfilled') platformStatus.value = platformUpdate.value
  if (setup.status === 'fulfilled') setupState.value = setup.value
  const failed = results.filter((item) => item.status === 'rejected').length
  if (failed === results.length) errorMessage.value = '当前无法读取旁路服务，请检查控制面状态。'
  else if (failed) errorMessage.value = `${failed} 项状态暂不可用，已保留其余实时数据。`
  loading.value = false
}

async function action(key: string, path: string, payload: unknown, message: string): Promise<boolean> {
  busy.value = key
  try {
    const result = await api<{ message?: string }>(path, { method: 'POST', body: JSON.stringify(payload) })
    notify(result.message || message)
    await load()
    return true
  } catch (error) {
    notify(error instanceof Error ? error.message : '操作失败')
    return false
  } finally {
    busy.value = ''
  }
}

function joinDevice(device: Device) {
  action(`join-${device.ip}`, '/api/enable', { ip: device.ip }, '设备已加入旁路')
}

function removeDevice(device: Device) {
  if (!window.confirm(`将 ${device.ip} 恢复直连并清理旧连接？`)) return
  action(`remove-${device.ip}`, '/api/remove', { ip: device.ip }, '设备已恢复直连')
}

function toggleFavorite(device: Device) {
  action(`favorite-${device.mac}`, '/api/device/preference', { mac: device.mac, favorite: !device.favorite }, device.favorite ? '已移出常用设备' : '已加入常用设备')
}

function openRename(device: Device) {
  renameTarget.value = device
  renameDraft.value = device.name || ''
  iconDraft.value = device.icon || 'phone'
}

function openIconPicker(device: Device) {
  iconPickerTarget.value = device
  iconDraft.value = device.icon || 'phone'
}

function wireguardInterfaceLabel(item: WireGuardInterface) {
  return item.alias || item.name || item.label || '未命名接口'
}

function wireguardPeerLabel(peer: WireGuardPeer) {
  return peer.alias || peer.name || peer.display_name || '未命名 Peer'
}

function wireguardHandshake(value: unknown) {
  if (value === undefined || value === null || value === '') return '尚无握手'
  const seconds = Number(value)
  if (!Number.isFinite(seconds)) return '尚无握手'
  if (seconds < 60) return `${Math.max(0, Math.floor(seconds))} 秒前`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}

function openWireguardInterfaceRename(item: WireGuardInterface) {
  wireguardRenameTarget.value = {
    key: item.alias_key || `interface:${item.name || ''}`,
    label: wireguardInterfaceLabel(item),
    defaultLabel: item.name || item.label || '',
    alias: item.alias || '',
  }
  wireguardRenameDraft.value = item.alias || ''
}

function openWireguardPeerRename(peer: WireGuardPeer) {
  wireguardRenameTarget.value = {
    key: peer.alias_key || `peer:${peer.name || ''}`,
    label: wireguardPeerLabel(peer),
    defaultLabel: peer.name || peer.display_name || '',
    alias: peer.alias || '',
  }
  wireguardRenameDraft.value = peer.alias || ''
}

async function saveWireguardRename() {
  if (!wireguardRenameTarget.value) return
  busy.value = 'wireguard-rename'
  try {
    const result = await api<{ message?: string }>('/api/wireguard/preference', {
      method: 'POST',
      body: JSON.stringify({ key: wireguardRenameTarget.value.key, alias: wireguardRenameDraft.value.trim() }),
    })
    wireguardRenameTarget.value = null
    notify(result.message || 'WireGuard 名称已保存')
    await load()
  } catch (error) {
    notify(error instanceof Error ? error.message : 'WireGuard 名称保存失败')
  } finally {
    busy.value = ''
  }
}

function remoteWireguardClientState(client: RemoteWireGuardClient) {
  return client.active ? '在线' : client.last_handshake_seconds === undefined || client.last_handshake_seconds === null ? '等待连接' : '已离线'
}

function remoteWireguardClientTraffic(client: RemoteWireGuardClient) {
  return `↓ ${formatBytes(client.rx_bytes)} · ↑ ${formatBytes(client.tx_bytes)}`
}

async function generateRemoteWireguard() {
  const name = remoteWireguardName.value.trim()
  const endpoint = remoteWireguardEndpoint.value.trim()
  if (!name || !endpoint) {
    notify('请填写客户端名称和公网域名/IP')
    return
  }
  if (!window.confirm(`将在 RouterOS 创建「${name}」的 WireGuard 客户端，并允许其访问家庭 LAN。继续吗？`)) return
  busy.value = 'remote-wg-generate'
  try {
    const result = await api<{ message: string; client: { name: string; address: string }; config: string }>('/api/wireguard/remote-access/generate', {
      method: 'POST',
      body: JSON.stringify({
        name,
        endpoint,
        port: Number(remoteWireguardPort.value),
        dns: remoteWireguardDns.value.trim(),
      }),
    })
    const qr = await qrToDataURL(result.config, { width: 292, margin: 2, errorCorrectionLevel: 'M' })
    remoteWireguardConfig.value = { name: result.client.name, address: result.client.address, config: result.config, qr }
    notify(result.message)
    await loadOpsFeature()
  } catch (error) {
    notify(error instanceof Error ? error.message : 'WireGuard 客户端创建失败')
  } finally {
    busy.value = ''
  }
}

function downloadRemoteWireguard() {
  if (!remoteWireguardConfig.value) return
  const fileName = `${remoteWireguardConfig.value.name.replace(/[^\w.-]+/g, '-') || 'family-wireguard'}.conf`
  const url = URL.createObjectURL(new Blob([remoteWireguardConfig.value.config], { type: 'text/plain;charset=utf-8' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = fileName
  anchor.click()
  URL.revokeObjectURL(url)
}

async function revokeRemoteWireguard(client: RemoteWireGuardClient) {
  if (!client.id || !window.confirm(`撤销「${client.name || '该客户端'}」后，已导入的配置将立即失效。继续吗？`)) return
  busy.value = `remote-wg-revoke-${client.id}`
  try {
    const result = await api<{ message: string }>('/api/wireguard/remote-access/revoke', {
      method: 'POST',
      body: JSON.stringify({ id: client.id }),
    })
    notify(result.message)
    await loadOpsFeature()
  } catch (error) {
    notify(error instanceof Error ? error.message : 'WireGuard 客户端撤销失败')
  } finally {
    busy.value = ''
  }
}

function setHomeKitDirect(device: Device) {
  const enabled = !device.homekit_direct
  if (enabled && !window.confirm('仅为 HomeKit 摄像头、Apple TV、iPhone 或 iPad 保留本地直连；不会改变该设备的外网旁路。继续吗？')) return
  action(`homekit-${device.mac}`, '/api/device/preference', {
    mac: device.mac,
    homekit_direct: enabled,
    icon: device.icon || 'phone',
  }, enabled ? '已启用 HomeKit 本地直连' : '已关闭 HomeKit 本地直连')
}

function openAddDevice() {
  searchQuery.value = ''
  filter.value = 'online'
  selectView('members')
}

async function saveRename() {
  if (!renameTarget.value) return
  const saved = await action('rename', '/api/device/preference', {
    mac: renameTarget.value.mac,
    alias: renameDraft.value.trim(),
    icon: iconDraft.value,
  }, '设备信息已保存')
  if (saved) renameTarget.value = null
}

async function saveDeviceIcon() {
  const device = iconPickerTarget.value
  if (!device) return
  const saved = await action('icon', '/api/device/preference', { mac: device.mac, icon: iconDraft.value }, '设备图标已更新')
  if (saved) {
    iconPickerTarget.value = null
    await load()
  }
}

async function checkMihomo() {
  await action('mihomo-check', '/api/mihomo/upgrade/check', {}, 'Mihomo 更新检查已启动')
}

async function checkPlatform() {
  await action('platform-check', '/api/platform/updates/check', {}, '设备系统更新检查已启动')
}

async function loadDnsOverview() {
  const results = await Promise.allSettled([
    dnsApi<JsonRecord>('/api/v2/audit/stats'),
    dnsApi<JsonRecord>('/api/v2/audit/stats/windows'),
    dnsApi<JsonRecord[]>('/api/v2/audit/rank/domain?limit=6'),
    dnsApi<JsonRecord[]>('/api/v2/audit/rank/client?limit=6'),
    dnsApi<JsonRecord[]>('/api/v2/audit/rank/effective?limit=6'),
    dnsApi<JsonRecord[]>('/api/v2/audit/rank/slowest?limit=6'),
    dnsApi<JsonRecord>('/api/v1/upstream/runtime/domestic'),
    dnsApi<JsonRecord>('/api/v1/upstream/runtime/foreign'),
    dnsMaintenanceApi<JsonRecord>('/metrics'),
  ])
  const [stats, windows, domains, clients, effective, slowest, domestic, foreign, performance] = results
  if (stats.status === 'fulfilled') dnsStats.value = stats.value
  if (windows.status === 'fulfilled') dnsWindows.value = windows.value
  if (domains.status === 'fulfilled') dnsDomains.value = arrayFrom(domains.value, ['items', 'domains'])
  if (clients.status === 'fulfilled') dnsClients.value = arrayFrom(clients.value, ['items', 'clients'])
  if (effective.status === 'fulfilled') dnsEffective.value = arrayFrom(effective.value, ['items'])
  if (slowest.status === 'fulfilled') dnsSlowest.value = arrayFrom(slowest.value, ['items'])
  if (domestic.status === 'fulfilled') dnsDomestic.value = domestic.value
  if (foreign.status === 'fulfilled') dnsForeign.value = foreign.value
  if (performance.status === 'fulfilled') dnsPerformance.value = performance.value
  if (results.every((item) => item.status === 'rejected')) notify('DNS 概览暂时无法读取')
}

async function loadDnsLogs() {
  try {
    const result = await dnsApi<JsonRecord>('/api/v2/audit/logs?limit=500')
    dnsLogs.value = arrayFrom(result, ['logs', 'items']) as DnsLog[]
  } catch (error) {
    notify(error instanceof Error ? `DNS 日志读取失败：${error.message}` : 'DNS 日志读取失败')
  }
}

async function loadDnsData() {
  const results = await Promise.allSettled([
    dnsApi<JsonRecord>('/api/v1/audit/status'),
    dnsApi<JsonRecord>('/api/v1/audit/capacity'),
    dnsApi<JsonRecord | JsonRecord[]>('/plugins/geosite_cn/config'),
    dnsApi<JsonRecord | JsonRecord[]>('/plugins/geosite_no_cn/config'),
    dnsApi<JsonRecord | JsonRecord[]>('/plugins/geoip_cn/config'),
    dnsApi<JsonRecord[]>('/plugins/adguard/rules'),
    dnsMaintenanceApi<JsonRecord>('/rules/status'),
    dnsMaintenanceApi<JsonRecord>('/adblock/status'),
    dnsMaintenanceApi<JsonRecord>('/verify/status'),
  ])
  const [capture, capacity, cn, noCn, cnIp, adblockRules, rules, adblock, verify] = results
  if (capture.status === 'fulfilled') dnsCapture.value = capture.value
  if (capacity.status === 'fulfilled') dnsCapacity.value = capacity.value
  if (cn.status === 'fulfilled' || noCn.status === 'fulfilled' || cnIp.status === 'fulfilled') {
    dnsRuleData.value = {
      domestic: cn.status === 'fulfilled' ? (Array.isArray(cn.value) ? cn.value[0] : cn.value) : {},
      foreign: noCn.status === 'fulfilled' ? (Array.isArray(noCn.value) ? noCn.value[0] : noCn.value) : {},
      ip: cnIp.status === 'fulfilled' ? (Array.isArray(cnIp.value) ? cnIp.value[0] : cnIp.value) : {},
      extras: adblockRules.status === 'fulfilled' ? adblockRules.value : [],
    }
  }
  if (rules.status === 'fulfilled') dnsRuleUpdate.value = rules.value
  if (adblock.status === 'fulfilled') dnsAdblock.value = adblock.value
  if (verify.status === 'fulfilled') dnsVerify.value = verify.value
}

function dnsRouteName(log: DnsLog) {
  const raw = `${log.effective_tag || ''} ${log.domain_set || ''} ${log.matched_rule_source || ''}`.toLowerCase()
  if (raw.includes('foreign') || raw.includes('nocn') || raw.includes('代理')) return '代理'
  if (raw.includes('domestic') || raw.includes('cn') || raw.includes('直连') || raw.includes('白名单')) return '直连'
  return textValue(log.effective_tag, '默认')
}

function dnsUpstreamItems(data: JsonRecord): unknown[] {
  const value = data.runtime_targets || data.targets || data.upstreams || data.items
  if (Array.isArray(value)) return value
  if (value && typeof value === 'object') return Object.values(value)
  return []
}

function dnsUpstreamLine(item: unknown) {
  if (typeof item === 'string') return item
  if (!item || typeof item !== 'object') return ''
  const record = item as JsonRecord
  const address = record.addr || record.address || record.url || record.name || ''
  return `${address}${record.dial_addr ? ` | ${record.dial_addr}` : ''}`
}

const dnsRouteCards = computed(() => [
  { id: 'domestic', label: '国内解析', data: dnsDomestic.value, downstream: '本地网络直连', tone: 'domestic' },
  { id: 'foreign', label: '国外解析', data: dnsForeign.value, downstream: 'Mihomo SOCKS', tone: 'foreign' },
])

function toggleDnsRace(group: string) {
  dnsRaceOpen.value = dnsRaceOpen.value === group ? null : group
}

function dnsRaceSummary(group: string) {
  const best = dnsRaceItems(group)[0]
  if (!best) return '尚无该组并发竞速样本'
  return `当前最优：${best.name || '未命名上游'} · 胜率 ${dnsRaceWinRate(best).toFixed(1)}% · 平均 ${msValue(best.average_ms)} · 错误 ${Number(best.error_rate || 0).toFixed(2)}%`
}

function dnsRaceItems(group: string) {
  const items = Array.isArray(dnsPerformance.value.upstreams) ? dnsPerformance.value.upstreams : []
  return items
    .filter((item: JsonRecord) => item.group === group)
    .slice()
    .sort((left: JsonRecord, right: JsonRecord) => {
      const leftError = Number(left.error_rate || 0)
      const rightError = Number(right.error_rate || 0)
      if (leftError !== rightError) return leftError - rightError
      const leftWin = Number(left.queries || 0) ? Number(left.winners || 0) / Number(left.queries) : 0
      const rightWin = Number(right.queries || 0) ? Number(right.winners || 0) / Number(right.queries) : 0
      if (leftWin !== rightWin) return rightWin - leftWin
      return Number(left.average_ms || 0) - Number(right.average_ms || 0)
    })
}

function dnsRaceWinRate(item: JsonRecord) {
  const queries = Number(item.queries || 0)
  return queries ? Number(item.winners || 0) / queries * 100 : 0
}

function dnsRaceErrorClass(item: JsonRecord) {
  const errors = Number(item.error_rate || 0)
  return errors >= 1 ? 'bad' : errors > 0 ? 'warn' : 'good'
}

function dnsFirst(data: JsonRecord, key: string) {
  const value = data[key]
  return Number(value || 0)
}

function dnsWindow(key: string) {
  const items = arrayFrom(dnsWindows.value, ['items'])
  return items.find((item) => item.key === key) || {}
}

async function openDnsUpstreams(side: 'domestic' | 'foreign' = 'domestic') {
  const source = side === 'domestic' ? dnsDomestic.value : dnsForeign.value
  const draft = side === 'domestic' ? dnsDomesticDraft : dnsForeignDraft
  if (!draft.value) draft.value = dnsUpstreamItems(source).map(dnsUpstreamLine).filter(Boolean).join('\n')
  dnsUpstreamEditSide.value = side
  dnsUpstreamsOpen.value = true
}

async function saveDnsUpstreams() {
  const side = dnsUpstreamEditSide.value
  const untouched = side === 'domestic' ? dnsForeign.value : dnsDomestic.value
  const domestic = side === 'domestic' ? dnsDomesticDraft.value : dnsUpstreamItems(untouched).map(dnsUpstreamLine).filter(Boolean).join('\n')
  const foreign = side === 'foreign' ? dnsForeignDraft.value : dnsUpstreamItems(untouched).map(dnsUpstreamLine).filter(Boolean).join('\n')
  if (!domestic.trim() || !foreign.trim()) {
    notify('国内和国外至少各保留一个上游服务器')
    return
  }
  busy.value = 'dns-upstreams'
  try {
    await dnsMaintenanceApi('/upstreams', { method: 'POST', body: JSON.stringify({ domestic, foreign }) })
    dnsUpstreamsOpen.value = false
    dnsUpstreamEditSide.value = null
    notify('DNS 上游已保存并通过验证')
    await loadDnsOverview()
  } catch (error) {
    notify(error instanceof Error ? error.message : 'DNS 上游保存失败')
  } finally {
    busy.value = ''
  }
}

async function runDnsAction(path: string, message: string, payload: unknown = {}) {
  try {
    await dnsMaintenanceApi(path, { method: 'POST', body: JSON.stringify(payload) })
    notify(message)
    await loadDnsData()
  } catch (error) {
    notify(error instanceof Error ? error.message : 'DNS 操作失败')
  }
}

async function updateDnsRules() {
  if (dnsRuleBusy.value) return
  dnsRuleBusy.value = true
  dnsRuleUpdate.value = { ...dnsRuleUpdate.value, phase: 'checking', message: '正在下载并校验官方规则…' }
  try {
    await dnsMaintenanceApi('/rules/update', { method: 'POST', body: '{}' })
    let phase = ''
    for (let attempt = 0; attempt < 40; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1500))
      const status = await dnsMaintenanceApi<JsonRecord>('/rules/status')
      dnsRuleUpdate.value = status
      phase = String(status.phase || '')
      if (!['checking', 'updating', 'busy', 'starting', ''].includes(phase)) break
    }
    if (['failed', 'error', 'rolled_back'].includes(phase)) {
      notify(`规则更新失败${dnsRuleUpdate.value.message ? `：${dnsRuleUpdate.value.message}` : ''}`)
    } else if (['updated', 'up_to_date'].includes(phase)) {
      notify('规则已更新并通过校验')
    } else {
      notify('规则更新任务已提交，仍在后台进行')
    }
  } catch (error) {
    notify(error instanceof Error ? `规则更新失败：${error.message}` : '规则更新失败')
  } finally {
    dnsRuleBusy.value = false
    await loadDnsData()
  }
}

function dnsRulePhaseLabel(phase?: string) {
  if (!phase || phase === 'idle') return '尚未执行'
  if (phase === 'updated' || phase === 'up_to_date') return '更新完成'
  if (phase === 'checking' || phase === 'updating' || phase === 'busy' || phase === 'starting') return '更新中'
  if (phase === 'failed' || phase === 'error' || phase === 'rolled_back') return '更新失败'
  if (phase === 'available') return '有可用更新'
  return phase
}

function dnsRulePhaseWarn(phase?: string) {
  return ['checking', 'updating', 'busy', 'starting', 'failed', 'error', 'rolled_back', 'available'].includes(String(phase || ''))
}

function dnsRulePhaseBusy(phase?: string) {
  return ['checking', 'updating', 'busy', 'starting'].includes(String(phase || ''))
}

async function toggleDnsRuleAuto() {
  const enabled = !Boolean(dnsRuleUpdate.value.config?.rule_auto_enabled)
  await runDnsAction('/rules/auto', enabled ? '规则自动更新已开启' : '规则自动更新已关闭', { enabled })
}

async function setDnsAdblockMode(mode: string) {
  if (busy.value === 'dns-adblock') return
  if (mode === 'block' && !window.confirm('启用后，命中的广告和成人域名会返回 NXDOMAIN。继续吗？')) return
  if (mode === dnsAdblock.value.mode) return
  busy.value = 'dns-adblock'
  dnsAdblock.value = { ...dnsAdblock.value, mode, message: mode === 'observe' ? '正在切换为观察模式…' : mode === 'block' ? '正在切换为拦截模式…' : '正在关闭内容过滤…' }
  try {
    await dnsMaintenanceApi('/adblock/mode', { method: 'POST', body: JSON.stringify({ mode }) })
    notify(mode === 'off' ? '内容过滤已关闭' : mode === 'observe' ? '已切换为观察模式' : '已切换为拦截模式')
  } catch (error) {
    notify(error instanceof Error ? error.message : '切换过滤模式失败')
  } finally {
    busy.value = ''
    await loadDnsData()
  }
}

async function updateDnsAdblock() {
  await runDnsAction('/adblock/update', '已开始使用本地网络更新内容过滤规则')
}

async function toggleDnsAdblockAuto() {
  const enabled = !Boolean(dnsAdblock.value.auto_enabled)
  await runDnsAction('/adblock/auto', enabled ? '内容过滤自动更新已开启' : '内容过滤自动更新已关闭', { enabled })
}

function openDnsAllowlist() {
  dnsAllowlistDraft.value = String(dnsAdblock.value.allowlist || '')
  dnsAllowlistOpen.value = true
}

async function saveDnsAllowlist() {
  await runDnsAction('/adblock/allowlist', '放行名单已保存并通过验证', { value: dnsAllowlistDraft.value })
  dnsAllowlistOpen.value = false
}

async function runDnsVerify(mode: string) {
  if (mode === 'full' && !window.confirm('完整回归会清理 DNS 路由缓存，首次查询可能短暂变慢。继续吗？')) return
  await runDnsAction('/verify/run', mode === 'full' ? '已开始完整 DNS 回归' : '已开始快速 DNS 检查', { mode })
}

async function flushDnsCaches() {
  if (!window.confirm('确定清空 DNS 缓存吗？')) return
  const tags = ['cache_all', 'cache_cn', 'cache_all_noleak', 'cache_cnmihomo', 'cache_google', 'cache_google_node', 'cache_node']
  const results = await Promise.allSettled(tags.map((tag) => dnsApi(`/plugins/${tag}/flush`, { method: 'POST' })))
  const ok = results.filter((item) => item.status === 'fulfilled').length
  notify(ok ? `已清理 ${ok} 组 DNS 缓存` : 'DNS 缓存清理失败')
}

async function toggleDnsCapture() {
  const active = Boolean(dnsCapture.value.capturing)
  await dnsApi(`/api/v1/audit/${active ? 'stop' : 'start'}`, { method: 'POST' })
  notify(active ? '已暂停查询记录采集' : '已开始查询记录采集')
  await loadDnsData()
}

async function clearDnsLogs() {
  if (!window.confirm('确定清空全部查询日志吗？此操作无法撤销。')) return
  await dnsApi('/api/v1/audit/clear', { method: 'POST' })
  dnsLogs.value = []
  notify('查询日志已清空')
  await loadDnsOverview()
}

async function loadAirportState() {
  try {
    const [state, catalog] = await Promise.all([
      airportApi<AirportState>('/api/state'),
      airportApi<AirportState>('/api/nodes'),
    ])
    const merged = { ...state, ...catalog, pools: state.pools || catalog.pools, settings: state.settings || catalog.settings }
    airportState.value = merged
    airportPools.value = Object.fromEntries(Object.entries(merged.pools || {}).map(([key, values]) => [key, [...values]]))
    airportSettings.value = merged.settings || {}
    return merged
  } catch (error) {
    notify(error instanceof Error ? `机场状态读取失败：${error.message}` : '机场状态读取失败')
    return null
  }
}

async function loadAirportRuntime() {
  const results = await Promise.allSettled([
    airportApi<JsonRecord>('/api/status'),
    airportApi<JsonRecord>('/api/probes'),
  ])
  if (results[0].status === 'fulfilled') airportStatus.value = results[0].value
  if (results[1].status === 'fulfilled') airportProbes.value = results[1].value
}

function airportMetric(node: string) {
  const results = arrayFrom(airportState.value.tests, ['results'])
  return results.find((item) => item.name === node) || {}
}

function airportFilteredNodes(pool: string) {
  const query = airportFilter.value.trim().toLowerCase()
  const used = new Set(airportPools.value[pool] || [])
  return (airportState.value.nodes || []).filter((node) => !used.has(String(node.name || '')) && (!query || String(node.name || '').toLowerCase().includes(query)))
}

function addAirportNode(pool: string, node: string) {
  if (!node) return
  if ((airportPools.value[pool] || []).length >= 5) {
    notify('每个候选池最多保留 5 个节点')
    return
  }
  airportPools.value[pool] = [...(airportPools.value[pool] || []), node]
}

function selectAirportNode(pool: string, event: Event) {
  const select = event.target as HTMLSelectElement
  addAirportNode(pool, select.value)
  select.value = ''
}

function historyText(value: unknown) {
  const history = Array.isArray(value) ? value : []
  return history.map((item) => `${number((item as JsonRecord).delay)} ms`).join(' · ') || '暂无记录'
}

async function probeAirportPool(name: string) {
  try {
    await airportApi('/api/pool-probe', { method: 'POST', body: JSON.stringify({ pool: name }) })
    notify(`${name} 专项复测已启动`)
    await loadAirportRuntime()
  } catch (error) {
    notify(error instanceof Error ? error.message : '业务池复测失败')
  }
}

function moveAirportNode(pool: string, index: number, delta: number) {
  const values = [...(airportPools.value[pool] || [])]
  const target = index + delta
  if (target < 0 || target >= values.length) return
  ;[values[index], values[target]] = [values[target], values[index]]
  airportPools.value[pool] = values
}

function removeAirportNode(pool: string, index: number) {
  const values = [...(airportPools.value[pool] || [])]
  if (values.length <= 1) {
    notify('候选池至少保留一个节点')
    return
  }
  values.splice(index, 1)
  airportPools.value[pool] = values
}

async function importAirport(slot: AirportSource) {
  const url = (airportUrls.value[slot.slot] || '').trim()
  if (!url) {
    notify('请先填写原生 HTTPS 订阅地址')
    return
  }
  busy.value = `airport-import-${slot.slot}`
  try {
    await airportApi('/api/import', { method: 'POST', body: JSON.stringify({ slot: slot.slot, url }) })
    airportUrls.value[slot.slot] = ''
    notify(`${slot.label} 已直连导入并完成校验`)
    await loadAirportState()
  } catch (error) {
    notify(error instanceof Error ? error.message : '订阅导入失败')
  } finally {
    busy.value = ''
  }
}

async function clearAirportSource(slot: AirportSource) {
  if (!window.confirm(`清空「${slot.label}」？当前生效候选池仍需保持可用。`)) return
  try {
    await airportApi('/api/remove', { method: 'POST', body: JSON.stringify({ slot: slot.slot }) })
    notify(`${slot.label} 已清空`)
    await loadAirportState()
  } catch (error) {
    notify(error instanceof Error ? error.message : '机场来源清理失败')
  }
}

async function addAirportSource() {
  try {
    const source = await airportApi<AirportSource>('/api/sources', { method: 'POST', body: '{}' })
    airportUrls.value[source.slot] = ''
    notify('已新增备用机场来源')
    await loadAirportState()
  } catch (error) {
    notify(error instanceof Error ? error.message : '新增机场来源失败')
  }
}

async function removeAirportSource(slot: AirportSource) {
  if (!window.confirm(`删除「${slot.label}」？若候选池仍引用它，系统会拒绝删除。`)) return
  try {
    await airportApi('/api/source-remove', { method: 'POST', body: JSON.stringify({ slot: slot.slot }) })
    notify(`${slot.label} 已删除`)
    await loadAirportState()
  } catch (error) {
    notify(error instanceof Error ? error.message : '删除机场来源失败')
  }
}

async function testAirportAll() {
  busy.value = 'airport-test'
  airportActionText.value = ''
  try {
    const result = await airportApi<JsonRecord>('/api/test-all', { method: 'POST', body: '{}' })
    airportTestStatus.value = { ...result }
    startAirportTestPolling()
  } catch (error) {
    stopAirportTestPolling()
    notify(error instanceof Error ? error.message : '稳定性测速失败')
  } finally {
    busy.value = ''
  }
}

async function saveAirportPools() {
  busy.value = 'airport-pools'
  airportActionText.value = '正在校验并应用候选池…'
  try {
    await airportApi('/api/pools', { method: 'POST', body: JSON.stringify({ pools: airportPools.value }) })
    notify('候选池已校验并生效')
    await loadAirportState()
    await loadAirportRuntime()
  } catch (error) {
    notify(error instanceof Error ? error.message : '候选池应用失败')
  } finally {
    airportActionText.value = ''
    busy.value = ''
  }
}

async function retestAirportPools() {
  busy.value = 'airport-retest'
  airportActionText.value = ''
  try {
    const result = await airportApi<JsonRecord>('/api/retest-apply', { method: 'POST', body: JSON.stringify({ pools: airportPools.value }) })
    airportTestStatus.value = { ...result }
    startAirportTestPolling()
  } catch (error) {
    stopAirportTestPolling()
    notify(error instanceof Error ? error.message : '候选池复测失败')
  } finally {
    busy.value = ''
  }
}

async function rollbackAirportPools() {
  if (!window.confirm('回退到上一版候选池并重新验证？')) return
  airportActionText.value = '正在回退上一版候选池…'
  try {
    await airportApi('/api/rollback', { method: 'POST', body: '{}' })
    notify('已验证并恢复上一版候选池')
    await loadAirportState()
  } catch (error) {
    notify(error instanceof Error ? error.message : '候选池回退失败')
  } finally {
    airportActionText.value = ''
  }
}

function openAirportPoolEditor(pool: string) {
  airportPoolEditor.value = pool
  airportPoolMode.value = airportSettings.value[pool]?.type || 'fallback'
}

async function saveAirportPoolMode() {
  const pool = airportPoolEditor.value
  if (!pool) return
  busy.value = 'airport-mode'
  try {
    const settings = { ...airportSettings.value, [pool]: { type: airportPoolMode.value } }
    const result = await airportApi<JsonRecord>('/api/pool-settings', { method: 'POST', body: JSON.stringify({ settings }) })
    airportSettings.value = result.settings || settings
    airportPools.value = result.pools || airportPools.value
    airportPoolEditor.value = ''
    notify(`${pool} 已切换为${airportPoolMode.value === 'url-test' ? '自动测速' : airportPoolMode.value === 'select' ? '手动选择' : '故障切换'}`)
    await loadAirportState()
  } catch (error) {
    notify(error instanceof Error ? error.message : '候选池模式保存失败')
  } finally {
    busy.value = ''
  }
}

async function loadRules() {
  try {
    const data = await api<RulePayload>('/api/rules')
    rulesPayload.value = data
    ruleDraft.value = [...(data.rules || [])]
    ruleCardLabels.value = { ...(data.rule_card_labels || {}) }
    ruleCardLabelsVersion.value = data.rule_card_labels_version || ''
    ruleDirty.value = false
  } catch (error) {
    notify(error instanceof Error ? `规则读取失败：${error.message}` : '规则读取失败')
  }
}

function ruleIsProtected(rule: string) {
  return Boolean((rulesPayload.value.protected || []).includes(rule) || rule.toUpperCase().startsWith('MATCH,'))
}

function ruleParts(rule: string) {
  const parts = rule.split(',')
  const type = (parts[0] || 'DOMAIN-SUFFIX').toUpperCase()
  if (type === 'MATCH') return { type, value: '', policy: parts[1] || 'Others' }
  return { type, value: parts[1] || '', policy: parts[2] || 'Others' }
}

const ruleCardCategories: Record<string, string> = {
  apple: 'Apple',
  microsoft: 'Microsoft',
  openai: 'AI',
  gemini: 'Gemini',
  telegram: 'Telegram',
  tiktok: 'TikTok',
  youtube: 'YouTube',
  google: 'Google',
}

function isGithubRule(model: ReturnType<typeof ruleParts>) {
  return ['DOMAIN', 'DOMAIN-SUFFIX'].includes(model.type) && new Set(['github.com', 'githubusercontent.com', 'githubassets.com', 'githubapp.com']).has(model.value.toLowerCase().replace(/^\./, ''))
}

function ruleCardKey(rule: string) {
  const model = ruleParts(rule)
  if (model.type === 'MATCH') return '__default__'
  if (isGithubRule(model)) return '__github__'
  if (model.policy === 'DIRECT') return '__direct__'
  if (model.type === 'GEOSITE' && ruleCardCategories[model.value.toLowerCase()]) return `__category__${model.value.toLowerCase()}`
  return `__custom__${encodeURIComponent(rule)}`
}

function ruleSetIndexForRule(raw: string) {
  const provider = raw.split(',')[1] || ''
  return ruleSets.value.findIndex((set) => arrayFrom(set.sources).some((source: JsonRecord) => provider === `family-${set.key}-${source.key}`))
}

function managedRulesForSet(set: JsonRecord) {
  return arrayFrom(set.sources).map((source: JsonRecord) => `RULE-SET,family-${set.key}-${source.key},${set.policy || 'Others'}${source.behavior === 'ipcidr' ? ',no-resolve' : ''}`)
}

function ruleCardEntries(key: string) {
  return ruleDraft.value.map((raw, index) => ({ raw, index, model: ruleParts(raw) })).filter((entry) => {
    if (entry.raw.startsWith('RULE-SET,family-') && ruleSetIndexForRule(entry.raw) >= 0) return false
    return ruleCardKey(entry.raw) === key
  })
}

function ruleItemEntries(item: string) {
  if (!item.startsWith('set:')) return ruleCardEntries(item.slice(5))
  const set = ruleSets.value.find((value) => value.key === item.slice(4))
  if (!set) return []
  return ruleDraft.value.map((raw, index) => ({ raw, index, model: ruleParts(raw) })).filter((entry) => {
    const provider = entry.raw.split(',')[1] || ''
    return arrayFrom(set.sources).some((source: JsonRecord) => provider === `family-${set.key}-${source.key}`)
  })
}

function itemMatchesRule(item: string, raw: string) {
  if (item.startsWith('set:')) {
    const set = ruleSets.value.find((value) => value.key === item.slice(4))
    const provider = raw.split(',')[1] || ''
    return Boolean(set && arrayFrom(set.sources).some((source: JsonRecord) => provider === `family-${set.key}-${source.key}`))
  }
  return !raw.startsWith('RULE-SET,family-') && ruleCardKey(raw) === item.slice(5)
}

function ruleCardTitle(key: string, entries: Array<{ raw: string; model: ReturnType<typeof ruleParts> }>) {
  if (key === '__default__') return '默认兜底'
  if (key === '__direct__') return '直连与国内服务'
  if (key === '__github__') return 'GitHub'
  if (key.startsWith('__category__')) return ruleCardCategories[key.slice('__category__'.length)] || '网站分类'
  const first = entries[0]
  return (first && ruleCardLabels.value[first.raw]) || (first ? `${first.model.type === 'DOMAIN-SUFFIX' ? '域名后缀' : first.model.type === 'DOMAIN' ? '域名' : first.model.type === 'GEOSITE' ? '网站分类' : first.model.type === 'GEOIP' ? 'IP 地区' : first.model.type.startsWith('IP-') ? 'IP 网段' : '规则'}：${first.model.value || '未命名规则'}` : '未命名规则')
}

function ruleCardLabel(key: string) {
  return ruleCardEntries(key)[0] ? ruleCardLabels.value[ruleCardEntries(key)[0].raw] || '' : ''
}

function ruleCardSourceCount(item: JsonRecord) {
  return item.entries?.length || arrayFrom(item.set?.sources).length
}

function ruleCardSummary(entries: Array<{ model: ReturnType<typeof ruleParts> }>) {
  return entries.slice(0, 2).map((entry) => entry.model.type === 'MATCH' ? '未被前面规则匹配的流量' : `${entry.model.type} ${entry.model.value || '未填写'}`).join('；') || '尚未添加规则'
}

function ruleCardSubtitle(key: string, entries: Array<{ model: ReturnType<typeof ruleParts> }>) {
  if (key === '__default__') return '未被前面规则匹配的流量'
  if (key === '__direct__') return '不经过机场，使用本地网络'
  const routes = [...new Set(entries.map((entry) => entry.model.policy))]
  return routes.length === 1 ? `出口：${routes[0]}` : `出口：${routes.length} 个出口`
}

function moveRuleCardLabel(previous: string, next: string) {
  if (ruleCardLabels.value[previous]) {
    ruleCardLabels.value[next] = ruleCardLabels.value[previous]
    delete ruleCardLabels.value[previous]
  }
}

function setRule(index: number, key: string, value: string) {
  const previous = ruleDraft.value[index]
  const parts = ruleParts(ruleDraft.value[index])
  if (key === 'type') parts.type = value
  if (key === 'value') parts.value = value
  if (key === 'policy') parts.policy = value
  ruleDraft.value[index] = `${parts.type},${parts.value},${parts.policy}`
  moveRuleCardLabel(previous, ruleDraft.value[index])
  ruleDirty.value = true
}

function setRuleFromEvent(index: number, key: string, event: Event) {
  const target = event.target as HTMLInputElement | HTMLSelectElement
  setRule(index, key, target.value)
}

function addRule(policy = 'Others') {
  const matchIndex = ruleDraft.value.findIndex((rule) => rule.toUpperCase().startsWith('MATCH,'))
  const index = matchIndex < 0 ? ruleDraft.value.length : matchIndex
  ruleDraft.value.splice(index, 0, `DOMAIN-SUFFIX,example.com,${policy}`)
  ruleDirty.value = true
}

function moveRule(index: number, delta: number) {
  const target = index + delta
  if (target < 0 || target >= ruleDraft.value.length || ruleIsProtected(ruleDraft.value[index]) || ruleDraft.value[target].toUpperCase().startsWith('MATCH,')) return
  ;[ruleDraft.value[index], ruleDraft.value[target]] = [ruleDraft.value[target], ruleDraft.value[index]]
  ruleDirty.value = true
}

function removeRule(index: number) {
  if (ruleIsProtected(ruleDraft.value[index])) return
  delete ruleCardLabels.value[ruleDraft.value[index]]
  ruleDraft.value.splice(index, 1)
  ruleDirty.value = true
}

function setRawRule(index: number, event: Event) {
  const previous = ruleDraft.value[index]
  ruleDraft.value[index] = (event.target as HTMLInputElement).value
  moveRuleCardLabel(previous, ruleDraft.value[index])
  ruleDirty.value = true
}

async function saveRules() {
  if (!ruleDirty.value) return
  if (!window.confirm(`应用当前 ${ruleDraft.value.length} 条代理规则和 ${(rulesPayload.value.rule_sets || []).length} 个规则集合？`)) return
  busy.value = 'rules-save'
  try {
    const data = await api<RulePayload & { message?: string }>('/api/rules', {
      method: 'POST',
      body: JSON.stringify({
        rules: ruleDraft.value,
        version: rulesPayload.value.version,
        rule_sets: rulesPayload.value.rule_sets,
        rule_sets_version: rulesPayload.value.rule_sets_version,
        rule_card_labels: ruleCardLabels.value,
        rule_card_labels_version: ruleCardLabelsVersion.value,
      }),
    })
    rulesPayload.value = data
    ruleDraft.value = [...(data.rules || [])]
    ruleCardLabels.value = { ...(data.rule_card_labels || {}) }
    ruleCardLabelsVersion.value = data.rule_card_labels_version || ''
    ruleDirty.value = false
    notify(data.message || '规则已通过校验并生效')
  } catch (error) {
    notify(error instanceof Error ? error.message : '规则应用失败')
  } finally {
    busy.value = ''
  }
}

function openRuleSetEditor(index = -1) {
  const current = index >= 0 ? rulesPayload.value.rule_sets?.[index] : undefined
  const source = current?.sources?.[0] || {}
  ruleSetEditorIndex.value = index
  ruleSetName.value = current?.name || ''
  ruleSetUrls.value = arrayFrom(current?.sources).map((item: JsonRecord) => item.url).join('\n')
  ruleSetPolicy.value = current?.policy || rulesPayload.value.policies?.find((item) => item.includes('Proxy')) || 'Proxy-Auto'
  ruleSetPriority.value = current?.priority || 'normal'
  ruleSetInterval.value = String(current?.interval || 86400)
  ruleSetBehavior.value = source.behavior || 'domain'
  ruleSetFormat.value = source.format || 'mrs'
  ruleSetEditorOpen.value = true
}

function applyRuleSetPreset(event: Event) {
  const select = event.target as HTMLSelectElement
  const preset = ruleSetPresetItems.find((item) => item.id === select.value)
  select.value = ''
  if (!preset) return
  const urls = [...new Set(ruleSetUrls.value.split(/\n/).map((value) => value.trim()).filter(Boolean))]
  const wasEmpty = urls.length === 0
  if (!urls.includes(preset.url)) urls.push(preset.url)
  ruleSetUrls.value = urls.join('\n')
  if (!ruleSetName.value.trim()) ruleSetName.value = preset.group || preset.name
  if (wasEmpty) {
    ruleSetPolicy.value = preset.policy || ruleSetPolicy.value
    ruleSetPriority.value = preset.priority || ruleSetPriority.value
    ruleSetInterval.value = String(preset.interval || ruleSetInterval.value)
  }
  ruleSetBehavior.value = preset.behavior || ruleSetBehavior.value
  ruleSetFormat.value = preset.format || ruleSetFormat.value
  notify(`${preset.name} 已追加到规则集合草稿`)
}

function addRuleSet() {
  const name = ruleSetName.value.trim()
  const urls = [...new Set(ruleSetUrls.value.split(/\n/).map((value) => value.trim()).filter(Boolean))]
  if (!name || !urls.length || urls.some((url) => !/^https:\/\//i.test(url))) {
    notify('规则集合需要名称和至少一条 HTTPS 地址')
    return
  }
  const key = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || `set-${Date.now()}`
  if (ruleSetBehavior.value === 'classical' && ruleSetFormat.value === 'mrs') {
    notify('复合规则不能使用 MRS 格式')
    return
  }
  const current = [...(rulesPayload.value.rule_sets || [])]
  const existing = ruleSetEditorIndex.value >= 0 ? current[ruleSetEditorIndex.value] : undefined
  const stableKey = existing?.key || key
  const sources = urls.map((url, index) => ({ key: `${stableKey}-${index + 1}`, url, behavior: ruleSetBehavior.value, format: ruleSetFormat.value }))
  const candidate = { key: stableKey, name, sources, policy: ruleSetPolicy.value, priority: ruleSetPriority.value, interval: Number(ruleSetInterval.value) }
  if (ruleSetEditorIndex.value >= 0) current[ruleSetEditorIndex.value] = candidate
  else current.push(candidate)
  rulesPayload.value.rule_sets = current
  ruleDirty.value = true
  ruleSetEditorOpen.value = false
  ruleSetEditorIndex.value = -1
  notify(`${existing ? '规则集合已更新' : '规则集合已加入草稿'}，点击“校验并应用”后才会生效`)
}

function removeRuleSet(index: number) {
  const sets = [...(rulesPayload.value.rule_sets || [])]
  if (!window.confirm(`删除规则集合「${sets[index]?.name || '未命名'}」？`)) return
  sets.splice(index, 1)
  rulesPayload.value.rule_sets = sets
  ruleDirty.value = true
}

function moveRuleSet(index: number, delta: number) {
  const sets = [...(rulesPayload.value.rule_sets || [])]
  const target = index + delta
  if (target < 0 || target >= sets.length) return
  ;[sets[index], sets[target]] = [sets[target], sets[index]]
  rulesPayload.value.rule_sets = sets
  ruleDirty.value = true
}

function ruleSetUrlsText(set: JsonRecord) {
  return arrayFrom(set.sources).map((source: JsonRecord) => source.url).join(' · ')
}

function ensureRuleItemInDraft(item: string) {
  if (!item.startsWith('set:') || ruleDraft.value.some((raw) => itemMatchesRule(item, raw))) return
  const set = ruleSets.value.find((value) => value.key === item.slice(4))
  if (!set) return
  const matchIndex = ruleDraft.value.findIndex((raw) => raw.toUpperCase().startsWith('MATCH,'))
  ruleDraft.value.splice(matchIndex < 0 ? ruleDraft.value.length : matchIndex, 0, ...managedRulesForSet(set))
}

function startRuleItemDrag(event: Event, item: string) {
  const card = ruleCardItems.value.find((value) => value.key === item)
  if (!card?.movable) return
  const dragEvent = event as DragEvent
  draggingRuleItem.value = item
  dragEvent.dataTransfer?.setData('text/plain', item)
  if (dragEvent.dataTransfer) dragEvent.dataTransfer.effectAllowed = 'move'
}

function endRuleItemDrag() {
  draggingRuleItem.value = ''
  dropTargetRuleItem.value = ''
}

function dragRuleItemOver(event: Event, item: string) {
  if (!draggingRuleItem.value || draggingRuleItem.value === item) return
  event.preventDefault()
  dropTargetRuleItem.value = item
  const dragEvent = event as DragEvent
  if (dragEvent.dataTransfer) dragEvent.dataTransfer.dropEffect = 'move'
}

function dragRuleItemLeave(item: string) {
  if (dropTargetRuleItem.value === item) dropTargetRuleItem.value = ''
}

function dropRuleItem(event: Event, target: string) {
  event.preventDefault()
  const source = draggingRuleItem.value
  endRuleItemDrag()
  if (!source || source === target) return

  const movingEntries = ruleItemEntries(source)
  const movingRules = movingEntries.length ? movingEntries.map((entry) => entry.raw) : (() => {
    if (!source.startsWith('set:')) return []
    const set = ruleSets.value.find((value) => value.key === source.slice(4))
    return set ? managedRulesForSet(set) : []
  })()
  if (!movingRules.length) return

  const movingIndexes = new Set(movingEntries.map((entry) => entry.index))
  ruleDraft.value = ruleDraft.value.filter((_, index) => !movingIndexes.has(index))
  ensureRuleItemInDraft(target)
  const insertAt = ruleDraft.value.findIndex((raw) => itemMatchesRule(target, raw))
  if (insertAt < 0) {
    notify('目标卡片没有可排序的规则')
    return
  }
  ruleDraft.value.splice(insertAt, 0, ...movingRules)
  ruleDirty.value = true
  notify('规则卡片顺序已调整，点击“校验并应用”后才会生效')
}

function openRuleCardEditor(key: string) {
  ruleCardEditorKey.value = key
  ruleCardEditorOpen.value = true
}

function closeRuleCardEditor() {
  ruleCardEditorOpen.value = false
  ruleCardEditorKey.value = ''
}

function addRuleToCard(key: string) {
  if (key === '__default__' || key.startsWith('set:')) return
  const entries = ruleCardEntries(key)
  const policy = key === '__direct__' ? 'DIRECT' : entries[0]?.model.policy || 'Others'
  const matchIndex = ruleDraft.value.findIndex((raw) => raw.toUpperCase().startsWith('MATCH,'))
  ruleDraft.value.splice(matchIndex < 0 ? ruleDraft.value.length : matchIndex, 0, `DOMAIN-SUFFIX,example.com,${policy}`)
  ruleDirty.value = true
}

function setRuleCardLabel(key: string, event: Event) {
  const entries = ruleCardEntries(key)
  const first = entries[0]
  if (!first) return
  const value = (event.target as HTMLInputElement).value.trim()
  if (value) ruleCardLabels.value[first.raw] = value
  else delete ruleCardLabels.value[first.raw]
  ruleDirty.value = true
}

function deleteRuleCard(key: string) {
  const entries = ruleCardEntries(key).filter((entry) => !ruleIsProtected(entry.raw))
  if (!entries.length) {
    notify('系统保护规则不能删除')
    return
  }
  if (!window.confirm(`删除「${ruleCardTitle(key, entries)}」中的 ${entries.length} 条规则？`)) return
  const indexes = new Set(entries.map((entry) => entry.index))
  entries.forEach((entry) => delete ruleCardLabels.value[entry.raw])
  ruleDraft.value = ruleDraft.value.filter((_, index) => !indexes.has(index))
  ruleDirty.value = true
  closeRuleCardEditor()
}

function platformItem(key: string) {
  return ((platformStatus.value as JsonRecord)[key] || {}) as UpdatePayload
}

function mosdnsUpdateState() {
  const phase = String(mosdnsStatus.value.phase || '')
  return phase === 'idle' ? 'current' : phase || 'unknown'
}

function previewRule() {
  const target = rulePreviewTarget.value.trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase()
  if (!target) {
    rulePreview.value = { tone: 'error', title: '无法预览', detail: '请输入域名或网址' }
    return
  }
  let runtimeRules = 0
  for (let index = 0; index < ruleDraft.value.length; index += 1) {
    const raw = ruleDraft.value[index]
    const model = ruleParts(raw)
    const type = model.type.toUpperCase()
    if (type === 'MATCH') {
      rulePreview.value = { tone: runtimeRules ? 'runtime' : 'known', title: runtimeRules ? '需要 Mihomo 运行时判断' : '确定命中兜底规则', detail: `${target} 最终使用「${model.policy}」`, rule: `第 ${index + 1} 条：${raw}` }
      return
    }
    const value = model.value.toLowerCase().replace(/^\*\./, '')
    const matched = type === 'DOMAIN' ? target === value : type === 'DOMAIN-SUFFIX' ? (target === value || target.endsWith(`.${value}`)) : type === 'DOMAIN-KEYWORD' ? target.includes(value) : false
    if (matched) {
      rulePreview.value = { tone: runtimeRules ? 'runtime' : 'known', title: runtimeRules ? '可能命中此规则' : '确定命中此规则', detail: `${target} 将使用「${model.policy}」`, rule: `第 ${index + 1} 条：${raw}` }
      return
    }
    if (['GEOSITE', 'GEOIP', 'IP-CIDR', 'IP-CIDR6'].includes(type)) runtimeRules += 1
  }
  rulePreview.value = { tone: 'runtime', title: '需要 Mihomo 运行时判断', detail: `${target} 未发现可由页面直接判断的域名规则`, rule: `共扫描 ${ruleDraft.value.length} 条规则` }
}

async function loadOpsFeature() {
  const results = await Promise.allSettled([
    dnsMaintenanceApi<JsonRecord>('/status'),
    api<JsonRecord>('/api/alerts'),
    api<RemoteWireGuardPayload>('/api/wireguard/remote-access'),
  ])
  if (results[0].status === 'fulfilled') mosdnsStatus.value = results[0].value
  if (results[1].status === 'fulfilled') alertConfig.value = results[1].value
  if (results[2].status === 'fulfilled') {
    remoteWireguard.value = results[2].value
    if (results[2].value.interface?.listen_port) remoteWireguardPort.value = String(results[2].value.interface.listen_port)
  }
}

async function saveAlerts() {
  busy.value = 'alerts-save'
  try {
    await api('/api/alerts', {
      method: 'POST',
      body: JSON.stringify({
        enabled: Boolean(alertConfig.value.enabled),
        notify_recovery: alertConfig.value.notify_recovery !== false,
        source_slots: alertConfig.value.source_slots || [],
        token: alertToken.value.trim(),
        chat_id: alertChat.value.trim(),
      }),
    })
    alertToken.value = ''
    alertChat.value = ''
    notify('Telegram 告警设置已保存')
    await loadOpsFeature()
  } catch (error) {
    notify(error instanceof Error ? error.message : '告警设置保存失败')
  } finally {
    busy.value = ''
  }
}

async function testAlerts() {
  try {
    const result = await api<JsonRecord>('/api/alerts/test', { method: 'POST', body: '{}' })
    notify(result.message || '测试通知已发送')
  } catch (error) {
    notify(error instanceof Error ? error.message : '测试通知发送失败')
  }
}

function toggleAlertSource(slot: string) {
  const selected = new Set((alertConfig.value.source_slots || []) as string[])
  if (selected.has(slot)) selected.delete(slot)
  else selected.add(slot)
  alertConfig.value.source_slots = [...selected]
}

async function checkMosdns() {
  try {
    await dnsMaintenanceApi('/check', { method: 'POST', body: '{}' })
    notify('MosDNS 更新检查已启动')
    await loadOpsFeature()
  } catch (error) {
    notify(error instanceof Error ? error.message : 'MosDNS 检查失败')
  }
}

async function applyMosdns() {
  if (!window.confirm('升级将短暂重启 MosDNS，失败时自动回退。继续吗？')) return
  try {
    await dnsMaintenanceApi('/update', { method: 'POST', body: '{}' })
    notify('MosDNS 升级已启动')
    await loadOpsFeature()
  } catch (error) {
    notify(error instanceof Error ? error.message : 'MosDNS 升级失败')
  }
}

async function applyMihomo() {
  if (!window.confirm('升级将短暂重建 Mihomo 容器，失败时自动回退。继续吗？')) return
  await action('mihomo-apply', '/api/mihomo/upgrade/apply', {}, 'Mihomo 升级已启动')
}

async function loadFeatureView(view: string) {
  if (view === 'overview') {
    await loadDnsOverview()
  } else if (view === 'dns') {
    await Promise.all([loadDnsOverview(), loadDnsData()])
    if (dnsTab.value === 'logs' && !dnsLogs.value.length) await loadDnsLogs()
  } else if (view === 'airport') {
    await loadAirportState()
    await refreshAirportTestStatus()
    if (airportTestRunning.value) startAirportTestPolling()
    if (airportTab.value === 'runtime') await loadAirportRuntime()
  } else if (view === 'rules') {
    await loadRules()
  } else if (view === 'ops') {
    await loadOpsFeature()
  }
}

const devices = computed(() => devicePayload.value.devices || [])
const summary = computed(() => (devicePayload.value.summary || {}) as SummaryPayload)
const checks = computed(() => (summary.value.checks || {}) as Record<string, unknown>)
const standaloneMode = computed(() => summary.value.mode === 'standalone' || system.value.mode === 'standalone' || setupState.value.mode === 'standalone' || platformStatus.value.mode === 'standalone')
const navigationViews = computed(() => standaloneMode.value
  ? views.map((item) => item.id === 'members'
    ? { ...item, label: '代理设备', caption: '手动代理' }
    : item.id === 'traffic'
      ? { ...item, label: '流量观察', caption: '代理快照' }
      : item)
  : views)
const managedDevices = computed(() => devices.value.filter((device) => device.managed))
const onlineDevices = computed(() => devices.value.filter((device) => device.status === 'bound'))
const onlineManagedDevices = computed(() => onlineDevices.value.filter((device) => device.managed))
const totalPackets = computed(() => managedDevices.value.reduce((sum, device) => sum + number(device.packets), 0))
const totalConnections = computed(() => managedDevices.value.reduce((sum, device) => sum + number(device.connections), 0))
const ready = computed(() => Boolean(summary.value.ready && (standaloneMode.value || summary.value.netwatch === 'up')))
const healthChecks = computed(() => standaloneMode.value
  ? [
      { label: '运行模式', detail: '独立旁路', ok: true, icon: Server },
      { label: '国内解析', detail: checks.value.dns ? 'MosDNS 正常' : '需要检查', ok: Boolean(checks.value.dns), icon: Globe2 },
      { label: '代理入口', detail: checks.value.mihomo ? '7890 / 7893 已就绪' : '需要检查', ok: Boolean(checks.value.mihomo), icon: Network },
      { label: '设备接管', detail: '未启用，保持手动控制', ok: true, icon: Users },
      { label: '路由策略', detail: '请由家庭网关或客户端配置', ok: true, icon: SlidersHorizontal },
    ]
  : [
      { label: '管理连接', detail: summary.value.router === 'connected' ? 'RB5009 已连接' : '未连接', ok: summary.value.router === 'connected', icon: Router },
      { label: '国内解析', detail: checks.value.dns ? 'MosDNS 正常' : '需要检查', ok: Boolean(checks.value.dns), icon: Globe2 },
      { label: '控制接口', detail: checks.value.mihomo ? 'Mihomo 在线' : '需要检查', ok: Boolean(checks.value.mihomo), icon: Network },
      { label: '自动回退', detail: summary.value.netwatch === 'up' ? '已启用' : '未就绪', ok: summary.value.netwatch === 'up', icon: ShieldCheck },
    ])
const healthCheckFailures = computed(() => healthChecks.value.filter((item) => !item.ok).length)

const filteredDevices = computed(() => {
  const query = searchQuery.value.toLowerCase()
  return devices.value.filter((device) => {
    const matchesFilter = filter.value === 'all' || (filter.value === 'managed' && device.managed) || (filter.value === 'online' && device.status === 'bound') || (filter.value === 'favorites' && device.favorite)
    const text = `${device.name || ''} ${device.router_name || ''} ${device.ip} ${device.mac}`.toLowerCase()
    return matchesFilter && (!query || text.includes(query))
  })
})
const summaryDetail = computed(() => (summary.value.detail as Record<string, unknown> | undefined)?.proxy)
const trafficDevices = computed(() => [...managedDevices.value].sort((a, b) => number(b.packets) - number(a.packets)))
const maxPackets = computed(() => Math.max(1, ...trafficDevices.value.map((device) => number(device.packets))))
const visibleWireguardInterfaces = computed(() => (wireguard.value.interfaces || []).map((item) => {
  const peers = item.peers || []
  const livePeers = item.kind === 'site' && item.probe?.reachable ? peers : peers.filter((peer) => peer.active === true)
  return { ...item, peers: livePeers }
}).filter((item) => item.kind === 'site'
  ? Boolean(item.probe?.reachable || item.peers?.some((peer) => peer.active === true))
  : Boolean(item.peers?.length)))
const wireguardPeers = computed(() => visibleWireguardInterfaces.value.reduce((sum, item) => sum + (item.peers?.length || 0), 0))
const currentTemp = computed(() => number(system.value.temperature?.cpu_c, NaN))
const z4proUpdate = computed(() => platformStatus.value.z4pro || {})
const mihomoState = computed(() => updateStatus.value.state || 'unknown')
const z4proState = computed(() => z4proUpdate.value.state || 'unknown')
const platformItems = computed(() => standaloneMode.value
  ? [{ key: 'host', label: 'Linux 旁路主机' }, { key: 'mihomo', label: 'Mihomo' }, { key: 'mosdns', label: 'MosDNS' }]
  : [{ key: 'routeros', label: 'RouterOS' }, { key: 'z4pro', label: 'Z4Pro NAS' }, { key: 'mihomo', label: 'Mihomo' }, { key: 'mosdns', label: 'MosDNS' }])
const dnsTotal = computed(() => dnsFirst(dnsStats.value, 'total') || dnsFirst(dnsStats.value, 'total_queries') || dnsFirst(dnsStats.value, 'request_count'))
const dnsAverage = computed(() => dnsFirst(dnsStats.value, 'average_duration_ms') || dnsFirst(dnsStats.value, 'average_ms'))
const dnsRuleCount = computed(() => Object.values(dnsRuleData.value).filter((value) => value && typeof value === 'object' && !Array.isArray(value)).reduce((sum, value) => sum + number((value as JsonRecord).rule_count), 0))
const dnsFilteredLogs = computed(() => dnsLogs.value.filter((log) => {
  const query = dnsLogQuery.value.toLowerCase()
  if (query && !`${log.query_name || ''} ${log.client_ip || ''}`.toLowerCase().includes(query)) return false
  if (dnsLogFilter.value === 'direct') return dnsRouteName(log) === '直连'
  if (dnsLogFilter.value === 'proxy') return dnsRouteName(log) === '代理'
  if (dnsLogFilter.value === 'slow') return number(log.duration_ms) >= 100
  if (dnsLogFilter.value === 'error') return String(log.response_code || '').toUpperCase() !== 'NOERROR'
  return true
}))
const airportSources = computed(() => airportState.value.slots || [])
const airportPoolNames = computed(() => Object.keys(airportPools.value))
const airportTestedAt = computed(() => airportState.value.tests?.tested_at)
const airportTestStatus = ref<JsonRecord>({})
let airportTestPoll: number | undefined
let airportTestPrevRunning = false
const airportActionText = ref('')
const airportTestRunning = computed(() => Boolean(airportTestStatus.value.running))
const airportTestProgress = computed(() => {
  const total = Number(airportTestStatus.value.total || 0)
  const done = Number(airportTestStatus.value.completed || 0)
  return total ? Math.min(100, Math.round((done / total) * 100)) : 0
})
const airportTestStatusText = computed(() => {
  const s = airportTestStatus.value
  const action = String(s.action || '')
  if (s.running) {
    const base = action === 'retest-apply' ? '候选池复测中' : '全量测速中'
    const extra = action !== 'retest-apply' && s.phase === 'github' ? '（GitHub 专项）' : ''
    return `${base}：${s.completed ?? 0}/${s.total ?? 0} 个节点已完成${extra}`
  }
  if (s.error) return action === 'retest-apply' ? `复测未生效：${s.error}` : `测速未完成：${s.error}`
  if (s.finished_at && action === 'retest-apply') return s.applied ? '复测、专项、配置校验与运行验证均通过，候选池已生效' : '复测完成，但未生效'
  if (s.finished_at && action === 'full-test') return s.proposal_ready ? '测速完成，已生成待生效建议；点击“复测并生效”后更新出口' : '测速完成，但有业务池没有连续三次成功的节点'
  if (airportActionText.value) return airportActionText.value
  return ''
})
const airportProgressVisible = computed(() => Boolean(airportTestRunning.value || airportTestStatusText.value))
async function refreshAirportTestStatus() {
  try {
    const status = await airportApi<JsonRecord>('/api/test-status')
    const running = Boolean(status.running)
    airportTestStatus.value = status
    if (airportTestPrevRunning && !running) {
      airportTestPrevRunning = false
      stopAirportTestPolling()
      const pools = ((status.suggestions || {}) as { pools?: Record<string, string[]> }).pools
      if (pools && Object.keys(pools).length) {
        airportPools.value = Object.fromEntries(Object.entries(pools).map(([key, values]) => [key, [...values]]))
      }
      await loadAirportState()
    }
    airportTestPrevRunning = running
    if (!running) stopAirportTestPolling()
  } catch { /* keep last status */ }
}
function startAirportTestPolling() {
  stopAirportTestPolling()
  airportTestPrevRunning = true
  airportTestPoll = window.setInterval(refreshAirportTestStatus, 1000)
}
function stopAirportTestPolling() {
  if (airportTestPoll) { window.clearInterval(airportTestPoll); airportTestPoll = undefined }
}
const airportRuntimeGroups = computed(() => Object.entries((airportStatus.value.groups || {}) as Record<string, JsonRecord>))
const airportFailsafeEntries = computed(() => Object.entries((airportStatus.value.failsafes || {}) as Record<string, JsonRecord>))
const rulePolicies = computed(() => rulesPayload.value.policies || ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'Others'])
const ruleSets = computed(() => rulesPayload.value.rule_sets || [])
const ruleCardItems = computed(() => {
  const keys: string[] = []
  for (const raw of ruleDraft.value) {
    const setIndex = ruleSetIndexForRule(raw)
    const item = setIndex >= 0 ? `set:${ruleSets.value[setIndex].key}` : `rule:${ruleCardKey(raw)}`
    if (!keys.includes(item)) keys.push(item)
  }
  for (const set of ruleSets.value) {
    const item = `set:${set.key}`
    if (keys.includes(item)) continue
    const index = set.priority === 'high'
      ? keys.findIndex((value) => value !== 'rule:__direct__' && value !== 'rule:__default__')
      : keys.findIndex((value) => value === 'rule:__direct__')
    keys.splice(index < 0 ? keys.length : index, 0, item)
  }
  return keys.map((item) => {
    if (item.startsWith('set:')) {
      const set = ruleSets.value.find((value) => value.key === item.slice(4)) || {}
      const entries = ruleItemEntries(item)
      return {
        key: item,
        kind: 'set',
        set,
        entries,
        title: set.name || '未命名规则集合',
        subtitle: set.priority === 'high' ? '高优先级规则集合' : '普通优先规则集合',
        policy: set.policy || 'Others',
        summary: ruleSetUrlsText(set),
        facts: `${arrayFrom(set.sources).length} 条来源 · 每 ${Math.round(Number(set.interval || 86400) / 3600)} 小时更新`,
        movable: true,
        editable: true,
        priority: set.priority || 'normal',
        ruleSetIndex: ruleSets.value.findIndex((value) => value.key === set.key),
      }
    }
    const key = item.slice(5)
    const entries = ruleCardEntries(key)
    const editable = entries.some((entry) => !ruleIsProtected(entry.raw))
    const first = entries[0]?.index
    const last = entries.at(-1)?.index
    return {
      key: item,
      kind: 'rule',
      set: null,
      entries,
      title: ruleCardTitle(key, entries),
      subtitle: ruleCardSubtitle(key, entries),
      policy: entries[0]?.model.policy || 'Others',
      summary: ruleCardSummary(entries),
      facts: `${entries.length} 条规则 · ${first === undefined ? '未排序' : `第 ${first + 1}${last !== first ? `-${(last || first) + 1}` : ''} 条`}`,
      movable: editable && key !== '__direct__' && key !== '__default__',
      editable,
      protected: key === '__default__',
      ruleKey: key,
    }
  })
})
function updateLabel(state: string) {
  return ({ current: '已是最新', checked: '检查完成', up_to_date: '已是最新', available: '有可用更新', update_available: '有可用更新', checking: '检查中', check_failed: '检查失败', error: '检查失败', preview_ignored: '已忽略预发布', applying: '升级中', updating: '升级中', updated: '升级完成', success: '升级完成', rolled_back: '已自动回退', failed: '维护失败', unknown: '待检查' } as Record<string, string>)[state] || state
}
function updateTone(state: string) {
  return ['current', 'checked', 'up_to_date', 'updated', 'success'].includes(state) ? 'good' : ['available', 'update_available', 'checking', 'applying', 'updating', 'busy'].includes(state) ? 'warn' : ''
}
function updateVersion(value: unknown) {
  const version = textValue(value, '')
  if (version.startsWith('sha256:') && version.length > 28) return `${version.slice(0, 17)}...${version.slice(-8)}`
  return version
}
const setupUrl = computed(() => setupState.value.url || '/setup')

watch(isDark, (value) => setTheme(value), { immediate: true })
onMounted(() => {
  window.addEventListener('hashchange', () => {
    activeView.value = normalizeView(window.location.hash.slice(1))
    void loadFeatureView(activeView.value)
  })
  load()
  void loadFeatureView(activeView.value)
  poller = window.setInterval(load, 30000)
})
onUnmounted(() => { if (poller) window.clearInterval(poller); if (airportTestPoll) window.clearInterval(airportTestPoll); window.clearTimeout(toastTimer) })
</script>

<template>
  <div class="app-frame">
    <aside class="sidebar">
      <div class="brand-lockup">
        <div class="brand-mark"><Zap :size="18" :stroke-width="2.4" /></div>
        <div><strong>家庭网络控制台</strong><span>HOME NETWORK</span></div>
      </div>
      <div class="connection-pill" :class="{ warning: !ready }"><span class="status-dot" />{{ ready ? '旁路运行正常' : '需要检查' }}</div>
      <nav class="side-nav" aria-label="主导航">
        <button v-for="item in navigationViews" :key="item.id" class="nav-item" :class="{ active: activeView === item.id }" @click="selectView(item.id)">
          <component :is="item.icon" :size="18" :stroke-width="1.9" /><span><b>{{ item.label }}</b><small>{{ item.caption }}</small></span><ChevronRight v-if="activeView === item.id" :size="15" />
        </button>
      </nav>
      <div class="sidebar-bottom">
        <div class="mini-availability"><HeartPulse :size="16" /><span>系统可用性</span><strong>{{ ready ? '99.9%' : '检查中' }}</strong></div>
        <a class="secondary-button sidebar-console-switch" href="/legacy" title="回到原版管理界面" aria-label="回到原版管理界面"><ArrowUpRight :size="15" /><span>回到原版</span></a>
        <div class="sidebar-version">Family Proxy <span :title="String(summary.build_id || '')">{{ summary.version || '0.11.12' }}</span></div>
      </div>
    </aside>

    <main class="main-content">
      <header class="topbar">
        <div class="mobile-brand"><div class="brand-mark"><Zap :size="16" /></div><strong>家庭网络控制台</strong></div>
        <div class="breadcrumb"><span>控制台</span><ChevronRight :size="14" /><strong>{{ navigationViews.find((item) => item.id === activeView)?.label }}</strong></div>
        <div class="top-actions">
          <button class="icon-button" title="刷新状态" aria-label="刷新状态" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spin: loading }" /></button>
          <button class="icon-button mobile-rules-link" title="规则配置" aria-label="规则配置" @click="selectView('rules')"><SlidersHorizontal :size="17" /></button>
          <button class="icon-button" title="页面显示设置" aria-label="页面显示设置" @click="consoleSettingsOpen = true"><Settings2 :size="17" /></button>
          <button class="icon-button" :title="isDark ? '切换浅色模式' : '切换深色模式'" :aria-label="isDark ? '切换浅色模式' : '切换深色模式'" @click="setTheme(!isDark)"><Sun v-if="isDark" :size="17" /><Moon v-else :size="17" /></button>
          <div class="profile-dot">家</div>
        </div>
      </header>

      <div class="page-wrap">
        <div v-if="errorMessage" class="notice-bar"><AlertTriangle :size="16" /><span>{{ errorMessage }}</span><button class="text-button" @click="load">重试</button></div>

        <section v-if="activeView === 'overview'" class="view-panel">
          <div class="page-heading hero-heading"><div><span class="eyebrow">{{ standaloneMode ? 'STANDALONE ROUTING' : 'SELECTIVE ROUTING' }} · {{ ready ? 'LIVE' : 'CHECK' }}</span><h1>{{ standaloneMode ? '独立旁路，按需使用。' : '让家庭网络，' }}<em v-if="!standaloneMode">自然地工作。</em></h1><p>{{ standaloneMode ? '旁路主机不会读取或接管家庭设备；请手动设置代理，或在家庭网关配置策略路由。' : '一眼掌握旁路状态、设备接管和当前流量，让每个连接都走在正确的路径上。' }}</p></div><div class="heading-status" :class="{ warning: !ready }"><span class="status-dot" /><div><strong>{{ !ready && healthCheckFailures ? `${healthCheckFailures} 项需检查` : ready ? (standaloneMode ? '独立旁路已就绪' : '网络状态良好') : '网络需要检查' }}</strong><small>刚刚更新 · 自动刷新 30 秒</small></div></div></div>
          <div class="metric-grid">
            <article class="metric-card metric-card-action accent-blue" role="button" tabindex="0" :title="standaloneMode ? '打开代理设备' : '打开接管设备'" @click="selectView('members')" @keyup.enter="selectView('members')"><div class="metric-icon"><ShieldCheck :size="19" /></div><span class="metric-label">{{ standaloneMode ? '代理设备' : '已接管设备' }}</span><strong>{{ standaloneMode ? '手动' : managedDevices.length }}</strong><small>{{ standaloneMode ? '不自动接管' : `${onlineManagedDevices.length} 台在线设备` }}</small><ArrowUpRight class="metric-arrow" :size="16" /></article>
            <article class="metric-card accent-green"><div class="metric-icon"><Wifi :size="19" /></div><span class="metric-label">活动连接</span><strong>{{ totalConnections }}</strong><small>当前连接数</small></article>
            <article class="metric-card metric-card-action metric-value-long accent-orange" role="button" tabindex="0" title="查看机场候选池" @click="selectView('airport')" @keyup.enter="selectView('airport')"><div class="metric-icon"><Globe2 :size="19" /></div><span class="metric-label">当前出口</span><strong :title="String(summaryDetail || '')">{{ summaryDetail || '未就绪' }}</strong><small>{{ standaloneMode ? '代理入口 7890 / 7893' : '当前业务出口' }}</small><ArrowUpRight class="metric-arrow" :size="16" /></article>
            <article class="metric-card metric-card-action accent-purple" role="button" tabindex="0" title="打开 DNS 管理" @click="selectView('dns')" @keyup.enter="selectView('dns')"><div class="metric-icon"><Gauge :size="19" /></div><span class="metric-label">DNS 平均处理</span><strong>{{ msValue(dnsAverage) }}</strong><small>平均处理时间</small><ArrowUpRight class="metric-arrow" :size="16" /></article>
          </div>
          <div class="section-grid overview-grid">
            <section class="surface-card status-card"><div class="card-heading"><div><span class="eyebrow">SYSTEM HEALTH</span><h2>运行状态</h2></div><span class="soft-badge" :class="{ good: ready }">{{ ready ? '全部正常' : '需检查' }}</span></div><div class="health-list"><div v-for="item in healthChecks" :key="item.label" class="health-row"><div class="health-icon"><component :is="item.icon" :size="17" /></div><div><strong>{{ item.label }}</strong><small>{{ item.detail }}</small></div><CheckCircle2 v-if="item.ok" class="health-check good" :size="18" /><AlertTriangle v-else class="health-check warning" :size="18" /></div></div><div v-if="(summary.drift || []).length" class="overview-alert"><AlertTriangle :size="14" /><span>配置对账：{{ (summary.drift || []).join('；') }}</span></div><button class="card-link" @click="selectView('ops')">查看系统维护 <ChevronRight :size="15" /></button></section>
            <section class="surface-card insight-card"><div class="card-heading"><div><span class="eyebrow">NETWORK OVERVIEW</span><h2>家庭网络概况</h2></div><MoreHorizontal :size="19" class="muted-icon" /></div><div class="network-visual"><div class="network-node router-node"><Router :size="24" /><span>{{ standaloneMode ? '家庭网关' : 'RB5009' }}</span><small>{{ standaloneMode ? '未接入 RouterOS' : (summary.router === 'connected' ? '已连接' : '未连接') }}</small></div><div class="network-line"><span /><span /><span /></div><div class="network-node proxy-node"><div class="proxy-icon"><div class="node-pulse" /><ShieldCheck :size="24" /></div><span>{{ standaloneMode ? '独立旁路主机' : '旁路控制面' }}</span><small>{{ checks.mihomo ? 'Mihomo 在线' : '控制接口不可用' }}</small></div></div><div class="insight-footer"><div><small>{{ standaloneMode ? '代理入口' : '自动回退' }}</small><strong>{{ standaloneMode ? '7890 / 7893' : (summary.netwatch === 'up' ? '已启用' : '未就绪') }}</strong></div><div><small>{{ standaloneMode ? '设备接管' : '远程互联' }}</small><strong>{{ standaloneMode ? '未启用' : `${wireguardPeers} 个 Peer` }}</strong></div><div><small>CPU</small><strong>{{ number(system.cpu?.percent).toFixed(1) }}%</strong></div></div></section>
          </div>
          <section class="surface-card capability-card"><div class="card-heading"><div><span class="eyebrow">QUICK ACCESS</span><h2>常用入口</h2></div></div><div class="capability-grid"><button class="capability" @click="selectView('members')"><div class="capability-icon blue"><Users :size="20" /></div><span><strong>{{ standaloneMode ? '代理设备' : '接管设备' }}</strong><small>{{ standaloneMode ? '手动设置代理或查看使用边界' : '设备、名称、图标与接管状态' }}</small></span><ChevronRight :size="17" /></button><button class="capability" @click="selectView('traffic')"><div class="capability-icon green"><Activity :size="20" /></div><span><strong>流量观察</strong><small>{{ standaloneMode ? '查看旁路主机代理快照' : '查看当前设备流量快照' }}</small></span><ChevronRight :size="17" /></button><button class="capability" @click="selectView('dns')"><div class="capability-icon orange"><Globe2 :size="20" /></div><span><strong>DNS 管理</strong><small>解析状态、日志与数据维护</small></span><ChevronRight :size="17" /></button><button class="capability" @click="selectView('airport')"><div class="capability-icon blue"><Server :size="20" /></div><span><strong>机场候选池</strong><small>订阅、测速与自动切换</small></span><ChevronRight :size="17" /></button><button class="capability" @click="selectView('rules')"><div class="capability-icon orange"><SlidersHorizontal :size="20" /></div><span><strong>规则配置</strong><small>打开分流规则管理</small></span><ChevronRight :size="17" /></button></div></section>
        </section>

        <section v-else-if="activeView === 'members'" class="view-panel">
          <div class="page-heading">
            <div><span class="eyebrow">{{ standaloneMode ? 'STANDALONE PROXY' : 'MANAGED DEVICES' }}</span><h1>{{ standaloneMode ? '代理设备' : '接管设备' }}</h1><p>{{ standaloneMode ? '当前为独立旁路模式，不读取家庭网关设备，也不会自动接管客户端。' : '管理旁路接管、HomeKit 本地直连、设备名称和显示图标。' }}</p></div>
            <button v-if="!standaloneMode" class="primary-button" @click="openAddDevice"><Plus :size="16" />加入设备</button>
          </div>
          <section v-if="standaloneMode" class="surface-card standalone-guide"><div class="card-heading"><div><span class="eyebrow">MANUAL ROUTING</span><h2>独立旁路已就绪</h2></div><ShieldCheck :size="19" class="muted-icon" /></div><p>系统不会连接 RouterOS、读取 DHCP 设备或写入接管规则。家庭设备默认保持原网络行为。</p><div class="standalone-guide-grid"><div><span>代理地址</span><strong>{{ summary.proxy_ip || '旁路主机局域网 IP' }}</strong></div><div><span>混合代理</span><strong>7890 · HTTP / SOCKS5</strong></div><div><span>透明入口</span><strong>7893 · 需网关策略路由</strong></div></div><div class="data-note-line">需要使用代理的设备，请手动设置代理；需要透明代理时，请在家庭网关将指定设备或网段指向此主机。</div></section>
          <div v-if="!standaloneMode" class="toolbar">
            <div class="search-field"><Search :size="17" /><input v-model="searchQuery" placeholder="搜索名称、IP 或 MAC" /></div>
            <div class="segmented"><button v-for="item in [{ id: 'managed', label: '已接管' }, { id: 'online', label: '在线' }, { id: 'favorites', label: '常用' }, { id: 'all', label: '全部' }]" :key="item.id" :class="{ active: filter === item.id }" @click="filter = item.id">{{ item.label }}</button></div>
          </div>
          <section v-if="!standaloneMode" class="surface-card member-card">
            <div class="table-head"><span>设备</span><span>网络地址</span><span>状态</span><span>旁路状态</span><span>操作</span></div>
            <div v-if="filteredDevices.length" class="member-list">
              <div v-for="device in filteredDevices" :key="device.mac" class="member-row">
                <div class="member-title"><button type="button" class="device-avatar-trigger" title="选择设备图标" :aria-label="`选择${device.name || '设备'}的图标`" @click="openIconPicker(device)"><div class="device-avatar"><component :is="iconFor(device.icon)" :size="17" /></div></button><div><strong>{{ device.name || '未命名设备' }}</strong><small>{{ device.custom_name ? (device.router_name || '自定义名称') : device.status === 'bound' ? '在线设备' : '已发现设备' }}</small></div></div>
                <div class="address-cell"><strong>{{ device.ip }}</strong><small>{{ device.mac }}</small></div>
                <div><span class="status-label" :class="device.status === 'bound' ? 'online' : 'offline'"><span />{{ device.status === 'bound' ? '在线' : '离线' }}</span></div>
                <div><span class="state-label" :class="device.managed ? (device.effective ? 'active' : 'pending') : 'idle'">{{ !device.managed ? '未接管' : device.effective ? '已生效' : '等待新流量' }}</span><small v-if="device.managed">{{ number(device.packets).toLocaleString() }} 个包</small></div>
                <div class="row-actions">
                  <button class="icon-button small" title="编辑设备名称和图标" aria-label="编辑设备名称和图标" @click="openRename(device)"><Pencil :size="15" /></button>
                  <button v-if="device.managed || device.favorite || device.status === 'bound'" class="compact-button homekit-control" :class="{ enabled: device.homekit_direct }" :disabled="busy === `homekit-${device.mac}`" :title="device.homekit_direct ? '关闭 HomeKit 本地直连' : '启用 HomeKit 本地直连'" @click="setHomeKitDirect(device)"><House :size="14" />{{ device.homekit_direct ? (device.homekit_route_active ? 'HomeKit 已生效' : 'HomeKit 已选择') : 'HomeKit 直连' }}</button>
                  <button v-if="device.managed && !device.fixed" class="compact-button danger" :disabled="busy === `remove-${device.ip}`" @click="removeDevice(device)">恢复直连</button>
                  <button v-else-if="!device.managed" class="compact-button" :disabled="busy === `join-${device.ip}`" @click="joinDevice(device)">加入旁路</button>
                  <button class="icon-button small" :class="{ selected: device.favorite }" :title="device.favorite ? '取消常用' : '加入常用'" :aria-label="device.favorite ? '取消常用' : '加入常用'" @click="toggleFavorite(device)">★</button>
                </div>
              </div>
            </div>
            <div v-else class="empty-state"><Users :size="28" /><strong>没有匹配的设备</strong><span>点击“加入设备”查看在线设备。</span></div>
          </section>
          <div class="data-note"><CircleHelp :size="15" /><span>{{ standaloneMode ? '独立旁路模式不读取家庭网关设备；代理流量由客户端或家庭网关显式送入。' : '列表来自 RouterOS DHCP、连接和旁路规则的实时合并结果。' }}</span><span v-if="!standaloneMode" class="last-refresh">自动刷新 · 30 秒</span></div>
        </section>

        <section v-else-if="activeView === 'traffic'" class="view-panel traffic-view">
          <div class="page-heading"><div><span class="eyebrow">TRAFFIC OBSERVATION</span><h1>流量观察</h1><p>以当前控制面快照呈现设备活动，不把瞬时数据包装成历史统计。</p></div><span class="live-badge"><span class="status-dot" />实时快照</span></div>
          <div class="metric-grid traffic-metrics"><article class="metric-card accent-blue"><span class="metric-label">观测设备</span><strong>{{ trafficDevices.length }}</strong><small>{{ standaloneMode ? '独立模式不接管设备' : '当前已接管设备' }}</small></article><article class="metric-card accent-green"><span class="metric-label">连接数</span><strong>{{ totalConnections }}</strong><small>{{ standaloneMode ? '旁路主机当前连接' : 'RouterOS 当前连接' }}</small></article><article class="metric-card accent-orange"><span class="metric-label">数据包</span><strong>{{ totalPackets.toLocaleString() }}</strong><small>{{ standaloneMode ? '当前代理快照' : '旁路规则命中快照' }}</small></article></div>
          <section class="section-grid traffic-grid"><section class="surface-card traffic-card"><div class="card-heading"><div><span class="eyebrow">BY DEVICE</span><h2>{{ standaloneMode ? '代理流量' : '设备活动' }}</h2></div><span class="muted-caption">{{ standaloneMode ? '当前代理快照' : '按数据包排序' }}</span></div><div v-if="trafficDevices.length" class="traffic-list"><div v-for="device in trafficDevices" :key="device.mac" class="traffic-row"><div class="traffic-label"><button type="button" class="device-avatar-trigger" title="选择设备图标" :aria-label="`选择${device.name || '设备'}的图标`" @click="openIconPicker(device)"><div class="device-avatar"><component :is="iconFor(device.icon)" :size="15" /></div></button><span>{{ device.custom_name || device.name || device.ip }}</span></div><div class="traffic-bar"><span :style="{ width: `${Math.max(4, (number(device.packets) / maxPackets) * 100)}%` }" /></div><strong>{{ number(device.packets).toLocaleString() }}</strong><small>包</small></div></div><div v-else class="empty-state"><Activity :size="28" /><strong>暂无流量快照</strong><span>{{ standaloneMode ? '独立旁路仅展示经代理入口观测到的流量。' : '设备接管后，这里会显示当前观测到的数据包。' }}</span></div></section><section class="surface-card observation-card"><div class="card-heading"><div><span class="eyebrow">OBSERVATION</span><h2>观测指标</h2></div><Gauge :size="19" class="muted-icon" /></div><div class="observation-stat"><span>连接活跃度</span><strong>{{ totalConnections ? '有活动' : '暂无活动' }}</strong><small>{{ standaloneMode ? '来源：本机代理快照' : '来源：RouterOS 连接表' }}</small></div><div class="observation-stat"><span>出口路径</span><strong>{{ checks.mihomo ? 'Mihomo' : '不可用' }}</strong><small>{{ summaryDetail || '当前接口未提供策略详情' }}</small></div><div class="observation-stat"><span>历史数据</span><strong>未启用</strong><small>当前版本仅展示实时快照</small></div></section></section>
        </section>

        <section v-else-if="activeView === 'dns'" class="view-panel feature-view dns-view">
          <div class="page-heading"><div><span class="eyebrow">DNS CONTROL</span><h1>DNS 管理</h1><p>查看解析路径、查询日志和规则数据；日常维护不会改变现有设备接管与分流边界。</p></div><span class="soft-badge" :class="{ good: Boolean(checks.dns) }"><span class="status-dot" />{{ checks.dns ? '运行正常' : '需要检查' }}</span></div>
          <div class="feature-tabs"><button :class="{ active: dnsTab === 'overview' }" @click="dnsTab = 'overview'; loadDnsOverview()">概览</button><button :class="{ active: dnsTab === 'logs' }" @click="dnsTab = 'logs'; loadDnsLogs()">查询日志</button><button :class="{ active: dnsTab === 'data' }" @click="dnsTab = 'data'; loadDnsData()">数据管理</button></div>

          <template v-if="dnsTab === 'overview'"><div class="dns-overview-stack">
            <div class="metric-grid feature-metrics"><article class="metric-card accent-blue"><span class="metric-label">累计查询</span><strong>{{ dnsTotal.toLocaleString() }}</strong><small>审计记录总量</small></article><article class="metric-card accent-green"><span class="metric-label">平均处理时间</span><strong>{{ msValue(dnsAverage) }}</strong><small>当前查询平均值</small></article><article class="metric-card accent-orange"><span class="metric-label">最近 1 小时</span><strong>{{ Number(dnsWindow('1h').request_count || 0).toLocaleString() }}</strong><small>平均 {{ msValue(dnsWindow('1h').average_duration_ms) }}</small></article><article class="metric-card accent-purple"><span class="metric-label">规则数量</span><strong>{{ dnsRuleCount.toLocaleString() }}</strong><small>国内、国外与国内 IP</small></article></div>
            <div class="route-cards"><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">DOMESTIC DNS</span><h2>国内解析</h2></div><div class="route-summary-actions"><button class="icon-button small dns-race-trigger" :class="{ active: dnsRaceOpen === 'domestic' }" :data-tooltip="dnsRaceSummary('domestic')" :aria-label="'国内解析并发竞速结果'" :aria-expanded="dnsRaceOpen === 'domestic'" title="查看并发竞速结果" @click.stop="toggleDnsRace('domestic')"><CircleHelp :size="15" /></button><button class="icon-button small" title="编辑国内解析地址" aria-label="编辑国内解析地址" @click="openDnsUpstreams('domestic')"><Pencil :size="15" /></button></div></div><p class="card-subtitle">国内规则直连解析 · 下游本地网络直连</p><div class="route-lines"><div class="route-upstreams"><span class="route-upstreams-label">上游</span><div class="route-upstreams-values"><div v-for="(item, index) in dnsUpstreamItems(dnsDomestic)" :key="`domestic-${index}-${dnsUpstreamLine(item)}`" class="route-line"><strong :title="dnsUpstreamLine(item)">{{ dnsUpstreamLine(item) }}</strong></div><div v-if="!dnsUpstreamItems(dnsDomestic).length" class="route-line"><strong>已配置</strong></div></div></div><div class="route-line"><span>下游</span><strong>本地网络直连</strong></div><div class="route-line"><span>状态</span><strong>配置已载入</strong></div></div></section><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">FOREIGN DNS</span><h2>国外解析</h2></div><div class="route-summary-actions"><button class="icon-button small dns-race-trigger" :class="{ active: dnsRaceOpen === 'foreign' }" :data-tooltip="dnsRaceSummary('foreign')" :aria-label="'国外解析并发竞速结果'" :aria-expanded="dnsRaceOpen === 'foreign'" title="查看并发竞速结果" @click.stop="toggleDnsRace('foreign')"><CircleHelp :size="15" /></button><button class="icon-button small" title="编辑国外解析地址" aria-label="编辑国外解析地址" @click="openDnsUpstreams('foreign')"><Pencil :size="15" /></button></div></div><p class="card-subtitle">国外规则经 Mihomo 解析 · 下游 Mihomo SOCKS</p><div class="route-lines"><div class="route-upstreams"><span class="route-upstreams-label">上游</span><div class="route-upstreams-values"><div v-for="(item, index) in dnsUpstreamItems(dnsForeign)" :key="`foreign-${index}-${dnsUpstreamLine(item)}`" class="route-line"><strong :title="dnsUpstreamLine(item)">{{ dnsUpstreamLine(item) }}</strong></div><div v-if="!dnsUpstreamItems(dnsForeign).length" class="route-line"><strong>已配置</strong></div></div></div><div class="route-line"><span>下游</span><strong>Mihomo SOCKS</strong></div><div class="route-line"><span>状态</span><strong>配置已载入</strong></div></div></section></div><div class="info-strip">{{ standaloneMode ? '这里只影响主动使用本机 MosDNS 的查询；不会修改家庭网关、DHCP DNS 或设备接管状态。' : '这里只影响主动使用 Z4Pro MosDNS 的查询，不修改 RouterOS、DHCP DNS 或设备接管状态。' }}</div>
            
<div class="section-grid"><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">RECENT RANKING</span><h2>常用域名与活跃设备</h2></div><Globe2 :size="18" class="muted-icon" /></div><div class="rank-columns"><div><span class="muted-caption">常用域名</span><div v-for="item in dnsDomains" :key="String(item.key)" class="rank-row"><span>{{ item.key || '未知' }}</span><strong>{{ Number(item.count || 0).toLocaleString() }}</strong></div><div v-if="!dnsDomains.length" class="empty-inline">暂无数据</div></div><div><span class="muted-caption">活跃设备</span><div v-for="item in dnsClients" :key="String(item.key)" class="rank-row"><span>{{ String(item.key || '--').replace(/^::ffff:/, '') }}</span><strong>{{ Number(item.count || 0).toLocaleString() }}</strong></div><div v-if="!dnsClients.length" class="empty-inline">暂无数据</div></div></div></section></div>
            <div class="section-grid feature-grid-two"><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">EFFECTIVE ROUTE</span><h2>实际分流结果</h2></div></div><div v-for="item in dnsEffective" :key="String(item.key)" class="rank-row"><span>{{ item.key || '默认' }}</span><strong>{{ Number(item.count || 0).toLocaleString() }}</strong></div><div v-if="!dnsEffective.length" class="empty-inline">暂无数据</div></section><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">SLOW QUERIES</span><h2>较慢查询</h2></div><Gauge :size="18" class="muted-icon" /></div><div v-for="item in dnsSlowest" :key="String(item.query_name || item.key)" class="rank-row"><span>{{ item.query_name || item.key || '未知' }}</span><strong>{{ msValue(item.duration_ms || item.value) }}</strong></div><div v-if="!dnsSlowest.length" class="empty-inline">暂无数据</div></section></div>
          </div></template>

          <template v-else-if="dnsTab === 'logs'">
            <div class="toolbar feature-toolbar"><div class="search-field"><Search :size="17" /><input v-model="dnsLogQuery" placeholder="搜索域名或设备 IP" /></div><div class="segmented"><button v-for="item in [{ id: 'all', label: '全部' }, { id: 'direct', label: '直连' }, { id: 'proxy', label: '代理' }, { id: 'slow', label: '慢查询' }, { id: 'error', label: '错误' }]" :key="item.id" :class="{ active: dnsLogFilter === item.id }" @click="dnsLogFilter = item.id">{{ item.label }}</button></div><button class="secondary-button" @click="loadDnsLogs"><RefreshCw :size="15" />重新载入</button></div>
            <section class="surface-card log-card"><div class="table-head log-head"><span>时间</span><span>域名</span><span>设备</span><span>类型</span><span>分流</span><span>上游</span><span>耗时</span><span>结果</span></div><div v-for="(log, index) in dnsFilteredLogs" :key="`${log.query_time}-${index}`" class="log-row"><span>{{ log.query_time ? new Date(log.query_time).toLocaleTimeString('zh-CN', { hour12: false }) : '--' }}</span><strong>{{ log.query_name || '--' }}</strong><span>{{ String(log.client_ip || '--').replace(/^::ffff:/, '') }}</span><span>{{ log.query_type || '--' }}</span><span class="soft-badge mini" :class="{ good: dnsRouteName(log) === '直连' }">{{ dnsRouteName(log) }}</span><span class="log-upstream">{{ log.final_upstream || log.selected_upstream || '--' }}</span><span>{{ msValue(log.duration_ms) }}</span><span>{{ log.response_code || '--' }}</span></div><div v-if="!dnsFilteredLogs.length" class="empty-state compact-empty"><Activity :size="26" /><strong>没有符合条件的查询记录</strong><span>可重新载入或调整筛选条件。</span></div><div class="table-foot"><span>显示 {{ dnsFilteredLogs.length }} 条，共读取 {{ dnsLogs.length }} 条</span><span>慢查询：≥ 100 ms</span></div></section>
          </template>

          <template v-else>
            <div class="section-grid data-layout"><div class="data-stack"><section class="surface-card rule-data-card"><div class="card-heading"><div><span class="eyebrow">RULE DATA</span><h2>规则数据</h2></div><span class="soft-badge">{{ Number(dnsCapacity.capacity || 0).toLocaleString() }} 条日志容量</span></div><div class="data-list"><div v-for="item in [{ label: '国内域名', value: dnsRuleData.domestic?.rule_count }, { label: '国外域名', value: dnsRuleData.foreign?.rule_count }, { label: '国内 IP', value: dnsRuleData.ip?.rule_count }]" :key="item.label" class="data-line"><span>{{ item.label }}</span><strong>{{ Number(item.value || 0).toLocaleString() }} 条</strong></div><div v-for="item in (dnsRuleData.extras || [])" :key="item.tag || item.name" class="data-line"><span>{{ item.name || item.tag || '附加规则' }}</span><strong>{{ Number(item.rule_count || 0).toLocaleString() }} 条</strong></div></div></section><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">CONTENT FILTER</span><h2>内容过滤</h2></div><span class="soft-badge" :class="{ good: dnsAdblock.mode === 'block' }">{{ dnsAdblock.mode === 'block' ? '正在拦截' : dnsAdblock.mode === 'observe' ? '观察中' : '已关闭' }}</span></div><div class="adblock-modes"><button v-for="mode in [{ id: 'off', label: '关闭' }, { id: 'observe', label: '观察' }, { id: 'block', label: '拦截' }]" :key="mode.id" type="button" :class="{ active: dnsAdblock.mode === mode.id, block: mode.id === 'block' }" :disabled="busy === 'dns-adblock'" @click="setDnsAdblockMode(mode.id)">{{ busy === 'dns-adblock' && dnsAdblock.mode === mode.id ? '切换中…' : mode.label }}</button></div><div class="filter-summary"><div><span>近期命中</span><strong>{{ Number(dnsAdblock.hits?.total || 0).toLocaleString() }} 次</strong></div><div><span>放行域名</span><strong>{{ Number(dnsAdblock.allowlist_count || 0) }} 个</strong></div><div><span>自动更新</span><strong>{{ dnsAdblock.auto_enabled ? `每 ${Number(dnsAdblock.interval_hours || 24)} 小时` : '已关闭' }}</strong></div></div><div class="data-note-line">{{ dnsAdblock.message || '尚未准备内容过滤规则' }} · 国内广告 {{ Number(dnsAdblock.hits?.cn_ads || 0) }} 次，成人内容 {{ Number(dnsAdblock.hits?.adult || 0) }} 次</div><div class="inline-actions"><button class="primary-button" @click="updateDnsAdblock">更新并校验</button><button class="secondary-button" @click="toggleDnsAdblockAuto">{{ dnsAdblock.auto_enabled ? '关闭自动更新' : '开启自动更新' }}</button><button class="secondary-button" @click="openDnsAllowlist">编辑放行名单</button></div><div v-if="dnsAllowlistOpen" class="inline-editor"><textarea v-model="dnsAllowlistDraft" placeholder="每行一个域名" /><div class="inline-actions"><button class="secondary-button" @click="dnsAllowlistOpen = false">取消</button><button class="primary-button" @click="saveDnsAllowlist">保存并校验</button></div></div></section><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">RULE UPDATES</span><h2>规则自动更新</h2></div><span class="soft-badge" :class="{ good: dnsRuleUpdate.phase === 'updated' || dnsRuleUpdate.phase === 'up_to_date', warn: dnsRulePhaseWarn(dnsRuleUpdate.phase) }">{{ dnsRulePhaseLabel(dnsRuleUpdate.phase) }}</span></div><div class="filter-summary"><div><span>更新范围</span><strong>官方国内/国外/国内 IP</strong></div><div><span>更新周期</span><strong>{{ dnsRuleUpdate.config?.rule_auto_enabled ? `每 ${dnsRuleUpdate.config?.rule_interval_hours || 24} 小时` : '已关闭' }}</strong></div><div><span>最近结果</span><strong>{{ dnsRulePhaseBusy(dnsRuleUpdate.phase) ? '进行中…' : timeValue(dnsRuleUpdate.completed_at || dnsRuleUpdate.updated_at) }}</strong></div></div><div class="data-note-line">{{ dnsRuleUpdate.message || '更新前备份，数量或探针异常时自动回滚。' }}</div><div class="inline-actions"><button class="primary-button" :disabled="dnsRuleBusy" @click="updateDnsRules">{{ dnsRuleBusy ? '更新中…' : '立即检查并更新' }}</button><button class="secondary-button" @click="toggleDnsRuleAuto">{{ dnsRuleUpdate.config?.rule_auto_enabled ? '关闭自动更新' : '开启自动更新' }}</button></div></section></div><aside class="surface-card maintenance-card dns-actions"><div class="card-heading"><div><span class="eyebrow">MAINTENANCE</span><h2>维护操作</h2></div><Settings2 :size="18" class="muted-icon" /></div><div class="action-block"><strong>刷新页面数据</strong><small>重新读取状态、规则数量与上游配置。</small><button class="secondary-button" @click="loadDnsData"><RefreshCw :size="14" />重新载入</button></div><div class="action-block"><strong>DNS 回归检查</strong><small>{{ dnsVerify.message || '快速检查保留缓存；完整回归会清理路由缓存。' }}</small><div class="inline-actions"><button class="secondary-button" @click="runDnsVerify('quick')">快速检查</button><button class="secondary-button" @click="runDnsVerify('full')">完整回归</button></div></div><div class="action-block"><strong>清空 DNS 缓存</strong><small>用于排查旧解析结果，清空后首次访问可能稍慢。</small><button class="secondary-button" @click="flushDnsCaches">清空缓存</button></div><div class="action-block"><strong>查询记录采集</strong><small>{{ dnsCapture.capturing ? '当前正在采集查询记录。' : '当前已暂停采集，解析服务仍然正常。' }}</small><button class="secondary-button" @click="toggleDnsCapture">{{ dnsCapture.capturing ? '暂停采集' : '开始采集' }}</button></div><div class="action-block"><strong>清空查询日志</strong><small>删除当前审计记录，不影响 DNS 解析。</small><button class="compact-button danger" @click="clearDnsLogs">清空日志</button></div></aside></div>
          </template>
        </section>

        <section v-else-if="activeView === 'airport'" class="view-panel feature-view">
          <div class="page-heading"><div><span class="eyebrow">PROXY SOURCES</span><h1>机场与候选池</h1><p>订阅只负责导入节点；业务流量仅使用经过筛选的候选池。订阅链接不会保存在页面配置中。</p></div><span class="soft-badge" :class="{ good: airportSources.some((source) => source.imported) }">{{ airportSources.filter((source) => source.imported).length }} 个来源已导入</span></div>
          <div class="feature-tabs"><button :class="{ active: airportTab === 'sources' }" @click="airportTab = 'sources'">订阅来源</button><button :class="{ active: airportTab === 'pools' }" @click="airportTab = 'pools'">候选池</button><button :class="{ active: airportTab === 'runtime' }" @click="airportTab = 'runtime'; loadAirportRuntime()">切换状态</button></div>

          <section v-if="airportTab === 'runtime'" class="surface-card failsafe-card"><div class="card-heading"><div><span class="eyebrow">FAILSAFE STATUS</span><h2>故障回退</h2><p class="card-subtitle">连续异常后按需启用应急节点；常态下保持当前业务出口不变。</p></div><div class="failsafe-summary"><span class="soft-badge good">{{ airportFailsafeEntries.length }} 个出口组</span><span class="soft-badge">{{ airportFailsafeEntries.filter((entry) => entry[1].phase === 'emergency').length }} 个应急切换</span></div></div><div v-if="airportFailsafeEntries.length" class="failsafe-list"><div class="failsafe-columns" aria-hidden="true"><span>出口组</span><span>主力 / 应急</span><span>当前状态</span><span>最近检查</span></div><div v-for="entry in airportFailsafeEntries" :key="entry[0]" class="failsafe-row"><div class="failsafe-group"><strong>{{ entry[0] }}</strong><small>业务出口</small></div><div class="failsafe-route"><strong>主力：{{ entry[1].primary || '未配置' }}</strong><small>应急：{{ entry[1].emergency || '未配置' }}</small></div><span class="failsafe-phase" :class="{ good: entry[1].phase === 'normal', warning: entry[1].phase !== 'normal' }">{{ entry[1].phase === 'emergency' ? `应急：${entry[1].emergency_node || '待确认'}` : entry[1].phase === 'exhausted' ? '候选耗尽' : entry[1].phase === 'manual-direct' ? '人工直连' : '常态运行' }}</span><div class="failsafe-check"><strong>{{ entry[1].last_error ? '异常' : entry[1].checked_at ? '已检查' : '未检查' }}</strong><small>{{ entry[1].last_error || (entry[1].checked_at ? timeValue(entry[1].checked_at) : '尚无检查记录') }}</small></div></div></div><div v-else class="empty-inline">尚无故障回退状态</div></section>
          <template v-if="airportTab === 'sources'">
            <section class="surface-card source-panel"><div class="card-heading"><div><span class="eyebrow">DIRECT IMPORT</span><h2>订阅来源</h2><p class="card-subtitle">{{ standaloneMode ? '由独立旁路主机直连拉取，不经过家庭网关代理、Fake-IP 或第三方转换；导入失败时保留当前可用配置。' : '由 Z4Pro 直连拉取，不经过代理、Fake-IP 或第三方转换；导入失败时保留当前可用配置。' }}</p></div><button class="secondary-button" @click="addAirportSource"><Plus :size="15" />新增备用机场</button></div><div class="source-list"><article v-for="source in airportSources" :key="source.slot" class="source-row"><div class="source-name"><span class="source-index">{{ source.slot === 'primary' ? '01' : '02' }}</span><div><strong>{{ source.label }}</strong><span class="source-state" :class="{ empty: !source.imported }">{{ source.imported ? `已导入 ${source.nodes || 0} 个有效节点` : '尚未导入' }}</span><small class="source-updated">{{ source.imported ? `最后更新 · ${source.updated_at}` : '导入后可在候选池中选择节点' }}</small></div></div><div class="source-actions"><button v-if="source.slot !== 'primary'" class="icon-button small source-remove" title="删除机场来源" aria-label="删除机场来源" @click="removeAirportSource(source)"><X :size="15" /></button><button class="primary-button" :disabled="busy === `airport-import-${source.slot}`" @click="importAirport(source)"><ArrowUpRight :size="15" />直连导入或替换</button><button class="secondary-button" @click="clearAirportSource(source)">清空</button></div><div class="source-url"><input v-model="airportUrls[source.slot]" type="url" autocomplete="off" placeholder="HTTPS 原生 Clash/Mihomo 订阅链接" /></div></article></div></section>
          </template>

          <template v-else-if="airportTab === 'pools'">
            <section class="surface-card"><div class="toolbar feature-toolbar"><div class="search-field"><Search :size="17" /><input v-model="airportFilter" placeholder="筛选节点名称" /></div><button class="primary-button" :disabled="busy === 'airport-test'" @click="testAirportAll"><Activity :size="15" />三次稳定性测速</button><button class="secondary-button" :disabled="busy === 'airport-retest'" @click="retestAirportPools">复测并生效</button><button class="secondary-button" @click="saveAirportPools">校验并应用</button><button class="compact-button danger" @click="rollbackAirportPools">回退上一版</button></div><div v-if="airportProgressVisible" class="airport-progress"><div class="airport-progress-bar"><span :style="{ width: `${airportTestProgress}%` }" /></div><span>{{ airportTestStatusText }}</span></div><div class="data-note-line">{{ airportTestedAt ? `上次稳定性测速：${timeValue(airportTestedAt)}` : '尚未执行稳定性测速；每次只在人工操作时测试节点。' }}</div></section><div class="pool-grid"><article v-for="pool in airportPoolNames" :key="pool" class="surface-card pool-card"><div class="card-heading"><div><h2>{{ pool }}</h2><span class="muted-caption">{{ (airportPools[pool] || []).length }}/5 个候选</span></div><button class="icon-button small" title="编辑候选池模式" aria-label="编辑候选池模式" @click="openAirportPoolEditor(pool)"><Pencil :size="15" /></button></div><div class="pool-mode"><span class="soft-badge mini">{{ airportSettings[pool]?.type === 'url-test' ? '自动测速' : airportSettings[pool]?.type === 'select' ? '手动选择' : '故障切换' }}</span><span class="muted-caption">按业务专项探针排序</span></div><div v-for="(node, index) in airportPools[pool] || []" :key="node" class="pool-node"><div><strong>{{ node }}</strong><small v-if="airportMetric(node).delay !== undefined">{{ airportMetric(node).delay }} ms · 抖动 {{ airportMetric(node).jitter }} · {{ airportMetric(node).success }}/3</small></div><div class="pool-node-actions"><button class="icon-button small" title="上移" aria-label="上移" @click="moveAirportNode(pool, index, -1)">↑</button><button class="icon-button small" title="下移" aria-label="下移" @click="moveAirportNode(pool, index, 1)">↓</button><button class="icon-button small" title="移除节点" aria-label="移除节点" @click="removeAirportNode(pool, index)"><X :size="14" /></button></div></div><div class="pool-add"><select @change="selectAirportNode(pool, $event)"><option value="">添加候选节点</option><option v-for="node in airportFilteredNodes(pool)" :key="node.name" :value="node.name">{{ node.name }}</option></select></div></article></div>
          </template>

          <template v-else>
            <section class="surface-card feature-note"><div class="card-heading"><div><span class="eyebrow">RUNTIME FAILOVER</span><h2>当前出口</h2></div><button class="secondary-button" @click="loadAirportRuntime"><RefreshCw :size="15" />刷新状态</button></div><p>显示 fallback 当前策略、实际叶子节点和最近自动切换，不主动触发冷备扫描。</p></section><div class="runtime-grid"><article v-for="entry in airportRuntimeGroups" :key="entry[0]" class="surface-card runtime-card"><div class="card-heading"><h2>{{ entry[0] }}</h2><span class="soft-badge" :class="{ good: entry[1].type !== 'unavailable' }">{{ entry[1].phase || entry[1].type || '不可用' }}</span></div><div class="runtime-facts"><div><span>策略</span><strong>{{ entry[1].now || '未选择' }}</strong></div><div><span>实际节点</span><strong>{{ entry[1].leaf || '未选择' }}</strong></div><div><span>来源</span><strong>{{ entry[1].source || '不可用' }}</strong></div><div><span>最近探测</span><strong>{{ historyText(entry[1].history) }}</strong></div></div></article></div><section class="surface-card event-card"><div class="card-heading"><div><span class="eyebrow">RECENT EVENTS</span><h2>最近自动切换</h2></div></div><div v-for="(event, index) in ((airportStatus.events || []).slice().reverse())" :key="`${event.time}-${index}`" class="event-row"><strong>{{ event.group }}</strong><span>{{ event.from }} → {{ event.to }}</span><small>{{ timeValue(event.time) }} · {{ event.reason }}</small></div><div v-if="!airportStatus.events?.length" class="empty-inline">尚无自动切换记录</div></section><section class="surface-card probe-card"><div class="card-heading"><div><span class="eyebrow">BUSINESS REACHABILITY</span><h2>业务可达性报告</h2></div></div><div class="probe-grid"><div v-for="(report, name) in (airportProbes.pools || {})" :key="String(name)"><span>{{ name }}</span><strong>{{ report.success || 0 }}/{{ report.candidate_count || 0 }} 通过</strong><small>{{ report.median_ms ? `中位 ${report.median_ms} ms · 抖动 ${report.max_jitter_ms || 0} ms` : '尚无专项复测' }}</small><button class="compact-button" @click="probeAirportPool(String(name))">复测此业务池</button></div></div></section>
          </template>
        </section>

        <section v-else-if="activeView === 'rules'" class="view-panel feature-view">
          <div class="page-heading"><div><span class="eyebrow">ROUTING RULES</span><h1>规则配置</h1><p>按从上到下的顺序匹配分流规则；规则集合优先级和自定义规则都会在校验后一次生效。</p></div><span class="soft-badge" :class="{ good: !ruleDirty }">{{ ruleDirty ? '有未应用修改' : `${ruleDraft.length} 条规则已生效` }}</span></div>
          <div class="toolbar rules-toolbar"><div class="toolbar-left"><h2>规则卡片顺序</h2><label class="toggle-control"><input v-model="ruleAdvanced" type="checkbox" /><span>详细编辑</span></label></div><div class="toolbar-right"><button class="secondary-button" @click="loadRules"><RefreshCw :size="15" />重新载入</button><button class="secondary-button" @click="addRule()"><Plus :size="15" />新增规则</button><button class="primary-button" :disabled="!ruleDirty || busy === 'rules-save'" @click="saveRules"><Check :size="15" />校验并应用</button></div></div>
          <section class="surface-card route-preview-card"><div class="card-heading"><div><span class="eyebrow">ROUTE PREVIEW</span><h2>规则命中预览</h2><p>输入域名或网址，查看当前规则中可确定的第一条命中。Geosite、GEOIP 和 IP 网段会明确标注为运行时判断。</p></div><SlidersHorizontal :size="18" class="muted-icon" /></div><div class="route-preview-form"><input v-model="rulePreviewTarget" inputmode="url" autocomplete="off" placeholder="例如 chatgpt.com 或 https://www.youtube.com" @keyup.enter="previewRule" /><button class="primary-button" @click="previewRule">查看路径</button></div><div v-if="rulePreview" class="route-preview-result" :class="rulePreview.tone"><strong>{{ rulePreview.title }}</strong><span>{{ rulePreview.detail }}</span><code>{{ rulePreview.rule }}</code></div></section>

          <section class="surface-card rule-set-section rule-card-section"><div class="card-heading"><div><span class="eyebrow">RULE CARDS</span><h2>规则卡片</h2><p>规则集合和普通规则共用一条匹配顺序；一张集合卡片可管理多条 HTTPS 来源。</p></div><button class="secondary-button" @click="openRuleSetEditor()"><Plus :size="15" />新增集合</button></div><div v-if="ruleCardItems.length" class="rule-card-grid"><article v-for="item in ruleCardItems" :key="item.key" class="rule-card" :class="{ direct: item.ruleKey === '__direct__', default: item.ruleKey === '__default__', high: item.kind === 'set' && item.priority === 'high', dragging: draggingRuleItem === item.key, 'drop-target': dropTargetRuleItem === item.key }" :draggable="item.movable" @dragstart="startRuleItemDrag($event, item.key)" @dragend="endRuleItemDrag" @dragover="dragRuleItemOver($event, item.key)" @dragleave="dragRuleItemLeave(item.key)" @drop="dropRuleItem($event, item.key)"><div class="rule-card-head"><div><h3>{{ item.title }}</h3><p>{{ item.subtitle }}</p></div><div class="rule-card-tools"><span class="soft-badge mini">{{ item.policy }}</span><div class="card-actions"><template v-if="item.kind === 'set'"><button class="icon-button small" title="编辑规则集合" aria-label="编辑规则集合" @click.stop="openRuleSetEditor(Number(item.ruleSetIndex))"><Pencil :size="14" /></button><button class="icon-button small danger" title="删除规则集合" aria-label="删除规则集合" @click.stop="removeRuleSet(Number(item.ruleSetIndex))"><Trash2 :size="14" /></button></template><template v-else><button class="icon-button small" title="编辑规则卡片" aria-label="编辑规则卡片" @click.stop="openRuleCardEditor(String(item.ruleKey || ''))"><Pencil :size="14" /></button><button class="icon-button small danger" title="删除规则卡片" aria-label="删除规则卡片" :disabled="!item.editable" @click.stop="deleteRuleCard(String(item.ruleKey || ''))"><Trash2 :size="14" /></button></template></div></div></div><div class="card-facts"><div class="card-fact"><span>{{ item.kind === 'set' ? '来源' : '规则' }}</span><strong>{{ item.kind === 'set' ? ruleCardSourceCount(item) : item.entries.length }} 条</strong></div><div class="card-fact"><span>顺序</span><strong>{{ item.facts }}</strong></div></div><p class="card-rules" :title="item.summary">{{ item.summary }}</p><div v-if="item.kind === 'set'" class="rule-card-meta"><span class="rule-set-pill" :class="{ high: item.priority === 'high' }">{{ item.priority === 'high' ? '高优先级' : '普通优先级' }}</span></div><div v-if="!item.movable" class="card-footer"><span class="card-order">{{ item.ruleKey === '__default__' ? '固定在末尾' : '系统锚点' }}</span></div></article></div><div v-else class="empty-inline">尚未配置规则</div></section>

          <section v-if="ruleAdvanced" class="surface-card rule-list-card"><div class="card-heading"><div><span class="eyebrow">DETAILED EDITOR</span><h2>逐条编辑规则</h2><p>卡片用于排序；这里保留逐条表单和原始 Mihomo 语法编辑。</p></div><span class="muted-caption">{{ ruleDraft.length }} 条，顶部优先</span></div><div v-if="ruleDraft.length" class="rule-list"><div v-for="(rule, index) in ruleDraft" :key="`${index}-${rule}`" class="rule-row" :class="{ protected: ruleIsProtected(rule) }"><span class="rule-index">{{ index + 1 }}</span><template v-if="ruleAdvanced"><input class="control raw-control" :value="rule" :readonly="ruleIsProtected(rule)" @input="setRawRule(index, $event)" /><span v-if="ruleIsProtected(rule)" class="system-badge">系统保护</span></template><template v-else><label><span>匹配方式</span><select class="control" :value="ruleParts(rule).type" :disabled="ruleIsProtected(rule)" @change="setRuleFromEvent(index, 'type', $event)"><option value="DOMAIN">域名</option><option value="DOMAIN-SUFFIX">域名及子域名</option><option value="DOMAIN-KEYWORD">域名关键词</option><option value="GEOSITE">网站分类</option><option value="GEOIP">地区 IP</option><option value="IP-CIDR">IPv4 网段</option><option value="IP-CIDR6">IPv6 网段</option><option value="MATCH">兜底</option></select></label><label><span>匹配内容</span><input class="control" :value="ruleParts(rule).value" :readonly="ruleIsProtected(rule) || ruleParts(rule).type === 'MATCH'" placeholder="例如 example.com" @input="setRuleFromEvent(index, 'value', $event)" /></label><label><span>出口</span><select class="control" :value="ruleParts(rule).policy" :disabled="ruleIsProtected(rule)" @change="setRuleFromEvent(index, 'policy', $event)"><option v-for="policy in rulePolicies" :key="policy" :value="policy">{{ policy }}</option></select></label></template><div class="rule-actions"><button class="icon-button small" title="上移" aria-label="上移" :disabled="index === 0 || ruleIsProtected(rule)" @click="moveRule(index, -1)"><ArrowUp :size="14" /></button><button class="icon-button small" title="下移" aria-label="下移" :disabled="index === ruleDraft.length - 1 || ruleIsProtected(rule)" @click="moveRule(index, 1)"><ArrowDown :size="14" /></button><button class="icon-button small danger" title="删除规则" aria-label="删除规则" :disabled="ruleIsProtected(rule)" @click="removeRule(index)"><Trash2 :size="14" /></button></div><span v-if="ruleIsProtected(rule)" class="system-badge">系统保护</span></div></div><div v-else class="empty-state"><SlidersHorizontal :size="28" /><strong>暂无代理规则</strong><span>点击“新增规则”开始配置。</span></div></section>
        </section>

        <section v-else-if="activeView === 'setup'" class="view-panel">
          <div class="page-heading"><div><span class="eyebrow">GETTING STARTED</span><h1>首次配置</h1><p>确认关键服务是否就绪。安装向导只在首次配置尚未完成时开放。</p></div><a v-if="setupState.pending" class="primary-button" :href="setupUrl" target="_blank" rel="noreferrer"><ArrowUpRight :size="16" />打开安装向导</a><span v-else class="soft-badge good">首次配置已完成</span></div>
          <section class="surface-card setup-card"><div class="setup-progress"><div class="progress-ring" :class="{ warning: !ready }"><Check :size="22" /></div><div><span class="eyebrow">CURRENT INSTANCE</span><h2>{{ ready ? '基础配置已就绪' : '配置仍需检查' }}</h2><p>{{ ready ? '控制面已连接 RouterOS，并能读取旁路状态。' : '请先检查 RouterOS、DNS 或 Mihomo 服务。' }}</p></div></div><div class="setup-steps"><div v-for="(item, index) in healthChecks" :key="item.label" class="setup-step"><div class="step-number" :class="{ done: item.ok }">{{ item.ok ? '✓' : index + 1 }}</div><div><strong>{{ item.label }}</strong><small>{{ item.detail }}</small></div><span class="step-state" :class="{ done: item.ok }">{{ item.ok ? '已完成' : '待检查' }}</span></div></div></section>
          <div class="section-grid setup-grid"><section class="surface-card setup-info"><div class="card-heading"><div><span class="eyebrow">INSTALLATION</span><h2>安装方式</h2></div><Sparkles :size="19" class="muted-icon" /></div><p>{{ setupState.pending ? '首次安装和敏感参数录入由一次性安装向导完成。' : '本机已经完成首次配置；重新安装需要在 NAS 终端重新生成一次性向导地址。' }} 完成后回到本页面查看实时状态。</p><code>sudo ./scripts/install-one-click.sh</code><div class="info-line"><ShieldCheck :size="15" />凭据保存在本机权限受限的配置文件中</div></section><section class="surface-card setup-info"><div class="card-heading"><div><span class="eyebrow">NETWORK BOUNDARY</span><h2>运行边界</h2></div><Network :size="19" class="muted-icon" /></div><div class="boundary-row"><span>控制面</span><strong>Python · 18093</strong></div><div class="boundary-row"><span>统一入口</span><strong>Gateway · 18088</strong></div><div class="boundary-row"><span>RouterOS</span><strong>仅通过现有 API</strong></div></section></div>
        </section>

        <section v-else class="view-panel" :class="{ 'standalone-ops': standaloneMode }">
          <div class="page-heading"><div><span class="eyebrow">OPERATIONS</span><h1>系统维护</h1><p>{{ standaloneMode ? '这里显示 Linux 旁路主机、Mihomo 和 MosDNS 状态；家庭网关策略由你自行维护。' : '这里显示 Z4Pro NAS 主机、Mihomo 旁路服务、RB5009 路由器和 WireGuard 互联状态。' }}</p></div><span class="soft-badge" :class="{ good: system.healthy }">{{ system.healthy ? '系统正常' : '实时状态' }}</span></div>
          <section v-if="standaloneMode" class="surface-card standalone-ops-card"><div class="card-heading"><div><span class="eyebrow">STANDALONE HOST</span><h2>独立旁路运行环境</h2></div><Server :size="19" class="muted-icon" /></div><div class="standalone-ops-grid"><div><span>运行模式</span><strong>独立旁路</strong><small>未接入 RouterOS</small></div><div><span>代理入口</span><strong>7890 / 7893</strong><small>手动代理或策略路由</small></div><div><span>设备接管</span><strong>未启用</strong><small>不会读取 DHCP 设备</small></div></div><div class="standalone-update-list"><div v-for="item in platformItems" :key="item.key" class="standalone-update-row"><div><strong>{{ item.label }}</strong><small>{{ platformItem(item.key).current_version || platformItem(item.key).current || '当前版本未记录' }}</small></div><span class="standalone-update-state" :class="{ good: ['current', 'checked', 'up_to_date', 'updated', 'success'].includes(platformItem(item.key).state || '') }">{{ updateLabel(platformItem(item.key).state || 'unknown') }}</span></div></div><div class="data-note-line">系统更新只检查本机 Linux、Mihomo 和 MosDNS；家庭网关、DNS 接管和 IPv6 策略由现有网络设备维护。</div></section>
          <section v-if="!standaloneMode" class="surface-card remote-wg-card"><div class="card-heading"><div><span class="eyebrow">WIREGUARD ACCESS</span><h2>异地回家</h2><p>生成官方 WireGuard 客户端配置；连接后全 IPv4 流量经家庭出口，并可访问家庭 LAN 设备。</p></div><span class="soft-badge" :class="{ good: remoteWireguard.supported && remoteWireguard.interface?.running }">{{ remoteWireguard.supported === false ? '不可用' : remoteWireguard.interface?.running ? '接口在线' : '待创建' }}</span></div><div v-if="remoteWireguard.supported === false" class="remote-wg-unavailable"><AlertTriangle :size="17" /><span>{{ remoteWireguard.message || 'RouterOS 版本不支持自动生成客户端配置。' }}</span></div><div v-else class="remote-wg-layout"><form class="remote-wg-form" @submit.prevent="generateRemoteWireguard"><div class="remote-wg-fields"><label>客户端名称<input v-model="remoteWireguardName" maxlength="40" autocomplete="off" placeholder="例如 iPhone 16 Pro Max" /></label><label>外部域名或公网 IP<input v-model="remoteWireguardEndpoint" maxlength="253" autocomplete="off" placeholder="例如 vpn.example.com" /></label><label>WireGuard UDP 端口<input v-model="remoteWireguardPort" inputmode="numeric" type="number" min="1" max="65535" /></label><label>家庭 DNS<input v-model="remoteWireguardDns" autocomplete="off" placeholder="默认使用旁路主机 MosDNS" /></label></div><div class="data-note-line">{{ remoteWireguard.interface ? `服务端 ${remoteWireguard.interface.name} · ${remoteWireguard.interface.network} · UDP ${remoteWireguard.interface.listen_port}` : '首次生成时会创建独立的 WireGuard 接口和家庭出口 NAT。' }}</div><button class="primary-button" type="submit" :disabled="busy === 'remote-wg-generate'"><Plus :size="15" />生成客户端二维码</button></form><div class="remote-wg-client-list"><div class="remote-wg-list-head"><span>已生成客户端</span><strong>{{ remoteWireguard.clients?.length || 0 }}</strong></div><div v-if="remoteWireguard.clients?.length" class="remote-wg-list"><div v-for="client in remoteWireguard.clients" :key="client.id" class="remote-wg-client"><div><strong>{{ client.name || '未命名客户端' }}</strong><small>{{ client.address || '未分配地址' }} · {{ remoteWireguardClientTraffic(client) }}</small></div><div class="remote-wg-client-actions"><span :class="{ good: client.active }">{{ remoteWireguardClientState(client) }}</span><button class="icon-button small danger" title="撤销客户端" aria-label="撤销客户端" :disabled="busy === `remote-wg-revoke-${client.id}`" @click="revokeRemoteWireguard(client)"><Trash2 :size="14" /></button></div></div></div><div v-else class="empty-inline">还没有生成远程客户端</div></div></div></section>
          <div class="resource-grid"><article class="resource-card"><div class="resource-head"><Cpu :size="18" /><span>{{ standaloneMode ? 'Linux 主机 · CPU' : 'Z4Pro NAS · CPU' }}</span><strong>{{ number(system.cpu?.percent).toFixed(1) }}%</strong></div><div class="resource-track"><span :style="{ width: `${Math.min(100, number(system.cpu?.percent))}%` }" /></div><small>{{ system.cpu?.cores || '—' }} 核 · 负载 {{ system.cpu?.load_1m ?? '—' }}</small></article><article class="resource-card"><div class="resource-head"><HardDrive :size="18" /><span>{{ standaloneMode ? 'Linux 主机 · 内存' : 'Z4Pro NAS · 内存' }}</span><strong>{{ number(system.memory?.percent).toFixed(1) }}%</strong></div><div class="resource-track green"><span :style="{ width: `${Math.min(100, number(system.memory?.percent))}%` }" /></div><small>{{ formatBytes(system.memory?.used) }} / {{ formatBytes(system.memory?.total) }}</small></article><article class="resource-card"><div class="resource-head"><Thermometer :size="18" /><span>{{ standaloneMode ? 'Linux 主机 · 温度' : 'Z4Pro NAS · 温度' }}</span><strong>{{ Number.isFinite(currentTemp) ? `${currentTemp.toFixed(0)}°C` : '不可用' }}</strong></div><div class="resource-track orange"><span :style="{ width: `${Math.min(100, number(system.temperature?.cpu_c))}%` }" /></div><small>{{ standaloneMode ? 'Linux 主机温度 · 传感器状态' : 'NAS CPU 温度 · 传感器状态' }}</small></article></div>
          <div class="section-grid ops-grid"><section class="surface-card maintenance-card"><div class="card-heading"><div><span class="eyebrow">COMPONENTS</span><h2>核心组件与设备</h2></div><RefreshCw :size="18" class="muted-icon" /></div><div class="component-row"><div class="component-icon"><Zap :size="17" /></div><div><strong>Mihomo 旁路代理</strong><small>{{ standaloneMode ? 'Linux 主机 Docker 旁路服务' : 'Z4Pro NAS Docker 旁路服务' }} · {{ updateStatus.current_version || '尚无版本记录' }}{{ updateStatus.latest_version ? ` · 最新 ${updateStatus.latest_version}` : '' }}</small></div><span class="component-state" :class="updateTone(mihomoState)">{{ updateLabel(mihomoState) }}</span><button class="compact-button" :disabled="busy === 'mihomo-check'" @click="checkMihomo">检查更新</button><button v-if="mihomoState === 'update_available'" class="compact-button" @click="applyMihomo">升级并应用</button></div><div v-if="!standaloneMode" class="component-row"><div class="component-icon"><Server :size="17" /></div><div><strong>Z4Pro NAS 系统</strong><small>当前运行的 NAS 主机系统 · {{ z4proUpdate.current_version || '尚无版本记录' }}{{ z4proUpdate.latest_version ? ` · 最新 ${z4proUpdate.latest_version}` : '' }}</small></div><span class="component-state" :class="updateTone(z4proState)">{{ updateLabel(z4proState) }}</span><button class="compact-button" :disabled="busy === 'platform-check'" @click="checkPlatform">检查更新</button></div><div class="component-row"><div class="component-icon"><Globe2 :size="17" /></div><div><strong>MosDNS 解析服务</strong><small>规则、广告过滤与 DNS 回归检查 · {{ mosdnsStatus.current_version || '尚无版本记录' }}{{ mosdnsStatus.latest_image ? ' · 最新 ' + updateVersion(mosdnsStatus.latest_image) : '' }}</small></div><span class="component-state" :class="updateTone(mosdnsUpdateState())">{{ updateLabel(mosdnsUpdateState()) }}</span><button class="compact-button" @click="checkMosdns">检查更新</button><button v-if="mosdnsStatus.phase === 'update_available'" class="compact-button" @click="applyMosdns">升级并应用</button></div><div v-if="!standaloneMode" class="component-row"><div class="component-icon"><Router :size="17" /></div><div><strong>RB5009 路由器</strong><small>{{ summary.router === 'connected' ? '家庭网关 API 管理连接正常 · ' + (summary.router_resource?.version || '版本未记录') : '家庭网关 API 管理连接不可用' }}</small></div><span class="component-state" :class="{ good: summary.router === 'connected' }">{{ summary.router === 'connected' ? '在线' : '检查' }}</span><button class="compact-button" @click="load">重新读取</button></div><div class="data-note-line">平台更新上次检查：{{ platformStatus.checked_at ? timeValue(platformStatus.checked_at) : '尚未执行平台更新检查。' }}</div></section><section v-if="!standaloneMode" class="surface-card maintenance-card"><div class="card-heading"><div><span class="eyebrow">RUNTIME</span><h2>Z4Pro NAS 运行详情</h2></div><MoreHorizontal :size="19" class="muted-icon" /></div><div class="runtime-list"><div><span>NAS 运行时间</span><strong>{{ formatUptime(system.uptime_seconds) }}</strong></div><div><span>Docker 容器</span><strong>{{ system.docker?.running ?? '—' }} / {{ system.docker?.total ?? '—' }}</strong></div><div><span>NAS 系统盘</span><strong>{{ number(system.disk?.percent).toFixed(1) }}%</strong></div><div><span>WireGuard 远程互联</span><strong>{{ wireguardPeers }} 个 Peer</strong></div></div><button class="card-link" @click="loadOpsFeature"><RefreshCw :size="15" />刷新详细维护状态</button></section></div>
          <div class="section-grid ops-extra-grid"><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">FAILOVER ALERTS</span><h2>故障告警</h2></div><span class="soft-badge" :class="{ good: alertConfig.enabled && alertConfig.configured }">{{ alertConfig.enabled && alertConfig.configured ? '已启用' : alertConfig.configured ? '已配置' : '未配置' }}</span></div><div class="alert-options"><label class="toggle-control"><input v-model="alertConfig.enabled" type="checkbox" /><span>启用机场出口故障告警</span></label><label class="toggle-control"><input v-model="alertConfig.notify_recovery" type="checkbox" /><span>恢复后发送通知</span></label><label v-for="source in (alertConfig.available_sources || [])" :key="source.slot" class="source-option"><input type="checkbox" :checked="(alertConfig.source_slots || []).includes(source.slot)" @change="toggleAlertSource(source.slot)" /><span>{{ source.label }}</span></label></div><div class="alert-fields"><input v-model="alertToken" type="password" autocomplete="off" placeholder="Bot Token（留空保持不变）" /><input v-model="alertChat" autocomplete="off" placeholder="Chat ID（留空保持不变）" /></div><div class="inline-actions"><button class="primary-button" @click="saveAlerts">保存告警设置</button><button class="secondary-button" @click="testAlerts">发送测试通知</button></div><div class="data-note-line">{{ alertConfig.enabled && alertConfig.configured ? '所选机场来源的候选节点全部不可用时推送；同一故障只通知一次。' : alertConfig.configured ? '凭据已保存，选择机场来源并启用后开始监控。' : '请填写 Bot Token 与 Chat ID 后保存。' }}</div></section><section class="surface-card"><div class="card-heading"><div><span class="eyebrow">WIREGUARD</span><h2>远程互联</h2></div><Network :size="18" class="muted-icon" /></div><div v-for="item in visibleWireguardInterfaces" :key="item.name" class="wg-interface"><template v-if="item.kind === 'mobile'"><div v-for="peer in item.peers || []" :key="peer.id || peer.name" class="wg-peer wg-mobile-peer"><div><strong>{{ wireguardPeerLabel(peer) }}</strong><small v-if="peer.alias">{{ peer.name }} · {{ peer.endpoint || '未建立' }}</small><small v-else>{{ peer.endpoint || '未建立' }}</small></div><div class="wg-peer-meta"><span>{{ wireguardHandshake(peer.last_handshake_seconds) }}</span><button class="icon-button small" title="编辑 Peer 名称" aria-label="编辑 Peer 名称" @click="openWireguardPeerRename(peer)"><Pencil :size="13" /></button></div></div></template><div v-else class="wg-peer wg-site-peer"><div><strong>{{ wireguardInterfaceLabel(item) }}</strong><small>{{ item.peers?.[0]?.endpoint || '固定父母家庭连接' }}</small></div><div class="wg-peer-meta"><span>{{ item.probe?.reachable ? '链路正常' : wireguardHandshake(item.peers?.[0]?.last_handshake_seconds) }}</span><button class="icon-button small" title="编辑固定 WG 名称" aria-label="编辑固定 WG 名称" @click="openWireguardInterfaceRename(item)"><Pencil :size="13" /></button></div></div></div><div v-if="!visibleWireguardInterfaces.length" class="empty-inline">当前没有活跃的 WireGuard 连接</div></section></div>
        </section>
      </div>

      <nav class="mobile-nav" aria-label="移动端主导航"><button v-for="item in navigationViews" :key="item.id" :class="{ active: activeView === item.id }" @click="selectView(item.id)"><component :is="item.icon" :size="18" /><span>{{ item.label }}</span></button></nav>
    </main>
    <div v-if="toastMessage" class="toast"><CheckCircle2 :size="16" />{{ toastMessage }}</div>
    <div v-if="consoleSettingsOpen" class="modal-backdrop" @click.self="consoleSettingsOpen = false"><section class="modal-card console-settings-card"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="consoleSettingsOpen = false"><X :size="17" /></button><span class="eyebrow">DISPLAY SETTINGS</span><h2>页面显示</h2><p>调整控制台外观，或打开旧版页面的区块显示设置。</p><div class="console-settings-row"><div><strong>主题</strong><small>{{ isDark ? '当前为深色模式' : '当前为浅色模式' }}</small></div><button type="button" class="secondary-button" @click="setTheme(!isDark)">{{ isDark ? '切换浅色' : '切换深色' }}</button></div><div class="console-settings-row"><div><strong>旧版页面设置</strong><small>DNS、机场、规则和维护页可以分别隐藏和排序区块。</small></div><a class="secondary-button" href="/legacy" @click="consoleSettingsOpen = false"><Settings2 :size="15" />打开旧版</a></div></section></div>
    <div v-if="renameTarget" class="modal-backdrop" @click.self="renameTarget = null"><form class="modal-card device-editor" @submit.prevent="saveRename"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="renameTarget = null"><X :size="17" /></button><span class="eyebrow">DEVICE PROFILE</span><h2>编辑设备</h2><p>{{ renameTarget.ip }} · {{ renameTarget.mac }}</p><label>显示名称<input v-model="renameDraft" autofocus maxlength="40" /></label><div class="modal-actions"><button type="button" class="secondary-button" @click="renameTarget = null">取消</button><button class="primary-button" type="submit" :disabled="busy === 'rename'">保存</button></div></form></div>
    <div v-if="dnsRaceOpen" class="modal-backdrop dns-race-backdrop" @click.self="dnsRaceOpen = null"><div class="modal-card dns-race-modal"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="dnsRaceOpen = null"><X :size="17" /></button><span class="eyebrow">UPSTREAM RACE</span><h2>{{ dnsRaceOpen === 'domestic' ? '国内上游' : '国外上游' }}</h2><p class="dns-race-popover-summary">{{ dnsRaceSummary(dnsRaceOpen) }}</p><div v-if="dnsRaceItems(dnsRaceOpen).length" class="dns-race-list"><div class="dns-race-columns" aria-hidden="true"><span>上游</span><span>胜率</span><span>平均延迟</span><span>错误率</span></div><div v-for="(item, index) in dnsRaceItems(dnsRaceOpen)" :key="`${dnsRaceOpen}-race-${item.name}-${item.address}`" class="dns-race-row" :class="{ best: index === 0 }"><div class="dns-race-leading"><span class="dns-race-rank">{{ index + 1 }}</span><div class="dns-race-identity"><strong>{{ item.name || '未命名上游' }}<em v-if="index === 0">当前最优</em></strong><small>{{ item.address || '地址未上报' }}</small></div></div><div class="dns-race-metric dns-race-win"><strong>{{ dnsRaceWinRate(item).toFixed(1) }}%</strong><small>{{ Number(item.winners || 0).toLocaleString() }} / {{ Number(item.queries || 0).toLocaleString() }} 次胜出</small><div class="dns-race-track"><span :style="{ width: `${Math.min(100, Math.max(0, dnsRaceWinRate(item)))}%` }" /></div></div><div class="dns-race-metric dns-race-latency"><strong>{{ msValue(item.average_ms) }}</strong><small>P95 {{ msValue(item.p95_ms) }} · P99 {{ msValue(item.p99_ms) }}</small></div><span class="dns-race-error" :class="dnsRaceErrorClass(item)">错误 {{ Number(item.error_rate || 0).toFixed(2) }}%</span></div></div><div v-else class="empty-inline">暂无可展示的竞速结果</div><div class="dns-race-note"><Gauge :size="15" /><span>排名来自 MosDNS 当前累计竞速样本；P95/P99 用于观察尾部延迟，不代表每次查询都固定耗时。</span><span v-if="dnsPerformance.sample_size">样本 {{ Number(dnsPerformance.sample_size).toLocaleString() }} 条</span></div></div></div>
    <div v-if="iconPickerTarget" class="modal-backdrop" @click.self="iconPickerTarget = null"><div class="modal-card icon-picker-card"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="iconPickerTarget = null"><X :size="17" /></button><span class="eyebrow">DEVICE ICON</span><h2>选择设备图标</h2><p>{{ iconPickerTarget.ip }} · {{ iconPickerTarget.mac }}</p><fieldset class="icon-picker"><legend>显示图标</legend><div class="icon-options"><button v-for="item in deviceIconOptions" :key="item.key" type="button" class="icon-choice" :class="{ selected: iconDraft === item.key }" :title="item.label" :aria-label="item.label" @click="iconDraft = item.key"><component :is="item.icon" :size="19" /><span>{{ item.label }}</span></button></div></fieldset><div class="modal-actions"><button type="button" class="secondary-button" @click="iconPickerTarget = null">取消</button><button class="primary-button" :disabled="busy === 'icon'" @click="saveDeviceIcon">保存</button></div></div></div>
    <div v-if="wireguardRenameTarget" class="modal-backdrop" @click.self="wireguardRenameTarget = null"><form class="modal-card" @submit.prevent="saveWireguardRename"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="wireguardRenameTarget = null"><X :size="17" /></button><span class="eyebrow">WIREGUARD NAME</span><h2>编辑远程互联名称</h2><p>当前显示：{{ wireguardRenameTarget.label }}；留空即可恢复原始名称。</p><label>显示名称<input v-model="wireguardRenameDraft" autofocus maxlength="40" :placeholder="wireguardRenameTarget.defaultLabel" /></label><div class="modal-actions"><button type="button" class="secondary-button" @click="wireguardRenameTarget = null">取消</button><button class="primary-button" type="submit" :disabled="busy === 'wireguard-rename'">保存</button></div></form></div>
    <div v-if="remoteWireguardConfig" class="modal-backdrop" @click.self="remoteWireguardConfig = null"><div class="modal-card remote-wg-qr-modal"><button type="button" class="modal-close icon-button" title="关闭二维码" aria-label="关闭二维码" @click="remoteWireguardConfig = null"><X :size="17" /></button><span class="eyebrow">WIREGUARD CLIENT</span><h2>{{ remoteWireguardConfig.name }}</h2><p>使用官方 WireGuard 客户端扫描二维码；客户端地址 {{ remoteWireguardConfig.address }}。二维码包含私钥，请勿转发。</p><div class="remote-wg-qr"><img :src="remoteWireguardConfig.qr" alt="WireGuard 客户端二维码" /></div><div class="modal-actions"><button type="button" class="secondary-button" @click="downloadRemoteWireguard"><ArrowDown :size="15" />下载 .conf</button><button type="button" class="primary-button" @click="remoteWireguardConfig = null">完成</button></div></div></div>
    <div v-if="dnsUpstreamsOpen" class="modal-backdrop" @click.self="dnsUpstreamsOpen = false"><form class="modal-card wide-editor" @submit.prevent="saveDnsUpstreams"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="dnsUpstreamsOpen = false"><X :size="17" /></button><span class="eyebrow">DNS UPSTREAMS</span><h2>{{ dnsUpstreamEditSide === 'foreign' ? '编辑国外解析地址' : '编辑国内解析地址' }}</h2><p>一行一个地址；带有 `|` 的内容会作为拨号地址保留。保存时会先做健康检查，失败不会替换当前配置。</p><label v-if="dnsUpstreamEditSide !== 'foreign'">国内上游<textarea v-model="dnsDomesticDraft" spellcheck="false" placeholder="223.5.5.5&#10;https://dns.alidns.com/dns-query" /></label><label v-if="dnsUpstreamEditSide === 'foreign'">国外上游<textarea v-model="dnsForeignDraft" spellcheck="false" placeholder="https://1.1.1.1/dns-query" /></label><div class="modal-actions"><button type="button" class="secondary-button" @click="dnsUpstreamsOpen = false">取消</button><button class="primary-button" type="submit" :disabled="busy === 'dns-upstreams'">校验并应用</button></div></form></div>
    <div v-if="airportPoolEditor" class="modal-backdrop" @click.self="airportPoolEditor = ''"><form class="modal-card" @submit.prevent="saveAirportPoolMode"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="airportPoolEditor = ''"><X :size="17" /></button><span class="eyebrow">POOL MODE</span><h2>编辑 {{ airportPoolEditor }}</h2><p>模式只改变当前候选池的选择方式，不会修改订阅内容。</p><label>候选池模式<select v-model="airportPoolMode"><option value="fallback">故障切换：按顺序使用候选</option><option value="url-test">自动测速：按延迟和健康度选择</option><option value="select">手动选择：保持当前节点</option></select></label><div class="modal-actions"><button type="button" class="secondary-button" @click="airportPoolEditor = ''">取消</button><button class="primary-button" type="submit" :disabled="busy === 'airport-mode'">保存模式</button></div></form></div>
    <div v-if="ruleCardEditorOpen" class="modal-backdrop" @click.self="closeRuleCardEditor"><form class="modal-card wide-editor rule-card-editor" @submit.prevent="closeRuleCardEditor"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="closeRuleCardEditor"><X :size="17" /></button><span class="eyebrow">RULE CARD</span><h2>{{ ruleCardTitle(ruleCardEditorKey, ruleCardEntries(ruleCardEditorKey)) }}</h2><p>修改会直接写入当前草稿；跨卡片的优先级请回到卡片网格拖动调整。</p><label v-if="ruleCardEditorKey.startsWith('__custom__')">卡片名称<input :value="ruleCardLabel(ruleCardEditorKey)" maxlength="40" placeholder="留空则显示匹配内容" @input="setRuleCardLabel(ruleCardEditorKey, $event)" /></label><div v-if="ruleCardEntries(ruleCardEditorKey).length" class="rule-card-editor-list"><div v-for="entry in ruleCardEntries(ruleCardEditorKey)" :key="`${entry.index}-${entry.raw}`" class="rule-card-editor-row"><div class="editor-rule-top"><span>第 {{ entry.index + 1 }} 条</span><span v-if="ruleIsProtected(entry.raw)" class="system-badge">系统保护</span></div><template v-if="ruleAdvanced"><input class="control raw-control" :value="entry.raw" :readonly="ruleIsProtected(entry.raw)" @input="setRawRule(entry.index, $event)" /></template><template v-else><div class="editor-two-column"><label>匹配方式<select class="control" :value="entry.model.type" :disabled="ruleIsProtected(entry.raw)" @change="setRuleFromEvent(entry.index, 'type', $event)"><option value="DOMAIN">域名</option><option value="DOMAIN-SUFFIX">域名及子域名</option><option value="DOMAIN-KEYWORD">域名关键词</option><option value="GEOSITE">网站分类</option><option value="GEOIP">地区 IP</option><option value="IP-CIDR">IPv4 网段</option><option value="IP-CIDR6">IPv6 网段</option><option value="MATCH">兜底</option></select></label><label>匹配内容<input class="control" :value="entry.model.value" :readonly="ruleIsProtected(entry.raw) || entry.model.type === 'MATCH'" placeholder="例如 example.com" @input="setRuleFromEvent(entry.index, 'value', $event)" /></label><label>出口<select class="control" :value="entry.model.policy" :disabled="ruleIsProtected(entry.raw)" @change="setRuleFromEvent(entry.index, 'policy', $event)"><option v-for="policy in rulePolicies" :key="policy" :value="policy">{{ policy }}</option></select></label></div></template><div class="modal-actions editor-row-actions"><span v-if="ruleIsProtected(entry.raw)" class="muted-caption">系统规则不可改写</span><button v-else type="button" class="compact-button danger" @click="removeRule(entry.index)"><Trash2 :size="14" />删除此规则</button></div></div></div><div v-else class="empty-inline">此卡片暂时没有可编辑规则</div><div class="modal-actions"><button v-if="ruleCardEditorKey !== '__default__' && !ruleCardEditorKey.startsWith('set:')" type="button" class="secondary-button" @click="addRuleToCard(ruleCardEditorKey)"><Plus :size="15" />新增到此卡片</button><button type="submit" class="primary-button">完成</button></div></form></div>
    <div v-if="ruleSetEditorOpen" class="modal-backdrop" @click.self="ruleSetEditorOpen = false"><form class="modal-card rule-set-editor" @submit.prevent="addRuleSet"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="ruleSetEditorOpen = false"><X :size="17" /></button><span class="eyebrow">RULE SET</span><h2>{{ ruleSetEditorIndex >= 0 ? '编辑规则集合' : '新增规则集合' }}</h2><p>支持多条 HTTPS 来源；由现有 Proxy 候选池下载，失败时保留上一份本地缓存。</p><label>常用集合<select @change="applyRuleSetPreset"><option value="">选择后追加旧版预置来源</option><option v-for="preset in ruleSetPresetItems" :key="preset.id" :value="preset.id">{{ preset.name }} · {{ preset.group }}</option></select></label><label>集合名称<input v-model="ruleSetName" maxlength="40" placeholder="例如 我的 AI 规则" /></label><label>出口<select v-model="ruleSetPolicy"><option v-if="!rulePolicies.includes(ruleSetPolicy)" :value="ruleSetPolicy">{{ ruleSetPolicy }}</option><option v-for="policy in rulePolicies" :key="policy" :value="policy">{{ policy }}</option></select></label><label>规则集 HTTPS 地址<textarea v-model="ruleSetUrls" spellcheck="false" placeholder="https://raw.githubusercontent.com/.../rules.mrs&#10;一行一条" /></label><div class="editor-two-column"><label>匹配类型<select v-model="ruleSetBehavior"><option value="domain">域名</option><option value="ipcidr">IP 网段</option><option value="classical">复合规则</option></select></label><label>文件格式<select v-model="ruleSetFormat"><option value="mrs">MRS（二进制）</option><option value="yaml">YAML</option><option value="text">文本</option></select></label><label>匹配优先级<select v-model="ruleSetPriority"><option value="normal">普通优先级</option><option value="high">高优先级</option></select></label><label>更新周期<select v-model="ruleSetInterval"><option value="21600">每 6 小时</option><option value="86400">每天</option><option value="604800">每周</option></select></label></div><div class="data-note-line">旧版集合预置只追加到草稿，点击“保存到草稿”并通过校验后才会生效。</div><div class="modal-actions"><button type="button" class="secondary-button" @click="ruleSetEditorOpen = false">取消</button><button class="primary-button" type="submit">保存到草稿</button></div></form></div>
  </div>
</template>
