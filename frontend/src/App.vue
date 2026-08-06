<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch, type Component } from 'vue'
import {
  Activity, AlertTriangle, ArrowUpRight, Camera, Check, CheckCircle2, ChevronRight,
  CircleHelp, Cpu, Gamepad2, Gauge, Globe2, HardDrive, HeartPulse, House,
  Laptop, LayoutDashboard, Menu, Monitor, Moon, MoreHorizontal, Network, Pencil,
  Plus, RefreshCw, Router, Search, Server, Settings2, ShieldCheck,
  SlidersHorizontal, Smartphone, Sparkles, Speaker, Sun, Tablet, Thermometer,
  Tv, Users, Watch, Wifi, X, Zap,
} from '@lucide/vue'

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
}

type SetupPayload = { pending?: boolean; url?: string }

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
]

function iconFor(key?: string) {
  return deviceIconOptions.find((item) => item.key === key)?.icon || Smartphone
}

type StatusPayload = {
  healthy?: boolean
  updated_at?: number
  uptime_seconds?: number
  cpu?: { percent?: number; cores?: number; load_1m?: number; load_5m?: number }
  memory?: { percent?: number; used?: number; total?: number; swap_percent?: number }
  disk?: { percent?: number; used?: number; total?: number }
  temperature?: { cpu_c?: number; nvme_c?: number; hdd?: Array<{ name?: string; temperature_c?: number }> }
  docker?: { running?: number; total?: number; unhealthy?: number }
  kernel?: string
}

type WireGuardPayload = { interfaces?: Array<{ name?: string; peers?: Array<{ latest_handshake?: number }> }> }
type UpdatePayload = { state?: string; status?: string; current?: string; latest?: string; current_version?: string; latest_version?: string; checked_at?: number; message?: string }
type PlatformPayload = { checked_at?: number; routeros?: UpdatePayload; z4pro?: UpdatePayload; mihomo?: UpdatePayload; mosdns?: UpdatePayload }

const views = [
  { id: 'overview', label: '总览', caption: '网络概况', icon: LayoutDashboard },
  { id: 'members', label: '接管设备', caption: '设备与策略', icon: Users },
  { id: 'traffic', label: '流量观察', caption: '实时快照', icon: Activity },
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
const searchQuery = ref('')
const filter = ref('all')
const renameTarget = ref<Device | null>(null)
const renameDraft = ref('')
const iconDraft = ref('phone')
let poller: number | undefined
let toastTimer: number | undefined

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

async function checkMihomo() {
  await action('mihomo-check', '/api/mihomo/upgrade/check', {}, 'Mihomo 更新检查已启动')
}

async function checkPlatform() {
  await action('platform-check', '/api/platform/updates/check', {}, '设备系统更新检查已启动')
}

const devices = computed(() => devicePayload.value.devices || [])
const summary = computed(() => devicePayload.value.summary || {})
const checks = computed(() => (summary.value.checks || {}) as Record<string, unknown>)
const managedDevices = computed(() => devices.value.filter((device) => device.managed))
const onlineDevices = computed(() => devices.value.filter((device) => device.status === 'bound'))
const onlineManagedDevices = computed(() => onlineDevices.value.filter((device) => device.managed))
const totalPackets = computed(() => managedDevices.value.reduce((sum, device) => sum + number(device.packets), 0))
const totalConnections = computed(() => managedDevices.value.reduce((sum, device) => sum + number(device.connections), 0))
const ready = computed(() => Boolean(summary.value.ready && summary.value.netwatch === 'up'))
const healthChecks = computed(() => [
  { label: '管理连接', detail: summary.value.router === 'connected' ? 'RB5009 已连接' : '未连接', ok: summary.value.router === 'connected', icon: Router },
  { label: '国内解析', detail: checks.value.dns ? 'MosDNS 正常' : '需要检查', ok: Boolean(checks.value.dns), icon: Globe2 },
  { label: '控制接口', detail: checks.value.mihomo ? 'Mihomo 在线' : '需要检查', ok: Boolean(checks.value.mihomo), icon: Network },
  { label: '自动回退', detail: summary.value.netwatch === 'up' ? '已启用' : '未就绪', ok: summary.value.netwatch === 'up', icon: ShieldCheck },
])
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
const wireguardPeers = computed(() => wireguard.value.interfaces?.reduce((sum, item) => sum + (item.peers?.length || 0), 0) || 0)
const currentTemp = computed(() => number(system.value.temperature?.cpu_c, NaN))
const z4proUpdate = computed(() => platformStatus.value.z4pro || {})
const mihomoState = computed(() => updateStatus.value.state || 'unknown')
const z4proState = computed(() => z4proUpdate.value.state || 'unknown')
function updateLabel(state: string) {
  return ({ current: '已是最新', update_available: '有可用更新', check_failed: '检查失败', unknown: '待检查' } as Record<string, string>)[state] || state
}
function updateTone(state: string) {
  return ['current', 'checked'].includes(state) ? 'good' : ['update_available', 'applying', 'busy'].includes(state) ? 'warn' : ''
}
const setupUrl = computed(() => setupState.value.url || '/setup')

watch(isDark, (value) => setTheme(value), { immediate: true })
onMounted(() => {
  window.addEventListener('hashchange', () => { activeView.value = normalizeView(window.location.hash.slice(1)) })
  load()
  poller = window.setInterval(load, 30000)
})
onUnmounted(() => { if (poller) window.clearInterval(poller); window.clearTimeout(toastTimer) })
</script>

<template>
  <div class="app-frame">
    <aside class="sidebar">
      <div class="brand-lockup">
        <div class="brand-mark"><Zap :size="18" :stroke-width="2.4" /></div>
        <div><strong>家庭旁路</strong><span>HOME NETWORK</span></div>
      </div>
      <div class="connection-pill" :class="{ warning: !ready }"><span class="status-dot" />{{ ready ? '旁路运行正常' : '需要检查' }}</div>
      <nav class="side-nav" aria-label="主导航">
        <button v-for="item in views" :key="item.id" class="nav-item" :class="{ active: activeView === item.id }" @click="selectView(item.id)">
          <component :is="item.icon" :size="18" :stroke-width="1.9" /><span><b>{{ item.label }}</b><small>{{ item.caption }}</small></span><ChevronRight v-if="activeView === item.id" :size="15" />
        </button>
        <a class="nav-item nav-link" href="/rules">
          <SlidersHorizontal :size="18" :stroke-width="1.9" /><span><b>规则配置</b><small>分流与策略</small></span><ArrowUpRight :size="15" />
        </a>
      </nav>
      <div class="sidebar-bottom">
        <div class="mini-availability"><HeartPulse :size="16" /><span>系统可用性</span><strong>{{ ready ? '99.9%' : '检查中' }}</strong></div>
        <a class="secondary-button sidebar-console-switch" href="/legacy" title="回到原版管理界面" aria-label="回到原版管理界面"><ArrowUpRight :size="15" /><span>回到原版</span></a>
        <div class="sidebar-version">Family Proxy <span>0.11</span></div>
      </div>
    </aside>

    <main class="main-content">
      <header class="topbar">
        <div class="mobile-brand"><div class="brand-mark"><Zap :size="16" /></div><strong>家庭旁路</strong></div>
        <div class="breadcrumb"><span>控制台</span><ChevronRight :size="14" /><strong>{{ views.find((item) => item.id === activeView)?.label }}</strong></div>
        <div class="top-actions">
          <a class="secondary-button console-switch" href="/legacy" title="回到旧版入口" aria-label="回到旧版入口"><ArrowUpRight :size="15" /><span>回到旧版入口</span></a>
          <button class="icon-button" title="刷新状态" aria-label="刷新状态" :disabled="loading" @click="load"><RefreshCw :size="17" :class="{ spin: loading }" /></button>
          <a class="icon-button mobile-rules-link" href="/rules" title="规则配置" aria-label="规则配置"><SlidersHorizontal :size="17" /></a>
          <button class="icon-button" :title="isDark ? '切换浅色模式' : '切换深色模式'" :aria-label="isDark ? '切换浅色模式' : '切换深色模式'" @click="setTheme(!isDark)"><Sun v-if="isDark" :size="17" /><Moon v-else :size="17" /></button>
          <div class="profile-dot">家</div>
        </div>
      </header>

      <div class="page-wrap">
        <div v-if="errorMessage" class="notice-bar"><AlertTriangle :size="16" /><span>{{ errorMessage }}</span><button class="text-button" @click="load">重试</button></div>

        <section v-if="activeView === 'overview'" class="view-panel">
          <div class="page-heading hero-heading"><div><span class="eyebrow">SELECTIVE ROUTING · {{ ready ? 'LIVE' : 'CHECK' }}</span><h1>让家庭网络，<em>自然地工作。</em></h1><p>一眼掌握旁路状态、设备接管和当前流量，让每个连接都走在正确的路径上。</p></div><div class="heading-status" :class="{ warning: !ready }"><span class="status-dot" /><div><strong>{{ ready ? '网络状态良好' : '网络需要检查' }}</strong><small>刚刚更新 · 自动刷新 30 秒</small></div></div></div>
          <div class="metric-grid">
            <article class="metric-card metric-card-action accent-blue" role="button" tabindex="0" title="打开接管设备" @click="selectView('members')" @keyup.enter="selectView('members')"><div class="metric-icon"><ShieldCheck :size="19" /></div><span class="metric-label">已接管设备</span><strong>{{ managedDevices.length }}</strong><small>{{ onlineManagedDevices.length }} 台在线设备</small><ArrowUpRight class="metric-arrow" :size="16" /></article>
            <article class="metric-card accent-green"><div class="metric-icon"><Wifi :size="19" /></div><span class="metric-label">活动连接</span><strong>{{ totalConnections }}</strong><small>当前连接数</small><ArrowUpRight class="metric-arrow" :size="16" /></article>
            <article class="metric-card accent-orange"><div class="metric-icon"><Activity :size="19" /></div><span class="metric-label">流量快照</span><strong>{{ totalPackets.toLocaleString() }}</strong><small>已观测数据包</small><ArrowUpRight class="metric-arrow" :size="16" /></article>
            <article class="metric-card accent-purple"><div class="metric-icon"><Server :size="19" /></div><span class="metric-label">运行时间</span><strong>{{ formatUptime(system.uptime_seconds) }}</strong><small>{{ system.kernel || '内核信息不可用' }}</small><ArrowUpRight class="metric-arrow" :size="16" /></article>
          </div>
          <div class="section-grid overview-grid">
            <section class="surface-card status-card"><div class="card-heading"><div><span class="eyebrow">SYSTEM HEALTH</span><h2>运行状态</h2></div><span class="soft-badge" :class="{ good: ready }">{{ ready ? '全部正常' : '需检查' }}</span></div><div class="health-list"><div v-for="item in healthChecks" :key="item.label" class="health-row"><div class="health-icon"><component :is="item.icon" :size="17" /></div><div><strong>{{ item.label }}</strong><small>{{ item.detail }}</small></div><CheckCircle2 v-if="item.ok" class="health-check good" :size="18" /><AlertTriangle v-else class="health-check warning" :size="18" /></div></div><button class="card-link" @click="selectView('ops')">查看系统维护 <ChevronRight :size="15" /></button></section>
            <section class="surface-card insight-card"><div class="card-heading"><div><span class="eyebrow">NETWORK OVERVIEW</span><h2>家庭网络概况</h2></div><MoreHorizontal :size="19" class="muted-icon" /></div><div class="network-visual"><div class="network-node router-node"><Router :size="24" /><span>RB5009</span><small>{{ summary.router === 'connected' ? '已连接' : '未连接' }}</small></div><div class="network-line"><span /><span /><span /></div><div class="network-node proxy-node"><div class="node-pulse" /><ShieldCheck :size="24" /><span>旁路控制面</span><small>{{ checks.mihomo ? 'Mihomo 在线' : '控制接口不可用' }}</small></div></div><div class="insight-footer"><div><small>自动回退</small><strong>{{ summary.netwatch === 'up' ? '已启用' : '未就绪' }}</strong></div><div><small>远程互联</small><strong>{{ wireguardPeers }} 个 Peer</strong></div><div><small>CPU</small><strong>{{ number(system.cpu?.percent).toFixed(1) }}%</strong></div></div></section>
          </div>
          <section class="surface-card capability-card"><div class="card-heading"><div><span class="eyebrow">QUICK ACCESS</span><h2>常用入口</h2></div></div><div class="capability-grid"><button class="capability" @click="selectView('members')"><div class="capability-icon blue"><Users :size="20" /></div><span><strong>接管设备</strong><small>设备、名称、图标与接管状态</small></span><ChevronRight :size="17" /></button><button class="capability" @click="selectView('traffic')"><div class="capability-icon green"><Activity :size="20" /></div><span><strong>流量观察</strong><small>查看当前设备流量快照</small></span><ChevronRight :size="17" /></button><a class="capability" href="/rules"><div class="capability-icon orange"><SlidersHorizontal :size="20" /></div><span><strong>规则配置</strong><small>打开分流规则管理</small></span><ArrowUpRight :size="17" /></a></div></section>
        </section>

        <section v-else-if="activeView === 'members'" class="view-panel">
          <div class="page-heading">
            <div><span class="eyebrow">MANAGED DEVICES</span><h1>接管设备</h1><p>管理旁路接管、HomeKit 本地直连、设备名称和显示图标。</p></div>
            <button class="primary-button" @click="openAddDevice"><Plus :size="16" />加入设备</button>
          </div>
          <div class="toolbar">
            <div class="search-field"><Search :size="17" /><input v-model="searchQuery" placeholder="搜索名称、IP 或 MAC" /></div>
            <div class="segmented"><button v-for="item in [{ id: 'all', label: '全部' }, { id: 'managed', label: '已接管' }, { id: 'online', label: '在线' }, { id: 'favorites', label: '常用' }]" :key="item.id" :class="{ active: filter === item.id }" @click="filter = item.id">{{ item.label }}</button></div>
          </div>
          <section class="surface-card member-card">
            <div class="table-head"><span>设备</span><span>网络地址</span><span>状态</span><span>旁路状态</span><span>操作</span></div>
            <div v-if="filteredDevices.length" class="member-list">
              <div v-for="device in filteredDevices" :key="device.mac" class="member-row">
                <div class="member-title"><div class="device-avatar"><component :is="iconFor(device.icon)" :size="17" /></div><div><strong>{{ device.name || '未命名设备' }}</strong><small>{{ device.custom_name ? (device.router_name || '自定义名称') : device.status === 'bound' ? '在线设备' : '已发现设备' }}</small></div></div>
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
          <div class="data-note"><CircleHelp :size="15" /><span>列表来自 RouterOS DHCP、连接和旁路规则的实时合并结果。</span><span class="last-refresh">自动刷新 · 30 秒</span></div>
        </section>

        <section v-else-if="activeView === 'traffic'" class="view-panel">
          <div class="page-heading"><div><span class="eyebrow">TRAFFIC OBSERVATION</span><h1>流量观察</h1><p>以当前控制面快照呈现设备活动，不把瞬时数据包装成历史统计。</p></div><span class="live-badge"><span class="status-dot" />实时快照</span></div>
          <div class="metric-grid traffic-metrics"><article class="metric-card accent-blue"><span class="metric-label">观测设备</span><strong>{{ trafficDevices.length }}</strong><small>当前已接管设备</small></article><article class="metric-card accent-green"><span class="metric-label">连接数</span><strong>{{ totalConnections }}</strong><small>RouterOS 当前连接</small></article><article class="metric-card accent-orange"><span class="metric-label">数据包</span><strong>{{ totalPackets.toLocaleString() }}</strong><small>旁路规则命中快照</small></article></div>
          <section class="section-grid traffic-grid"><section class="surface-card traffic-card"><div class="card-heading"><div><span class="eyebrow">BY DEVICE</span><h2>设备活动</h2></div><span class="muted-caption">按数据包排序</span></div><div v-if="trafficDevices.length" class="traffic-list"><div v-for="device in trafficDevices" :key="device.mac" class="traffic-row"><div class="traffic-label"><div class="device-avatar"><Activity :size="15" /></div><span>{{ device.custom_name || device.name || device.ip }}</span></div><div class="traffic-bar"><span :style="{ width: `${Math.max(4, (number(device.packets) / maxPackets) * 100)}%` }" /></div><strong>{{ number(device.packets).toLocaleString() }}</strong><small>包</small></div></div><div v-else class="empty-state"><Activity :size="28" /><strong>暂无流量快照</strong><span>设备接管后，这里会显示当前观测到的数据包。</span></div></section><section class="surface-card observation-card"><div class="card-heading"><div><span class="eyebrow">OBSERVATION</span><h2>观测指标</h2></div><Gauge :size="19" class="muted-icon" /></div><div class="observation-stat"><span>连接活跃度</span><strong>{{ totalConnections ? '有活动' : '暂无活动' }}</strong><small>来源：RouterOS 连接表</small></div><div class="observation-stat"><span>出口路径</span><strong>{{ checks.mihomo ? 'Mihomo' : '不可用' }}</strong><small>{{ summaryDetail || '当前接口未提供策略详情' }}</small></div><div class="observation-stat"><span>历史数据</span><strong>未启用</strong><small>当前版本仅展示实时快照</small></div></section></section>
        </section>

        <section v-else-if="activeView === 'setup'" class="view-panel">
          <div class="page-heading"><div><span class="eyebrow">GETTING STARTED</span><h1>首次配置</h1><p>确认关键服务是否就绪。安装向导只在首次配置尚未完成时开放。</p></div><a v-if="setupState.pending" class="primary-button" :href="setupUrl" target="_blank" rel="noreferrer"><ArrowUpRight :size="16" />打开安装向导</a><span v-else class="soft-badge good">首次配置已完成</span></div>
          <section class="surface-card setup-card"><div class="setup-progress"><div class="progress-ring" :class="{ warning: !ready }"><Check :size="22" /></div><div><span class="eyebrow">CURRENT INSTANCE</span><h2>{{ ready ? '基础配置已就绪' : '配置仍需检查' }}</h2><p>{{ ready ? '控制面已连接 RouterOS，并能读取旁路状态。' : '请先检查 RouterOS、DNS 或 Mihomo 服务。' }}</p></div></div><div class="setup-steps"><div v-for="(item, index) in healthChecks" :key="item.label" class="setup-step"><div class="step-number" :class="{ done: item.ok }">{{ item.ok ? '✓' : index + 1 }}</div><div><strong>{{ item.label }}</strong><small>{{ item.detail }}</small></div><span class="step-state" :class="{ done: item.ok }">{{ item.ok ? '已完成' : '待检查' }}</span></div></div></section>
          <div class="section-grid setup-grid"><section class="surface-card setup-info"><div class="card-heading"><div><span class="eyebrow">INSTALLATION</span><h2>安装方式</h2></div><Sparkles :size="19" class="muted-icon" /></div><p>{{ setupState.pending ? '首次安装和敏感参数录入由一次性安装向导完成。' : '本机已经完成首次配置；重新安装需要在 NAS 终端重新生成一次性向导地址。' }} 完成后回到本页面查看实时状态。</p><code>sudo ./scripts/install-one-click.sh</code><div class="info-line"><ShieldCheck :size="15" />凭据保存在本机权限受限的配置文件中</div></section><section class="surface-card setup-info"><div class="card-heading"><div><span class="eyebrow">NETWORK BOUNDARY</span><h2>运行边界</h2></div><Network :size="19" class="muted-icon" /></div><div class="boundary-row"><span>控制面</span><strong>Python · 18093</strong></div><div class="boundary-row"><span>统一入口</span><strong>Gateway · 18088</strong></div><div class="boundary-row"><span>RouterOS</span><strong>仅通过现有 API</strong></div></section></div>
        </section>

        <section v-else class="view-panel">
          <div class="page-heading"><div><span class="eyebrow">OPERATIONS</span><h1>系统维护</h1><p>这里显示 Z4Pro NAS 主机、Mihomo 旁路服务、RB5009 路由器和 WireGuard 互联状态。</p></div><span class="soft-badge" :class="{ good: system.healthy }">{{ system.healthy ? '系统正常' : '实时状态' }}</span></div>
          <div class="resource-grid"><article class="resource-card"><div class="resource-head"><Cpu :size="18" /><span>Z4Pro NAS · CPU</span><strong>{{ number(system.cpu?.percent).toFixed(1) }}%</strong></div><div class="resource-track"><span :style="{ width: `${Math.min(100, number(system.cpu?.percent))}%` }" /></div><small>{{ system.cpu?.cores || '—' }} 核 · 负载 {{ system.cpu?.load_1m ?? '—' }}</small></article><article class="resource-card"><div class="resource-head"><HardDrive :size="18" /><span>Z4Pro NAS · 内存</span><strong>{{ number(system.memory?.percent).toFixed(1) }}%</strong></div><div class="resource-track green"><span :style="{ width: `${Math.min(100, number(system.memory?.percent))}%` }" /></div><small>{{ formatBytes(system.memory?.used) }} / {{ formatBytes(system.memory?.total) }}</small></article><article class="resource-card"><div class="resource-head"><Thermometer :size="18" /><span>Z4Pro NAS · 温度</span><strong>{{ Number.isFinite(currentTemp) ? `${currentTemp.toFixed(0)}°C` : '不可用' }}</strong></div><div class="resource-track orange"><span :style="{ width: `${Math.min(100, number(system.temperature?.cpu_c))}%` }" /></div><small>NAS CPU 温度 · 传感器状态</small></article></div>
          <div class="section-grid ops-grid"><section class="surface-card maintenance-card"><div class="card-heading"><div><span class="eyebrow">COMPONENTS</span><h2>核心组件与设备</h2></div><RefreshCw :size="18" class="muted-icon" /></div><div class="component-row"><div class="component-icon"><Zap :size="17" /></div><div><strong>Mihomo 旁路代理</strong><small>Z4Pro NAS Docker 旁路服务 · {{ updateStatus.current_version || '尚无版本记录' }}{{ updateStatus.latest_version ? ` · 最新 ${updateStatus.latest_version}` : '' }}</small></div><span class="component-state" :class="updateTone(mihomoState)">{{ updateLabel(mihomoState) }}</span><button class="compact-button" :disabled="busy === 'mihomo-check'" @click="checkMihomo">检查更新</button></div><div class="component-row"><div class="component-icon"><Server :size="17" /></div><div><strong>Z4Pro NAS 系统</strong><small>当前运行的 NAS 主机系统 · {{ z4proUpdate.current_version || '尚无版本记录' }}{{ z4proUpdate.latest_version ? ` · 最新 ${z4proUpdate.latest_version}` : '' }}</small></div><span class="component-state" :class="updateTone(z4proState)">{{ updateLabel(z4proState) }}</span><button class="compact-button" :disabled="busy === 'platform-check'" @click="checkPlatform">检查更新</button></div><div class="component-row"><div class="component-icon"><Router :size="17" /></div><div><strong>RB5009 路由器</strong><small>{{ summary.router === 'connected' ? '家庭网关 API 管理连接正常' : '家庭网关 API 管理连接不可用' }}</small></div><span class="component-state" :class="{ good: summary.router === 'connected' }">{{ summary.router === 'connected' ? '在线' : '检查' }}</span><button class="compact-button" @click="load">重新读取</button></div></section><section class="surface-card maintenance-card"><div class="card-heading"><div><span class="eyebrow">RUNTIME</span><h2>Z4Pro NAS 运行详情</h2></div><MoreHorizontal :size="19" class="muted-icon" /></div><div class="runtime-list"><div><span>NAS 运行时间</span><strong>{{ formatUptime(system.uptime_seconds) }}</strong></div><div><span>Docker 容器</span><strong>{{ system.docker?.running ?? '—' }} / {{ system.docker?.total ?? '—' }}</strong></div><div><span>NAS 系统盘</span><strong>{{ number(system.disk?.percent).toFixed(1) }}%</strong></div><div><span>WireGuard 远程互联</span><strong>{{ wireguardPeers }} 个 Peer</strong></div></div><a class="card-link" href="/mihomo-maintenance">打开 Mihomo 详细维护页 <ArrowUpRight :size="15" /></a></section></div>
        </section>
      </div>

      <nav class="mobile-nav" aria-label="移动端主导航"><button v-for="item in views" :key="item.id" :class="{ active: activeView === item.id }" @click="selectView(item.id)"><component :is="item.icon" :size="18" /><span>{{ item.label }}</span></button></nav>
    </main>
    <div v-if="toastMessage" class="toast"><CheckCircle2 :size="16" />{{ toastMessage }}</div>
    <div v-if="renameTarget" class="modal-backdrop" @click.self="renameTarget = null"><form class="modal-card device-editor" @submit.prevent="saveRename"><button type="button" class="modal-close icon-button" title="关闭" aria-label="关闭" @click="renameTarget = null"><X :size="17" /></button><span class="eyebrow">DEVICE PROFILE</span><h2>编辑设备</h2><p>{{ renameTarget.ip }} · {{ renameTarget.mac }}</p><label>显示名称<input v-model="renameDraft" autofocus maxlength="40" /></label><fieldset class="icon-picker"><legend>显示图标</legend><div class="icon-options"><button v-for="item in deviceIconOptions" :key="item.key" type="button" class="icon-choice" :class="{ selected: iconDraft === item.key }" :title="item.label" :aria-label="item.label" @click="iconDraft = item.key"><component :is="item.icon" :size="19" /><span>{{ item.label }}</span></button></div></fieldset><div class="modal-actions"><button type="button" class="secondary-button" @click="renameTarget = null">取消</button><button class="primary-button" type="submit" :disabled="busy === 'rename'">保存</button></div></form></div>
  </div>
</template>
