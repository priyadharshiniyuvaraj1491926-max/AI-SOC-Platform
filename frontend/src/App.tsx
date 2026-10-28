import React, { createContext, FormEvent, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { Link, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Activity, AlertOctagon, ArrowDownToLine, ArrowLeft, ArrowUpRight, Bell, Check, CheckCircle2,
  ChevronDown, ChevronLeft, ChevronRight, CircleHelp, Clock3, Command, Database, FileSearch2,
  FileText, Fingerprint, Gauge, Globe2, HardDriveUpload, LayoutDashboard, LoaderCircle, LockKeyhole,
  LogOut, Menu, Network, Plus, Radio, RefreshCw, Search, Shield, ShieldAlert, ShieldCheck,
  SlidersHorizontal, Sparkles, UserRound, Users, X, Zap,
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { api, clearCsrf, setCsrf } from './api'

type User = { id: number; name: string; email: string; csrf_token?: string }
type AuthState = { user: User | null; loading: boolean; setUser: (user: User | null) => void }
const Auth = createContext<AuthState>({ user: null, loading: true, setUser: () => {} })
const SEVERITY_COLORS: Record<string, string> = { Critical: '#ff4d57', High: '#ff7957', Medium: '#f3b64b', Low: '#64cfa0' }
const navItems = [
  { label: 'Overview', to: '/dashboard', icon: LayoutDashboard },
  { label: 'Ingestion', to: '/ingestion', icon: HardDriveUpload },
  { label: 'Events', to: '/events', icon: Activity },
  { label: 'Alerts', to: '/alerts', icon: ShieldAlert },
  { label: 'Investigations', to: '/investigations', icon: FileSearch2 },
  { label: 'Analytics', to: '/analytics', icon: Gauge },
]

function notify(message: string, kind: 'success' | 'error' | 'info' = 'success') {
  window.dispatchEvent(new CustomEvent('aisoc-toast', { detail: { message, kind } }))
}
function ToastCenter() {
  const [items, setItems] = useState<{ id: number; message: string; kind: string }[]>([])
  useEffect(() => {
    const listen = (event: Event) => {
      const detail = (event as CustomEvent).detail
      const id = Date.now() + Math.random()
      setItems((old) => [...old, { id, ...detail }])
      window.setTimeout(() => setItems((old) => old.filter((item) => item.id !== id)), 4200)
    }
    window.addEventListener('aisoc-toast', listen)
    return () => window.removeEventListener('aisoc-toast', listen)
  }, [])
  return <div className="toast-stack" aria-live="polite">{items.map((item) => <div className={`toast toast-${item.kind}`} key={item.id}><span className="toast-dot" />{item.message}<button onClick={() => setItems((old) => old.filter((x) => x.id !== item.id))} aria-label="Dismiss"><X size={14} /></button></div>)}</div>
}

function NetworkBackground() {
  const canvas = useRef<HTMLCanvasElement>(null)
  const cursor = useRef({ x: -1000, y: -1000 })
  useEffect(() => {
    const element = canvas.current
    if (!element) return
    const context = element.getContext('2d')
    if (!context) return
    let frame = 0
    let width = 0, height = 0
    const nodes: { x: number; y: number; phase: number; speed: number }[] = []
    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2)
      width = element.clientWidth; height = element.clientHeight
      element.width = width * ratio; element.height = height * ratio
      context.setTransform(ratio, 0, 0, ratio, 0, 0)
      nodes.length = 0
      const count = Math.max(24, Math.min(70, Math.round(width * height / 18000)))
      for (let i = 0; i < count; i++) nodes.push({ x: Math.random() * width, y: Math.random() * height, phase: Math.random() * Math.PI * 2, speed: .12 + Math.random() * .35 })
    }
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const draw = () => {
      if (!context) return
      context.clearRect(0, 0, width, height)
      const pointer = cursor.current
      nodes.forEach((node, index) => {
        const drift = reduced ? 0 : Math.sin(Date.now() * .00018 * node.speed + node.phase)
        const x = node.x + drift * 8 + (pointer.x > -500 ? (pointer.x - width / 2) * -.006 : 0)
        const y = node.y + Math.cos(Date.now() * .00014 * node.speed + node.phase) * (reduced ? 0 : 6) + (pointer.y > -500 ? (pointer.y - height / 2) * -.006 : 0)
        for (let j = index + 1; j < nodes.length; j++) {
          const other = nodes[j]
          const dx = x - other.x, dy = y - other.y, d = Math.sqrt(dx * dx + dy * dy)
          if (d < 150) {
            context.strokeStyle = `rgba(207,45,59,${(1 - d / 150) * .18})`
            context.lineWidth = .6; context.beginPath(); context.moveTo(x, y); context.lineTo(other.x, other.y); context.stroke()
          }
        }
        context.beginPath(); context.arc(x, y, index % 7 === 0 ? 1.7 : 1.1, 0, Math.PI * 2)
        context.fillStyle = index % 6 === 0 ? 'rgba(255,102,108,.75)' : 'rgba(220,225,234,.45)'; context.fill()
      })
      if (!reduced) frame = requestAnimationFrame(draw)
    }
    const move = (event: PointerEvent) => { cursor.current = { x: event.clientX, y: event.clientY } }
    resize(); draw(); window.addEventListener('resize', resize); window.addEventListener('pointermove', move)
    return () => { cancelAnimationFrame(frame); window.removeEventListener('resize', resize); window.removeEventListener('pointermove', move) }
  }, [])
  return <><div className="auth-glow auth-glow-one" /><div className="auth-glow auth-glow-two" /><canvas className="network-canvas" ref={canvas} aria-hidden="true" /></>
}

function AuthFrame({ children }: { children: React.ReactNode }) {
  return <main className="auth-screen"><NetworkBackground /><div className="auth-mark"><span className="brand-mark"><Shield size={19} strokeWidth={2.2} /><i /></span><span>AI<span className="brand-red">·</span>SOC</span><span className="auth-mark-caption">SECURITY OPERATIONS</span></div>{children}<div className="auth-footer"><span><LockKeyhole size={13} /> LOCAL-FIRST SECURITY WORKSPACE</span><span>ENCRYPTED SESSION <i className="green-pulse" /></span></div></main>
}

function Login() {
  const [email, setEmail] = useState(''); const [password, setPassword] = useState('')
  const [show, setShow] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState('')
  const { setUser } = useContext(Auth); const navigate = useNavigate()
  async function submit(event: FormEvent) {
    event.preventDefault(); setError('')
    if (!email.trim() || !password) { setError('Enter your email and password to continue.'); return }
    setBusy(true)
    try { const user = await api<User>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }); setCsrf(user.csrf_token || ''); setUser(user); navigate('/dashboard') }
    catch (err) { setError(err instanceof Error ? err.message : 'Sign in failed. Try again.') }
    finally { setBusy(false) }
  }
  return <AuthFrame><motion.section className="auth-card" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .45 }}>
    <div className="auth-eyebrow"><span className="eyebrow-line" /> SECURE ACCESS <span className="eyebrow-line" /></div>
    <h1>Welcome back<span className="brand-red">.</span></h1><p className="auth-subtitle">Your investigations are waiting.</p>
    <form onSubmit={submit} className="auth-form">
      <label>Email address <span className="input-wrap"><UserRound size={16} /><input value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="email" placeholder="analyst@organization.com" required /></span></label>
      <label>Password <span className="input-wrap"><LockKeyhole size={16} /><input value={password} onChange={(e) => setPassword(e.target.value)} type={show ? 'text' : 'password'} autoComplete="current-password" placeholder="Enter your password" required /><button className="input-action" type="button" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'}</button></span></label>
      <div className="auth-options"><span><span className="online-dot" /> Private session</span><button type="button" className="text-button" onClick={() => notify('Password reset is not configured. Ask your workspace administrator to reset your account.', 'info')}>Forgot password?</button></div>
      {error && <div className="form-error" role="alert"><AlertOctagon size={15} />{error}</div>}
      <button className="button button-primary auth-submit" type="submit" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={17} /> Verifying credentials</> : <>Sign in to workspace <ArrowUpRight size={16} /></>}</button>
    </form>
    <div className="auth-divider"><span />NEW TO AI-SOC?<span /></div>
    <Link className="button button-quiet auth-create" to="/signup">Create an analyst account <ArrowUpRight size={15} /></Link>
  </motion.section></AuthFrame>
}

function Signup() {
  const [name, setName] = useState(''); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState('')
  const { setUser } = useContext(Auth); const navigate = useNavigate()
  const strength = [password.length >= 10, /[A-Z]/.test(password) && /[a-z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)].filter(Boolean).length
  async function submit(event: FormEvent) {
    event.preventDefault(); setError('')
    if (password !== confirm) { setError('The passwords do not match.'); return }
    if (strength < 3) { setError('Choose a stronger password: 10+ characters with a mix of letter, number, and symbol.'); return }
    setBusy(true)
    try { const user = await api<User>('/auth/register', { method: 'POST', body: JSON.stringify({ name, email, password }) }); setCsrf(user.csrf_token || ''); setUser(user); notify('Your analyst account is ready.'); navigate('/dashboard') }
    catch (err) { setError(err instanceof Error ? err.message : 'Account creation failed.') }
    finally { setBusy(false) }
  }
  return <AuthFrame><motion.section className="auth-card signup-card" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .45 }}>
    <div className="auth-eyebrow"><span className="eyebrow-line" /> ANALYST REGISTRATION <span className="eyebrow-line" /></div>
    <h1>Build your workspace<span className="brand-red">.</span></h1><p className="auth-subtitle">A private place to turn events into evidence.</p>
    <form onSubmit={submit} className="auth-form signup-form">
      <label>Full name <span className="input-wrap"><UserRound size={16} /><input value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" placeholder="Alex Morgan" minLength={2} required /></span></label>
      <label>Work email <span className="input-wrap"><Globe2 size={16} /><input value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="email" placeholder="alex@organization.com" required /></span></label>
      <label>Password <span className="input-wrap"><LockKeyhole size={16} /><input value={password} onChange={(e) => setPassword(e.target.value)} type={show ? 'text' : 'password'} autoComplete="new-password" minLength={10} placeholder="At least 10 characters" required /><button className="input-action" type="button" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'}</button></span></label>
      <div className="strength-row"><span>Password strength</span><span className="strength-bars">{[1,2,3,4].map((n) => <i className={strength >= n ? `strength-${strength}` : ''} key={n} />)}</span><b>{password ? ['Weak','Fair','Good','Strong','Strong'][strength] : '—'}</b></div>
      <label>Confirm password <span className="input-wrap"><Check size={16} /><input value={confirm} onChange={(e) => setConfirm(e.target.value)} type={show ? 'text' : 'password'} autoComplete="new-password" placeholder="Re-enter your password" required /></span></label>
      {error && <div className="form-error" role="alert"><AlertOctagon size={15} />{error}</div>}
      <button className="button button-primary auth-submit" type="submit" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={17} /> Creating secure account</> : <>Create account <ArrowUpRight size={16} /></>}</button>
    </form>
    <div className="auth-divider"><span />ALREADY REGISTERED?<span /></div>
    <Link className="button button-quiet auth-create" to="/login"><ArrowLeft size={15} /> Back to sign in</Link>
  </motion.section></AuthFrame>
}

function Protected({ children }: { children: React.ReactNode }) {
  const { user, loading } = useContext(Auth)
  if (loading) return <div className="full-loader"><LoaderCircle className="spin" /><span>Opening secure workspace</span></div>
  return user ? <>{children}</> : <Navigate to="/login" replace />
}

function Workspace() {
  const { user, setUser } = useContext(Auth); const location = useLocation(); const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(localStorage.getItem('aisoc-sidebar') === 'collapsed')
  const [profileOpen, setProfileOpen] = useState(false); const [query, setQuery] = useState('')
  const title = useMemo(() => {
    const path = location.pathname.split('/').filter(Boolean)
    if (path[0] === 'alerts' && path.length > 1) return 'Alert detail'
    if (path[0] === 'investigations' && path.length > 1) return 'Investigation workspace'
    return ({ dashboard: 'Overview', ingestion: 'Log ingestion', events: 'Event explorer', alerts: 'Alert queue', investigations: 'Investigations', analytics: 'Analytics', sources: 'Data sources', iocs: 'Indicators', settings: 'Workspace settings' } as Record<string,string>)[path[0]] || 'Overview'
  }, [location.pathname])
  function toggleSidebar() { const next = !collapsed; setCollapsed(next); localStorage.setItem('aisoc-sidebar', next ? 'collapsed' : 'expanded') }
  async function signout() { try { await api('/auth/logout', { method: 'POST' }) } catch {} clearCsrf(); setUser(null); navigate('/login') }
  function searchSubmit(e: FormEvent) { e.preventDefault(); if (query.trim()) navigate(`/events?search=${encodeURIComponent(query.trim())}`) }
  return <div className={`workspace ${collapsed ? 'sidebar-collapsed' : ''}`}>
    <aside className="sidebar">
      <Link className="sidebar-brand" to="/dashboard"><span className="brand-mark"><Shield size={18} strokeWidth={2.2} /><i /></span>{!collapsed && <span className="brand-name">AI<span className="brand-red">·</span>SOC <small>OPERATIONS</small></span>}</Link>
      {!collapsed && <div className="sidebar-label">WORKSPACE</div>}
      <nav className="side-nav">{navItems.map(({ label, to, icon: Icon }) => <NavLink key={to} to={to} title={collapsed ? label : undefined} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Icon size={18} strokeWidth={1.8} /><span>{label}</span>{label === 'Alerts' && <span className="nav-live" />}</NavLink>)}</nav>
      {!collapsed && <div className="sidebar-label secondary-label">INTELLIGENCE</div>}
      <nav className="side-nav compact-nav"><NavLink to="/sources" title={collapsed ? 'Data sources' : undefined} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Database size={18} /><span>Data sources</span></NavLink><NavLink to="/iocs" title={collapsed ? 'Indicators' : undefined} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Fingerprint size={18} /><span>Indicators</span></NavLink></nav>
      <div className="sidebar-spacer" />
      {!collapsed && <div className="sidebar-status"><span className="status-icon"><Radio size={15} /></span><span><b>Local workspace</b><small>Operational · private</small></span><i className="green-pulse" /></div>}
      <NavLink to="/settings" title={collapsed ? 'Settings' : undefined} className={({ isActive }) => `nav-link settings-link ${isActive ? 'active' : ''}`}><SlidersHorizontal size={18} /><span>Settings</span></NavLink>
      <button className="collapse-button" onClick={toggleSidebar} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>{collapsed ? <ChevronRight size={17} /> : <><ChevronLeft size={17} /><span>Collapse sidebar</span></>}</button>
    </aside>
    <div className="main-column">
      <header className="topbar"><div className="topbar-left"><button className="mobile-menu" aria-label="Toggle sidebar" onClick={toggleSidebar}><Menu size={18} /></button><span className="breadcrumb-root">AI-SOC</span><ChevronRight size={14} className="crumb-chevron" /><span className="breadcrumb-current">{title}</span></div><div className="topbar-right"><form className="global-search" onSubmit={searchSubmit}><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search events, hosts, users…" aria-label="Search events" /><kbd>↵</kbd></form><span className="topbar-divider" /><button className="icon-button" aria-label="View audit trail" title="Audit trail" onClick={() => navigate('/settings#audit')}><Clock3 size={17} /></button><div className="profile-wrap"><button className="profile-button" onClick={() => setProfileOpen(!profileOpen)} aria-expanded={profileOpen}><span className="avatar">{user?.name?.slice(0,1).toUpperCase()}</span><span className="profile-name">{user?.name?.split(' ')[0]}</span><ChevronDown size={14} /></button>{profileOpen && <div className="profile-menu"><div className="profile-menu-head"><b>{user?.name}</b><span>{user?.email}</span></div><button onClick={() => { setProfileOpen(false); navigate('/settings') }}><UserRound size={15} /> Workspace settings</button><button className="signout" onClick={signout}><LogOut size={15} /> Sign out</button></div>}</div></div></header>
      <main className="page-content"><AnimatePresence mode="wait"><motion.div key={location.pathname} className="route-frame" initial={{ opacity: 0, y: 7 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -3 }} transition={{ duration: .18 }}><Outlet /></motion.div></AnimatePresence></main>
    </div><ToastCenter />
  </div>
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="page-eyebrow"><span />{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action && <div className="heading-actions">{action}</div>}</div>
}
function Panel({ title, subtitle, action, children, className = '' }: { title: string; subtitle?: string; action?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="panel-head"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>{children}</section>
}
function Severity({ value }: { value: string }) { return <span className={`severity severity-${(value || 'low').toLowerCase()}`}><i />{value || 'Unknown'}</span> }
function Risk({ value, size = 'small' }: { value: number; size?: string }) { const tone = value >= 75 ? 'critical' : value >= 50 ? 'high' : value >= 25 ? 'medium' : 'low'; return <span className={`risk risk-${tone} risk-${size}`}>{value}<small>/100</small></span> }
function EmptyState({ icon: Icon = ShieldCheck, title, text, action }: { icon?: any; title: string; text: string; action?: React.ReactNode }) { return <div className="empty-state"><span className="empty-icon"><Icon size={21} /></span><h3>{title}</h3><p>{text}</p>{action}</div> }
function Loading({ label = 'Loading workspace data' }: { label?: string }) { return <div className="loading-state"><LoaderCircle size={18} className="spin" />{label}</div> }
function ErrorState({ error, retry }: { error: string; retry: () => void }) { return <div className="error-state"><AlertOctagon size={18} /><span>{error}</span><button onClick={retry}><RefreshCw size={14} />Retry</button></div> }

function Dashboard() {
  const [data, setData] = useState<any>(null); const [error, setError] = useState(''); const [refreshing, setRefreshing] = useState(false); const [period, setPeriod] = useState('7 days')
  async function load(days = period === '7 days' ? 7 : 30) { setError(''); setRefreshing(true); try { setData(await api(`/dashboard?days=${days}`)) } catch (e) { setError(e instanceof Error ? e.message : 'Could not load dashboard') } finally { setRefreshing(false) } }
  useEffect(() => { load() }, [])
  if (error && !data) return <ErrorState error={error} retry={load} />
  if (!data) return <Loading />
  const metrics = data.metrics
  const kpis = [
    { label: 'Ingested events', value: metrics.events, icon: Activity, tone: 'red', to: '/events', note: 'Normalized records' },
    { label: 'Active alerts', value: metrics.alerts, icon: ShieldAlert, tone: 'amber', to: '/alerts', note: 'All recorded detections' },
    { label: 'Critical priority', value: metrics.critical, icon: AlertOctagon, tone: 'rose', to: '/alerts?severity=Critical', note: 'Risk score ≥ 75' },
    { label: 'Open investigations', value: metrics.open_investigations, icon: FileSearch2, tone: 'blue', to: '/investigations', note: 'Awaiting analyst review' },
  ]
  return <>
    <PageHeading eyebrow="SECURITY OPERATIONS / LIVE VIEW" title="Good to have you back." description="A clear view of the evidence in your workspace." action={<><button className="button button-quiet" onClick={() => { const next = period === '7 days' ? '30 days' : '7 days'; setPeriod(next); load(next === '7 days' ? 7 : 30) }}><Clock3 size={15} />{period}<ChevronDown size={14} /></button><button className="button button-outline" onClick={() => load()} disabled={refreshing}>{refreshing ? <LoaderCircle className="spin" size={15} /> : <RefreshCw size={15} />}Refresh</button></>} />
    {error && <ErrorState error={error} retry={load} />}
    {metrics.events === 0 ? <div className="onboarding-banner"><div className="onboarding-icon"><Sparkles size={19} /></div><div><b>Your workspace is ready for its first investigation.</b><span>Load the labeled demo scenario or upload your own security logs to see real detections and evidence.</span></div><Link to="/ingestion" className="button button-primary">Start with log data <ArrowUpRight size={15} /></Link></div> : data.demo_events > 0 && <div className="demo-banner"><span className="demo-tag">DEMO DATA</span><span>{data.demo_events} demo events are included in these workspace metrics.</span><Link to="/ingestion">Manage demo data <ArrowUpRight size={13} /></Link></div>}
    <div className="kpi-grid">{kpis.map(({ label, value, icon: Icon, tone, to, note }) => <Link to={to} className="kpi-card" key={label}><div className="kpi-top"><span>{label}</span><span className={`kpi-icon tone-${tone}`}><Icon size={17} /></span></div><div className="kpi-value">{value.toLocaleString()}</div><div className="kpi-note"><span className="kpi-note-dot" />{note}<ArrowUpRight size={13} /></div></Link>)}</div>
    <div className="dashboard-grid"><Panel className="trend-panel" title="Event & alert activity" subtitle={`Daily volume · last ${period}`} action={<span className="chart-legend"><i className="legend-events" />Events <i className="legend-alerts" />Alerts</span>}>
      <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data.event_trend} margin={{ top: 8, right: 5, left: -18, bottom: 0 }}><defs><linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#e6414d" stopOpacity={.22} /><stop offset="95%" stopColor="#e6414d" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="rgba(255,255,255,.055)" vertical={false} /><XAxis dataKey="date" tickFormatter={(v) => v.slice(5)} axisLine={false} tickLine={false} tick={{ fill: '#747984', fontSize: 11 }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#747984', fontSize: 11 }} /><Tooltip contentStyle={{ background: '#17191e', border: '1px solid #30333b', borderRadius: 9, fontSize: 12 }} labelStyle={{ color: '#eee' }} /><Area type="monotone" dataKey="events" stroke="#e34a55" strokeWidth={2} fill="url(#eventGradient)" /><Area type="monotone" dataKey="alerts" stroke="#e2a73e" strokeWidth={1.8} fill="transparent" /></AreaChart></ResponsiveContainer></div>
    </Panel><Panel title="Severity distribution" subtitle="Detection priority across all alerts"><div className="severity-panel-content">{metrics.alerts === 0 ? <EmptyState icon={ShieldCheck} title="No alerts recorded" text="Detections appear here after log data is processed." /> : <><div className="donut-wrap"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data.severity_distribution} dataKey="value" nameKey="name" innerRadius="69%" outerRadius="88%" paddingAngle={4} stroke="none">{data.severity_distribution.map((entry: any) => <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />)}</Pie><Tooltip contentStyle={{ background: '#17191e', border: '1px solid #30333b', borderRadius: 9, fontSize: 12 }} /></PieChart></ResponsiveContainer><div className="donut-center"><b>{metrics.alerts}</b><span>Total alerts</span></div></div><div className="severity-legend">{data.severity_distribution.map((entry: any) => <Link to={`/alerts?severity=${entry.name}`} key={entry.name}><i style={{ background: SEVERITY_COLORS[entry.name] }} /><span>{entry.name}</span><b>{entry.value}</b></Link>)}</div></>}</div></Panel></div>
    <div className="dashboard-bottom"><Panel title="Recent alerts" subtitle="Newest detections from your log data" action={<Link className="panel-link" to="/alerts">All alerts <ArrowUpRight size={13} /></Link>}>
      {data.recent_alerts.length ? <div className="recent-alert-list">{data.recent_alerts.slice(0, 5).map((alert: any) => <Link className="recent-alert" to={`/alerts/${alert.id}`} key={alert.id}><span className={`alert-severity-bar bar-${alert.severity.toLowerCase()}`} /><span className="recent-alert-main"><b>{alert.name}</b><small>{alert.rule_id} <i /> {new Date(alert.created_at).toLocaleString()}</small></span><Risk value={alert.risk_score} /><ArrowUpRight size={14} className="row-arrow" /></Link>)}</div> : <EmptyState icon={ShieldCheck} title="Waiting for a signal" text="Upload logs and the deterministic detection rules will look for supported patterns." action={<Link to="/ingestion" className="text-link">Open ingestion <ArrowUpRight size={13} /></Link>} />}
    </Panel><Panel title="Recent ingestion" subtitle="Latest files processed in this workspace" action={<Link className="panel-link" to="/ingestion">Open ingestion <ArrowUpRight size={13} /></Link>}>
      {data.recent_ingestions.length ? <div className="ingestion-list">{data.recent_ingestions.map((item: any) => <div className="ingestion-row" key={item.id}><span className="file-icon"><FileText size={16} /></span><span className="ingestion-name"><b>{item.filename}</b><small>{new Date(item.created_at).toLocaleString()}{item.is_demo && <em className="demo-mini">DEMO</em>}</small></span><span className="ingestion-count"><b>{item.event_count}</b><small>events</small></span><CheckCircle2 size={15} className="success-icon" /></div>)}</div> : <EmptyState icon={HardDriveUpload} title="No files yet" text="A short sample scenario can show the full workflow." action={<Link to="/ingestion" className="text-link">Upload a file <ArrowUpRight size={13} /></Link>} />}
    </Panel></div>
    <div className="dashboard-bottom dashboard-intelligence"><Panel title="Detection categories" subtitle="Rule groups observed in stored alerts" action={<Link className="panel-link" to="/analytics">Analytics <ArrowUpRight size={13} /></Link>}><RankList items={data.detection_categories} empty="Detections will appear when uploaded data supports them." /></Panel><Panel title="Data sources" subtitle="Source labels observed in normalized events" action={<Link className="panel-link" to="/sources">Sources <ArrowUpRight size={13} /></Link>}><RankList items={data.data_source_distribution} empty="Source distribution appears after log ingestion." /></Panel></div>
  </>
}

function Ingestion() {
  const [items, setItems] = useState<any[]>([]); const [drag, setDrag] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [summary, setSummary] = useState<any>(null)
  const input = useRef<HTMLInputElement>(null); const accept = '.txt,.log,.json,.jsonl,.csv'
  async function load() { try { setItems(await api('/ingestions')) } catch (e) { setError(e instanceof Error ? e.message : 'Could not load ingestion history') } }
  useEffect(() => { load() }, [])
  async function upload(files: FileList | File[]) {
    if (!files.length) return
    setBusy(true); setError(''); setSummary(null)
    const invalid = Array.from(files).filter((file) => !accept.split(',').some((ext) => file.name.toLowerCase().endsWith(ext)))
    if (invalid.length) { setError(`Unsupported file type: ${invalid.map((x) => x.name).join(', ')}`); setBusy(false); return }
    const body = new FormData(); Array.from(files).forEach((file) => body.append('files', file))
    try { const result = await api<{results: any[]}>('/ingestions', { method: 'POST', body }); setSummary(result.results); const saved = result.results.filter((x) => x.status !== 'failed'); if (saved.length) notify(`${saved.reduce((n, x) => n + x.event_count, 0)} events stored from ${saved.length} file(s).`); if (saved.length !== result.results.length) setError(result.results.filter((x) => x.status === 'failed').map((x) => `${x.filename}: ${x.error}`).join(' · ')); await load() }
    catch (e) { setError(e instanceof Error ? e.message : 'Upload failed') }
    finally { setBusy(false); if (input.current) input.current.value = '' }
  }
  async function loadDemo() { setBusy(true); setError(''); setSummary(null); try { const result = await api('/ingestions/sample', { method: 'POST' }); setSummary([result]); notify('Labeled demo events processed through the normal pipeline.'); await load() } catch (e) { setError(e instanceof Error ? e.message : 'Demo load failed') } finally { setBusy(false) } }
  async function reprocess(id: number) { setBusy(true); try { const result = await api<any>(`/ingestions/${id}/reprocess`, { method: 'POST' }); notify(`Reprocessed events · ${result.alerts_created} new alerts, ${result.alerts_updated} refreshed.`); await load() } catch (e) { notify(e instanceof Error ? e.message : 'Reprocessing failed', 'error') } finally { setBusy(false) } }
  async function clearDemo() { if (!window.confirm('Remove demo ingestions, their events, and alerts created from those ingestions? Real uploaded data will be kept.')) return; setBusy(true); try { const result = await api<any>('/ingestions/demo-data', { method: 'DELETE' }); notify(`Removed ${result.deleted_events} demo events.`); setSummary(null); await load() } catch (e) { setError(e instanceof Error ? e.message : 'Could not clear demo data') } finally { setBusy(false) } }
  return <>
    <PageHeading eyebrow="DATA PIPELINE / INGEST" title="Bring your logs into focus." description="Parse, normalize, and run deterministic detections on the evidence you provide." action={<button className="button button-outline" onClick={() => input.current?.click()}><Plus size={15} />Choose files</button>} />
    <div className="ingest-layout"><div className={`dropzone ${drag ? 'dropzone-active' : ''} ${busy ? 'dropzone-busy' : ''}`} onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={(e) => { e.preventDefault(); setDrag(false); upload(e.dataTransfer.files) }}>
      <input ref={input} type="file" accept={accept} multiple hidden onChange={(e) => e.target.files && upload(e.target.files)} />
      <span className="drop-icon"><ArrowDownToLine size={22} /></span>{busy ? <><h2>Processing evidence…</h2><p>Your file is being parsed and normalized, then rules run against stored events.</p><LoaderCircle className="spin upload-spinner" size={19} /></> : <><h2>Drop security logs here</h2><p>Or <button className="inline-link" onClick={() => input.current?.click()}>browse files</button> from your device</p><div className="format-pills">{['JSON','JSONL','CSV','LOG','TXT'].map((x) => <span key={x}>{x}</span>)}</div><small>Up to 10 MB per file · Up to 10 files per batch · UTF-8 text</small></>}
    </div><div className="ingest-side"><div className="side-info-card"><span className="info-kicker"><ShieldCheck size={14} /> PRIVATE BY DEFAULT</span><h3>Your evidence stays in this workspace.</h3><p>Files are parsed in memory. Normalized events and original event content are saved to your local database. Files are never executed or sent to external services.</p></div><div className="side-info-card demo-card"><span className="info-kicker"><Sparkles size={14} /> INTERACTIVE DEMO</span><h3>See the investigation flow.</h3><p>Load a labeled scenario with authentication failures, a success sequence, process indicators, scan ports, and an unusual DNS query.</p><button className="button button-quiet" onClick={loadDemo} disabled={busy}><Zap size={14} />Load demo scenario</button><button className="text-button clear-demo" onClick={clearDemo} disabled={busy}>Clear demo data</button></div></div></div>
    {error && <div className="form-error page-error"><AlertOctagon size={15} />{error}</div>}
    {summary && <Panel className="result-panel" title="Processing summary" subtitle="The response reflects records stored in the database"><div className="result-grid">{summary.map((result: any) => <div className={`result-card ${result.status === 'failed' ? 'result-failed' : ''}`} key={result.id || result.filename}><div className="result-head">{result.status === 'failed' ? <AlertOctagon size={16} /> : <CheckCircle2 size={16} />}<b>{result.filename}</b>{result.is_demo && <span className="demo-tag">DEMO DATA</span>}</div>{result.status === 'failed' ? <p className="failed-reason">{result.error}</p> : <><div className="result-metrics"><span><b>{result.event_count}</b>events saved</span><span><b>{result.alert_count}</b>alerts generated</span><span><b>{result.rejected_count}</b>rows rejected</span></div>{Object.keys(result.summary?.detection_summary || {}).length > 0 && <div className="detection-tags">{Object.entries(result.summary.detection_summary).map(([key, count]) => <span key={key}>{key} <b>{String(count)}</b></span>)}</div>}{result.summary?.errors?.length > 0 && <details className="parse-errors"><summary>View parsing notes ({result.summary.errors.length})</summary>{result.summary.errors.map((item: any, i: number) => <p key={i}>Row {item.row}: {item.error}</p>)}</details>}</>}</div>)}</div></Panel>}
    <Panel className="history-panel" title="Ingestion history" subtitle="Files processed for this account" action={<button className="icon-button" onClick={load} aria-label="Refresh ingestion history"><RefreshCw size={15} /></button>}>
      {items.length ? <div className="table-wrap"><table><thead><tr><th>FILE</th><th>STATUS</th><th>EVENTS</th><th>ALERTS</th><th>UPLOADED</th><th>TYPE</th><th>ACTION</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><span className="table-file"><FileText size={15} />{item.filename}</span></td><td><span className={`table-status status-${item.status.replaceAll('_','-')}`}><i />{item.status.replaceAll('_',' ')}</span></td><td>{item.event_count}</td><td>{item.alert_count}</td><td>{new Date(item.created_at).toLocaleString()}</td><td>{item.is_demo ? <span className="demo-tag">DEMO</span> : 'Uploaded'}</td><td><button className="table-action" disabled={busy || !item.event_count} onClick={() => reprocess(item.id)} title="Re-run detections on stored normalized events">Reprocess</button></td></tr>)}</tbody></table></div> : <EmptyState icon={HardDriveUpload} title="No ingestion history yet" text="Processed files and sample data will show up here." />}
    </Panel>
  </>
}

function Events() {
  const [params, setParams] = useSearchParams(); const [data, setData] = useState<any>(null); const [search, setSearch] = useState(params.get('search') || ''); const [error, setError] = useState(''); const [page, setPage] = useState(1)
  async function load(value = search) { setError(''); try { setData(await api(`/events?search=${encodeURIComponent(value)}&page=${page}&limit=50`)) } catch (e) { setError(e instanceof Error ? e.message : 'Could not load events') } }
  useEffect(() => { const value = params.get('search') || ''; setSearch(value); load(value) }, [params, page])
  function submit(e: FormEvent) { e.preventDefault(); setParams(search ? { search } : {}); setPage(1); load(search) }
  return <><PageHeading eyebrow="EVIDENCE / NORMALIZED EVENTS" title="Event explorer" description="Search the normalized record set while preserving the source evidence." action={<button className="button button-outline" onClick={() => load()}><RefreshCw size={15} />Refresh</button>} />
    <Panel title="Normalized events" subtitle={`${data?.total ?? '—'} records in this workspace`} action={<form className="panel-search" onSubmit={submit}><Search size={14} /><input placeholder="Search host, user, IP…" value={search} onChange={(e) => setSearch(e.target.value)} /><button aria-label="Submit search"><ArrowUpRight size={14} /></button></form>}>
      {error ? <ErrorState error={error} retry={() => load()} /> : !data ? <Loading /> : data.items.length ? <><div className="table-wrap events-table"><table><thead><tr><th>TIMESTAMP</th><th>EVENT</th><th>HOST / USER</th><th>NETWORK</th><th>STATUS</th><th>SOURCE</th></tr></thead><tbody>{data.items.map((event: any) => <tr key={event.id}><td className="mono muted-cell">{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Timestamp unavailable'}</td><td><b>{event.event_type || event.action || 'Unclassified event'}</b><small className="table-sub">{event.process_name || event.destination_domain || event.source || 'Normalized event'}</small></td><td><span>{event.host || '—'}</span><small className="table-sub">{event.user || 'No user field'}</small></td><td className="mono">{event.src_ip || '—'}{event.dst_ip ? <small className="table-sub">→ {event.dst_ip}{event.dst_port ? `:${event.dst_port}` : ''}</small> : ''}</td><td><span className={`event-status ${String(event.status || '').toLowerCase().includes('fail') ? 'event-failed' : ''}`}>{event.status || 'Observed'}</span></td><td>{event.source || 'Upload'}</td></tr>)}</tbody></table></div><div className="pagination"><span>Page {data.page} · {data.items.length} of {data.total}</span><div><button disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label="Previous page"><ChevronLeft size={16} /></button><button disabled={page * data.limit >= data.total} onClick={() => setPage(page + 1)} aria-label="Next page"><ChevronRight size={16} /></button></div></div></> : <EmptyState icon={Activity} title="No matching events" text="Try a different search or ingest a log file to populate this view." action={<Link to="/ingestion" className="text-link">Open ingestion <ArrowUpRight size={13} /></Link>} />}
    </Panel>
  </>
}

function Alerts() {
  const [params] = useSearchParams(); const [data, setData] = useState<any>(null); const [search, setSearch] = useState(''); const [severity, setSeverity] = useState(params.get('severity') || ''); const [status, setStatus] = useState(''); const [days, setDays] = useState('0'); const [sort, setSort] = useState('time'); const [error, setError] = useState(''); const [page, setPage] = useState(1)
  const navigate = useNavigate()
  async function load() { setError(''); try { const query = new URLSearchParams({ search, severity, status, days, sort, page: String(page), limit: '50' }); setData(await api(`/alerts?${query}`)) } catch (e) { setError(e instanceof Error ? e.message : 'Could not load alerts') } }
  useEffect(() => { setSeverity(params.get('severity') || '') }, [params])
  useEffect(() => { load() }, [search, severity, status, days, sort, page])
  return <><PageHeading eyebrow="DETECTIONS / TRIAGE QUEUE" title="Alerts" description="Prioritize rule-based observations, inspect supporting evidence, and record your decision." action={<button className="button button-outline" onClick={load}><RefreshCw size={15} />Refresh</button>} />
    <div className="filter-row"><div className="filter-search"><Search size={15} /><input placeholder="Search detections…" value={search} onChange={(e) => { setPage(1); setSearch(e.target.value) }} /></div><label className="select-wrap"><SlidersHorizontal size={14} /><select value={severity} onChange={(e) => { setPage(1); setSeverity(e.target.value) }}><option value="">All severities</option>{['Critical','High','Medium','Low'].map((v) => <option key={v}>{v}</option>)}</select></label><label className="select-wrap"><select value={status} onChange={(e) => { setPage(1); setStatus(e.target.value) }}><option value="">All statuses</option>{['New','Investigating','Escalated','Resolved','False Positive'].map((v) => <option key={v}>{v}</option>)}</select></label><label className="select-wrap"><Clock3 size={13} /><select value={days} onChange={(e) => { setPage(1); setDays(e.target.value) }}><option value="0">Any time</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option></select></label><label className="select-wrap"><select value={sort} onChange={(e) => { setPage(1); setSort(e.target.value) }}><option value="time">Newest first</option><option value="risk">Highest risk</option></select></label></div>
    {error ? <ErrorState error={error} retry={load} /> : !data ? <Loading /> : data.items.length ? <Panel className="alert-table-panel" title="Detection queue" subtitle={`${data.total} alert${data.total === 1 ? '' : 's'} recorded`}><div className="table-wrap"><table className="alert-table"><thead><tr><th>DETECTION</th><th>SEVERITY</th><th>RISK</th><th>STATUS</th><th>OBSERVED</th><th /></tr></thead><tbody>{data.items.map((alert: any) => <tr key={alert.id} className="click-row" onClick={() => navigate(`/alerts/${alert.id}`)}><td><div className="alert-cell"><span className={`alert-cell-icon icon-${alert.severity.toLowerCase()}`}><ShieldAlert size={16} /></span><span><b>{alert.name}</b><small>{alert.rule_id} · {alert.confidence}</small></span></div></td><td><Severity value={alert.severity} /></td><td><Risk value={alert.risk_score} /></td><td><span className={`status-pill status-${alert.status.toLowerCase().replaceAll(' ','-')}`}>{alert.status}</span></td><td>{new Date(alert.created_at).toLocaleString()}</td><td><ArrowUpRight size={14} className="row-arrow" /></td></tr>)}</tbody></table></div><div className="pagination"><span>Page {data.page} · {data.items.length} of {data.total}</span><div><button disabled={page <= 1} onClick={() => setPage(page - 1)}><ChevronLeft size={16} /></button><button disabled={page * data.limit >= data.total} onClick={() => setPage(page + 1)}><ChevronRight size={16} /></button></div></div></Panel> : <Panel title="Detection queue"><EmptyState icon={ShieldCheck} title="No alerts match these filters" text="Upload supported log data or reset the filters to review available detections." action={<Link to="/ingestion" className="text-link">Go to ingestion <ArrowUpRight size={13} /></Link>} /></Panel>}
    <Routes><Route path=":alertId" element={<AlertDetail />} /></Routes>
  </>
}

function AlertDetail() {
  const { alertId } = useParams(); const navigate = useNavigate(); const [data, setData] = useState<any>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function load() { try { setData(await api(`/alerts/${alertId}`)); setError('') } catch (e) { setError(e instanceof Error ? e.message : 'Could not load alert') } }
  useEffect(() => { load() }, [alertId])
  async function updateStatus(status: string) { setBusy(true); try { await api(`/alerts/${alertId}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }); notify(`Alert marked ${status.toLowerCase()}.`); await load() } catch (e) { notify(e instanceof Error ? e.message : 'Could not update status', 'error') } finally { setBusy(false) } }
  if (error) return <div className="detail-overlay" onClick={() => navigate('/alerts')}><div className="detail-drawer" onClick={(e) => e.stopPropagation()}><button className="icon-button drawer-close" onClick={() => navigate('/alerts')}><X size={18} /></button><ErrorState error={error} retry={load} /></div></div>
  if (!data) return <div className="detail-overlay" onClick={() => navigate('/alerts')}><div className="detail-drawer" onClick={(e) => e.stopPropagation()}><Loading /></div></div>
  return <div className="detail-overlay" onClick={() => navigate('/alerts')}><motion.div className="detail-drawer" onClick={(e) => e.stopPropagation()} initial={{ x: 30, opacity: .6 }} animate={{ x: 0, opacity: 1 }}><button className="icon-button drawer-close" onClick={() => navigate('/alerts')} aria-label="Close alert details"><X size={18} /></button><div className="drawer-eyebrow">ALERT {String(data.id).padStart(5,'0')} · {data.rule_id}</div><h2>{data.name}</h2><p className="drawer-description">{data.description}</p><div className="drawer-badges"><Severity value={data.severity} /><span className={`status-pill status-${data.status.toLowerCase().replaceAll(' ','-')}`}>{data.status}</span></div><div className="drawer-risk"><span><small>RISK PRIORITY</small><Risk value={data.risk_score} size="large" /></span><div className="risk-factors">{Object.entries(data.risk_breakdown).filter(([k]) => k !== 'formula').map(([key, val]) => <div key={key}><span>{key}</span><b>{String(val)}</b></div>)}</div></div><div className="drawer-section"><h3>Observed evidence</h3><div className="evidence-list">{Object.entries(data.evidence).map(([key, value]) => <div key={key}><span>{key.replaceAll('_',' ')}</span><b>{String(value)}</b></div>)}</div>{data.events.length ? <div className="event-evidence">{data.events.map((event: any) => <details key={event.id}><summary><span className="timeline-dot" />{event.event_type || event.action || 'Event'} <small>{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'time unavailable'}</small></summary><pre>{JSON.stringify(event.raw_event, null, 2)}</pre></details>)}</div> : <p className="muted-text">No event IDs were linked to this detection.</p>}</div><div className="drawer-section"><h3>MITRE ATT&amp;CK</h3>{data.mitre.length ? data.mitre.map((item: any) => <a className="mitre-chip" href={`https://attack.mitre.org/techniques/${item.id.replace('.','/')}/`} target="_blank" rel="noreferrer" key={item.id}><span>{item.id}</span>{item.name}<ArrowUpRight size={12} /></a>) : <p className="muted-text">No technique mapping is assigned to this rule.</p>}</div><div className="drawer-section"><h3>Recommended analyst checks <em>ADVISORY</em></h3><ul className="recommendations">{data.recommendations.map((item: string) => <li key={item}>{item}</li>)}</ul></div><div className="drawer-actions"><button className="button button-quiet" disabled={busy} onClick={() => updateStatus('Investigating')}>Mark investigating</button>{data.investigation_id && <Link to={`/investigations/${data.investigation_id}`} className="button button-primary" onClick={() => navigate(`/investigations/${data.investigation_id}`)}>Open investigation <ArrowUpRight size={15} /></Link>}</div></motion.div></div>
}

function Investigations() {
  const [data, setData] = useState<any[]>([]); const [error, setError] = useState('')
  async function load() { try { setData(await api('/investigations')); setError('') } catch (e) { setError(e instanceof Error ? e.message : 'Could not load investigations') } }
  useEffect(() => { load() }, [])
  return <><PageHeading eyebrow="CASE MANAGEMENT / L1 WORKSPACE" title="Investigations" description="Review the evidence trail, record analyst findings, and document the next action." action={<button className="button button-outline" onClick={load}><RefreshCw size={15} />Refresh</button>} />
    <Panel title="Investigation queue" subtitle={`${data.length} investigation${data.length === 1 ? '' : 's'} in your workspace`}>
      {error ? <ErrorState error={error} retry={load} /> : data.length ? <div className="investigation-list">{data.map((item) => <Link className="investigation-row" to={`/investigations/${item.id}`} key={item.id}><span className={`investigation-icon ${item.priority.toLowerCase()}`}><FileSearch2 size={17} /></span><span className="investigation-primary"><b>{item.title}</b><small>INV-{String(item.id).padStart(5,'0')} · {item.alert_id ? `Alert #${item.alert_id}` : 'Manually created'}</small></span><Severity value={item.priority} /><span className={`status-pill status-${item.status.toLowerCase()}`}>{item.status}</span><span className="investigation-time">Updated {new Date(item.updated_at).toLocaleDateString()}</span><ArrowUpRight size={15} className="row-arrow" /></Link>)}</div> : <EmptyState icon={FileSearch2} title="No investigations yet" text="When detections are generated, the platform opens an investigation with linked evidence and an L1 checklist." action={<Link to="/ingestion" className="button button-primary">Ingest a sample <ArrowUpRight size={14} /></Link>} />}
    </Panel><Routes><Route path=":investigationId" element={<InvestigationDetail />} /></Routes>
  </>
}

function InvestigationDetail() {
  const { investigationId } = useParams(); const navigate = useNavigate(); const [data, setData] = useState<any>(null); const [error, setError] = useState(''); const [note, setNote] = useState(''); const [busy, setBusy] = useState(false)
  const { user } = useContext(Auth)
  async function load() { try { setData(await api(`/investigations/${investigationId}`)); setError('') } catch (e) { setError(e instanceof Error ? e.message : 'Could not load investigation') } }
  useEffect(() => { load() }, [investigationId])
  async function updateStatus(status: string) { setBusy(true); try { await api(`/investigations/${investigationId}`, { method: 'PATCH', body: JSON.stringify({ status }) }); notify(`Investigation marked ${status.toLowerCase()}.`); await load() } catch (e) { notify(e instanceof Error ? e.message : 'Update failed', 'error') } finally { setBusy(false) } }
  async function toggle(index: number) { const checklist = data.checklist.map((item: any, i: number) => i === index ? { ...item, done: !item.done } : item); try { await api(`/investigations/${investigationId}/checklist`, { method: 'PATCH', body: JSON.stringify({ checklist }) }); setData({ ...data, checklist }) } catch (e) { notify(e instanceof Error ? e.message : 'Could not update checklist', 'error') } }
  async function addNote(e: FormEvent) { e.preventDefault(); if (!note.trim()) return; setBusy(true); try { await api(`/investigations/${investigationId}/notes`, { method: 'POST', body: JSON.stringify({ body: note.trim() }) }); setNote(''); await load(); notify('Analyst note saved to the audit trail.') } catch (err) { notify(err instanceof Error ? err.message : 'Could not save note', 'error') } finally { setBusy(false) } }
  if (error) return <div className="detail-overlay" onClick={() => navigate('/investigations')}><div className="detail-drawer" onClick={(e) => e.stopPropagation()}><button className="icon-button drawer-close" onClick={() => navigate('/investigations')}><X size={18} /></button><ErrorState error={error} retry={load} /></div></div>
  if (!data) return <div className="detail-overlay" onClick={() => navigate('/investigations')}><div className="detail-drawer" onClick={(e) => e.stopPropagation()}><Loading /></div></div>
  const alert = data.alert
  return <div className="detail-overlay" onClick={() => navigate('/investigations')}><motion.div className="detail-drawer investigation-drawer" onClick={(e) => e.stopPropagation()} initial={{ x: 30, opacity: .6 }} animate={{ x: 0, opacity: 1 }}><button className="icon-button drawer-close" onClick={() => navigate('/investigations')}><X size={18} /></button><div className="drawer-eyebrow">INVESTIGATION {String(data.id).padStart(5,'0')}</div><h2>{data.title}</h2><div className="drawer-badges">{alert && <Severity value={alert.severity} />}<span className={`status-pill status-${data.status.toLowerCase()}`}>{data.status}</span></div><div className="investigation-controls"><label className="select-wrap"><span>Update status</span><select value={data.status} disabled={busy} onChange={(e) => updateStatus(e.target.value)}>{['Open','Investigating','Escalated','Resolved','Closed'].map((x) => <option key={x}>{x}</option>)}</select></label>{alert && <span className="mini-risk">Risk <Risk value={alert.risk_score} /></span>}</div>
    <div className="drawer-section"><h3>L1 investigation checklist <span className="checklist-progress">{data.checklist.filter((x: any) => x.done).length}/{data.checklist.length}</span></h3><div className="checklist">{data.checklist.map((item: any, index: number) => <label className={item.done ? 'checked' : ''} key={index}><input type="checkbox" checked={item.done} onChange={() => toggle(index)} /><span className="check-custom"><Check size={12} /></span><span>{item.label}</span></label>)}</div></div>
    <div className="drawer-section"><h3>Evidence timeline <span className="count-badge">{data.events.length}</span></h3>{data.events.length ? <div className="timeline">{data.events.map((event: any) => <div className="timeline-item" key={event.id}><span className="timeline-dot" /><div className="timeline-card"><span className="timeline-time">{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Timestamp unavailable'}</span><b>{event.event_type || event.action || 'Normalized event'}</b><span>{[event.user, event.host, event.src_ip].filter(Boolean).join(' · ') || 'No user, host, or IP attribution'}</span><details><summary>Inspect raw evidence</summary><pre>{JSON.stringify(event.raw_event, null, 2)}</pre></details></div></div>)}</div> : <p className="muted-text">No linked events are available.</p>}</div>
    <div className="drawer-section"><h3>Correlation &amp; uncertainty</h3>{data.correlations.length ? data.correlations.map((item: any, i: number) => <div className="correlation-card" key={i}><Network size={15} /><div><b>{item.why}</b><p>{item.uncertainty}</p></div></div>) : <p className="muted-text">No multi-event correlation is supported by this alert evidence.</p>}</div>
    {alert && <div className="drawer-section"><h3>Rule explanation &amp; risk</h3><p className="assistant-summary">{data.assistant.summary}</p><p className="muted-text">{data.assistant.why_alerted}</p><div className="risk-factors wide-risk">{Object.entries(alert.risk_breakdown).filter(([k]) => k !== 'formula').map(([key, val]) => <div key={key}><span>{key}</span><b>{String(val)}</b></div>)}</div><p className="formula-note">{alert.risk_breakdown.formula}</p>{alert.mitre.map((x: any) => <a className="mitre-chip" key={x.id} href={`https://attack.mitre.org/techniques/${x.id.replace('.','/')}/`} target="_blank" rel="noreferrer"><span>{x.id}</span>{x.name}<ArrowUpRight size={12} /></a>)}</div>}
    <div className="drawer-section"><h3>Analyst advisory <em>RULE-BASED · NO AI MODEL USED</em></h3><ul className="recommendations">{(data.assistant.next_steps || []).map((x: string) => <li key={x}>{x}</li>)}</ul>{data.assistant.missing_evidence?.length > 0 && <div className="missing-evidence"><b>Additional evidence would help:</b><span>{data.assistant.missing_evidence.join(' · ')}</span></div>}<p className="muted-text">{data.assistant.response_note}</p></div>
    <div className="drawer-section"><h3>Analyst notes</h3><form className="note-form" onSubmit={addNote}><textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={10000} placeholder="Record an observation or decision…" aria-label="New analyst note" /><button className="button button-primary" disabled={busy || !note.trim()}><Plus size={14} />Add note</button></form><div className="note-list">{data.notes.map((item: any) => <div className="note-card" key={item.id}><p>{item.body}</p><small>{new Date(item.created_at).toLocaleString()} · {user?.name || 'Analyst'}</small></div>)}</div>{data.history.length > 0 && <div className="case-history"><h4>Investigation history</h4>{data.history.map((item: any, index: number) => <div key={index}><span>{item.action.replaceAll('_',' ')}</span><small>{JSON.stringify(item.details)} · {new Date(item.created_at).toLocaleString()}</small></div>)}</div>}</div>
    </motion.div></div>
}

function Analytics() {
  const [data, setData] = useState<any>(null); const [error, setError] = useState(''); const [days, setDays] = useState('0')
  async function load(range = days) { try { setData(await api(`/analytics?days=${range}`)); setError('') } catch (e) { setError(e instanceof Error ? e.message : 'Could not load analytics') } }
  useEffect(() => { load() }, [days])
  return <><PageHeading eyebrow="MEASUREMENT / WORKSPACE RECORDS" title="Analytics" description="A compact view of ingested events, observed alerts, and investigation signals." action={<><label className="select-wrap"><Clock3 size={13} /><select value={days} onChange={(e) => setDays(e.target.value)}><option value="0">All time</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option></select></label><button className="button button-outline" onClick={() => load()}><RefreshCw size={15} />Refresh</button></>} />
    {error ? <ErrorState error={error} retry={load} /> : !data ? <Loading /> : <>{data.total_events === 0 ? <div className="demo-banner"><span className="info-circle"><CircleHelp size={14} /></span><span>Charts use stored workspace records. With no events yet, they show empty values.</span><Link to="/ingestion">Ingest logs <ArrowUpRight size={13} /></Link></div> : <div className="analytics-summary"><span><b>{data.total_events}</b> events stored</span><span><b>{data.total_alerts}</b> alerts generated</span><span><b>{data.correlation_count}</b> linked event relationships</span></div>}
      <div className="analytics-grid"><Panel title="Events & alerts" subtitle="Daily records from the current workspace"><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data.trend}><CartesianGrid stroke="rgba(255,255,255,.055)" vertical={false} /><XAxis dataKey="date" tickFormatter={(v) => v.slice(5)} axisLine={false} tickLine={false} tick={{ fill: '#747984', fontSize: 11 }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#747984', fontSize: 11 }} /><Tooltip contentStyle={{ background: '#17191e', border: '1px solid #30333b', borderRadius: 9 }} /><Area dataKey="events" stroke="#e34a55" fill="#e34a5526" /><Area dataKey="alerts" stroke="#e3ad49" fill="transparent" /></AreaChart></ResponsiveContainer></div></Panel>
      <Panel title="Severity mix" subtitle="Alert records by assigned priority"><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={data.severity_distribution} layout="vertical" margin={{ left: 8, right: 14 }}><CartesianGrid stroke="rgba(255,255,255,.055)" horizontal={false} /><XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#747984', fontSize: 11 }} /><YAxis type="category" dataKey="name" width={70} axisLine={false} tickLine={false} tick={{ fill: '#c7cad0', fontSize: 11 }} /><Tooltip contentStyle={{ background: '#17191e', border: '1px solid #30333b', borderRadius: 9 }} /><Bar dataKey="value" radius={[0,5,5,0]}>{data.severity_distribution.map((x: any) => <Cell key={x.name} fill={SEVERITY_COLORS[x.name]} />)}</Bar></BarChart></ResponsiveContainer></div></Panel>
      <Panel title="Risk-score bands" subtitle="Prioritization scores, not probability estimates"><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={data.risk_distribution}><CartesianGrid stroke="rgba(255,255,255,.055)" vertical={false} /><XAxis dataKey="range" axisLine={false} tickLine={false} tick={{ fill: '#9b9fa8', fontSize: 11 }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#747984', fontSize: 11 }} /><Tooltip contentStyle={{ background: '#17191e', border: '1px solid #30333b', borderRadius: 9 }} /><Bar dataKey="value" fill="#e34a55" radius={[5,5,0,0]} /></BarChart></ResponsiveContainer></div></Panel>
      <Panel title="Detection categories" subtitle="Generated by deterministic rules"><RankList items={data.detection_categories} empty="Detections will appear when uploaded data supports them." /></Panel>
      <Panel title="Top affected hosts" subtitle="From normalized events"><RankList items={data.top_hosts} empty="No host values are available." /></Panel>
      <Panel title="Top affected accounts" subtitle="From normalized events"><RankList items={data.top_accounts} empty="No account values are available." /></Panel>
      <Panel title="Data source distribution" subtitle="Source field values in ingested events"><RankList items={data.data_sources} empty="No event sources are available." /></Panel>
      <Panel title="Frequently observed rules" subtitle="Stored alerts"><RankList items={data.frequent_rules} empty="No alerts have been generated." /></Panel></div>
    </>}
  </>
}
function RankList({ items, empty }: { items: any[]; empty: string }) { if (!items.length) return <div className="rank-empty">{empty}</div>; const max = Math.max(...items.map((x) => x.value)); return <div className="rank-list">{items.slice(0,6).map((item, i) => <div className="rank-row" key={item.name}><span className="rank-index">{String(i+1).padStart(2,'0')}</span><div className="rank-body"><div><b>{item.name}</b><span>{item.value}</span></div><i style={{ width: `${Math.max(5, item.value / max * 100)}%` }} /></div></div>)}</div> }

function Sources() {
  const [data, setData] = useState<any[]>([]); const [error, setError] = useState('')
  async function load() { try { setData(await api('/connectors')) } catch (e) { setError(e instanceof Error ? e.message : 'Could not load sources') } }
  useEffect(() => { load() }, [])
  const icon: Record<string, any> = { 'File upload': HardDriveUpload, Splunk: Database, Wazuh: Shield, 'Microsoft Sentinel': ShieldCheck, 'Elastic Security': Activity, 'Generic API': Network }
  return <><PageHeading eyebrow="INTEGRATIONS / SOURCE REGISTRY" title="Data sources" description="Upload is ready to use. Optional SIEM adapters are listed with their honest implementation state." action={<button className="button button-outline" onClick={load}><RefreshCw size={15} />Refresh status</button>} />
    <div className="source-notice"><span><Database size={17} /></span><div><b>Normalized event interface</b><p>All uploaded records enter the same common event schema used by the detection pipeline. Connector status only changes after an implemented, real health check.</p></div></div>
    {error ? <ErrorState error={error} retry={load} /> : !data.length ? <Loading /> : <div className="source-grid">{data.map((item) => { const Icon = icon[item.name] || Database; return <article className="source-card" key={item.name}><div className="source-card-top"><span className="source-icon"><Icon size={19} /></span><span className={`connector-state ${item.status === 'Available' ? 'connected' : 'not-implemented'}`}><i />{item.status}</span></div><h3>{item.name}</h3><p>{item.description}</p><div className="source-foot"><span>Health check {item.status === 'Available' ? 'available' : 'not available'}</span>{item.status === 'Available' ? <Link to="/ingestion">Open ingestion <ArrowUpRight size={13} /></Link> : <span className="not-ready">Setup adapter</span>}</div></article> })}</div>}
    <Panel className="connector-notes" title="Integration notes" subtitle="Optional providers require adapter development and credential management"><ul className="plain-list"><li><CheckCircle2 size={15} />Uploading logs works independently of external systems.</li><li><CheckCircle2 size={15} />This workspace does not store connector credentials or send events to third parties.</li><li><CircleHelp size={15} />Splunk, Wazuh, Microsoft Sentinel, Elastic Security, and Generic API adapters are not implemented.</li></ul></Panel>
  </>
}

function Indicators() {
  const [data, setData] = useState<any[]>([]); const [error, setError] = useState('')
  async function load() { try { setData(await api('/iocs')); setError('') } catch (e) { setError(e instanceof Error ? e.message : 'Could not load indicators') } }
  useEffect(() => { load() }, [])
  return <><PageHeading eyebrow="EVIDENCE / OBSERVED INDICATORS" title="Indicators" description="Format-validated values extracted from events. Unknown reputation is not a malicious verdict." action={<button className="button button-outline" onClick={load}><RefreshCw size={15} />Refresh</button>} />
    {error ? <ErrorState error={error} retry={load} /> : data.length ? <Panel title="Extracted indicators" subtitle={`${data.length} values observed in uploaded events`}><div className="table-wrap"><table><thead><tr><th>VALUE</th><th>TYPE</th><th>FIRST SEEN</th><th>ASSOCIATED RECORDS</th><th>ASSESSMENT</th></tr></thead><tbody>{data.map((ioc) => <tr key={ioc.id}><td className="mono">{ioc.value}</td><td>{ioc.kind}</td><td>{new Date(ioc.first_seen).toLocaleString()}</td><td>{ioc.event_ids.length} event(s) · {ioc.alert_ids.length} alert(s)</td><td><span className={`ioc-assessment ${ioc.match_status === 'Local test IOC match' ? 'ioc-match' : ''}`}><i />{ioc.match_status}</span></td></tr>)}</tbody></table></div></Panel> : <Panel title="Extracted indicators"><EmptyState icon={Fingerprint} title="No indicators extracted" text="Valid IP addresses, domains, and file hashes in future ingestion records will appear here. Format alone does not indicate maliciousness." /></Panel>}
  </>
}

function Settings() {
  const [audit, setAudit] = useState<any[]>([]); const [error, setError] = useState(''); const { user } = useContext(Auth)
  async function load() { try { setAudit(await api('/audit')); setError('') } catch (e) { setError(e instanceof Error ? e.message : 'Could not load audit events') } }
  useEffect(() => { load() }, [])
  return <><PageHeading eyebrow="WORKSPACE / PREFERENCES & AUDIT" title="Settings" description="Your account, session security, local storage, and analyst action history." />
    <div className="settings-grid"><Panel title="Analyst profile" subtitle="Authenticated account for this workspace"><div className="setting-profile"><span className="avatar avatar-large">{user?.name?.slice(0,1).toUpperCase()}</span><div><b>{user?.name}</b><span>{user?.email}</span><small>Account created with secure password hashing</small></div></div><div className="security-note"><LockKeyhole size={15} /><span>Session is held in an HTTP-only signed cookie. State-changing requests use a CSRF token.</span></div></Panel><Panel title="Local environment" subtitle="Current service configuration"><div className="setting-row"><span>Database</span><b><i className="green-pulse" /> SQLite local storage</b></div><div className="setting-row"><span>External AI</span><b>Not configured · deterministic advisory available</b></div><div className="setting-row"><span>Upload size limit</span><b>10 MB per file (configurable)</b></div><div className="setting-row"><span>Security response</span><b>Manual recommendations only</b></div></Panel></div>
    <Panel title="Analyst audit trail" subtitle="Status changes, notes, ingestion actions, and demo-data changes" action={<button className="icon-button" onClick={load} aria-label="Refresh audit log"><RefreshCw size={15} /></button>}><div id="audit">{error ? <ErrorState error={error} retry={load} /> : audit.length ? <div className="audit-list">{audit.map((item) => <div className="audit-row" key={item.id}><span className="audit-icon"><Clock3 size={14} /></span><span><b>{item.action.replaceAll('_',' ')}</b><small>{item.entity_type} #{item.entity_id} · {JSON.stringify(item.details)}</small></span><time>{new Date(item.created_at).toLocaleString()}</time></div>)}</div> : <EmptyState icon={Clock3} title="No analyst actions yet" text="Workspace changes will be recorded here." />}</div></Panel>
  </>
}

export default function App() {
  const [user, setUser] = useState<User | null>(null); const [loading, setLoading] = useState(true)
  useEffect(() => { api<User>('/auth/me').then((value) => { setUser(value); setCsrf(value.csrf_token || '') }).catch(() => { clearCsrf(); setUser(null) }).finally(() => setLoading(false)) }, [])
  const auth = useMemo(() => ({ user, loading, setUser }), [user, loading])
  return <Auth.Provider value={auth}><Routes><Route path="/login" element={user ? <Navigate to="/dashboard" replace /> : <Login />} /><Route path="/signup" element={user ? <Navigate to="/dashboard" replace /> : <Signup />} /><Route path="/*" element={<Protected><Workspace /></Protected>}><Route index element={<Navigate to="/dashboard" replace />} /><Route path="dashboard" element={<Dashboard />} /><Route path="ingestion" element={<Ingestion />} /><Route path="events" element={<Events />} /><Route path="alerts/*" element={<Alerts />} /><Route path="investigations/*" element={<Investigations />} /><Route path="analytics" element={<Analytics />} /><Route path="sources" element={<Sources />} /><Route path="iocs" element={<Indicators />} /><Route path="settings" element={<Settings />} /><Route path="*" element={<Navigate to="/dashboard" replace />} /></Route></Routes></Auth.Provider>
}
