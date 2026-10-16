/**
 * dsh-capture: HTTP 路由的请求 / 响应类型声明（纯类型，无运行时）。
 *
 * 目的：给宿主侧与外部调用方一个可核对的数据契约，而不是靠读 routes.js 反推。
 * 该文件不被打包执行，只在编辑器 / tsc 下用于类型检查。
 */

/** 抓包文件条目（`/sessions` 返回）。 */
export interface CaptureEntry {
  /** 寻址用 id（文件名的 sha256 前缀）。 */
  id: string;
  name: string;
  size: number;
  /** 毫秒时间戳。 */
  mtime: number;
  /** 包数（解析得出，无法解析时为 null）。 */
  packets: number | null;
}

/** 网卡条目（`/interfaces` 返回）。 */
export interface InterfaceEntry {
  index: number;
  /** 形如 `\Device\NPF_{GUID}` —— 抓包时用它寻址，绝不用 index。 */
  device: string;
  label: string;
  kind: 'wifi' | 'ethernet' | 'virtual' | 'loopback' | 'other';
  recommended: boolean;
}

/** 后端环境报告（`/status` 返回的 backend）。 */
export interface BackendReport {
  platform: string;
  isWindows: boolean;
  /** 自动选定的后端。 */
  backend: 'npcap' | 'pktmon' | null;
  canCapture: boolean;
  needsElevation: boolean;
  npcap: {
    available: boolean;
    dir: string | null;
    dumpcap: string | null;
    tshark: string | null;
    interfaceCount: number;
    reason: string | null;
  } | null;
  npcapConfig: { adminOnly: number | null; winPcapCompatible: number | null; dir: string | null } | null;
  pktmon: { path: string; exists: boolean; usable: boolean; needsElevation: boolean; note: string } | null;
  interfaces?: InterfaceEntry[];
  defaultInterface?: InterfaceEntry | null;
}

/** TLS ClientHello / ServerHello 解析结果。 */
export interface TlsInfo {
  role?: 'client' | 'server';
  sni?: string | null;
  /** ClientHello：记录层版本名，如 "TLS 1.0"。 */
  recordVersionName?: string;
  /** ClientHello：客户端声明版本名。 */
  clientVersionName?: string;
  /** ClientHello：supported_versions 扩展列表。 */
  supportedVersions?: string[];
  /** ClientHello：密码套件规范名列表。 */
  cipherSuites?: string[];
  /** 扩展名列表。 */
  extensions?: string[];
  /** ServerHello：协商版本名。 */
  negotiatedVersionName?: string;
  /** ServerHello：协商密码套件名。 */
  cipherSuite?: string;
}

/** 重组后的 HTTP 事务（`/analyze` 的 transactions 项）。 */
export interface HttpTransaction {
  ts: number | null;
  time: string | null;
  stream: string;
  client: string;
  server: string | null;
  method: string | null;
  path: string | null;
  host: string | null;
  status: number | null;
  reason: string | null;
  requestContentType: string | null;
  responseContentType: string | null;
  /** 响应体字节数（Content-Length）。 */
  responseBytes: number | null;
  /** 请求体预览（仅文本类型）。 */
  requestBody: string | null;
  /** 响应体预览（仅文本类型）。 */
  responseBody: string | null;
  responseBodyTruncated: boolean;
}

/** 重组统计。 */
export interface ReassemblyStats {
  streams: number;
  skippedFlows: number;
  reassembledBytes: number;
  /** seq 空洞计数 —— 不为 0 说明重组结果不完整。 */
  gaps: number;
  disabled?: boolean;
}

/** 抓包摘要（`/analyze` 返回）。 */
export interface AnalyzeResult {
  ok: boolean;
  error?: string;
  file: string;
  sizeBytes: number;
  /** 时间戳单位为**该文件 if_tsresol 声明的每秒刻度数**（dumpcap 为 1e9）。 */
  meta: {
    format?: 'pcap' | 'pcapng';
    linkType?: number | null;
    packets: number;
    bytes: number;
    tcpPackets: number;
    udpPackets: number;
    firstTs: number | null;
    lastTs: number | null;
    /** ISO-8601 UTC。 */
    firstTime: string | null;
    lastTime: string | null;
    tsResolution?: number;
  };
  stats: { malformed: number; truncated: number; unsupportedLink: number; blocks?: number };
  reassembly: ReassemblyStats;
  talkers: Array<{ src: string; dst: string; packets: number; bytes: number }>;
  topPorts: Array<{ port: number; count: number }>;
  dns: Array<{ ts: number; src: string; dst: string; name: string; type: number | string; answers: number }>;
  sni: Array<{ name: string; count: number }>;
  http: Array<Record<string, unknown>>;
  tls: TlsInfo[];
  streams: Array<{
    key: string; client: string; server: string | null;
    packets: number; bytes: number; gaps: number; truncated: boolean;
    firstTime: string | null; hasHttp: boolean; hasTls: boolean;
  }>;
  httpTransactions: HttpTransaction[];
  /** 拍平的 HTTP 事务 —— 面板与 search 用的是这份。 */
  transactions: HttpTransaction[];
  headSample: Array<{
    ts: number; time: string | null; proto: string;
    src?: string; dst?: string; sport: number | null; dport: number | null;
    bytes: number; sni: string | null; tls: string | null; dns: string | null; http: string | null;
  }>;
  summary?: {
    dnsNames: number; httpsHosts: number; httpRequests: number;
    httpTransactions: number; tlsHandshakes: number; tcpStreams: number; endpoints: number;
  };
}

/** `/packets` 返回的一行。 */
export interface PacketRow {
  index: number;
  /** 秒（小数部分按 if_tsresol 换算）。 */
  ts: number;
  /** ISO-8601 UTC。 */
  time: string | null;
  proto: string;
  src: string | null;
  dst: string | null;
  sport: number | null;
  dport: number | null;
  /** 整帧字节数。 */
  bytes: number;
  /** TCP/UDP 载荷字节数。 */
  payloadBytes: number;
  sni: string | null;
  tls: string | null;
  dns: string[] | null;
  http: string | null;
  flags: { syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean } | null;
}

/** `/search` 返回。 */
export interface SearchResult {
  ok: boolean;
  pattern: string;
  dns: unknown[];
  sni: unknown[];
  http: unknown[];
  endpoints: unknown[];
  streams: unknown[];
  /** 命中重组后报文体的条目。 */
  bodies: Array<{
    stream: string;
    method: string | null;
    host: string | null;
    path: string | null;
    requestBody: string | null;
    responseBody: string | null;
  }>;
}

/** 插件配置（与 index.js 的 Config schema 对应）。 */
export interface CaptureConfig {
  /** 单次分析读入上限（字节），默认 96 MB。 */
  maxAnalyzeBytes?: number;
  /** 单次解析包数上限，默认 120000。 */
  maxAnalyzePackets?: number;
  /** 非提权时是否经 UAC 委托抓包。 */
  useElevation?: boolean;
  /** 默认每包截取字节数。 */
  defaultPktSize?: number;
  /** 是否允许 /download 返回原始抓包字节。 */
  allowDownload?: boolean;
  /** 是否做 TCP 流重组（关掉可省内存，但跨包 HTTP/TLS 读不全）。 */
  reassemble?: boolean;
  /** 每个方向保留的重组字节上限（KB）。 */
  streamCapKb?: number;
  /** 单次分析最多重组的 TCP 流数。 */
  maxStreams?: number;
  /** HTTP 报文体预览上限（字节，0 = 不取体）。 */
  httpBodyPreviewBytes?: number;
}
