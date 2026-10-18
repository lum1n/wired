import type { Socket } from 'node:net'
import type { Agent, AgentOptions, IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import type { EventEmitter } from 'node:events'

export interface JoinOptions {
  name: string
  /** Defaults to the WIRED_INVITE environment variable. */
  invite?: string
  stateDir?: string
  /** Keep keys in memory only. */
  ephemeral?: boolean
  /** Serve a relay behind a TLS-terminating proxy, reached at this URL (e.g. https://robin.exe.xyz). Needs relayBind. */
  relayUrl?: string
  /** Local address the relay listens on, e.g. 127.0.0.1:8790. */
  relayBind?: string
  /** Testing: never connect directly, only through relays. */
  relayOnly?: boolean
}

export interface AnchorOptions {
  name: string
  /** Address to bind (default 0.0.0.0). */
  bindHost?: string
  /** UDP port for peers and TCP port for the relay (default 7443, 0 = any). */
  port?: number
  /** UDP port for address discovery (default 7842, 0 = any). */
  qadPort?: number
  noQad?: boolean
  /** Host or IP others reach this machine at (default: the default route's IP). */
  publicHost?: string
  /** Don't serve a relay (this machine isn't reachable from the internet). */
  noRelay?: boolean
  /** Serve the relay behind a TLS-terminating proxy at this URL instead. Needs relayBind. */
  relayUrl?: string
  relayBind?: string
  /** Testing: never connect directly, only through relays. */
  relayOnly?: boolean
  /** Run as a replica of the network this invite is for. */
  replicaOf?: string
  stateDir?: string
  ephemeral?: boolean
}

export interface Peer {
  name: string
  id?: string
}

export interface WiredSocket extends Socket {
  wiredPeer: Peer
}

export interface ServiceOptions {
  /** Node names that may connect; default: every member. */
  allow?: string[]
}

export interface Relay {
  url: string
  /** Certificate pinned to a key (self-signed relay) rather than CA-checked. */
  pinned: boolean
  /** Id of the node serving it, if a member announced it. */
  owner?: string
}

export interface RelayProxy {
  /** Whether this request is for the relay (`/relay` or `/ping`). */
  matches(req: IncomingMessage): boolean
  request(req: IncomingMessage, res: ServerResponse): void
  upgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void
}

/** Forwards relay traffic from your HTTP server to a relay listening at `localAddr`. */
export declare function relayProxy(localAddr: string): RelayProxy

/** `api.laptop.wired` -> `api@laptop`; throws for other hosts. */
export declare function hostToTarget(host: string): string

export interface Member {
  name: string
  id: string
  anchor: boolean
}

export interface Task {
  readonly localAddr: string | null
  close(): void
}

export declare class WiredServer extends EventEmitter {
  readonly service: string
  on(event: 'connection', listener: (socket: WiredSocket) => void): this
  on(event: 'error', listener: (err: Error) => void): this
  on(event: 'close', listener: () => void): this
  close(): void
}

export declare class Node {
  static join(opts: JoinOptions): Promise<Node>
  static anchor(opts: AnchorOptions): Promise<Node>
  readonly name: string
  readonly id: string
  readonly invite: string
  readonly isAnchor: boolean
  readonly isRoot: boolean
  members(): Member[]
  relays(): Relay[]
  /** The relay this node serves, or null. */
  readonly servedRelay: { url: string; localAddr: string } | null
  /** Root only: lists a relay for the whole network. */
  addRelay(url: string): void
  /** Root only: stops listing a relay. */
  removeRelay(url: string): void
  /** Root only: removes a node now; returns the new invite. */
  revoke(name: string): string
  /** Root only: replaces the invite; returns the new one. */
  rotateInvite(): string
  /** Root only: lets the replica anchor with this id join. */
  approveAnchor(id: string): void
  dial(target: string): Promise<WiredSocket>
  listen(service: string, options?: ServiceOptions): WiredServer
  serve(service: string, server: EventEmitter, options?: ServiceOptions): WiredServer
  expose(service: string, target: string, options?: ServiceOptions): Task
  forward(local: string, target: string): Promise<Task>
  httpAgent(options?: AgentOptions): Agent
  path(node: string): 'direct' | 'relay' | null
  close(): Promise<void>
}
