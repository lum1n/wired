import type { Socket } from 'node:net'
import type { Agent, AgentOptions } from 'node:http'
import type { EventEmitter } from 'node:events'

export interface JoinOptions {
  name: string
  /** Defaults to the WIRED_INVITE environment variable. */
  invite?: string
  stateDir?: string
  /** Keep keys in memory only. */
  ephemeral?: boolean
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
  /** Host or IP put in the invite (default: the default route's IP). */
  publicHost?: string
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
