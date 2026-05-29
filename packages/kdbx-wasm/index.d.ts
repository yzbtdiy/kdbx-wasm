/**
 * KDBX password database parser for JavaScript
 *
 * This library provides a WebAssembly-based parser for KeePass KDBX 4 files.
 */

export class JsMetadata {
  get databaseName(): string | undefined;
  get databaseDescription(): string | undefined;
  get defaultUsername(): string | undefined;
  get maintenanceHistoryDays(): number;
  get color(): string | undefined;
}

export class JsKdfParams {
  get memory(): number | undefined;
  get iterations(): number | undefined;
  get parallelism(): number | undefined;
  get rounds(): number | undefined;
}

export class JsHeaderInfo {
  get version(): string;
  get encryptionAlgorithm(): 'AES-256' | 'ChaCha20';
  get kdfAlgorithm(): 'Argon2d' | 'Argon2id' | 'AES-KDF';
  get kdfParams(): JsKdfParams;
  get compression(): 'None' | 'Gzip';
  get entryCount(): number;
  get groupCount(): number;
}

export class JsFileInfo {
  get version(): string;
  get encryptionAlgorithm(): 'AES-256' | 'ChaCha20';
  get kdfAlgorithm(): 'Argon2d' | 'Argon2id' | 'AES-KDF';
  get compression(): 'None' | 'Gzip';
}

export interface KdbxEntry {
  uuid: string;
  iconId: number;
  groupId: string;
  title: string;
  username?: string;
  /**
   * WARNING: Password is only included when explicitly requested.
   * When returned, it is plain text and will NOT be automatically
   * cleared from JavaScript memory. Use sparingly.
   */
  password?: string;
  url?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
  accessedAt: string;
  expiresAt?: string;
  tags: string[];
  customFields: Record<string, string>;
}

export interface KdbxGroup {
  uuid: string;
  name: string;
  iconId: number;
  parentId?: string;
  createdAt: string;
  updatedAt: string;
  notes?: string;
  childGroups: string[];
  entries: string[];
}

/**
 * KDBX Database class
 *
 * Represents an opened KDBX password database.
 */
export class KdbxDatabase {
  /**
   * Open a KDBX file from bytes
   *
   * @param data - The KDBX file bytes as Uint8Array
   * @param password - Optional master password
   * @param keyFile - Optional key file bytes as Uint8Array
   * @throws Error if the file cannot be decrypted or parsed
   */
  constructor(data: Uint8Array, password?: string, keyFile?: Uint8Array);

  /** Get database metadata */
  get metadata(): JsMetadata;

  /** Get header information */
  get headerInfo(): JsHeaderInfo;

  /** Get the root group UUID */
  get rootGroupUuid(): string;

  /**
   * Get all entries as an array
   *
   * @param includePassword - Whether to include password fields (default: false)
   */
  getEntries(includePassword?: boolean): KdbxEntry[];

  /**
   * Get a specific entry by UUID
   *
   * @param uuid - The entry UUID
   * @param includePassword - Whether to include password field (default: false)
   */
  getEntry(uuid: string, includePassword?: boolean): KdbxEntry;

  /**
   * Get all groups as an array
   */
  getGroups(): KdbxGroup[];

  /**
   * Get a specific group by UUID
   *
   * @param uuid - The group UUID
   */
  getGroup(uuid: string): KdbxGroup;

  /**
   * Get entries in a specific group
   *
   * @param groupUuid - The group UUID
   * @param includePassword - Whether to include password fields (default: false)
   */
  getEntriesByGroup(groupUuid: string, includePassword?: boolean): KdbxEntry[];

  /**
   * Search entries by keyword
   *
   * @param query - The search query
   * @param includePassword - Whether to include password fields (default: false)
   */
  searchEntries(query: string, includePassword?: boolean): KdbxEntry[];

  /**
   * Advanced search with filters
   *
   * @param query - Text to search across title, username, URL, notes, tags, custom fields
   * @param groupUuid - Limit search to a specific group
   * @param excludeExpired - Skip expired entries
   * @param includePassword - Whether to include password fields (default: false)
   */
  searchEntriesAdvanced(
    query?: string,
    groupUuid?: string,
    excludeExpired?: boolean,
    includePassword?: boolean
  ): KdbxEntry[];

  /**
   * Get child groups of a specific group
   *
   * @param groupUuid - The parent group UUID
   */
  getChildGroups(groupUuid: string): KdbxGroup[];

  // ── Entry Mutations ──

  /**
   * Create a new entry in the specified group
   *
   * @param groupUuid - The group UUID to place the entry in
   * @param title - Entry title
   * @param password - Entry password
   * @returns The new entry's UUID
   */
  createEntry(groupUuid: string, title: string, password: string): string;

  /** Delete an entry by UUID */
  deleteEntry(uuid: string): void;

  /** Move an entry to a different group */
  moveEntry(entryUuid: string, targetGroupUuid: string): void;

  /** Update entry title */
  setEntryTitle(uuid: string, title: string): void;

  /** Update entry username (pass undefined to clear) */
  setEntryUsername(uuid: string, username?: string): void;

  /** Update entry password */
  setEntryPassword(uuid: string, password: string): void;

  /** Update entry URL (pass undefined to clear) */
  setEntryUrl(uuid: string, url?: string): void;

  /** Update entry notes (pass undefined to clear) */
  setEntryNotes(uuid: string, notes?: string): void;

  /** Update entry icon ID */
  setEntryIconId(uuid: string, iconId: number): void;

  /** Add a tag to an entry */
  addEntryTag(uuid: string, tag: string): void;

  /** Remove a tag from an entry */
  removeEntryTag(uuid: string, tag: string): void;

  /** Set or remove a custom field */
  setEntryCustomField(uuid: string, key: string, value?: string): void;

  /** Set or clear entry expiry date (RFC 3339 string) */
  setEntryExpires(uuid: string, expiresAt?: string): void;

  // ── Group Mutations ──

  /**
   * Create a new group
   *
   * @param name - Group name
   * @param parentUuid - Parent group UUID (omit to create root group)
   * @returns The new group's UUID
   */
  createGroup(name: string, parentUuid?: string): string;

  /** Delete a group (must be empty) */
  deleteGroup(uuid: string): void;

  /** Rename a group */
  renameGroup(uuid: string, name: string): void;

  /** Set or clear group notes */
  setGroupNotes(uuid: string, notes?: string): void;

  /** Update group icon ID */
  setGroupIconId(uuid: string, iconId: number): void;

  // ── Metadata Mutations ──

  /** Set or clear database name */
  setDatabaseName(name?: string): void;

  /** Set or clear database description */
  setDatabaseDescription(description?: string): void;

  /** Set or clear default username */
  setDefaultUsername(username?: string): void;

  // ── Export ──

  /**
   * Export the database to KDBX format bytes
   *
   * @param password - Optional master password for the exported file
   * @param keyFile - Optional key file bytes for the exported file
   * @returns The KDBX file bytes as Uint8Array
   */
  toBytes(password?: string, keyFile?: Uint8Array): Uint8Array;
}

/**
 * Check if data appears to be a valid KDBX file
 *
 * @param data - The file bytes to check
 * @returns True if the data appears to be a KDBX file
 */
export function isKdbxFile(data: Uint8Array): boolean;

/**
 * Get KDBX file version info without decrypting
 *
 * @param data - The KDBX file bytes
 * @returns File information including version and algorithms
 * @throws Error if the file header cannot be parsed
 */
export function getFileInfo(data: Uint8Array): JsFileInfo;

/**
 * Initialize the WASM module
 *
 * This function is automatically called when the module is imported.
 * You only need to call it manually if you want to handle initialization errors.
 */
export function start(): void;

/**
 * Initialize the WASM module with an optional module path.
 */
export function initKdbxWasm(module_or_path?: string | URL | Request | WebAssembly.Module): Promise<void>;
