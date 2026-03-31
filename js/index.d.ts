/**
 * KDBX password database parser for JavaScript
 * 
 * This library provides a WebAssembly-based parser for KeePass KDBX 4 files.
 */

export interface KdbxMetadata {
  databaseName?: string;
  databaseDescription?: string;
  defaultUsername?: string;
  maintenanceHistoryDays: number;
  color?: string;
}

export interface KdfParams {
  memory?: number;
  iterations?: number;
  parallelism?: number;
  rounds?: number;
}

export interface KdbxHeaderInfo {
  version: string;
  encryptionAlgorithm: 'AES-256' | 'ChaCha20';
  kdfAlgorithm: 'Argon2d' | 'Argon2id' | 'AES-KDF';
  kdfParams: KdfParams;
  compression: 'None' | 'Gzip';
  entryCount: number;
  groupCount: number;
}

export interface KdbxEntry {
  uuid: string;
  iconId: number;
  groupId: string;
  title: string;
  username?: string;
  password: string;
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

export interface KdbxFileInfo {
  version: string;
  encryptionAlgorithm: 'AES-256' | 'ChaCha20';
  kdfAlgorithm: 'Argon2d' | 'Argon2id' | 'AES-KDF';
  compression: 'None' | 'Gzip';
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
  get metadata(): KdbxMetadata;

  /** Get header information */
  get headerInfo(): KdbxHeaderInfo;

  /** Get the root group UUID */
  get rootGroupUuid(): string;

  /**
   * Get all entries as an array
   */
  getEntries(): KdbxEntry[];

  /**
   * Get a specific entry by UUID
   * 
   * @param uuid - The entry UUID
   */
  getEntry(uuid: string): KdbxEntry;

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
   */
  getEntriesByGroup(groupUuid: string): KdbxEntry[];

  /**
   * Search entries by keyword
   * 
   * @param query - The search query
   */
  searchEntries(query: string): KdbxEntry[];

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
export function getFileInfo(data: Uint8Array): KdbxFileInfo;

/**
 * Initialize the WASM module
 * 
 * This function is automatically called when the module is imported.
 * You only need to call it manually if you want to handle initialization errors.
 */
export function start(): void;
