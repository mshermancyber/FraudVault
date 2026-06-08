import bcrypt from 'bcrypt';
import type pg from 'pg';
import type { User, UserRole, PaginatedResponse } from '@scanboy/shared';
import { AppError } from '../middleware/errorHandler.js';
import type { AppConfig } from '../config.js';

interface ListQuery {
  page: number;
  pageSize: number;
  role?: UserRole;
}

interface CreateUserData {
  email: string;
  displayName: string;
  password: string;
  role: UserRole;
}

interface UpdateUserData {
  displayName?: string;
  role?: UserRole;
  mfaEnabled?: boolean;
}

/**
 * Row from PostgreSQL mapped to User interface.
 */
function mapRow(row: Record<string, unknown>): Omit<User, never> {
  return {
    id: row['id'] as string,
    email: row['email'] as string,
    displayName: row['display_name'] as string,
    role: row['role'] as UserRole,
    status: row['status'] as string,
    mfaEnabled: row['mfa_enabled'] as boolean,
    lastLoginAt: (row['last_login_at'] as string) ?? null,
    createdAt: row['created_at'] as string,
    updatedAt: row['updated_at'] as string,
  };
}

export class UserService {
  constructor(
    private readonly pool: pg.Pool,
    private readonly config?: AppConfig,
  ) {}

  async list(query: ListQuery): Promise<PaginatedResponse<User>> {
    const { page, pageSize, role } = query;
    const offset = (page - 1) * pageSize;

    const conditions: string[] = [`status = 'active'`];
    const params: Array<string | number> = [];

    if (role) {
      params.push(role);
      conditions.push(`role = $${String(params.length)}`);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await this.pool.query(
      `SELECT COUNT(*) as total FROM users ${whereClause}`,
      params,
    );
    const total = parseInt(countResult.rows[0]?.total as string, 10);

    params.push(pageSize, offset);
    const dataResult = await this.pool.query(
      `SELECT id, email, display_name, role, status, mfa_enabled, last_login_at, created_at, updated_at
       FROM users ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${String(params.length - 1)} OFFSET $${String(params.length)}`,
      params,
    );

    return {
      data: dataResult.rows.map((row) => mapRow(row as Record<string, unknown>)),
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    };
  }

  async getById(id: string): Promise<User> {
    const result = await this.pool.query(
      `SELECT id, email, display_name, role, status, mfa_enabled, last_login_at, created_at, updated_at
       FROM users WHERE id = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      throw new AppError(404, 'NOT_FOUND', 'User not found');
    }

    return mapRow(result.rows[0] as Record<string, unknown>);
  }

  async create(data: CreateUserData): Promise<User> {
    const passwordHash = await bcrypt.hash(data.password, this.config?.bcryptRounds ?? 12);

    try {
      const result = await this.pool.query(
        `INSERT INTO users (email, display_name, password_hash, role)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, display_name, role, status, mfa_enabled, last_login_at, created_at, updated_at`,
        [data.email, data.displayName, passwordHash, data.role],
      );
      return mapRow(result.rows[0] as Record<string, unknown>);
    } catch (err: unknown) {
      const pgErr = err as { code?: string };
      if (pgErr.code === '23505') {
        throw new AppError(409, 'CONFLICT', 'A user with this email already exists');
      }
      throw err;
    }
  }

  async update(id: string, data: UpdateUserData): Promise<User> {
    const setClauses: string[] = [];
    const params: Array<string | boolean> = [];

    if (data.displayName !== undefined) {
      params.push(data.displayName);
      setClauses.push(`display_name = $${String(params.length)}`);
    }

    if (data.role !== undefined) {
      params.push(data.role);
      setClauses.push(`role = $${String(params.length)}`);
    }

    if (data.mfaEnabled !== undefined) {
      params.push(data.mfaEnabled);
      setClauses.push(`mfa_enabled = $${String(params.length)}`);
    }

    if (setClauses.length === 0) {
      return this.getById(id);
    }

    setClauses.push('updated_at = NOW()');
    params.push(id);

    const result = await this.pool.query(
      `UPDATE users SET ${setClauses.join(', ')}
       WHERE id = $${String(params.length)}
       RETURNING id, email, display_name, role, status, mfa_enabled, last_login_at, created_at, updated_at`,
      params,
    );

    if (result.rows.length === 0) {
      throw new AppError(404, 'NOT_FOUND', 'User not found');
    }

    return mapRow(result.rows[0] as Record<string, unknown>);
  }

  async countByRole(role: UserRole): Promise<number> {
    const result = await this.pool.query(
      `SELECT COUNT(*) as count FROM users WHERE role = $1 AND status = 'active'`,
      [role],
    );
    return parseInt(result.rows[0]?.count as string, 10);
  }

  async delete(id: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE users SET status = 'disabled', updated_at = NOW() WHERE id = $1 AND status = 'active' RETURNING id`,
      [id],
    );

    if (result.rows.length === 0) {
      throw new AppError(404, 'NOT_FOUND', 'User not found');
    }
  }
}
