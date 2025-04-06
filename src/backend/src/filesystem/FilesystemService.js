/*
 * Copyright (C) 2024-present Puter Technologies Inc.
 *
 * This file is part of Puter.
 *
 * Puter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// FilesystemService: Manages all file system operations in Puter,
// including creating shortcuts and symlinks, updating paths,
// enforcing permissions, and fetching nodes and entries.

const { RESOURCE_STATUS_PENDING_CREATE } = require('../modules/puterfs/ResourceService.js');
const { TraceService } = require('../services/TraceService.js');
const PerformanceMonitor = require('../monitor/PerformanceMonitor.js');
const { NodePathSelector, NodeUIDSelector, NodeInternalIDSelector } = require('./node/selectors.js');
const FSNodeContext = require('./FSNodeContext.js');
const { AdvancedBase } = require('@heyputer/putility');
const { Context } = require('../util/context.js');
const { simple_retry } = require('../util/retryutil.js');
const APIError = require('../api/APIError.js');
const { LLMkdir } = require('./ll_operations/ll_mkdir.js');
const { LLCWrite, LLOWrite } = require('./ll_operations/ll_write.js');
const { LLCopy } = require('./ll_operations/ll_copy.js');
const { PermissionUtil, PermissionRewriter, PermissionImplicator, PermissionExploder } = require('../services/auth/PermissionService.js');
const { DB_WRITE } = require("../services/database/consts");
const { UserActorType } = require('../services/auth/Actor');
const { get_user } = require('../helpers');
const BaseService = require('../services/BaseService');
const { PuterFSProvider } = require('../modules/puterfs/lib/PuterFSProvider.js');

class FilesystemService extends BaseService {
    static MODULES = {
        _path: require('path'),
        uuidv4: require('uuid').v4,
        config: require('../config.js'),
    }

    // Sets up logging, database connection, and info strategy for fsentry.path
    old_constructor(args) {
        const { services } = args;

        // Register trace service
        services.registerService('traceService', TraceService);

        // Create a logger for filesystem operations
        this.log = services.get('log-service').create('filesystem-service');

        // Database handle for updating child paths
        this.db = services.get('database').get(DB_WRITE, 'filesystem');

        // Provide a strategy to resolve fsentry.path via UUID if missing
        const info = services.get('information');
        info.given('fs.fsentry').provide('fs.fsentry:path')
            .addStrategy('entry-or-delegate', async entry => {
                if (entry.path) return entry.path;
                return await info
                    .with('fs.fsentry:uuid')
                    .obtain('fs.fsentry:path')
                    .exec(entry.uuid);
            });
    }

    // Initializes dynamic permission rules for filesystem operations
    async _init() {
        this.old_constructor({ services: this.services });
        const svc_permission = this.services.get('permission');

        // Rewrite permissions from path-based to UID-based
        svc_permission.register_rewriter(PermissionRewriter.create({
            matcher: permission => permission.startsWith('fs:'),
            rewriter: async permission => {
                const [_, path, ...rest] = PermissionUtil.split(permission);
                const node = await this.node(new NodePathSelector(path));
                if (!await node.exists()) {
                    throw APIError.create('subject_does_not_exist');
                }
                const uid = await node.get('uid');
                if (!uid) {
                    throw new Error(`UID is undefined for path ${path}`);
                }
                return `fs:${uid}:${rest.join(':')}`;
            },
        }));

        // Implicate 'is-owner' permission if the user owns the node
        svc_permission.register_implicator(PermissionImplicator.create({
            id: 'is-owner',
            matcher: permission => permission.startsWith('fs:'),
            checker: async ({ actor, permission }) => {
                if (!(actor.type instanceof UserActorType)) return undefined;
                const [_, uid] = PermissionUtil.split(permission);
                const node = await this.node(new NodeUIDSelector(uid));
                if (!await node.exists()) return undefined;
                const owner_id = await node.get('user_id');
                if (owner_id === actor.type.user.id) return {};
                return undefined;
            },
        }));

        // Explode permissions into finer-grained actions (see->list->read->write)
        svc_permission.register_exploder(PermissionExploder.create({
            id: 'fs-access-levels',
            matcher: permission => permission.startsWith('fs:') && PermissionUtil.split(permission).length >= 3,
            exploder: async ({ permission }) => {
                const permissions = [permission];
                const parts = PermissionUtil.split(permission);
                const mode = parts[2];
                const rules = { see: ['list','read','write'], list: ['read','write'], read: ['write'] };
                if (rules[mode]) {
                    permissions.push(...rules[mode].map(m => PermissionUtil.join(parts[0], parts[1], m, ...parts.slice(3))));
                }
                return permissions;
            },
        }));
    }

    // Creates a shortcut: checks ACL, registers resource, inserts fsentry, emits event
    async mkshortcut({ parent, name, user, target }) {
        const svc_acl = this.services.get('acl');
        if (!await svc_acl.check(user, target, 'read')) throw await svc_acl.get_safe_acl_error(user, target, 'read');
        if (!await svc_acl.check(user, parent, 'write')) throw await svc_acl.get_safe_acl_error(user, parent, 'write');

        if (!await target.exists()) throw APIError.create('shortcut_to_does_not_exist');
        await target.fetchEntry({ thumbnail: true });

        const { _path, uuidv4 } = this.modules;
        const svc_fsEntry = this.services.get('fsEntryService');
        const resourceService = this.services.get('resourceService');
        const ts = Math.floor(Date.now() / 1000);
        const uid = uuidv4();

        resourceService.register({ uid, status: RESOURCE_STATUS_PENDING_CREATE });
        const raw_fsentry = {
            is_shortcut: 1,
            shortcut_to: target.mysql_id,
            is_dir: target.entry.is_dir,
            thumbnail: target.entry.thumbnail,
            uuid: uid,
            parent_uid: await parent.get('uid'),
            path: _path.join(await parent.get('path'), name),
            user_id: user.id,
            name,
            created: ts,
            updated: ts,
            modified: ts,
            immutable: false,
        };
        this.log.debug('creating fsentry', { fsentry: raw_fsentry });
        const entryOp = await svc_fsEntry.insert(raw_fsentry);
        (async () => {
            await entryOp.awaitDone();
            this.log.debug('finished creating fsentry', { uid });
            resourceService.free(uid);
        })();

        const node = await this.node(new NodeUIDSelector(uid));
        this.services.get('event').emit('fs.create.shortcut', { node, context: Context.get() });
        return node;
    }

    // Creates a symlink: checks ACL, registers resource, inserts fsentry, emits event
    async mklink({ parent, name, user, target }) {
        const svc_acl = this.services.get('acl');
        if (!await svc_acl.check(user, parent, 'write')) throw await svc_acl.get_safe_acl_error(user, parent, 'write');

        const { _path, uuidv4 } = this.modules;
        const resourceService = this.services.get('resourceService');
        const svc_fsEntry = this.services.get('fsEntryService');
        const ts = Math.floor(Date.now() / 1000);
        const uid = uuidv4();

        resourceService.register({ uid, status: RESOURCE_STATUS_PENDING_CREATE });
        const raw_fsentry = {
            is_symlink: 1,
            symlink_path: target,
            is_dir: 0,
            uuid: uid,
            parent_uid: await parent.get('uid'),
            path: _path.join(await parent.get('path'), name),
            user_id: user.id,
            name,
            created: ts,
            updated: ts,
            modified: ts,
            immutable: false,
        };
        this.log.debug('creating symlink', { fsentry: raw_fsentry });
        const entryOp = await svc_fsEntry.insert(raw_fsentry);
        (async () => {
            await entryOp.awaitDone();
            this.log.debug('finished creating symlink', { uid });
            resourceService.free(uid);
        })();

        const node = await this.node(new NodeUIDSelector(uid));
        this.services.get('event').emit('fs.create.symlink', { node, context: Context.get() });
        return node;
    }

    // Updates all child entry paths when a parent directory path changes
    async update_child_paths(old_path, new_path, user_id) {
        const monitor = this.services.get('performance-monitor').createContext('update_child_paths');
        if (!old_path.endsWith('/')) old_path += '/';
        if (!new_path.endsWith('/')) new_path += '/';
        await this.db.write(
            `UPDATE fsentries SET path = CONCAT(?, SUBSTRING(path, ?)) WHERE path LIKE ? AND user_id = ?`,
            [new_path, old_path.length + 1, old_path + '%', user_id]
        );
        this.services.get('log-service').create('update_child_paths').info(`updated ${old_path} -> ${new_path}`);
        monitor.end();
    }

    // Returns an FSNodeContext for the given selector (path, uid, or internal ID)
    async node(selector) {
        if (typeof selector === 'string') {
            selector = selector.startsWith('/')
                ? new NodePathSelector(selector)
                : new NodeUIDSelector(selector);
        }
        if (selector && selector.constructor.name === 'Object') {
            if (selector.path) selector = new NodePathSelector(selector.path);
            else if (selector.uid) selector = new NodeUIDSelector(selector.uid);
            else selector = new NodeInternalIDSelector('mysql', selector.mysql_id);
        }
        const provider = await this.services.get('mountpoint').get_provider(selector);
        return new FSNodeContext({ provider, services: this.services, selector, fs: this });
    }

    // Retrieves a raw filesystem entry for the given selector (not client-safe)
    async get_entry({ path, uid, id, mysql_id, ...options }) {
        const fsNode = await this.node({ path, uid, id, mysql_id });
        await fsNode.fetchEntry(options);
        return fsNode.entry;
    }
}

module.exports = { FilesystemService };
