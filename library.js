'use strict';

const plugin = module.exports;

const privileges = require.main.require('./src/privileges');
const db = require.main.require('./src/database');
const posts = require.main.require('./src/posts');
const topics = require.main.require('./src/topics');
const user = require.main.require('./src/user');
const plugins = require.main.require('./src/plugins');
const utils = require.main.require('./src/utils');

const PRIVILEGE = 'posts:edit_locked';

plugin.init = async function () {
	patchPostEditPrivilege();
	patchTopicPostDisplay();
};

plugin.addCategoryPrivilege = async function ({ privileges }) {
	if (privileges.has(PRIVILEGE)) {
		privileges.delete(PRIVILEGE);
	}

	const entries = Array.from(privileges.entries());
	const insertAfterIndex = entries.findIndex(([name]) => name === 'posts:edit');
	const privilegeData = {
		label: '[[edit-locked-topics:edit-posts-in-locked-topics]]',
		type: 'posting',
	};

	if (insertAfterIndex === -1) {
		privileges.set(PRIVILEGE, privilegeData);
		return;
	}

	entries.splice(insertAfterIndex + 1, 0, [PRIVILEGE, privilegeData]);
	privileges.clear();
	entries.forEach(([name, data]) => privileges.set(name, data));
};

plugin.addCategoryPrivilegeState = async function (data) {
	data[PRIVILEGE] = await canEditLockedTopicsInCategory(data.cid, data.uid);
	return data;
};

plugin.addTopicPrivilegeState = async function (data) {
	const topicData = await topics.getTopicFields(data.tid, ['cid']);
	data[PRIVILEGE] = await canEditLockedTopicsInCategory(topicData.cid, data.uid);
	return data;
};

async function canEditLockedTopicsInCategory(cid, uid) {
	if (!cid || parseInt(uid, 10) <= 0) {
		return false;
	}

	return await privileges.categories.can(PRIVILEGE, cid, uid);
}

function patchPostEditPrivilege() {
	if (privileges.posts.canEdit._editLockedTopicsPatched) {
		return;
	}

	const original = privileges.posts.canEdit;

	// Core (src/privileges/posts.js) rejects edits in a locked topic *before* it
	// fires `filter:privileges.posts.edit`, so the `posts:edit_locked` privilege
	// cannot be granted from that hook. Instead we delegate to core and intercept
	// only its specific "topic-locked" rejection, then re-run the exact checks core
	// performs after the lock gate. All other rules (admin, edit-duration, newbie,
	// remote handling) stay in core, so they can't drift out of sync on upgrade.
	privileges.posts.canEdit = async function (pid, uid) {
		const result = await original(pid, uid);
		if (!result || result.flag !== false || result.message !== '[[error:topic-locked]]') {
			return result;
		}

		const postData = await posts.getPostFields(pid, ['tid', 'timestamp', 'deleted', 'deleterUid']);
		const topicData = await topics.getTopicFields(postData.tid, ['cid']);
		if (!await canEditLockedTopicsInCategory(topicData.cid, uid)) {
			return result;
		}

		// The user is allowed to edit locked topics here — replicate core's
		// post-lock tail (the deleted-post guard, the edit hook and the final flag).
		const results = await utils.promiseParallel({
			isMod: posts.isModerator([pid], uid),
			isOwner: posts.isOwner(pid, uid),
			isEditor: db.isSetMember(`pid:${pid}:editors`, uid),
			edit: privileges.posts.can('posts:edit', pid, uid),
			userData: user.getUserFields(uid, ['reputation']),
		});
		results.isMod = results.isMod[0];
		results.isAdmin = false; // an admin would have returned flag:true before any lock check
		results.postData = postData;

		if (!results.isMod && postData.deleted && parseInt(uid, 10) !== parseInt(postData.deleterUid, 10)) {
			return { flag: false, message: '[[error:post-deleted]]' };
		}

		results.pid = utils.isNumber(pid) ? parseInt(pid, 10) : pid;
		results.uid = uid;
		results.editLocked = true;

		const hookResult = await plugins.hooks.fire('filter:privileges.posts.edit', results);
		return {
			flag: hookResult.edit && (hookResult.isOwner || hookResult.isEditor || hookResult.isMod),
			message: '[[error:no-privileges]]',
		};
	};

	privileges.posts.canEdit._editLockedTopicsPatched = true;
}

function patchTopicPostDisplay() {
	if (topics.modifyPostsByPrivilege._editLockedTopicsPatched) {
		return;
	}

	const original = topics.modifyPostsByPrivilege;
	topics.modifyPostsByPrivilege = function (topicData, topicPrivileges) {
		original(topicData, topicPrivileges);

		const canEditLocked = Boolean(
			topicData &&
			topicData.locked &&
			topicPrivileges &&
			!topicPrivileges.isAdminOrMod &&
			topicPrivileges[PRIVILEGE]
		);

		if (!canEditLocked || !Array.isArray(topicData.posts)) {
			return;
		}

		topicData.posts.forEach((post) => {
			if (!post || !post.selfPost) {
				return;
			}

			post.display_edit_tools = true;
			post.display_moderator_tools = post.display_edit_tools || post.display_delete_tools;

			if (!post.deleted) {
				post.display_post_menu = true;
			}
		});
	};

	topics.modifyPostsByPrivilege._editLockedTopicsPatched = true;
}
