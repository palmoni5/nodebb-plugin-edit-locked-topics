'use strict';

const plugin = module.exports;

const privileges = require.main.require('./src/privileges');
const db = require.main.require('./src/database');
const meta = require.main.require('./src/meta');
const posts = require.main.require('./src/posts');
const topics = require.main.require('./src/topics');
const user = require.main.require('./src/user');
const plugins = require.main.require('./src/plugins');
const utils = require.main.require('./src/utils');
const activitypub = require.main.require('./src/activitypub');

const PRIVILEGE = 'posts:edit_locked';

plugin.init = async function () {
	patchPostEditPrivilege();
	patchTopicPostDisplay();
};

plugin.addCategoryPrivilege = async function ({ privileges }) {
	privileges.set(PRIVILEGE, {
		label: '[[edit-locked-topics:edit-posts-in-locked-topics]]',
		type: 'posting',
	});
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

	privileges.posts.canEdit = async function (pid, uid) {
		const isRemote = activitypub.helpers.isUri(pid);
		const results = await utils.promiseParallel({
			isAdmin: user.isAdministrator(uid),
			isMod: posts.isModerator([pid], uid),
			isOwner: posts.isOwner(pid, uid),
			isEditor: db.isSetMember(`pid:${pid}:editors`, uid),
			edit: privileges.posts.can('posts:edit', pid, uid),
			postData: posts.getPostFields(pid, ['tid', 'timestamp', 'deleted', 'deleterUid']),
			userData: user.getUserFields(uid, ['reputation']),
		});

		results.isMod = results.isMod[0];
		if (results.isAdmin) {
			return { flag: true };
		}

		if (
			!isRemote && !results.isMod &&
			meta.config.postEditDuration &&
			(Date.now() - results.postData.timestamp > meta.config.postEditDuration * 1000)
		) {
			return { flag: false, message: `[[error:post-edit-duration-expired, ${meta.config.postEditDuration}]]` };
		}
		if (
			!isRemote && !results.isMod &&
			meta.config.newbiePostEditDuration > 0 &&
			meta.config.newbieReputationThreshold > results.userData.reputation &&
			Date.now() - results.postData.timestamp > meta.config.newbiePostEditDuration * 1000
		) {
			return { flag: false, message: `[[error:post-edit-duration-expired, ${meta.config.newbiePostEditDuration}]]` };
		}

		const topicData = await topics.getTopicFields(results.postData.tid, ['cid', 'locked']);
		const editLocked = await canEditLockedTopicsInCategory(topicData.cid, uid);
		if (!results.isMod && topicData.locked && !editLocked) {
			return { flag: false, message: '[[error:topic-locked]]' };
		}

		if (!results.isMod && results.postData.deleted && parseInt(uid, 10) !== parseInt(results.postData.deleterUid, 10)) {
			return { flag: false, message: '[[error:post-deleted]]' };
		}

		results.pid = utils.isNumber(pid) ? parseInt(pid, 10) : pid;
		results.uid = uid;
		results.editLocked = editLocked;

		const result = await plugins.hooks.fire('filter:privileges.posts.edit', results);
		return {
			flag: result.edit && (result.isOwner || result.isEditor || result.isMod),
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
