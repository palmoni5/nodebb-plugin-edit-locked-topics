'use strict';

(function () {
	require(['hooks', 'forum/topic/posts', 'forum/topic/threadTools'], function (hooks, Posts, ThreadTools) {
		const privilege = 'posts:edit_locked';

		function canEditLockedTopics() {
			return Boolean(
				app.user.uid &&
				ajaxify.data &&
				ajaxify.data.locked &&
				ajaxify.data.privileges &&
				ajaxify.data.privileges[privilege]
			);
		}

		function revealEditControls() {
			if (!canEditLockedTopics()) {
				return;
			}

			const selfPosts = $('[component="post"][data-uid="' + app.user.uid + '"]');
			selfPosts.not('.deleted').find('[component="post/tools"]').removeClass('hidden');
			selfPosts.find('[component="post/edit"]').removeClass('hidden');
		}

		const originalModifyPostsByPrivileges = Posts.modifyPostsByPrivileges;
		Posts.modifyPostsByPrivileges = function (posts) {
			originalModifyPostsByPrivileges(posts);

			if (!canEditLockedTopics()) {
				return;
			}

			posts.forEach(function (post) {
				if (!post || !post.selfPost || post.deleted) {
					return;
				}

				post.display_edit_tools = true;
				post.display_moderator_tools = true;
				post.display_post_menu = true;
			});
		};

		const originalSetLockedState = ThreadTools.setLockedState;
		ThreadTools.setLockedState = function (data) {
			originalSetLockedState(data);
			revealEditControls();
		};

		hooks.on('action:ajaxify.end', function () {
			revealEditControls();
		});
	});
}());
