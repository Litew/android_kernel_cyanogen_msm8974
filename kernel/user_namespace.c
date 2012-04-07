/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 */

#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/highuid.h>
#include <linux/cred.h>
#include <linux/securebits.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>

static struct kmem_cache *user_ns_cachep __read_mostly;

static bool new_idmap_permitted(struct user_namespace *ns, int cap_setid,
				struct uid_gid_map *map);

/*
 * Create a new user namespace, deriving the creator from the user in the
 * passed credentials, and replacing that user with the new root user for the
 * new namespace.
 *
 * This is called by copy_creds(), which will finish setting the target task's
 * credentials.
 */
int create_user_ns(struct cred *new)
{
	struct user_namespace *ns, *parent_ns = new->user_ns;
	kuid_t owner = new->euid;
	kgid_t group = new->egid;

	/* The creator needs a mapping in the parent user namespace
	 * or else we won't be able to reasonably tell userspace who
	 * created a user_namespace.
	 */
	if (!kuid_has_mapping(parent_ns, owner) ||
	    !kgid_has_mapping(parent_ns, group))
		return -EPERM;

	ns = kmem_cache_zalloc(user_ns_cachep, GFP_KERNEL);
	if (!ns)
		return -ENOMEM;

	kref_init(&ns->kref);
	ns->parent = parent_ns;
	ns->owner = owner;
	ns->group = group;

	/* Start with the same capabilities as init but useless for doing
	 * anything as the capabilities are bound to the new user namespace.
	 */
	new->securebits = SECUREBITS_DEFAULT;
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_permitted = CAP_FULL_SET;
	new->cap_effective = CAP_FULL_SET;
	new->cap_bset = CAP_FULL_SET;
#ifdef CONFIG_KEYS
	key_put(new->request_key_auth);
	new->request_key_auth = NULL;
#endif
	/* tgcred will be cleared in our caller bc CLONE_THREAD won't be set */

	/* Leave the new->user_ns reference with the new user namespace. */
	/* Leave the reference to our user_ns with the new cred. */
	new->user_ns = ns;

	return 0;
}

void free_user_ns(struct kref *kref)
{
	struct user_namespace *parent, *ns =
		container_of(kref, struct user_namespace, kref);

	parent = ns->parent;
	kmem_cache_free(user_ns_cachep, ns);
	put_user_ns(parent);
}
EXPORT_SYMBOL(free_user_ns);

static u32 map_id_range_down(struct uid_gid_map *map, u32 id, u32 count)
{
	unsigned idx, extents;
	u32 first, last, id2;

	id2 = id + count - 1;

	/* Find the matching extent */
	extents = map->nr_extents;
	smp_read_barrier_depends();
	for (idx = 0; idx < extents; idx++) {
		first = map->extent[idx].first;
		last = first + map->extent[idx].count - 1;
		if (id >= first && id <= last &&
		    (id2 >= first && id2 <= last))
			break;
	}
	/* Map the id or note failure */
	if (idx < extents)
		id = (id - first) + map->extent[idx].lower_first;
	else
		id = (u32) -1;

	return id;
}

static u32 map_id_down(struct uid_gid_map *map, u32 id)
{
	unsigned idx, extents;
	u32 first, last;

	/* Find the matching extent */
	extents = map->nr_extents;
	smp_read_barrier_depends();
	for (idx = 0; idx < extents; idx++) {
		first = map->extent[idx].first;
		last = first + map->extent[idx].count - 1;
		if (id >= first && id <= last)
			break;
	}
	/* Map the id or note failure */
	if (idx < extents)
		id = (id - first) + map->extent[idx].lower_first;
	else
		id = (u32) -1;

	return id;
}

static u32 map_id_up(struct uid_gid_map *map, u32 id)
{
	unsigned idx, extents;
	u32 first, last;

	/* Find the matching extent */
	extents = map->nr_extents;
	smp_read_barrier_depends();
	for (idx = 0; idx < extents; idx++) {
		first = map->extent[idx].lower_first;
		last = first + map->extent[idx].count - 1;
		if (id >= first && id <= last)
			break;
	}
	/* Map the id or note failure */
	if (idx < extents)
		id = (id - first) + map->extent[idx].first;
	else
		id = (u32) -1;

	return id;
}

/**
 *	make_kuid - Map a user-namespace uid pair into a kuid.
 *	@ns:  User namespace that the uid is in
 *	@uid: User identifier
 *
 *	Maps a user-namespace uid pair into a kernel internal kuid,
 *	and returns that kuid.
 *
 *	When there is no mapping defined for the user-namespace uid
 *	pair INVALID_UID is returned.  Callers are expected to test
 *	for and handle handle INVALID_UID being returned.  INVALID_UID
 *	may be tested for using uid_valid().
 */
kuid_t make_kuid(struct user_namespace *ns, uid_t uid)
{
	/* Map the uid to a global kernel uid */
	return KUIDT_INIT(map_id_down(&ns->uid_map, uid));
}
EXPORT_SYMBOL(make_kuid);

/**
 *	from_kuid - Create a uid from a kuid user-namespace pair.
 *	@targ: The user namespace we want a uid in.
 *	@kuid: The kernel internal uid to start with.
 *
 *	Map @kuid into the user-namespace specified by @targ and
 *	return the resulting uid.
 *
 *	There is always a mapping into the initial user_namespace.
 *
 *	If @kuid has no mapping in @targ (uid_t)-1 is returned.
 */
uid_t from_kuid(struct user_namespace *targ, kuid_t kuid)
{
	/* Map the uid from a global kernel uid */
	return map_id_up(&targ->uid_map, __kuid_val(kuid));
}
EXPORT_SYMBOL(from_kuid);

/**
 *	from_kuid_munged - Create a uid from a kuid user-namespace pair.
 *	@targ: The user namespace we want a uid in.
 *	@kuid: The kernel internal uid to start with.
 *
 *	Map @kuid into the user-namespace specified by @targ and
 *	return the resulting uid.
 *
 *	There is always a mapping into the initial user_namespace.
 *
 *	Unlike from_kuid from_kuid_munged never fails and always
 *	returns a valid uid.  This makes from_kuid_munged appropriate
 *	for use in syscalls like stat and getuid where failing the
 *	system call and failing to provide a valid uid are not an
 *	options.
 *
 *	If @kuid has no mapping but will be granted super user
 *	privileges over users in @targ 0 is returned.
 *
 *	If @kuid has no mapping in @targ overflowuid is returned.
 */
uid_t from_kuid_munged(struct user_namespace *targ, kuid_t kuid)
{
	uid_t uid;
	uid = from_kuid(targ, kuid);

	if (uid == (uid_t) -1) {
		struct user_namespace *ns;

		uid = overflowuid;

		/* Is kuid the creator of the target user_ns
		 * or the creator of one of it's parents?
		 */
		for (ns = targ;; ns = ns->parent) {
			if (uid_eq(ns->owner, kuid)) {
				uid = (uid_t) 0;
				break;
			}
			if (ns == &init_user_ns)
				break;
		}
	}
	return uid;
}
EXPORT_SYMBOL(from_kuid_munged);

/**
 *	make_kgid - Map a user-namespace gid pair into a kgid.
 *	@ns:  User namespace that the gid is in
 *	@uid: group identifier
 *
 *	Maps a user-namespace gid pair into a kernel internal kgid,
 *	and returns that kgid.
 *
 *	When there is no mapping defined for the user-namespace gid
 *	pair INVALID_GID is returned.  Callers are expected to test
 *	for and handle INVALID_GID being returned.  INVALID_GID may be
 *	tested for using gid_valid().
 */
kgid_t make_kgid(struct user_namespace *ns, gid_t gid)
{
	/* Map the gid to a global kernel gid */
	return KGIDT_INIT(map_id_down(&ns->gid_map, gid));
}
EXPORT_SYMBOL(make_kgid);

/**
 *	from_kgid - Create a gid from a kgid user-namespace pair.
 *	@targ: The user namespace we want a gid in.
 *	@kgid: The kernel internal gid to start with.
 *
 *	Map @kgid into the user-namespace specified by @targ and
 *	return the resulting gid.
 *
 *	There is always a mapping into the initial user_namespace.
 *
 *	If @kgid has no mapping in @targ (gid_t)-1 is returned.
 */
gid_t from_kgid(struct user_namespace *targ, kgid_t kgid)
{
	/* Map the gid from a global kernel gid */
	return map_id_up(&targ->gid_map, __kgid_val(kgid));
}
EXPORT_SYMBOL(from_kgid);

/**
 *	from_kgid_munged - Create a gid from a kgid user-namespace pair.
 *	@targ: The user namespace we want a gid in.
 *	@kgid: The kernel internal gid to start with.
 *
 *	Map @kgid into the user-namespace specified by @targ and
 *	return the resulting gid.
 *
 *	There is always a mapping into the initial user_namespace.
 *
 *	Unlike from_kgid from_kgid_munged never fails and always
 *	returns a valid gid.  This makes from_kgid_munged appropriate
 *	for use in syscalls like stat and getgid where failing the
 *	system call and failing to provide a valid gid are not options.
 *
 *	If @kuid has no mapping but will be granted super user
 *	privileges over users in @targ 0 is returned.
 *
 *	If @kgid has no mapping in @targ overflowgid is returned.
 */
gid_t from_kgid_munged(struct user_namespace *targ, kgid_t kgid)
{
	gid_t gid;
	gid = from_kgid(targ, kgid);

	if (gid == (gid_t) -1) {
		struct user_namespace *ns;

		gid = overflowgid;

		/* Is kgid the creator of the target user_ns
		 * or the creator of one of it's parents?
		 */
		for (ns = targ;; ns = ns->parent) {
			if (gid_eq(ns->group, kgid)) {
				gid = (uid_t) 0;
				break;
			}
			if (ns == &init_user_ns)
				break;
		}
	}
	return gid;
}
EXPORT_SYMBOL(from_kgid_munged);

static int uid_m_show(struct seq_file *seq, void *v)
{
	struct user_namespace *ns = seq->private;
	struct uid_gid_extent *extent = v;
	struct user_namespace *lower_ns;
	uid_t lower;

	lower_ns = current_user_ns();
	if ((lower_ns == ns) && lower_ns->parent)
		lower_ns = lower_ns->parent;

	lower = from_kuid(lower_ns, KUIDT_INIT(extent->lower_first));

	seq_printf(seq, "%10u %10u %10u\n",
		extent->first,
		lower,
		extent->count);

	return 0;
}

static int gid_m_show(struct seq_file *seq, void *v)
{
	struct user_namespace *ns = seq->private;
	struct uid_gid_extent *extent = v;
	struct user_namespace *lower_ns;
	gid_t lower;

	lower_ns = current_user_ns();
	if ((lower_ns == ns) && lower_ns->parent)
		lower_ns = lower_ns->parent;

	lower = from_kgid(lower_ns, KGIDT_INIT(extent->lower_first));

	seq_printf(seq, "%10u %10u %10u\n",
		extent->first,
		lower,
		extent->count);

	return 0;
}

static void *m_start(struct seq_file *seq, loff_t *ppos, struct uid_gid_map *map)
{
	struct uid_gid_extent *extent = NULL;
	loff_t pos = *ppos;

	if (pos < map->nr_extents)
		extent = &map->extent[pos];

	return extent;
}

static void *uid_m_start(struct seq_file *seq, loff_t *ppos)
{
	struct user_namespace *ns = seq->private;

	return m_start(seq, ppos, &ns->uid_map);
}

static void *gid_m_start(struct seq_file *seq, loff_t *ppos)
{
	struct user_namespace *ns = seq->private;

	return m_start(seq, ppos, &ns->gid_map);
}

static void *m_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return seq->op->start(seq, pos);
}

static void m_stop(struct seq_file *seq, void *v)
{
	return;
}

struct seq_operations proc_uid_seq_operations = {
	.start = uid_m_start,
	.stop = m_stop,
	.next = m_next,
	.show = uid_m_show,
};

struct seq_operations proc_gid_seq_operations = {
	.start = gid_m_start,
	.stop = m_stop,
	.next = m_next,
	.show = gid_m_show,
};

static DEFINE_MUTEX(id_map_mutex);

static ssize_t map_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos,
			 int cap_setid,
			 struct uid_gid_map *map,
			 struct uid_gid_map *parent_map)
{
	struct seq_file *seq = file->private_data;
	struct user_namespace *ns = seq->private;
	struct uid_gid_map new_map;
	unsigned idx;
	struct uid_gid_extent *extent, *last = NULL;
	unsigned long page = 0;
	char *kbuf, *pos, *next_line;
	ssize_t ret = -EINVAL;

	/*
	 * The id_map_mutex serializes all writes to any given map.
	 *
	 * Any map is only ever written once.
	 *
	 * An id map fits within 1 cache line on most architectures.
	 *
	 * On read nothing needs to be done unless you are on an
	 * architecture with a crazy cache coherency model like alpha.
	 *
	 * There is a one time data dependency between reading the
	 * count of the extents and the values of the extents.  The
	 * desired behavior is to see the values of the extents that
	 * were written before the count of the extents.
	 *
	 * To achieve this smp_wmb() is used on guarantee the write
	 * order and smp_read_barrier_depends() is guaranteed that we
	 * don't have crazy architectures returning stale data.
	 *
	 */
	mutex_lock(&id_map_mutex);

	ret = -EPERM;
	/* Only allow one successful write to the map */
	if (map->nr_extents != 0)
		goto out;

	/* Require the appropriate privilege CAP_SETUID or CAP_SETGID
	 * over the user namespace in order to set the id mapping.
	 */
	if (!ns_capable(ns, cap_setid))
		goto out;

	/* Get a buffer */
	ret = -ENOMEM;
	page = __get_free_page(GFP_TEMPORARY);
	kbuf = (char *) page;
	if (!page)
		goto out;

	/* Only allow <= page size writes at the beginning of the file */
	ret = -EINVAL;
	if ((*ppos != 0) || (count >= PAGE_SIZE))
		goto out;

	/* Slurp in the user data */
	ret = -EFAULT;
	if (copy_from_user(kbuf, buf, count))
		goto out;
	kbuf[count] = '\0';

	/* Parse the user data */
	ret = -EINVAL;
	pos = kbuf;
	new_map.nr_extents = 0;
	for (;pos; pos = next_line) {
		extent = &new_map.extent[new_map.nr_extents];

		/* Find the end of line and ensure I don't look past it */
		next_line = strchr(pos, '\n');
		if (next_line) {
			*next_line = '\0';
			next_line++;
			if (*next_line == '\0')
				next_line = NULL;
		}

		pos = skip_spaces(pos);
		extent->first = simple_strtoul(pos, &pos, 10);
		if (!isspace(*pos))
			goto out;

		pos = skip_spaces(pos);
		extent->lower_first = simple_strtoul(pos, &pos, 10);
		if (!isspace(*pos))
			goto out;

		pos = skip_spaces(pos);
		extent->count = simple_strtoul(pos, &pos, 10);
		if (*pos && !isspace(*pos))
			goto out;

		/* Verify there is not trailing junk on the line */
		pos = skip_spaces(pos);
		if (*pos != '\0')
			goto out;

		/* Verify we have been given valid starting values */
		if ((extent->first == (u32) -1) ||
		    (extent->lower_first == (u32) -1 ))
			goto out;

		/* Verify count is not zero and does not cause the extent to wrap */
		if ((extent->first + extent->count) <= extent->first)
			goto out;
		if ((extent->lower_first + extent->count) <= extent->lower_first)
			goto out;

		/* For now only accept extents that are strictly in order */
		if (last &&
		    (((last->first + last->count) > extent->first) ||
		     ((last->lower_first + last->count) > extent->lower_first)))
			goto out;

		new_map.nr_extents++;
		last = extent;

		/* Fail if the file contains too many extents */
		if ((new_map.nr_extents == UID_GID_MAP_MAX_EXTENTS) &&
		    (next_line != NULL))
			goto out;
	}
	/* Be very certaint the new map actually exists */
	if (new_map.nr_extents == 0)
		goto out;

	ret = -EPERM;
	/* Validate the user is allowed to use user id's mapped to. */
	if (!new_idmap_permitted(ns, cap_setid, &new_map))
		goto out;

	/* Map the lower ids from the parent user namespace to the
	 * kernel global id space.
	 */
	for (idx = 0; idx < new_map.nr_extents; idx++) {
		u32 lower_first;
		extent = &new_map.extent[idx];

		lower_first = map_id_range_down(parent_map,
						extent->lower_first,
						extent->count);

		/* Fail if we can not map the specified extent to
		 * the kernel global id space.
		 */
		if (lower_first == (u32) -1)
			goto out;

		extent->lower_first = lower_first;
	}

	/* Install the map */
	memcpy(map->extent, new_map.extent,
		new_map.nr_extents*sizeof(new_map.extent[0]));
	smp_wmb();
	map->nr_extents = new_map.nr_extents;

	*ppos = count;
	ret = count;
out:
	mutex_unlock(&id_map_mutex);
	if (page)
		free_page(page);
	return ret;
}

ssize_t proc_uid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	struct seq_file *seq = file->private_data;
	struct user_namespace *ns = seq->private;

	if (!ns->parent)
		return -EPERM;

	return map_write(file, buf, size, ppos, CAP_SETUID,
			 &ns->uid_map, &ns->parent->uid_map);
}

ssize_t proc_gid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	struct seq_file *seq = file->private_data;
	struct user_namespace *ns = seq->private;

	if (!ns->parent)
		return -EPERM;

	return map_write(file, buf, size, ppos, CAP_SETGID,
			 &ns->gid_map, &ns->parent->gid_map);
}

#ifdef CONFIG_KEYS
static struct cred *id_permissions_cache;

/*
 * Be stringent about the data userspace is allowed to instantiate.  So
 * we can assume the data is good elsewhere.
 *
 * The data must be a NUL-terminated string, with the NULL char accouted in
 * datalen.  The data must consist of ascending ranges of non-overlapping uids
 * encoded as uid<space>length[<space>uid<space>lenghth[...]]
 */
static int id_permission_instantiate(struct key *key, const void *data, size_t datalen)
{
	const char *str = data;
	char *pos;
	u32 first, count, last, last_count;

	/* Verify I have a '\0' terminated string */
	if (!str || datalen <= 1 || str[datalen - 1] != '\0')
		return -EINVAL;

	/* Verify that I have set of ranges in the key */
	last = 0;
	last_count = 0;
	for(pos = (char*)str; pos; pos++) {
		first = simple_strtoul(pos, &pos, 10);
		if (!isspace(*pos))
			return -EINVAL;
		pos++;
		count = simple_strtoul(pos, &pos, 10);
		if (!isspace(*pos) && *pos)
			return -EINVAL;
		/* Verify I have a good starting value */
		if (first == (u32) -1)
			return -EINVAL;
		/* Verify count is non-zero does not cause the extent to wrap */
		if ((first + count) <= first)
			return -EINVAL;
		/* Verify this range of uids is greator than the last range */
		if (last_count && ((last + last_count) > first))
			return -EINVAL;
		if (!isspace(*pos))
			break;
		last = first;
		last_count = count;
	}
	/* Verify we don't have garabage at the end of the string */
	if (*pos != '\0')
		return -EINVAL;

	return user_instantiate(key, data, datalen);
}

static struct key_type key_type_id_permissions = {
	.name		= "id_permissions",
	.instantiate	= id_permission_instantiate,
	.match		= user_match,
	.revoke		= user_revoke,
	.destroy	= user_destroy,
	.describe	= user_describe,
	.read		= user_read,
};

static bool new_idmap_permitted_by_key(struct user_namespace *ns,
				       int cap_setid, struct uid_gid_map *new_map)
{
	const struct cred *saved_cred;
	struct key *rkey;
	char description[32];
	struct user_key_payload *payload;
	bool permitted = false;
	char *pos;
	u32 first, count, last;
	unsigned idx;
	int ret;

	/* Ensure I don't have junk in cap_setid */
	switch (cap_setid) {
	case CAP_SETUID:
	case CAP_SETGID:
		break;
	default:
		return false;
	}

	/* Describe the desired key.
	 * The map of allowed uid or gids for the specified user.
	 */
	snprintf(description, sizeof(description),
		"%s:%u",
		((cap_setid == CAP_SETUID)? "uids" : "gids"),
		from_kuid(ns->parent, ns->owner));

	/* Lookup the desired key */
	saved_cred = override_creds(id_permissions_cache);
	rkey = request_key(&key_type_id_permissions, description, "");
	revert_creds(saved_cred);
	if (IS_ERR(rkey))
		return false;

	rcu_read_lock();
	rkey->perm |= KEY_USR_VIEW;

	ret = key_validate(rkey);
	if (ret < 0)
		goto out;

	payload = rcu_dereference(rkey->payload.data);
	if (IS_ERR_OR_NULL(payload))
		goto out;

	/* Ensure the lower ids from new_map are allowed. */
	for (idx = 0; idx < new_map->nr_extents; idx++) {
		bool extent_ok = false;
		u32 efirst, elast;
		efirst = new_map->extent[idx].lower_first;
		elast = efirst + new_map->extent[idx].count - 1;
		/* Walk through the key and verify that the new extent data is
		 * in a permitted range.
		 */
		for (pos = payload->data; pos && *pos;) {
			first = simple_strtoul(pos, &pos, 10);
			/* skip the space */
			pos++;
			count = simple_strtoul(pos, &pos, 10);
			if (*pos)
				pos++;
			last = first + count - 1;
			if (first <= efirst && efirst <= last &&
			    first <= elast && elast <= last)
			{
				extent_ok = true;
				break;
			}
		}
		if (!extent_ok)
			goto out;
	}
	/* All of the mapped to ids are permitted. */
	permitted = true;
out:
	rcu_read_unlock();
	key_put(rkey);
	return permitted;
}

static __init int id_permissions_init(void)
{
	struct cred *cred;
	struct key *keyring;
	int ret;

	/* Create an override credential set with a special thread keyring in
	 * which setuid permissions are cached.
	 *
	 * This is used to prevent malicious permissions rom being installed
	 * with add_key().
	 */
	cred = prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	keyring = key_alloc(&key_type_keyring, ".id_permissions",
			    cred->uid, cred->gid, cred,
			    (KEY_POS_ALL & ~KEY_POS_SETATTR) |
			    KEY_USR_VIEW | KEY_USR_READ,
			    KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto failed_put_cred;
	}

	ret = key_instantiate_and_link(keyring, NULL, 0, NULL, NULL);
	if (ret < 0)
		goto failed_put_key;

	ret = register_key_type(&key_type_id_permissions);
	if (ret < 0)
		goto failed_put_key;

	/* Instruct request_key to use this special keyring as a cache for
	 * the results it looks up.
	 */
	cred->thread_keyring = keyring;
	cred->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
	id_permissions_cache = cred;

	return 0;

failed_put_key:
	key_put(keyring);
failed_put_cred:
	put_cred(cred);
	return ret;
}

#else
static bool new_idmap_permitted_by_key(struct user_namespace *ns,
	int cap_setid, struct uid_gid_map *new_map)
{
	return false;
}

static __init int id_permissions_init(void)
{
	return 0;
}
#endif /* CONFIG_KEYS */

static bool new_idmap_permitted(struct user_namespace *ns, int cap_setid,
				struct uid_gid_map *new_map)
{
	if (new_idmap_permitted_by_key(ns, cap_setid, new_map))
		return true;

	/* Allow the specified ids if we have the appropriate capability
	 * (CAP_SETUID or CAP_SETGID) over the parent user namespace.
	 */
	if (ns_capable(ns->parent, cap_setid))
		return true;

	return false;
}

static __init int user_namespaces_init(void)
{
	user_ns_cachep = KMEM_CACHE(user_namespace, SLAB_PANIC);

	return id_permissions_init();
}
module_init(user_namespaces_init);
