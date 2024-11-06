


















hive_node_h hivex_root (hive_h *h)
{
  hive_node_h ret = h->rootoffs;
  if (!IS_VALID_BLOCK (h, ret)) {
    SET_ERRNO (HIVEX_NO_KEY, "no root key");
    return 0;
  }
  return ret;
}

size_t hivex_node_struct_length (hive_h *h, hive_node_h node)
{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return 0;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) ((char *) h->addr + node);
  size_t name_len = le16toh (nk->name_len);
  
  size_t ret = name_len + sizeof (struct ntreg_nk_record) - 1;
  int used;
  size_t seg_len = block_len (h, node, &used);
  if (ret > seg_len) {
    SET_ERRNO (EFAULT, "node name is too long (%zu, %zu)", name_len, seg_len);
    return 0;
  }
  return ret;
}

char * hivex_node_name (hive_h *h, hive_node_h node)
{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return NULL;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) ((char *) h->addr + node);

  
  size_t len = le16toh (nk->name_len);
  size_t seg_len = block_len (h, node, NULL);
  if (sizeof (struct ntreg_nk_record) + len - 1 > seg_len) {
    SET_ERRNO (EFAULT, "node name is too long (%zu, %zu)", len, seg_len);
    return NULL;
  }
  size_t flags = le16toh (nk->flags);
  if (flags & 0x20) {
    return _hivex_recode (h, latin1_to_utf8, nk->name, len, NULL);
  } else {
    return _hivex_recode (h, utf16le_to_utf8, nk->name, len, NULL);
  }
}

size_t hivex_node_name_len (hive_h *h, hive_node_h node)
{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return 0;
  }
  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) ((char *) h->addr + node);

  
  size_t len = le16toh (nk->name_len);
  size_t seg_len = block_len (h, node, NULL);
  if (sizeof (struct ntreg_nk_record) + len - 1 > seg_len) {
    SET_ERRNO (EFAULT, "node name is too long (%zu, %zu)", len, seg_len);
    return 0;
  }

  return _hivex_utf8_strlen (h, nk->name, len, ! (le16toh (nk->flags) & 0x20));
}


static int64_t timestamp_check (hive_h *h, hive_node_h node, int64_t timestamp)
{
  if (timestamp < 0) {
    SET_ERRNO (EINVAL, "negative time reported at %zu: %" PRIi64, node, timestamp);
    return -1;
  }

  return timestamp;
}

int64_t hivex_last_modified (hive_h *h)
{
  return timestamp_check (h, 0, h->last_modified);
}

int64_t hivex_node_timestamp (hive_h *h, hive_node_h node)
{
  int64_t ret;

  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return -1;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) ((char *) h->addr + node);

  ret = le64toh (nk->timestamp);
  return timestamp_check (h, node, ret);
}




hive_security_h hivex_node_security (hive_h *h, hive_node_h node)
{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return 0;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

  hive_node_h ret = le32toh (nk->sk);
  ret += 0x1000;
  if (!IS_VALID_BLOCK (h, ret)) {
    SET_ERRNO (EFAULT, "invalid block");
    return 0;
  }
  return ret;
}

hive_classname_h hivex_node_classname (hive_h *h, hive_node_h node)
{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return 0;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) (h->addr + node);

  hive_node_h ret = le32toh (nk->classname);
  ret += 0x1000;
  if (!IS_VALID_BLOCK (h, ret)) {
    SET_ERRNO (EFAULT, "invalid block");
    return 0;
  }
  return ret;
}


static int _get_children (hive_h *h, hive_node_h blkoff, offset_list *children, offset_list *blocks, int flags);

static int check_child_is_nk_block (hive_h *h, hive_node_h child, int flags);


int _hivex_get_children (hive_h *h, hive_node_h node, hive_node_h **children_ret, size_t **blocks_ret, int flags)


{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return -1;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) ((char *) h->addr + node);

  size_t nr_subkeys_in_nk = le32toh (nk->nr_subkeys);

  offset_list children, blocks;
  _hivex_init_offset_list (h, &children);
  _hivex_init_offset_list (h, &blocks);

  
  if (nr_subkeys_in_nk == 0)
    goto out;

  
  if (nr_subkeys_in_nk > HIVEX_MAX_SUBKEYS) {
    SET_ERRNO (ERANGE, "nr_subkeys_in_nk > HIVEX_MAX_SUBKEYS (%zu > %d)", nr_subkeys_in_nk, HIVEX_MAX_SUBKEYS);

    goto error;
  }

  
  _hivex_set_offset_list_limit (&children, nr_subkeys_in_nk);

  
  _hivex_set_offset_list_limit (&blocks, HIVEX_MAX_SUBKEYS);

  
  if (_hivex_grow_offset_list (&children, nr_subkeys_in_nk) == -1)
    goto error;

  
  size_t subkey_lf = le32toh (nk->subkey_lf);
  subkey_lf += 0x1000;
  if (!IS_VALID_BLOCK (h, subkey_lf)) {
    SET_ERRNO (EFAULT, "subkey_lf is not a valid block (0x%zx)", subkey_lf);
    goto error;
  }

  if (_get_children (h, subkey_lf, &children, &blocks, flags) == -1)
    goto error;

  
  size_t nr_children = _hivex_get_offset_list_length (&children);
  if (nr_subkeys_in_nk != nr_children) {
    if (!h->unsafe) {
      SET_ERRNO (ENOTSUP, "nr_subkeys_in_nk = %zu " "is not equal to number of children read %zu", nr_subkeys_in_nk, nr_children);


      goto error;
    } else {
      DEBUG (2, "nr_subkeys_in_nk = %zu " "is not equal to number of children read %zu", nr_subkeys_in_nk, nr_children);


    }
  }

 out:

  if (h->msglvl >= 2) {
    fprintf (stderr, "%s: %s: children = ", "hivex", __func__);
    _hivex_print_offset_list (&children, stderr);
    fprintf (stderr, "\n%s: %s: blocks = ", "hivex", __func__);
    _hivex_print_offset_list (&blocks, stderr);
    fprintf (stderr, "\n");
  }


  *children_ret = _hivex_return_offset_list (&children);
  *blocks_ret = _hivex_return_offset_list (&blocks);
  if (!*children_ret || !*blocks_ret)
    goto error;
  return 0;

 error:
  _hivex_free_offset_list (&children);
  _hivex_free_offset_list (&blocks);
  return -1;
}

static int _get_children (hive_h *h, hive_node_h blkoff, offset_list *children, offset_list *blocks, int flags)


{
  
  if (_hivex_add_to_offset_list (blocks, blkoff) == -1)
    return -1;

  struct ntreg_hbin_block *block = (struct ntreg_hbin_block *) ((char *) h->addr + blkoff);

  size_t len = block_len (h, blkoff, NULL);

  
  if (block->id[0] == 'l' && (block->id[1] == 'f' || block->id[1] == 'h')) {
    struct ntreg_lf_record *lf = (struct ntreg_lf_record *) block;

    
    size_t nr_subkeys_in_lf = le16toh (lf->nr_keys);

    if (8 + nr_subkeys_in_lf * 8 > len) {
      SET_ERRNO (EFAULT, "too many subkeys (%zu, %zu)", nr_subkeys_in_lf, len);
      return -1;
    }

    size_t i;
    for (i = 0; i < nr_subkeys_in_lf; ++i) {
      hive_node_h subkey = le32toh (lf->keys[i].offset);
      subkey += 0x1000;
      if (check_child_is_nk_block (h, subkey, flags) == -1) {
        if (h->unsafe) {
          DEBUG (2, "subkey at 0x%zx is not an NK block, skipping", subkey);
          continue;
        } else {
          return -1;
        }
      }
      if (_hivex_add_to_offset_list (children, subkey) == -1)
        return -1;
    }
  }
  
  else if (block->id[0] == 'l' && block->id[1] == 'i') {
    
    struct ntreg_ri_record *ri = (struct ntreg_ri_record *) block;

    
    size_t nr_offsets = le16toh (ri->nr_offsets);

    if (8 + nr_offsets * 4 > len) {
      SET_ERRNO (EFAULT, "too many offsets (%zu, %zu)", nr_offsets, len);
      return -1;
    }

    size_t i;
    for (i = 0; i < nr_offsets; ++i) {
      hive_node_h subkey = le32toh (ri->offset[i]);
      subkey += 0x1000;
      if (check_child_is_nk_block (h, subkey, flags) == -1) {
        if (h->unsafe) {
          DEBUG (2, "subkey at 0x%zx is not an NK block, skipping", subkey);
          continue;
        } else {
          return -1;
        }
      }
      if (_hivex_add_to_offset_list (children, subkey) == -1)
        return -1;
    }
  }
  
  else if (block->id[0] == 'r' && block->id[1] == 'i') {
    struct ntreg_ri_record *ri = (struct ntreg_ri_record *) block;

    size_t nr_offsets = le16toh (ri->nr_offsets);

    if (8 + nr_offsets * 4 > len) {
      SET_ERRNO (EFAULT, "too many offsets (%zu, %zu)", nr_offsets, len);
      return -1;
    }

    
    size_t i;
    for (i = 0; i < nr_offsets; ++i) {
      hive_node_h offset = le32toh (ri->offset[i]);
      offset += 0x1000;
      if (!IS_VALID_BLOCK (h, offset)) {
        if (h->unsafe) {
          DEBUG (2, "ri-offset is not a valid block (0x%zx), skipping", offset);
          continue;
        } else {
          SET_ERRNO (EFAULT, "ri-offset is not a valid block (0x%zx)", offset);
          return -1;
        }
      }

      if (_get_children (h, offset, children, blocks, flags) == -1)
        return -1;
    }
  }
  else {
    SET_ERRNO (ENOTSUP, "subkey block is not lf/lh/li/ri (0x%zx, %d, %d)", blkoff, block->id[0], block->id[1]);

    return -1;
  }

  return 0;
}

static int check_child_is_nk_block (hive_h *h, hive_node_h child, int flags)
{
  
  if (flags & GET_CHILDREN_NO_CHECK_NK)
    return 0;

  if (!IS_VALID_BLOCK (h, child)) {
    SET_ERRNO (EFAULT, "subkey is not a valid block (0x%zx)", child);
    return -1;
  }

  struct ntreg_hbin_block *block = (struct ntreg_hbin_block *) ((char *) h->addr + child);

  if (!block_id_eq (h, child, "nk")) {
    SET_ERRNO (EFAULT, "subkey is not an 'nk' block (0x%zx, %d, %d)", child, block->id[0], block->id[1]);
    return -1;
  }

  return 0;
}

hive_node_h * hivex_node_children (hive_h *h, hive_node_h node)
{
  hive_node_h *children;
  size_t *blocks;

  if (_hivex_get_children (h, node, &children, &blocks, 0) == -1)
    return NULL;

  free (blocks);
  return children;
}

size_t hivex_node_nr_children (hive_h *h, hive_node_h node)
{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO( EINVAL, "invalid block or not an 'nk' block");
    return 0;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) ((char *) h->addr + node);

  size_t nr_subkeys_in_nk = le32toh (nk->nr_subkeys);

  return nr_subkeys_in_nk;
}


hive_node_h hivex_node_get_child (hive_h *h, hive_node_h node, const char *nname)
{
  hive_node_h *children = NULL;
  char *name = NULL;
  hive_node_h ret = 0;

  children = hivex_node_children (h, node);
  if (!children) goto error;

  size_t i;
  for (i = 0; children[i] != 0; ++i) {
    name = hivex_node_name (h, children[i]);
    if (!name) goto error;
    if (STRCASEEQ (name, nname)) {
      ret = children[i];
      break;
    }
    free (name); name = NULL;
  }

 error:
  free (children);
  free (name);
  return ret;
}

hive_node_h hivex_node_parent (hive_h *h, hive_node_h node)
{
  if (!IS_VALID_BLOCK (h, node) || !block_id_eq (h, node, "nk")) {
    SET_ERRNO (EINVAL, "invalid block or not an 'nk' block");
    return 0;
  }

  struct ntreg_nk_record *nk = (struct ntreg_nk_record *) ((char *) h->addr + node);

  hive_node_h ret = le32toh (nk->parent);
  ret += 0x1000;
  if (!IS_VALID_BLOCK (h, ret)) {
    SET_ERRNO (EFAULT, "parent is not a valid block (0x%zx)", ret);
    return 0;
  }
  return ret;
}
